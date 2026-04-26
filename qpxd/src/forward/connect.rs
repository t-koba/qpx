use super::policy::{evaluate_forward_policy, ForwardPolicyDecision};
use crate::destination::DestinationInputs;
use crate::forward::request::{proxy_auth_required, resolve_upstream, resolve_upstream_url};
use crate::http::address::parse_authority_host_port;
use crate::http::body::Body;
use crate::http::common::{
    blocked_response as blocked, connect_established_response as connect_established,
    forbidden_response as forbidden, http_version_label,
    too_many_requests_response as too_many_requests,
};
use crate::http::h2_codec::{
    h1_headers_to_http, h2_response_to_hyper, http_headers_to_h1,
    parse_declared_content_length as parse_h2_content_length,
};
use crate::http::l7::{
    finalize_extended_connect_response_with_headers, finalize_response_for_request,
    finalize_response_with_headers, prepare_request_with_headers_in_place,
};
use crate::http::local_response::build_local_response;
use crate::io_copy::{copy_bidirectional_with_export_and_idle, BandwidthThrottle};
use crate::io_prefix::PrefixedIo;
use crate::policy_context::{
    apply_ext_authz_action_overrides, attach_log_context, emit_audit_log, enforce_ext_authz,
    resolve_identity, sanitize_headers_for_policy, validate_ext_authz_allow_mode, AuditRecord,
    EffectivePolicyContext, ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode,
};
use crate::rate_limit::RateLimitContext;
use crate::runtime::Runtime;
use crate::tls::client::preview_tls_certificate_with_options;
use crate::tls::client::{connect_tls_h2_h1_with_options, BoxTlsStream};
use crate::tls::{
    extract_client_hello_info, looks_like_tls_client_hello, try_read_client_hello_with_timeout,
    CompiledUpstreamTlsTrust, TlsClientHelloInfo, UpstreamCertificateInfo,
};
use crate::upstream::connect::{connect_tunnel_target, ConnectedTunnel};
use ::http::{
    HeaderMap, HeaderMap as Http1HeaderMap, Method, Request, Request as Http1Request, Response,
    Response as Http1Response, StatusCode, Uri,
};
#[cfg(feature = "mitm")]
use anyhow::Context;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::ext::Protocol as H2Protocol;
use h2::{client as h2_client, Reason as H2Reason, RecvStream as H2RecvStream};
use qpx_core::config::{ActionConfig, ActionKind, ListenerConfig};
use qpx_core::rules::RuleMatchContext;
use std::net::SocketAddr;
#[cfg(feature = "mitm")]
use std::sync::Arc;
use std::{
    future::{poll_fn, Future},
    pin::Pin,
    task::Poll,
};
use tokio::net::{lookup_host, TcpStream};
use tokio::task;
use tokio::time::{timeout, Duration};
use tracing::warn;

#[cfg(feature = "mitm")]
use crate::http::mitm::{proxy_mitm_request, MitmRouteContext};
#[cfg(feature = "mitm")]
use crate::tls::mitm::{accept_mitm_client, connect_mitm_upstream};

#[path = "connect_extended.rs"]
mod connect_extended;
#[path = "connect_h2.rs"]
mod connect_h2;
#[path = "connect_inspect.rs"]
mod connect_inspect;
#[path = "connect_tunnel.rs"]
mod connect_tunnel;

use self::connect_extended::{
    default_port_for_scheme, open_upstream_h2_extended_connect_stream,
    spawn_h2_extended_connect_relay, H2ExtendedConnectUpstream,
};
use self::connect_h2::handle_h2_extended_connect;
pub(super) use self::connect_inspect::{
    decide_connect_action_from_client_hello, decide_connect_action_from_tls_metadata,
    listener_requires_upstream_cert_preview, listener_upstream_trust, ConnectPolicyInput,
};
use self::connect_tunnel::{tunnel_connect, TunnelConnectContext};

pub(super) async fn handle_connect(
    req: Request<Body>,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: SocketAddr,
) -> Result<Response<Body>> {
    if req.version() == http::Version::HTTP_2 && req.extensions().get::<H2Protocol>().is_some() {
        return handle_h2_extended_connect(req, runtime, listener_name, remote_addr).await;
    }
    let state = runtime.state();
    let proxy_name = state.config.identity.proxy_name.as_str();
    let req_version = req.version();
    let listener_cfg = state
        .listener_config(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    let effective_policy =
        EffectivePolicyContext::from_single(listener_cfg.policy_context.as_ref());

    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| anyhow!("missing authority"))?
        .as_str()
        .to_string();
    let (host, port) = parse_authority_host_port(&authority, 443)
        .ok_or_else(|| anyhow!("invalid connect authority"))?;
    let audit_host = host.clone();
    let sanitized_headers =
        sanitize_headers_for_policy(&state, &effective_policy, remote_addr.ip(), req.headers())?;
    let mut identity = resolve_identity(
        &state,
        &effective_policy,
        remote_addr.ip(),
        Some(&sanitized_headers),
        None,
    )?;
    let destination = state.classify_destination(
        &DestinationInputs {
            host: Some(host.as_str()),
            ip: host.parse().ok(),
            sni: Some(host.as_str()),
            scheme: Some("https"),
            port: Some(port),
            ..Default::default()
        },
        listener_cfg.destination_resolution.as_ref(),
    );

    let ctx = RuleMatchContext {
        src_ip: Some(remote_addr.ip()),
        dst_port: Some(port),
        host: Some(host.as_str()),
        sni: Some(host.as_str()),
        method: Some("CONNECT"),
        path: None,
        authority: Some(authority.as_str()),
        http_version: Some(http_version_label(req_version)),
        destination_category: destination.category.as_deref(),
        destination_category_source: destination.category_source.as_deref(),
        destination_category_confidence: destination.category_confidence.map(u64::from),
        destination_reputation: destination.reputation.as_deref(),
        destination_reputation_source: destination.reputation_source.as_deref(),
        destination_reputation_confidence: destination.reputation_confidence.map(u64::from),
        destination_application: destination.application.as_deref(),
        destination_application_source: destination.application_source.as_deref(),
        destination_application_confidence: destination.application_confidence.map(u64::from),
        headers: Some(&sanitized_headers),
        user: identity.user.as_deref(),
        user_groups: &identity.groups,
        device_id: identity.device_id.as_deref(),
        posture: &identity.posture,
        tenant: identity.tenant.as_deref(),
        auth_strength: identity.auth_strength.as_deref(),
        idp: identity.idp.as_deref(),
        ..Default::default()
    };

    let (mut action, matched_rule) = match evaluate_forward_policy(
        &runtime,
        listener_name,
        ctx,
        &sanitized_headers,
        "CONNECT",
        &authority,
    )
    .await?
    {
        ForwardPolicyDecision::Allow(allowed) => {
            identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
            (allowed.action, allowed.matched_rule)
        }
        ForwardPolicyDecision::Challenge(chal) => {
            let log_context = identity.to_log_context(None, None, None);
            let response = proxy_auth_required(chal, state.messages.proxy_auth_required.as_str());
            let mut response = finalize_response_for_request(
                &Method::CONNECT,
                req_version,
                proxy_name,
                response,
                false,
            );
            attach_log_context(&mut response, &log_context);
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "forward",
                    name: listener_name,
                    remote_ip: remote_addr.ip(),
                    host: Some(host.as_str()),
                    sni: Some(host.as_str()),
                    method: Some("CONNECT"),
                    path: None,
                    outcome: "challenge",
                    status: Some(response.status().as_u16()),
                    matched_rule: None,
                    matched_route: None,
                    ext_authz_policy_id: None,
                },
                &log_context,
            );
            return Ok(response);
        }
        ForwardPolicyDecision::Forbidden => {
            let log_context = identity.to_log_context(None, None, None);
            let mut response = finalize_response_for_request(
                &Method::CONNECT,
                req_version,
                proxy_name,
                forbidden(state.messages.forbidden.as_str()),
                false,
            );
            attach_log_context(&mut response, &log_context);
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "forward",
                    name: listener_name,
                    remote_ip: remote_addr.ip(),
                    host: Some(host.as_str()),
                    sni: Some(host.as_str()),
                    method: Some("CONNECT"),
                    path: None,
                    outcome: "forbidden",
                    status: Some(response.status().as_u16()),
                    matched_rule: None,
                    matched_route: None,
                    ext_authz_policy_id: None,
                },
                &log_context,
            );
            return Ok(response);
        }
    };
    let request_limit_ctx =
        RateLimitContext::from_identity(remote_addr.ip(), &identity, matched_rule.as_deref(), None);
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_request(
        crate::rate_limit::RequestLimitCollectInput {
            listener: Some(listener_name),
            rule: matched_rule.as_deref(),
            profile: None,
            scope: crate::rate_limit::TransportScope::Connect,
            extra: None,
            ctx: &request_limit_ctx,
            cost: 1,
        },
    )?;
    if let Some(retry_after) = retry_after {
        return Ok(finalize_response_for_request(
            &Method::CONNECT,
            req_version,
            proxy_name,
            too_many_requests(Some(retry_after)),
            false,
        ));
    }
    let ext_authz = enforce_ext_authz(
        &state,
        &effective_policy,
        ExtAuthzInput {
            proxy_kind: "forward",
            proxy_name,
            scope_name: listener_name,
            remote_ip: remote_addr.ip(),
            dst_port: Some(port),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: None,
            uri: Some(authority.as_str()),
            matched_rule: matched_rule.as_deref(),
            matched_route: None,
            action: Some(&action),
            headers: Some(&sanitized_headers),
            identity: &identity,
        },
    )
    .await?;
    let ext_authz_policy_id = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_id.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_id.clone(),
    };
    let ext_authz_policy_tags = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_tags.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_tags.clone(),
    };
    let mut log_context = identity.to_log_context(
        matched_rule.as_deref(),
        None,
        ext_authz_policy_id.as_deref(),
    );
    log_context.policy_tags = ext_authz_policy_tags;
    let annotate = |response: &mut Response<Body>, outcome: &'static str| {
        attach_log_context(response, &log_context);
        emit_audit_log(
            &state,
            AuditRecord {
                kind: "forward",
                name: listener_name,
                remote_ip: remote_addr.ip(),
                host: Some(audit_host.as_str()),
                sni: Some(audit_host.as_str()),
                method: Some("CONNECT"),
                path: None,
                outcome,
                status: Some(response.status().as_u16()),
                matched_rule: matched_rule.as_deref(),
                matched_route: None,
                ext_authz_policy_id: ext_authz_policy_id.as_deref(),
            },
            &log_context,
        );
    };
    let (response_headers, timeout_override) = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ForwardConnect)?;
            if let Some(retry_after) = request_limits.merge_profile_and_check(
                &state.policy.rate_limiters,
                allow.rate_limit_profile.as_deref(),
                crate::rate_limit::TransportScope::Connect,
                &request_limit_ctx,
                1,
            )? {
                return Ok(finalize_response_for_request(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    too_many_requests(Some(retry_after)),
                    false,
                ));
            }
            apply_ext_authz_action_overrides(&mut action, &allow);
            (allow.headers, allow.timeout_override)
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let mut response = if let Some(local) = deny.local_response.as_ref() {
                finalize_response_with_headers(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    build_local_response(local)?,
                    deny.headers.as_deref(),
                    false,
                )
            } else {
                finalize_response_with_headers(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    forbidden(state.messages.forbidden.as_str()),
                    deny.headers.as_deref(),
                    false,
                )
            };
            annotate(
                &mut response,
                if deny.local_response.is_some() {
                    "ext_authz_local_response"
                } else {
                    "ext_authz_deny"
                },
            );
            return Ok(response);
        }
    };
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.config.runtime.upstream_http_timeout_ms));

    match action.kind {
        ActionKind::Block => {
            let mut response = finalize_response_with_headers(
                &Method::CONNECT,
                req_version,
                proxy_name,
                blocked(state.messages.blocked.as_str()),
                response_headers.as_deref(),
                false,
            );
            annotate(&mut response, "block");
            Ok(response)
        }
        ActionKind::Respond => {
            let local = action
                .local_response
                .as_ref()
                .ok_or_else(|| anyhow!("respond action requires local_response"))?;
            let mut response = finalize_response_with_headers(
                &Method::CONNECT,
                req_version,
                proxy_name,
                build_local_response(local)?,
                response_headers.as_deref(),
                false,
            );
            annotate(&mut response, "respond");
            Ok(response)
        }
        ActionKind::Inspect => {
            #[cfg(not(feature = "mitm"))]
            {
                let mut response = finalize_response_with_headers(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    blocked(state.messages.blocked.as_str()),
                    response_headers.as_deref(),
                    false,
                );
                annotate(&mut response, "block");
                Ok(response)
            }

            #[cfg(feature = "mitm")]
            {
                let tls_inspection = listener_cfg.tls_inspection.as_ref();
                if !tls_inspection.map(|t| t.enabled).unwrap_or(false) {
                    let mut response = finalize_response_with_headers(
                        &Method::CONNECT,
                        req_version,
                        proxy_name,
                        blocked(state.messages.blocked.as_str()),
                        response_headers.as_deref(),
                        false,
                    );
                    annotate(&mut response, "block");
                    return Ok(response);
                }
                let verify = tls_inspection
                    .map(|t| {
                        t.verify_upstream
                            && !state.tls_verify_exception_matches(listener_name, &host)
                    })
                    .unwrap_or(true);
                let upstream = resolve_upstream(&action, &state, listener_name)?;
                let rate_limit_ctx = RateLimitContext::from_identity(
                    remote_addr.ip(),
                    &identity,
                    matched_rule.as_deref(),
                    upstream.as_ref().map(|upstream| upstream.key()),
                );
                let concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_ctx)
                {
                    Some(permits) => Some(permits),
                    None => {
                        let mut response = finalize_response_with_headers(
                            &Method::CONNECT,
                            req_version,
                            proxy_name,
                            too_many_requests(None),
                            response_headers.as_deref(),
                            false,
                        );
                        annotate(&mut response, "concurrency_limited");
                        return Ok(response);
                    }
                };
                let upstream_connected = match connect_tunnel_target(
                    &host,
                    port,
                    upstream.as_ref(),
                    proxy_name,
                    upstream_timeout,
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(_) => {
                        let mut response = finalize_response_with_headers(
                            &Method::CONNECT,
                            req_version,
                            proxy_name,
                            Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(Body::from(state.messages.proxy_error.clone()))
                                .unwrap(),
                            response_headers.as_deref(),
                            false,
                        );
                        annotate(&mut response, "error");
                        return Ok(response);
                    }
                };
                let runtime_for_mitm = runtime.clone();
                let listener_name_owned = listener_name.to_string();
                let authority_for_task = authority.clone();
                let sanitized_headers_for_task = sanitized_headers.clone();
                let identity_for_task = identity.clone();
                let action_for_task = action.clone();
                task::spawn(async move {
                    if let Err(err) = tunnel_connect(
                        req,
                        upstream_connected,
                        runtime_for_mitm,
                        TunnelConnectContext {
                            remote_addr,
                            listener_name: listener_name_owned,
                            host,
                            port,
                            authority: authority_for_task,
                            sanitized_headers: sanitized_headers_for_task,
                            identity: identity_for_task,
                            initial_action: action_for_task,
                            verify_upstream: verify,
                            _concurrency_permits: concurrency_permits,
                            throttle: None,
                        },
                    )
                    .await
                    {
                        warn!(error = ?err, "mitm tunnel failed");
                    }
                });
                let mut response = finalize_response_with_headers(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    connect_established(),
                    response_headers.as_deref(),
                    false,
                );
                annotate(&mut response, "allow");
                Ok(response)
            }
        }
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {
            let upstream = resolve_upstream(&action, &state, listener_name)?;
            let rate_limit_ctx = RateLimitContext::from_identity(
                remote_addr.ip(),
                &identity,
                matched_rule.as_deref(),
                upstream.as_ref().map(|upstream| upstream.key()),
            );
            let concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_ctx) {
                Some(permits) => Some(permits),
                None => {
                    let mut response = finalize_response_with_headers(
                        &Method::CONNECT,
                        req_version,
                        proxy_name,
                        too_many_requests(None),
                        response_headers.as_deref(),
                        false,
                    );
                    annotate(&mut response, "concurrency_limited");
                    return Ok(response);
                }
            };
            let connected = match connect_tunnel_target(
                &host,
                port,
                upstream.as_ref(),
                proxy_name,
                upstream_timeout,
            )
            .await
            {
                Ok(stream) => stream,
                Err(_) => {
                    let mut response = finalize_response_with_headers(
                        &Method::CONNECT,
                        req_version,
                        proxy_name,
                        Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Body::from(state.messages.proxy_error.clone()))
                            .unwrap(),
                        response_headers.as_deref(),
                        false,
                    );
                    annotate(&mut response, "error");
                    return Ok(response);
                }
            };
            let throttle = BandwidthThrottle::with_context(
                rate_limit_ctx,
                request_limits.byte_limiters.clone(),
                request_limits.byte_quota_limiters.clone(),
            );
            let runtime_for_tunnel = runtime.clone();
            let listener_name_owned = listener_name.to_string();
            let authority_for_task = authority.clone();
            let sanitized_headers_for_task = sanitized_headers.clone();
            let identity_for_task = identity.clone();
            let action_for_task = action.clone();
            task::spawn(async move {
                if let Err(err) = tunnel_connect(
                    req,
                    connected,
                    runtime_for_tunnel,
                    TunnelConnectContext {
                        remote_addr,
                        listener_name: listener_name_owned,
                        host,
                        port,
                        authority: authority_for_task,
                        sanitized_headers: sanitized_headers_for_task,
                        identity: identity_for_task,
                        initial_action: action_for_task,
                        verify_upstream: false,
                        _concurrency_permits: concurrency_permits,
                        throttle,
                    },
                )
                .await
                {
                    warn!(error = ?err, "tunnel failed");
                }
            });
            let mut response = finalize_response_with_headers(
                &Method::CONNECT,
                req_version,
                proxy_name,
                connect_established(),
                response_headers.as_deref(),
                false,
            );
            annotate(&mut response, "allow");
            Ok(response)
        }
    }
}

#[cfg(test)]
#[path = "connect_tests.rs"]
mod tests;
