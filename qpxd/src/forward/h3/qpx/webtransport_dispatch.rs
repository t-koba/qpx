use self::established::{QpxWebTransportEstablishedContext, relay_established_webtransport};
use self::policy_response::WebTransportPolicyResponder;
use self::request_head::prepare_webtransport_connect_head;
use super::ForwardQpxHandler;
use super::connect_upstream::{
    OpenUpstreamQpxExtendedConnectInput, open_upstream_qpx_extended_connect_stream,
};
use super::response::send_qpx_static_response;
use crate::forward::policy::{ForwardPolicyDecision, evaluate_forward_policy};
#[cfg(feature = "auth-basic")]
use crate::forward::request::proxy_auth_required;
use crate::http::body::Body;
use crate::http::local_response::build_local_response;
use crate::http::protocol::common::{
    blocked_response as blocked, forbidden_response as forbidden, http_version_label,
    too_many_requests_response as too_many_requests,
};
use crate::http::protocol::l7::{finalize_response_for_request, finalize_response_with_headers};
use crate::policy_context::{
    ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode, apply_ext_authz_action_overrides,
    enforce_ext_authz, resolve_identity, sanitize_headers_for_policy,
    validate_ext_authz_allow_mode,
};
use crate::rate_limit::RateLimitContext;
use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use qpx_core::config::ActionKind;
use qpx_core::rules::RuleMatchContext;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::warn;

mod established;
mod policy_response;
mod request_head;

pub(super) async fn handle_qpx_webtransport_connect(
    handler: &ForwardQpxHandler,
    req_head: http::Request<()>,
    mut req_stream: qpx_h3::RequestStream,
    conn: qpx_h3::ConnectionInfo,
    session: qpx_h3::WebTransportSession,
) -> Result<()> {
    let state = handler.runtime.state();
    let proxy_name = state.plan.identity.proxy_name.to_string();
    let max_h3_response_body_bytes = state.plan.limits.body.max_h3_response_body_bytes;
    let tunnel_idle_timeout =
        Duration::from_millis(state.plan.limits.timeouts.tunnel_idle_timeout_ms.max(1));

    let prepared = match prepare_webtransport_connect_head(&req_head) {
        Ok(prepared) => prepared,
        Err(rejection) => {
            send_qpx_static_response(
                &mut req_stream,
                StatusCode::BAD_REQUEST,
                rejection.body,
                &http::Method::CONNECT,
                proxy_name.as_str(),
            )
            .await?;
            return Ok(());
        }
    };
    let req_authority = prepared.req_authority;
    let host = prepared.host;
    let port = prepared.port;
    let headers = prepared.headers;

    let base_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), None)
        .ok_or_else(|| anyhow!("listener plan not found"))?;
    let effective_policy = base_plan.policy_context.clone();
    let mut sanitized_headers = headers;
    sanitize_headers_for_policy(
        &state,
        &effective_policy,
        conn.remote_addr.ip(),
        &mut sanitized_headers,
    )?;
    let mut identity = resolve_identity(
        &state,
        &effective_policy,
        conn.remote_addr.ip(),
        Some(&sanitized_headers),
        conn.peer_certificates
            .as_deref()
            .map(|certs| certs.as_slice()),
    )?;

    let destination = state.classify_destination(
        &crate::destination::DestinationInputs {
            host: Some(host.as_str()),
            ip: host.parse().ok(),
            sni: Some(host.as_str()),
            scheme: req_head.uri().scheme_str(),
            port: Some(port),
            alpn: Some("h3"),
            ..Default::default()
        },
        base_plan.destination_resolution.as_ref(),
    );
    let audit_path = req_head
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string());
    let auth_uri = format!(
        "{}://{}{}",
        req_head.uri().scheme_str().unwrap_or("https"),
        req_authority,
        req_head
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );
    let policy_responder = WebTransportPolicyResponder {
        state: &state,
        listener_name: handler.listener_name.as_ref(),
        conn: &conn,
        host: host.as_str(),
        path: audit_path.as_deref(),
    };
    let ctx = RuleMatchContext {
        src_ip: Some(conn.remote_addr.ip()),
        dst_port: Some(port),
        host: Some(host.as_str()),
        sni: Some(host.as_str()),
        method: Some("CONNECT"),
        path: audit_path.as_deref(),
        authority: Some(req_authority.as_str()),
        http_version: Some(http_version_label(http::Version::HTTP_3)),
        alpn: Some("h3"),
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
        &handler.runtime,
        handler.listener_name.as_ref(),
        ctx,
        &sanitized_headers,
        "CONNECT",
        auth_uri.as_str(),
    )
    .await
    {
        Ok(ForwardPolicyDecision::Allow(allowed)) => {
            identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
            (
                allowed.action,
                allowed.matched_rule.map(|rule: Arc<str>| rule.to_string()),
            )
        }
        #[cfg(feature = "auth-basic")]
        Ok(ForwardPolicyDecision::Challenge(challenge)) => {
            let log_context = identity.to_log_context(None, None, None);
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                proxy_auth_required(challenge, state.messages.proxy_auth_required.as_str()),
                false,
            );
            policy_responder
                .send(
                    &mut req_stream,
                    response,
                    crate::http::dispatch::DispatchOutcome::Challenge,
                    None,
                    None,
                    &log_context,
                )
                .await?;
            return Ok(());
        }
        #[cfg(feature = "auth-basic")]
        Ok(ForwardPolicyDecision::Forbidden) => {
            let log_context = identity.to_log_context(None, None, None);
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                forbidden(state.messages.forbidden.as_str()),
                false,
            );
            policy_responder
                .send(
                    &mut req_stream,
                    response,
                    crate::http::dispatch::DispatchOutcome::Forbidden,
                    None,
                    None,
                    &log_context,
                )
                .await?;
            return Ok(());
        }
        Err(err) => {
            warn!(error = ?err, "forward HTTP/3 WebTransport policy evaluation failed");
            send_qpx_static_response(
                &mut req_stream,
                StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
                &http::Method::CONNECT,
                proxy_name.as_str(),
            )
            .await?;
            return Ok(());
        }
    };
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled WebTransport listener execution plan not found"))?;

    let request_limit_ctx = RateLimitContext::from_identity(
        conn.remote_addr.ip(),
        &identity,
        matched_rule.as_deref(),
        None,
    );
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &selected_plan.rate_limits,
        None,
        crate::rate_limit::TransportScope::Webtransport,
        &request_limit_ctx,
        1,
    )?;
    if let Some(retry_after) = retry_after {
        let log_context = identity.to_log_context(matched_rule.as_deref(), None, None);
        let response = finalize_response_for_request(
            &http::Method::CONNECT,
            http::Version::HTTP_3,
            proxy_name.as_str(),
            too_many_requests(Some(retry_after)),
            false,
        );
        policy_responder
            .send(
                &mut req_stream,
                response,
                crate::http::dispatch::DispatchOutcome::RateLimited,
                matched_rule.as_deref(),
                None,
                &log_context,
            )
            .await?;
        return Ok(());
    }

    let ext_authz = enforce_ext_authz(
        &state,
        &effective_policy,
        ExtAuthzInput {
            proxy_kind: crate::http::dispatch::ProxyKind::Forward,
            proxy_name: proxy_name.as_str(),
            scope_name: handler.listener_name.as_ref(),
            remote_ip: conn.remote_addr.ip(),
            dst_port: Some(port),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: audit_path.as_deref(),
            uri: Some(auth_uri.as_str()),
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
    let (response_headers, timeout_override, rate_limit_profile) = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ForwardConnect)?;
            let rate_limit_profile = allow.rate_limit_profile.clone();
            if let Some(retry_after) = request_limits.merge_profile_and_check(
                &state.policy.rate_limiters,
                rate_limit_profile.as_deref(),
                crate::rate_limit::TransportScope::Webtransport,
                &request_limit_ctx,
                1,
            )? {
                let response = finalize_response_for_request(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    too_many_requests(Some(retry_after)),
                    false,
                );
                policy_responder
                    .send(
                        &mut req_stream,
                        response,
                        crate::http::dispatch::DispatchOutcome::RateLimited,
                        matched_rule.as_deref(),
                        ext_authz_policy_id.as_deref(),
                        &log_context,
                    )
                    .await?;
                return Ok(());
            }
            apply_ext_authz_action_overrides(&mut action, &allow);
            (allow.headers, allow.timeout_override, rate_limit_profile)
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let response = if let Some(local) = deny.local_response.as_ref() {
                finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    build_local_response(local)?,
                    deny.headers.as_deref(),
                    false,
                )
            } else {
                finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    forbidden(state.messages.forbidden.as_str()),
                    deny.headers.as_deref(),
                    false,
                )
            };
            policy_responder
                .send(
                    &mut req_stream,
                    response,
                    if deny.local_response.is_some() {
                        crate::http::dispatch::DispatchOutcome::ExtAuthzLocalResponse
                    } else {
                        crate::http::dispatch::DispatchOutcome::ExtAuthzDeny
                    },
                    matched_rule.as_deref(),
                    ext_authz_policy_id.as_deref(),
                    &log_context,
                )
                .await?;
            return Ok(());
        }
    };

    match action.kind {
        ActionKind::Block => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                blocked(state.messages.blocked.as_str()),
                response_headers.as_deref(),
                false,
            );
            policy_responder
                .send(
                    &mut req_stream,
                    response,
                    crate::http::dispatch::DispatchOutcome::Block,
                    matched_rule.as_deref(),
                    ext_authz_policy_id.as_deref(),
                    &log_context,
                )
                .await?;
            return Ok(());
        }
        ActionKind::Respond => {
            let local = action
                .local_response
                .as_ref()
                .ok_or_else(|| anyhow!("respond action requires local_response"))?;
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                build_local_response(local)?,
                response_headers.as_deref(),
                false,
            );
            policy_responder
                .send(
                    &mut req_stream,
                    response,
                    crate::http::dispatch::DispatchOutcome::Respond,
                    matched_rule.as_deref(),
                    ext_authz_policy_id.as_deref(),
                    &log_context,
                )
                .await?;
            return Ok(());
        }
        ActionKind::Inspect => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                blocked(state.messages.blocked.as_str()),
                response_headers.as_deref(),
                false,
            );
            policy_responder
                .send(
                    &mut req_stream,
                    response,
                    crate::http::dispatch::DispatchOutcome::Block,
                    matched_rule.as_deref(),
                    ext_authz_policy_id.as_deref(),
                    &log_context,
                )
                .await?;
            return Ok(());
        }
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {}
    }

    let upstream_timeout = timeout_override.unwrap_or_else(|| {
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms)
    });
    let _concurrency_permits = match request_limits.acquire_concurrency(&request_limit_ctx) {
        Some(permits) => Some(permits),
        None => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                too_many_requests(None),
                response_headers.as_deref(),
                false,
            );
            policy_responder
                .send(
                    &mut req_stream,
                    response,
                    crate::http::dispatch::DispatchOutcome::RateLimited,
                    matched_rule.as_deref(),
                    ext_authz_policy_id.as_deref(),
                    &log_context,
                )
                .await?;
            return Ok(());
        }
    };
    let listener_cfg = state
        .ingress_edge_settings(handler.listener_name.as_ref())
        .ok_or_else(|| anyhow!("listener not found"))?;
    let listener_trust = crate::forward::connect::listener_upstream_trust(listener_cfg)?;
    let verify_upstream = listener_cfg
        .tls_inspection
        .as_ref()
        .map(|cfg| {
            cfg.verify_upstream
                && !state
                    .tls_verify_exception_matches(handler.listener_name.as_ref(), host.as_str())
        })
        .unwrap_or(true);
    let upstream =
        match open_upstream_qpx_extended_connect_stream(OpenUpstreamQpxExtendedConnectInput {
            req_head: &req_head,
            sanitized_headers: &sanitized_headers,
            proxy_name: proxy_name.as_str(),
            upstream: action.upstream.as_deref(),
            verify_upstream,
            trust: listener_trust.as_deref(),
            protocol: qpx_h3::Protocol::WebTransport,
            enable_datagram: session.datagrams.is_some(),
            timeout_dur: upstream_timeout,
        })
        .await
        {
            Ok(upstream) => upstream,
            Err(err) => {
                warn!(error = ?err, "forward HTTP/3 WebTransport CONNECT establish failed");
                let response = finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from(state.messages.proxy_error.clone()))?,
                    response_headers.as_deref(),
                    false,
                );
                policy_responder
                    .send(
                        &mut req_stream,
                        response,
                        crate::http::dispatch::DispatchOutcome::Error,
                        matched_rule.as_deref(),
                        ext_authz_policy_id.as_deref(),
                        &log_context,
                    )
                    .await?;
                return Ok(());
            }
        };

    relay_established_webtransport(QpxWebTransportEstablishedContext {
        handler,
        state: &state,
        req_stream,
        conn: &conn,
        session,
        upstream,
        host: host.as_str(),
        audit_path: audit_path.as_deref(),
        matched_rule: matched_rule.as_deref(),
        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        log_context: &log_context,
        response_headers: response_headers.as_deref(),
        request_limit_ctx,
        request_limits,
        rate_limit_profile: rate_limit_profile.as_deref(),
        proxy_name: proxy_name.as_str(),
        max_h3_response_body_bytes,
        tunnel_idle_timeout,
    })
    .await
}
