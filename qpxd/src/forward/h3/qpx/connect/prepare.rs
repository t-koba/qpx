use super::super::super::connect::parse::{
    default_connect_port_for_scheme, parse_connect_authority_with_default,
    parse_connect_udp_target, validate_connect_udp_scheme,
};
use super::super::connect_upstream::validate_qpx_connect_head;
use super::super::response::send_qpx_static_response;
use super::ForwardQpxHandler;
use crate::destination::DestinationInputs;
use crate::http3::codec::h1_headers_to_http;
use crate::policy_context::{resolve_identity, sanitize_headers_for_policy};
use crate::rate_limit::RateLimitContext;
use anyhow::{Result, anyhow};
use hyper::StatusCode;
use qpx_core::config::{ActionConfig, ConnectUdpConfig};
use qpx_core::rules::CompiledHeaderControl;
use qpx_observability::access_log::RequestLogContext;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::warn;

mod policy;

use self::policy::{apply_connect_rate_limits, evaluate_connect_policy};

#[derive(Debug)]
pub(super) struct PreparedQpxConnect {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) action: ActionConfig,
    pub(super) response_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) log_context: RequestLogContext,
    pub(super) matched_rule: Option<String>,
    pub(super) ext_authz_policy_id: Option<String>,
    pub(super) audit_path: Option<String>,
    pub(super) timeout_override: Option<Duration>,
    pub(super) rate_limit_profile: Option<String>,
    pub(super) rate_limit_context: RateLimitContext,
    pub(super) sanitized_headers: http::HeaderMap,
}

pub(super) struct PrepareQpxConnectInput<'a> {
    pub(super) req_head: &'a http::Request<()>,
    pub(super) req_stream: &'a mut qpx_h3::RequestStream,
    pub(super) handler: &'a ForwardQpxHandler,
    pub(super) conn: &'a qpx_h3::ConnectionInfo,
    pub(super) protocol: Option<&'a qpx_h3::Protocol>,
    pub(super) connect_udp_cfg: Option<&'a ConnectUdpConfig>,
}

pub(super) struct ValidatedQpxConnect {
    pub(super) req_authority: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) auth_uri: String,
    pub(super) headers: http::HeaderMap,
}

struct ValidatedQpxConnectTarget {
    host: String,
    port: u16,
    authority_host_for_validation: String,
    authority_port_for_validation: u16,
    auth_uri: String,
}

pub(super) struct ConnectPolicyContext {
    pub(super) req_authority: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) auth_uri: String,
    pub(super) sanitized_headers: http::HeaderMap,
    pub(super) identity: crate::policy_context::ResolvedIdentity,
    pub(super) effective_policy: crate::policy_context::EffectivePolicyContext,
    pub(super) destination: crate::destination::DestinationMetadata,
    pub(super) audit_path: Option<String>,
}

pub(super) struct EvaluatedConnectPolicy {
    pub(super) context: ConnectPolicyContext,
    pub(super) action: ActionConfig,
    pub(super) matched_rule: Option<String>,
}

pub(super) async fn prepare_qpx_connect_request(
    mut input: PrepareQpxConnectInput<'_>,
) -> Result<Option<Box<PreparedQpxConnect>>> {
    let Some(validated) = validate_connect_request(&mut input).await? else {
        return Ok(None);
    };
    let context = build_connect_policy_context(&input, validated)?;
    let Some(evaluated) = evaluate_connect_policy(&mut input, context).await? else {
        return Ok(None);
    };
    let Some(prepared) = apply_connect_rate_limits(&mut input, evaluated).await? else {
        return Ok(None);
    };
    Ok(Some(Box::new(prepared)))
}

async fn validate_connect_request(
    input: &mut PrepareQpxConnectInput<'_>,
) -> Result<Option<ValidatedQpxConnect>> {
    let req_head = input.req_head;
    let req_stream = &mut *input.req_stream;
    let handler = input.handler;
    let protocol = input.protocol;
    let connect_udp_cfg = input.connect_udp_cfg;
    let state = handler.runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let is_connect_udp = protocol == Some(&qpx_h3::Protocol::ConnectUdp);
    let is_extended_connect = protocol.is_some();

    if is_connect_udp && !connect_udp_cfg.is_some_and(|cfg| cfg.enabled) {
        return reject_qpx_connect(
            req_stream,
            StatusCode::NOT_IMPLEMENTED,
            state.messages.connect_udp_disabled.as_bytes(),
            proxy_name,
        )
        .await;
    }

    let req_authority = match req_head.uri().authority().map(|a| a.as_str().to_string()) {
        Some(authority) => authority,
        None => {
            let message = if is_connect_udp {
                b"missing CONNECT-UDP authority".as_slice()
            } else {
                b"missing CONNECT authority".as_slice()
            };
            return reject_bad_qpx_connect(req_stream, message, proxy_name).await;
        }
    };

    let Some(target) = resolve_qpx_connect_target(
        req_head,
        req_stream,
        connect_udp_cfg,
        req_authority.as_str(),
        is_connect_udp,
        is_extended_connect,
        proxy_name,
    )
    .await?
    else {
        return Ok(None);
    };

    let headers = match h1_headers_to_http(req_head.headers()) {
        Ok(headers) => headers,
        Err(_) => {
            let message = if is_connect_udp {
                b"invalid CONNECT-UDP headers".as_slice()
            } else {
                b"invalid CONNECT headers".as_slice()
            };
            return reject_bad_qpx_connect(req_stream, message, proxy_name).await;
        }
    };

    if let Err(err) = validate_qpx_connect_head(
        req_head,
        &headers,
        target.authority_host_for_validation.as_str(),
        target.authority_port_for_validation,
        protocol,
    ) {
        let message = if is_connect_udp {
            b"bad CONNECT-UDP request".as_slice()
        } else {
            b"bad CONNECT request".as_slice()
        };
        warn!(error = ?err, "invalid forward HTTP/3 qpx-h3 CONNECT request");
        return reject_bad_qpx_connect(req_stream, message, proxy_name).await;
    }
    Ok(Some(ValidatedQpxConnect {
        req_authority,
        host: target.host,
        port: target.port,
        auth_uri: target.auth_uri,
        headers,
    }))
}

async fn reject_qpx_connect<T>(
    req_stream: &mut qpx_h3::RequestStream,
    status: StatusCode,
    message: &[u8],
    proxy_name: &str,
) -> Result<Option<T>> {
    send_qpx_static_response(
        req_stream,
        status,
        message,
        &http::Method::CONNECT,
        proxy_name,
    )
    .await?;
    Ok(None)
}

async fn reject_bad_qpx_connect<T>(
    req_stream: &mut qpx_h3::RequestStream,
    message: &[u8],
    proxy_name: &str,
) -> Result<Option<T>> {
    reject_qpx_connect(req_stream, StatusCode::BAD_REQUEST, message, proxy_name).await
}

async fn resolve_qpx_connect_target(
    req_head: &http::Request<()>,
    req_stream: &mut qpx_h3::RequestStream,
    connect_udp_cfg: Option<&ConnectUdpConfig>,
    req_authority: &str,
    is_connect_udp: bool,
    is_extended_connect: bool,
    proxy_name: &str,
) -> Result<Option<ValidatedQpxConnectTarget>> {
    if is_connect_udp {
        return resolve_qpx_connect_udp_target(
            req_head,
            req_stream,
            connect_udp_cfg,
            req_authority,
            proxy_name,
        )
        .await;
    }
    let default_port = is_extended_connect
        .then(|| default_connect_port_for_scheme(req_head.uri().scheme_str()))
        .flatten();
    let (host, port) = match parse_connect_authority_with_default(req_authority, default_port) {
        Ok(parsed) => parsed,
        Err(_) => {
            return reject_bad_qpx_connect(req_stream, b"invalid CONNECT authority", proxy_name)
                .await;
        }
    };
    let auth_uri = if is_extended_connect {
        let scheme = req_head.uri().scheme_str().unwrap_or("https");
        let path = req_head
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        format!("{scheme}://{req_authority}{path}")
    } else {
        req_authority.to_owned()
    };
    Ok(Some(ValidatedQpxConnectTarget {
        authority_host_for_validation: host.clone(),
        authority_port_for_validation: port,
        auth_uri,
        host,
        port,
    }))
}

async fn resolve_qpx_connect_udp_target(
    req_head: &http::Request<()>,
    req_stream: &mut qpx_h3::RequestStream,
    connect_udp_cfg: Option<&ConnectUdpConfig>,
    req_authority: &str,
    proxy_name: &str,
) -> Result<Option<ValidatedQpxConnectTarget>> {
    let uri_template = connect_udp_cfg.and_then(|cfg| cfg.uri_template.as_deref());
    let (host, port) = match parse_connect_udp_target(req_head.uri(), uri_template) {
        Ok(parsed) => parsed,
        Err(_) => {
            return reject_bad_qpx_connect(req_stream, b"invalid CONNECT-UDP target", proxy_name)
                .await;
        }
    };
    let scheme = match validate_connect_udp_scheme(req_head.uri(), uri_template) {
        Ok(scheme) => scheme,
        Err(_) => {
            let message = if req_head.uri().scheme_str().is_some() {
                b"invalid CONNECT-UDP :scheme".as_slice()
            } else {
                b"missing CONNECT-UDP :scheme".as_slice()
            };
            return reject_bad_qpx_connect(req_stream, message, proxy_name).await;
        }
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return reject_bad_qpx_connect(req_stream, b"invalid CONNECT-UDP :scheme", proxy_name)
            .await;
    }
    let (authority_host, authority_port) =
        match parse_connect_authority_with_default(req_authority, Some(443)) {
            Ok(parsed) => parsed,
            Err(_) => {
                return reject_bad_qpx_connect(
                    req_stream,
                    b"invalid CONNECT-UDP authority",
                    proxy_name,
                )
                .await;
            }
        };
    let Some(path) = req_head.uri().path_and_query().map(|pq| pq.as_str()) else {
        return reject_bad_qpx_connect(req_stream, b"missing CONNECT-UDP :path", proxy_name).await;
    };
    Ok(Some(ValidatedQpxConnectTarget {
        host,
        port,
        authority_host_for_validation: authority_host,
        authority_port_for_validation: authority_port,
        auth_uri: format!("{scheme}://{req_authority}{path}"),
    }))
}

fn build_connect_policy_context(
    input: &PrepareQpxConnectInput<'_>,
    validated: ValidatedQpxConnect,
) -> Result<ConnectPolicyContext> {
    let req_head = input.req_head;
    let handler = input.handler;
    let conn = input.conn;
    let protocol = input.protocol;
    let state = handler.runtime.state();
    let is_connect_udp = protocol == Some(&qpx_h3::Protocol::ConnectUdp);
    let ValidatedQpxConnect {
        req_authority,
        host,
        port,
        auth_uri,
        headers,
    } = validated;
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
    let identity = resolve_identity(
        &state,
        &effective_policy,
        conn.remote_addr.ip(),
        Some(&sanitized_headers),
        conn.peer_certificates
            .as_deref()
            .map(|certs| certs.as_slice()),
    )?;
    let destination = state.classify_destination(
        &DestinationInputs {
            host: Some(host.as_str()),
            ip: host.parse().ok(),
            sni: Some(host.as_str()),
            scheme: if is_connect_udp {
                req_head.uri().scheme_str()
            } else {
                Some("https")
            },
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
    Ok(ConnectPolicyContext {
        req_authority,
        host,
        port,
        auth_uri,
        sanitized_headers,
        identity,
        effective_policy,
        destination,
        audit_path,
    })
}
