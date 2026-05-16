use super::*;

#[path = "h3_qpx_connect_policy.rs"]
mod h3_qpx_connect_policy;

use self::h3_qpx_connect_policy::{apply_connect_rate_limits, evaluate_connect_policy};

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

pub(super) enum QpxConnectPreparation {
    Continue(Box<PreparedQpxConnect>),
    Responded,
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
) -> Result<QpxConnectPreparation> {
    let Some(validated) = validate_connect_request(&mut input).await? else {
        return Ok(QpxConnectPreparation::Responded);
    };
    let context = build_connect_policy_context(&input, validated)?;
    let Some(evaluated) = evaluate_connect_policy(&mut input, context).await? else {
        return Ok(QpxConnectPreparation::Responded);
    };
    let Some(prepared) = apply_connect_rate_limits(&mut input, evaluated).await? else {
        return Ok(QpxConnectPreparation::Responded);
    };
    Ok(QpxConnectPreparation::Continue(Box::new(prepared)))
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
    let is_connect_udp = protocol == Some(&qpx_h3::Protocol::ConnectUdp);
    let is_extended_connect = protocol.is_some();

    if is_connect_udp {
        let Some(cfg) = connect_udp_cfg else {
            send_qpx_static_response(
                req_stream,
                StatusCode::NOT_IMPLEMENTED,
                state.messages.connect_udp_disabled.as_bytes(),
            )
            .await?;
            return Ok(None);
        };
        if !cfg.enabled {
            send_qpx_static_response(
                req_stream,
                StatusCode::NOT_IMPLEMENTED,
                state.messages.connect_udp_disabled.as_bytes(),
            )
            .await?;
            return Ok(None);
        }
    }

    let req_authority = match req_head.uri().authority().map(|a| a.as_str().to_string()) {
        Some(authority) => authority,
        None => {
            let message = if is_connect_udp {
                b"missing CONNECT-UDP authority".as_slice()
            } else {
                b"missing CONNECT authority".as_slice()
            };
            send_qpx_static_response(req_stream, StatusCode::BAD_REQUEST, message).await?;
            return Ok(None);
        }
    };

    let (host, port, authority_host_for_validation, authority_port_for_validation, auth_uri) =
        if is_connect_udp {
            let uri_template = connect_udp_cfg.and_then(|cfg| cfg.uri_template.as_deref());
            let (host, port) = match parse_connect_udp_target(req_head.uri(), uri_template) {
                Ok(parsed) => parsed,
                Err(_) => {
                    send_qpx_static_response(
                        req_stream,
                        StatusCode::BAD_REQUEST,
                        b"invalid CONNECT-UDP target",
                    )
                    .await?;
                    return Ok(None);
                }
            };
            let scheme = match req_head.uri().scheme_str() {
                Some(scheme) => scheme,
                None => {
                    send_qpx_static_response(
                        req_stream,
                        StatusCode::BAD_REQUEST,
                        b"missing CONNECT-UDP :scheme",
                    )
                    .await?;
                    return Ok(None);
                }
            };
            let default_port = match scheme {
                "http" => 80,
                "https" | "h3" => 443,
                _ => 443,
            };
            let authority = req_head
                .uri()
                .authority()
                .ok_or_else(|| anyhow!("CONNECT target authority missing"))?;
            let authority_host = authority.host().to_string();
            let authority_port = authority.port_u16().unwrap_or(default_port);
            let path = match req_head.uri().path_and_query().map(|pq| pq.as_str()) {
                Some(path) => path,
                None => {
                    send_qpx_static_response(
                        req_stream,
                        StatusCode::BAD_REQUEST,
                        b"missing CONNECT-UDP :path",
                    )
                    .await?;
                    return Ok(None);
                }
            };
            let auth_uri = format!("{scheme}://{req_authority}{path}");
            (host, port, authority_host, authority_port, auth_uri)
        } else {
            let (host, port) = match parse_connect_authority_required(&req_authority) {
                Ok(parsed) => parsed,
                Err(_) => {
                    send_qpx_static_response(
                        req_stream,
                        StatusCode::BAD_REQUEST,
                        b"invalid CONNECT authority",
                    )
                    .await?;
                    return Ok(None);
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
                req_authority.clone()
            };
            (host.clone(), port, host, port, auth_uri)
        };

    let headers = match h1_headers_to_http(req_head.headers()) {
        Ok(headers) => headers,
        Err(_) => {
            let message = if is_connect_udp {
                b"invalid CONNECT-UDP headers".as_slice()
            } else {
                b"invalid CONNECT headers".as_slice()
            };
            send_qpx_static_response(req_stream, StatusCode::BAD_REQUEST, message).await?;
            return Ok(None);
        }
    };

    if let Err(err) = validate_qpx_connect_head(
        req_head,
        &headers,
        authority_host_for_validation.as_str(),
        authority_port_for_validation,
        protocol,
    ) {
        let message = if is_connect_udp {
            b"bad CONNECT-UDP request".as_slice()
        } else {
            b"bad CONNECT request".as_slice()
        };
        warn!(error = ?err, "invalid forward HTTP/3 qpx-h3 CONNECT request");
        send_qpx_static_response(req_stream, StatusCode::BAD_REQUEST, message).await?;
        return Ok(None);
    }
    Ok(Some(ValidatedQpxConnect {
        req_authority,
        host,
        port,
        auth_uri,
        headers,
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
