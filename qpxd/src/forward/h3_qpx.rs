use super::policy::{evaluate_forward_policy, ForwardPolicyDecision};
use super::request::proxy_auth_required;
use crate::http::body::Body;
use crate::http::common::{
    blocked_response as blocked, forbidden_response as forbidden, http_version_label,
    too_many_requests_response as too_many_requests,
};
use crate::http::l7::{
    finalize_response_for_request, finalize_response_with_headers,
    prepare_request_with_headers_in_place,
};
use crate::http::local_response::build_local_response;
use crate::http3::codec::{h1_headers_to_http, h3_request_to_hyper, http_headers_to_h1};
use crate::http3::quinn_socket::{
    build_server_endpoint, prepare_server_endpoint_socket, NoopQuinnUdpIngressFilter,
    PreparedServerEndpointSocket, QuinnBrokerKind, QuinnBrokerStream, QuinnEndpointSocket,
};
use crate::policy_context::{
    apply_ext_authz_action_overrides, emit_audit_log, enforce_ext_authz, resolve_identity,
    sanitize_headers_for_policy, validate_ext_authz_allow_mode, AuditRecord,
    EffectivePolicyContext, ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode,
};
use crate::rate_limit::RateLimitContext;
use crate::runtime::Runtime;
use crate::sidecar_control::SidecarControl;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use hyper::{Response, StatusCode};
use qpx_core::config::{ActionKind, ConnectUdpConfig, Http3ListenerConfig, ListenerConfig};
use qpx_core::rules::{CompiledHeaderControl, RuleMatchContext};
use qpx_observability::access_log::RequestLogContext;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::lookup_host;
use tokio::sync::watch;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

#[path = "h3_connect_parse.rs"]
mod h3_connect_parse;
#[path = "h3_qpx_connect.rs"]
mod h3_qpx_connect;
#[path = "h3_qpx_relay.rs"]
mod h3_qpx_relay;
#[path = "h3_qpx_webtransport.rs"]
mod h3_qpx_webtransport;

use self::h3_connect_parse::{parse_connect_authority_required, parse_connect_udp_target};
use self::h3_qpx_connect::handle_qpx_connect_stream;
use self::h3_qpx_webtransport::{
    relay_qpx_webtransport_session, QpxWebTransportRelayContext, WebTransportFlowLimits,
};

pub(crate) fn prepare_http3_listener_socket(
    listener_name: &str,
    udp_socket: std::net::UdpSocket,
    inherited_broker: Option<QuinnBrokerStream>,
) -> Result<PreparedServerEndpointSocket> {
    prepare_server_endpoint_socket(
        listener_name,
        QuinnBrokerKind::Forward,
        udp_socket,
        inherited_broker,
        Arc::new(NoopQuinnUdpIngressFilter),
    )
}

pub(crate) async fn run_http3_listener(
    listener: ListenerConfig,
    runtime: Runtime,
    http3_cfg: Http3ListenerConfig,
    mut shutdown: watch::Receiver<SidecarControl>,
    endpoint_socket: QuinnEndpointSocket,
) -> Result<()> {
    let listen_addr: SocketAddr = http3_cfg
        .listen
        .clone()
        .unwrap_or_else(|| listener.listen.clone())
        .parse()?;
    let connect_udp = http3_cfg.connect_udp.unwrap_or(ConnectUdpConfig {
        enabled: false,
        idle_timeout_secs: 30,
        max_capsule_buffer_bytes: 256 * 1024,
        uri_template: None,
    });

    let runtime_cfg = runtime.state().config.runtime.clone();
    let tls_config = build_forward_tls_config(&listener, &runtime, listen_addr)?;
    let max_bidi = runtime_cfg
        .max_h3_streams_per_connection
        .min(u32::MAX as usize) as u32;
    let quic_config =
        crate::http3::quic::build_h3_server_config_from_tls(tls_config, max_bidi.max(1), 16)?;
    let endpoint = build_server_endpoint(endpoint_socket, quic_config)?;

    let handler = ForwardQpxHandler {
        runtime,
        listener_name: Arc::<str>::from(listener.name.as_str()),
        connect_udp,
    };
    let connection_semaphore = handler.runtime.state().connection_semaphore.clone();

    info!(
        listener = %listener.name,
        addr = %listen_addr,
        connect_udp = handler.connect_udp.enabled,
        "forward HTTP/3 listener starting (qpx-h3)"
    );

    loop {
        let connecting = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || shutdown.borrow().should_stop() {
                    None
                } else {
                    continue;
                }
            }
            connecting = endpoint.accept() => connecting,
        };
        let Some(connecting) = connecting else {
            break;
        };
        let permit = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || shutdown.borrow().should_stop() {
                    None
                } else {
                    continue;
                }
            }
            permit = connection_semaphore.clone().acquire_owned() => Some(permit?),
        };
        let Some(permit) = permit else {
            break;
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) =
                qpx_h3::serve_connection(connecting, listen_addr.port(), handler).await
            {
                warn!(error = ?err, "forward HTTP/3 qpx-h3 connection failed");
            }
        });
    }

    Ok(())
}

fn build_forward_tls_config(
    listener: &ListenerConfig,
    runtime: &Runtime,
    listen_addr: SocketAddr,
) -> Result<quinn::rustls::ServerConfig> {
    let state = runtime.state();
    let ca = state
        .security
        .ca
        .as_ref()
        .ok_or_else(|| anyhow!("forward HTTP/3 requires CA state"))?;

    let mut sans = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
        listen_addr.ip().to_string(),
        listener.name.clone(),
    ];
    sans.sort();
    sans.dedup();
    let (cert_chain, key) = ca.issue_server_cert(&sans)?;

    let provider = quinn::rustls::crypto::ring::default_provider();
    let tls = quinn::rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|_| anyhow!("failed to configure TLS versions for forward HTTP/3"))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    Ok(tls)
}

#[derive(Clone)]
struct ForwardQpxHandler {
    runtime: Runtime,
    listener_name: Arc<str>,
    connect_udp: ConnectUdpConfig,
}

#[async_trait]
impl qpx_h3::RequestHandler for ForwardQpxHandler {
    fn settings(&self) -> qpx_h3::Settings {
        let state = self.runtime.state();
        let limits = state.config.runtime.clone();
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: limits.max_h3_streams_per_connection.max(1) as u64,
            max_request_body_bytes: limits.max_h3_request_body_bytes,
            max_concurrent_streams_per_connection: limits.max_h3_streams_per_connection,
            read_timeout: Duration::from_millis(limits.h3_read_timeout_ms),
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        request: qpx_h3::Request,
        conn: qpx_h3::ConnectionInfo,
    ) -> Result<qpx_h3::Response> {
        if request.head.method() == http::Method::CONNECT {
            return self.handle_connect(request, conn.remote_addr).await;
        }

        let req = h3_request_to_hyper(request.head, request.body, request.trailers)?;
        let request_method = req.method().clone();
        let response = crate::forward::request::handle_request_inner(
            req,
            self.runtime.clone(),
            self.listener_name.as_ref(),
            conn.remote_addr,
        )
        .await?;
        collect_forward_response(
            response,
            &request_method,
            self.runtime
                .state()
                .config
                .runtime
                .max_h3_response_body_bytes,
            h3_body_read_timeout(&self.runtime),
        )
        .await
    }

    async fn handle_webtransport_connect(
        &self,
        req_head: http::Request<()>,
        req_stream: qpx_h3::RequestStream,
        conn: qpx_h3::ConnectionInfo,
        session: qpx_h3::WebTransportSession,
    ) -> Result<()> {
        self.handle_qpx_webtransport_connect(req_head, req_stream, conn, session)
            .await
    }

    async fn handle_connect_stream(
        &self,
        req_head: http::Request<()>,
        req_stream: qpx_h3::RequestStream,
        conn: qpx_h3::ConnectionInfo,
        protocol: qpx_h3::Protocol,
        datagrams: Option<qpx_h3::StreamDatagrams>,
    ) -> Result<()> {
        handle_qpx_connect_stream(self, req_head, req_stream, conn, protocol, datagrams).await
    }
}

impl ForwardQpxHandler {
    async fn handle_connect(
        &self,
        request: qpx_h3::Request,
        remote_addr: std::net::SocketAddr,
    ) -> Result<qpx_h3::Response> {
        match request.protocol {
            Some(qpx_h3::Protocol::ConnectUdp) => self.handle_connect_udp(request).await,
            Some(_) => {
                self.static_response(
                    http::Method::CONNECT,
                    StatusCode::NOT_IMPLEMENTED,
                    self.runtime.state().messages.proxy_error.clone(),
                )
                .await
            }
            None => {
                let req = crate::http3::codec::h3_request_to_hyper(
                    request.head,
                    request.body,
                    request.trailers,
                )?;
                let request_method = req.method().clone();
                let response = crate::forward::request::handle_request_inner(
                    req,
                    self.runtime.clone(),
                    self.listener_name.as_ref(),
                    remote_addr,
                )
                .await?;
                collect_forward_response(
                    response,
                    &request_method,
                    self.runtime
                        .state()
                        .config
                        .runtime
                        .max_h3_response_body_bytes,
                    h3_body_read_timeout(&self.runtime),
                )
                .await
            }
        }
    }

    async fn handle_connect_udp(&self, request: qpx_h3::Request) -> Result<qpx_h3::Response> {
        if !self.connect_udp.enabled {
            return self
                .static_response(
                    http::Method::CONNECT,
                    StatusCode::NOT_IMPLEMENTED,
                    self.runtime.state().messages.proxy_error.clone(),
                )
                .await;
        }

        crate::http::semantics::validate_h2_h3_request_headers(
            http::Version::HTTP_3,
            request.head.headers(),
        )
        .map_err(|err| anyhow!("invalid CONNECT-UDP headers: {err}"))?;
        crate::http::semantics::validate_expect_header(request.head.headers())
            .map_err(|err| anyhow!("invalid CONNECT-UDP headers: {err}"))?;

        let capsule = request
            .head
            .headers()
            .get("capsule-protocol")
            .and_then(|value| value.to_str().ok());
        if capsule != Some("?1") {
            return self
                .static_response(
                    http::Method::CONNECT,
                    StatusCode::BAD_REQUEST,
                    "CONNECT-UDP requires Capsule-Protocol: ?1".to_string(),
                )
                .await;
        }

        let _ =
            parse_connect_udp_target(request.head.uri(), self.connect_udp.uri_template.as_deref())?;

        let mut response = crate::http::common::connect_established_response();
        response.headers_mut().insert(
            http::header::HeaderName::from_static("capsule-protocol"),
            http::HeaderValue::from_static("?1"),
        );
        let response = crate::http::l7::finalize_response_for_request(
            &http::Method::CONNECT,
            http::Version::HTTP_3,
            self.runtime.state().config.identity.proxy_name.as_str(),
            response,
            false,
        );
        collect_forward_response(
            response,
            &http::Method::CONNECT,
            self.runtime
                .state()
                .config
                .runtime
                .max_h3_response_body_bytes,
            h3_body_read_timeout(&self.runtime),
        )
        .await
    }

    async fn static_response(
        &self,
        method: http::Method,
        status: StatusCode,
        body: String,
    ) -> Result<qpx_h3::Response> {
        let response = crate::http::l7::finalize_response_for_request(
            &method,
            http::Version::HTTP_3,
            self.runtime.state().config.identity.proxy_name.as_str(),
            Response::builder()
                .status(status)
                .body(crate::http::body::Body::from(body))?,
            false,
        );
        collect_forward_response(
            response,
            &method,
            self.runtime
                .state()
                .config
                .runtime
                .max_h3_response_body_bytes,
            h3_body_read_timeout(&self.runtime),
        )
        .await
    }

    async fn handle_qpx_webtransport_connect(
        &self,
        req_head: http::Request<()>,
        mut req_stream: qpx_h3::RequestStream,
        conn: qpx_h3::ConnectionInfo,
        session: qpx_h3::WebTransportSession,
    ) -> Result<()> {
        let state = self.runtime.state();
        let proxy_name = state.config.identity.proxy_name.clone();
        let max_h3_response_body_bytes = state.config.runtime.max_h3_response_body_bytes;
        let tunnel_idle_timeout =
            Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms.max(1));

        let req_authority = match req_head.uri().authority().map(|a| a.as_str().to_string()) {
            Some(authority) => authority,
            None => {
                send_qpx_static_response(
                    &mut req_stream,
                    StatusCode::BAD_REQUEST,
                    b"missing CONNECT authority",
                )
                .await?;
                return Ok(());
            }
        };
        let (host, port) = match parse_connect_authority_required(&req_authority) {
            Ok(parsed) => parsed,
            Err(_) => {
                send_qpx_static_response(
                    &mut req_stream,
                    StatusCode::BAD_REQUEST,
                    b"invalid CONNECT authority",
                )
                .await?;
                return Ok(());
            }
        };
        let headers = match h1_headers_to_http(req_head.headers()) {
            Ok(headers) => headers,
            Err(_) => {
                send_qpx_static_response(
                    &mut req_stream,
                    StatusCode::BAD_REQUEST,
                    b"invalid CONNECT headers",
                )
                .await?;
                return Ok(());
            }
        };
        if let Err(err) = validate_qpx_webtransport_head(&req_head, &headers, host.as_str(), port) {
            warn!(error = ?err, "invalid forward HTTP/3 WebTransport request");
            send_qpx_static_response(
                &mut req_stream,
                StatusCode::BAD_REQUEST,
                b"bad CONNECT request",
            )
            .await?;
            return Ok(());
        }

        let listener_cfg = state
            .listener_config(self.listener_name.as_ref())
            .ok_or_else(|| anyhow!("listener not found"))?;
        let effective_policy =
            EffectivePolicyContext::from_single(listener_cfg.policy_context.as_ref());
        let sanitized_headers = sanitize_headers_for_policy(
            &state,
            &effective_policy,
            conn.remote_addr.ip(),
            &headers,
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
            listener_cfg.destination_resolution.as_ref(),
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
            &self.runtime,
            self.listener_name.as_ref(),
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
            Ok(ForwardPolicyDecision::Challenge(challenge)) => {
                let log_context = identity.to_log_context(None, None, None);
                let response = finalize_response_for_request(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    proxy_auth_required(challenge, state.messages.proxy_auth_required.as_str()),
                    false,
                );
                send_qpx_policy_response(
                    &mut req_stream,
                    response,
                    QpxPolicyResponseContext {
                        state: &state,
                        listener_name: self.listener_name.as_ref(),
                        conn: &conn,
                        host: host.as_str(),
                        path: audit_path.as_deref(),
                        outcome: "challenge",
                        matched_rule: None,
                        ext_authz_policy_id: None,
                        log_context: &log_context,
                    },
                )
                .await?;
                return Ok(());
            }
            Ok(ForwardPolicyDecision::Forbidden) => {
                let log_context = identity.to_log_context(None, None, None);
                let response = finalize_response_for_request(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    forbidden(state.messages.forbidden.as_str()),
                    false,
                );
                send_qpx_policy_response(
                    &mut req_stream,
                    response,
                    QpxPolicyResponseContext {
                        state: &state,
                        listener_name: self.listener_name.as_ref(),
                        conn: &conn,
                        host: host.as_str(),
                        path: audit_path.as_deref(),
                        outcome: "forbidden",
                        matched_rule: None,
                        ext_authz_policy_id: None,
                        log_context: &log_context,
                    },
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
                )
                .await?;
                return Ok(());
            }
        };

        let request_limit_ctx = RateLimitContext::from_identity(
            conn.remote_addr.ip(),
            &identity,
            matched_rule.as_deref(),
            None,
        );
        let crate::rate_limit::RequestLimitAcquire {
            limits: mut request_limits,
            retry_after,
        } = state.policy.rate_limiters.collect_checked_request(
            crate::rate_limit::RequestLimitCollectInput {
                listener: Some(self.listener_name.as_ref()),
                rule: matched_rule.as_deref(),
                profile: None,
                scope: crate::rate_limit::TransportScope::Webtransport,
                extra: None,
                ctx: &request_limit_ctx,
                cost: 1,
            },
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
            send_qpx_policy_response(
                &mut req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: self.listener_name.as_ref(),
                    conn: &conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: "rate_limited",
                    matched_rule: matched_rule.as_deref(),
                    ext_authz_policy_id: None,
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(());
        }

        let ext_authz = enforce_ext_authz(
            &state,
            &effective_policy,
            ExtAuthzInput {
                proxy_kind: "forward",
                proxy_name: proxy_name.as_str(),
                scope_name: self.listener_name.as_ref(),
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
                    send_qpx_policy_response(
                        &mut req_stream,
                        response,
                        QpxPolicyResponseContext {
                            state: &state,
                            listener_name: self.listener_name.as_ref(),
                            conn: &conn,
                            host: host.as_str(),
                            path: audit_path.as_deref(),
                            outcome: "rate_limited",
                            matched_rule: matched_rule.as_deref(),
                            ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                            log_context: &log_context,
                        },
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
                send_qpx_policy_response(
                    &mut req_stream,
                    response,
                    QpxPolicyResponseContext {
                        state: &state,
                        listener_name: self.listener_name.as_ref(),
                        conn: &conn,
                        host: host.as_str(),
                        path: audit_path.as_deref(),
                        outcome: if deny.local_response.is_some() {
                            "ext_authz_local_response"
                        } else {
                            "ext_authz_deny"
                        },
                        matched_rule: matched_rule.as_deref(),
                        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                        log_context: &log_context,
                    },
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
                send_qpx_policy_response(
                    &mut req_stream,
                    response,
                    QpxPolicyResponseContext {
                        state: &state,
                        listener_name: self.listener_name.as_ref(),
                        conn: &conn,
                        host: host.as_str(),
                        path: audit_path.as_deref(),
                        outcome: "block",
                        matched_rule: matched_rule.as_deref(),
                        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                        log_context: &log_context,
                    },
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
                send_qpx_policy_response(
                    &mut req_stream,
                    response,
                    QpxPolicyResponseContext {
                        state: &state,
                        listener_name: self.listener_name.as_ref(),
                        conn: &conn,
                        host: host.as_str(),
                        path: audit_path.as_deref(),
                        outcome: "respond",
                        matched_rule: matched_rule.as_deref(),
                        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                        log_context: &log_context,
                    },
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
                send_qpx_policy_response(
                    &mut req_stream,
                    response,
                    QpxPolicyResponseContext {
                        state: &state,
                        listener_name: self.listener_name.as_ref(),
                        conn: &conn,
                        host: host.as_str(),
                        path: audit_path.as_deref(),
                        outcome: "block",
                        matched_rule: matched_rule.as_deref(),
                        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                        log_context: &log_context,
                    },
                )
                .await?;
                return Ok(());
            }
            ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {}
        }

        let upstream_timeout = timeout_override.unwrap_or_else(|| {
            Duration::from_millis(state.config.runtime.upstream_http_timeout_ms)
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
                send_qpx_policy_response(
                    &mut req_stream,
                    response,
                    QpxPolicyResponseContext {
                        state: &state,
                        listener_name: self.listener_name.as_ref(),
                        conn: &conn,
                        host: host.as_str(),
                        path: audit_path.as_deref(),
                        outcome: "rate_limited",
                        matched_rule: matched_rule.as_deref(),
                        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                        log_context: &log_context,
                    },
                )
                .await?;
                return Ok(());
            }
        };
        let upstream = match open_upstream_qpx_webtransport_stream(
            &req_head,
            &sanitized_headers,
            proxy_name.as_str(),
            action.upstream.as_deref(),
            state
                .listener_config(self.listener_name.as_ref())
                .and_then(|listener| listener.tls_inspection.as_ref())
                .map(|cfg| {
                    cfg.verify_upstream
                        && !state.tls_verify_exception_matches(
                            self.listener_name.as_ref(),
                            host.as_str(),
                        )
                })
                .unwrap_or(true),
            session.datagrams.is_some(),
            upstream_timeout,
        )
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
                send_qpx_policy_response(
                    &mut req_stream,
                    response,
                    QpxPolicyResponseContext {
                        state: &state,
                        listener_name: self.listener_name.as_ref(),
                        conn: &conn,
                        host: host.as_str(),
                        path: audit_path.as_deref(),
                        outcome: "error",
                        matched_rule: matched_rule.as_deref(),
                        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                        log_context: &log_context,
                    },
                )
                .await?;
                return Ok(());
            }
        };

        let qpx_h3::WebTransportSession {
            session_id,
            opener: downstream_opener,
            datagrams: downstream_datagrams,
            bidi_streams: downstream_bidi_streams,
            uni_streams: downstream_uni_streams,
        } = session;
        let qpx_h3::ExtendedConnectStream {
            interim,
            response,
            request_stream: upstream_request,
            datagrams: upstream_datagrams,
            opener: upstream_opener,
            associated_bidi,
            associated_uni,
            _critical_streams,
            _endpoint,
            driver,
            datagram_task,
            _connection_use,
        } = upstream;

        for interim in interim {
            let interim = crate::http3::codec::sanitize_interim_response_for_h3(interim)?;
            timeout(
                h3_body_read_timeout(&self.runtime),
                req_stream.send_response_head(&interim),
            )
            .await
            .map_err(|_| anyhow!("qpx-h3 interim response send timed out"))??;
        }
        if !response.status().is_success() {
            let response = upstream_qpx_extended_connect_error_response(
                response,
                upstream_request,
                proxy_name.as_str(),
                response_headers.as_deref(),
                h3_body_read_timeout(&self.runtime),
            )?;
            send_qpx_response_stream(
                &mut req_stream,
                response,
                &http::Method::CONNECT,
                max_h3_response_body_bytes,
                h3_body_read_timeout(&self.runtime),
            )
            .await?;
            if let Some(task) = datagram_task {
                task.abort();
                let _ = task.await;
            }
            let _ = driver.await;
            return Ok(());
        }

        let established = finalize_qpx_connect_head_response(
            response,
            proxy_name.as_str(),
            response_headers.as_deref(),
        )?;
        tokio::time::timeout(
            tunnel_idle_timeout,
            req_stream.send_response_head(&established),
        )
        .await
        .map_err(|_| anyhow!("forward qpx-h3 extended CONNECT response send timeout"))??;
        emit_audit_log(
            &state,
            AuditRecord {
                kind: "forward",
                name: self.listener_name.as_ref(),
                remote_ip: conn.remote_addr.ip(),
                host: Some(host.as_str()),
                sni: Some(host.as_str()),
                method: Some("CONNECT"),
                path: audit_path.as_deref(),
                outcome: "allow",
                status: Some(StatusCode::OK.as_u16()),
                matched_rule: matched_rule.as_deref(),
                matched_route: None,
                ext_authz_policy_id: ext_authz_policy_id.as_deref(),
            },
            &log_context,
        );
        let flow_limits = {
            let rate_limiters = &state.policy.rate_limiters;
            let listener = self.listener_name.as_ref();
            let rule = matched_rule.as_deref();
            let profile = rate_limit_profile.as_deref();
            WebTransportFlowLimits {
                bidi: rate_limiters.collect(
                    listener,
                    rule,
                    profile,
                    crate::rate_limit::TransportScope::WebtransportBidi,
                ),
                bidi_downstream: rate_limiters.collect(
                    listener,
                    rule,
                    profile,
                    crate::rate_limit::TransportScope::WebtransportBidiDownstream,
                ),
                bidi_upstream: rate_limiters.collect(
                    listener,
                    rule,
                    profile,
                    crate::rate_limit::TransportScope::WebtransportBidiUpstream,
                ),
                uni: rate_limiters.collect(
                    listener,
                    rule,
                    profile,
                    crate::rate_limit::TransportScope::WebtransportUni,
                ),
                uni_downstream: rate_limiters.collect(
                    listener,
                    rule,
                    profile,
                    crate::rate_limit::TransportScope::WebtransportUniDownstream,
                ),
                uni_upstream: rate_limiters.collect(
                    listener,
                    rule,
                    profile,
                    crate::rate_limit::TransportScope::WebtransportUniUpstream,
                ),
                datagram: rate_limiters.collect(
                    listener,
                    rule,
                    profile,
                    crate::rate_limit::TransportScope::WebtransportDatagram,
                ),
                datagram_downstream: rate_limiters.collect(
                    listener,
                    rule,
                    profile,
                    crate::rate_limit::TransportScope::WebtransportDatagramDownstream,
                ),
                datagram_upstream: rate_limiters.collect(
                    listener,
                    rule,
                    profile,
                    crate::rate_limit::TransportScope::WebtransportDatagramUpstream,
                ),
            }
        };
        let relay_result = relay_qpx_webtransport_session(QpxWebTransportRelayContext {
            downstream_request: req_stream,
            downstream_datagrams,
            downstream_opener,
            downstream_bidi_streams,
            downstream_uni_streams,
            upstream_request,
            upstream_datagrams,
            upstream_opener: upstream_opener
                .ok_or_else(|| anyhow!("missing upstream WebTransport opener"))?,
            upstream_bidi_streams: associated_bidi
                .ok_or_else(|| anyhow!("missing upstream WebTransport bidi channel"))?,
            upstream_uni_streams: associated_uni
                .ok_or_else(|| anyhow!("missing upstream WebTransport uni channel"))?,
            session_id,
            idle_timeout: tunnel_idle_timeout,
            rate_limit_ctx: request_limit_ctx,
            request_limits,
            flow_limits,
        })
        .await;
        if let Err(err) = relay_result {
            warn!(error = ?err, "forward HTTP/3 WebTransport relay failed");
        }
        if let Some(task) = datagram_task {
            task.abort();
            let _ = task.await;
        }
        let _ = driver.await;
        Ok(())
    }
}

async fn collect_forward_response(
    mut response: Response<crate::http::body::Body>,
    request_method: &http::Method,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<qpx_h3::Response> {
    let interim = crate::http::interim::take_interim_response_heads(&mut response)
        .into_iter()
        .filter_map(|head| {
            let mut response = http::Response::builder()
                .status(head.status)
                .body(())
                .ok()?;
            *response.headers_mut() = head.headers;
            Some(response)
        })
        .collect();
    let (head, body, trailers): (http::Response<()>, bytes::Bytes, Option<http::HeaderMap>) =
        crate::http3::codec::hyper_response_to_h3(
            response,
            request_method,
            max_body_bytes,
            body_read_timeout,
        )
        .await?;
    Ok(qpx_h3::Response {
        interim,
        response: head.map(|_| body),
        trailers,
    })
}

async fn send_qpx_static_response(
    req_stream: &mut qpx_h3::RequestStream,
    status: StatusCode,
    body: &[u8],
) -> Result<()> {
    const STATIC_RESPONSE_SEND_TIMEOUT: Duration = Duration::from_secs(30);

    let response = http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())?;
    tokio::time::timeout(
        STATIC_RESPONSE_SEND_TIMEOUT,
        req_stream.send_response_head(&response),
    )
    .await
    .map_err(|_| anyhow!("forward qpx-h3 response send timeout"))??;
    if !body.is_empty() {
        tokio::time::timeout(
            STATIC_RESPONSE_SEND_TIMEOUT,
            req_stream.send_data(Bytes::copy_from_slice(body)),
        )
        .await
        .map_err(|_| anyhow!("forward qpx-h3 response body send timeout"))??;
    }
    tokio::time::timeout(STATIC_RESPONSE_SEND_TIMEOUT, req_stream.finish())
        .await
        .map_err(|_| anyhow!("forward qpx-h3 response finish timeout"))?
}

async fn send_qpx_response_stream(
    req_stream: &mut qpx_h3::RequestStream,
    response: Response<Body>,
    request_method: &http::Method,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<()> {
    let (head, body, trailers): (http::Response<()>, Bytes, Option<http::HeaderMap>) =
        crate::http3::codec::hyper_response_to_h3(
            response,
            request_method,
            max_body_bytes,
            body_read_timeout,
        )
        .await?;
    tokio::time::timeout(body_read_timeout, req_stream.send_response_head(&head))
        .await
        .map_err(|_| anyhow!("forward qpx-h3 response send timeout"))??;
    if !body.is_empty() {
        tokio::time::timeout(body_read_timeout, req_stream.send_data(body))
            .await
            .map_err(|_| anyhow!("forward qpx-h3 response body send timeout"))??;
    }
    if let Some(trailers) = trailers.as_ref() {
        tokio::time::timeout(body_read_timeout, req_stream.send_trailers(trailers))
            .await
            .map_err(|_| anyhow!("forward qpx-h3 response trailer send timeout"))??;
    }
    tokio::time::timeout(body_read_timeout, req_stream.finish())
        .await
        .map_err(|_| anyhow!("forward qpx-h3 response finish timeout"))?
}

async fn send_qpx_policy_response(
    req_stream: &mut qpx_h3::RequestStream,
    response: Response<Body>,
    ctx: QpxPolicyResponseContext<'_>,
) -> Result<()> {
    let QpxPolicyResponseContext {
        state,
        listener_name,
        conn,
        host,
        path,
        outcome,
        matched_rule,
        ext_authz_policy_id,
        log_context,
    } = ctx;
    emit_audit_log(
        state,
        AuditRecord {
            kind: "forward",
            name: listener_name,
            remote_ip: conn.remote_addr.ip(),
            host: Some(host),
            sni: Some(host),
            method: Some("CONNECT"),
            path,
            outcome,
            status: Some(response.status().as_u16()),
            matched_rule,
            matched_route: None,
            ext_authz_policy_id,
        },
        log_context,
    );
    send_qpx_response_stream(
        req_stream,
        response,
        &http::Method::CONNECT,
        state.config.runtime.max_h3_response_body_bytes,
        Duration::from_millis(state.config.runtime.h3_read_timeout_ms.max(1)),
    )
    .await
}

fn h3_body_read_timeout(runtime: &Runtime) -> Duration {
    Duration::from_millis(runtime.state().config.runtime.h3_read_timeout_ms.max(1))
}

pub(super) struct QpxPolicyResponseContext<'a> {
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) listener_name: &'a str,
    pub(super) conn: &'a qpx_h3::ConnectionInfo,
    pub(super) host: &'a str,
    pub(super) path: Option<&'a str>,
    pub(super) outcome: &'static str,
    pub(super) matched_rule: Option<&'a str>,
    pub(super) ext_authz_policy_id: Option<&'a str>,
    pub(super) log_context: &'a RequestLogContext,
}

fn validate_qpx_webtransport_head(
    req_head: &http::Request<()>,
    headers: &http::HeaderMap,
    authority_host: &str,
    authority_port: u16,
) -> Result<()> {
    crate::http::semantics::validate_h2_h3_request_headers(http::Version::HTTP_3, headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    crate::http::semantics::validate_expect_header(headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    if req_head.method() != http::Method::CONNECT {
        return Err(anyhow!("CONNECT method required"));
    }
    let scheme = req_head
        .uri()
        .scheme_str()
        .ok_or_else(|| anyhow!("extended CONNECT requires :scheme"))?;
    if scheme.trim().is_empty() {
        return Err(anyhow!("extended CONNECT :scheme must not be empty"));
    }
    let path = req_head
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .ok_or_else(|| anyhow!("extended CONNECT requires :path"))?;
    if path.trim().is_empty() {
        return Err(anyhow!("extended CONNECT :path must not be empty"));
    }
    let host_values: Vec<_> = headers.get_all(http::header::HOST).iter().collect();
    if host_values.len() > 1 {
        return Err(anyhow!("multiple Host headers are not allowed"));
    }
    if let Some(value) = host_values.first() {
        let raw = value
            .to_str()
            .map_err(|_| anyhow!("invalid Host header"))?
            .trim();
        if raw.is_empty() {
            return Err(anyhow!("Host header must not be empty"));
        }
        let (host_name, host_port) =
            crate::http::address::parse_authority_host_port(raw, authority_port)
                .ok_or_else(|| anyhow!("invalid Host header"))?;
        if host_port != authority_port || !host_name.eq_ignore_ascii_case(authority_host) {
            return Err(anyhow!("Host header does not match CONNECT authority"));
        }
    }
    Ok(())
}

fn normalize_qpx_upstream_connect_headers(
    uri: &http::Uri,
    headers: &http::HeaderMap,
    proxy_name: &str,
) -> Result<http::HeaderMap> {
    let mut request = hyper::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri.to_string().parse::<http::Uri>()?)
        .body(Body::empty())?;
    *request.version_mut() = http::Version::HTTP_3;
    *request.headers_mut() = headers.clone();
    prepare_request_with_headers_in_place(&mut request, proxy_name, None, false);
    Ok(request.headers().clone())
}

async fn open_upstream_qpx_webtransport_stream(
    req_head: &http::Request<()>,
    sanitized_headers: &http::HeaderMap,
    proxy_name: &str,
    upstream: Option<&str>,
    verify_upstream: bool,
    enable_datagram: bool,
    timeout_dur: Duration,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let (connect_host, connect_port) =
        parse_qpx_extended_connect_upstream(req_head.uri(), upstream).await?;
    let upstream_addr: SocketAddr = match timeout(
        timeout_dur,
        lookup_host((connect_host.as_str(), connect_port)),
    )
    .await
    {
        Ok(Ok(mut addrs)) => addrs
            .next()
            .ok_or_else(|| anyhow!("failed to resolve extended CONNECT upstream"))?,
        Ok(Err(err)) => return Err(anyhow!(err)),
        Err(_) => return Err(anyhow!("extended CONNECT upstream resolution timed out")),
    };

    let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint
        .set_default_client_config(crate::http3::quic::build_h3_client_config(verify_upstream)?);
    let connection =
        match timeout(timeout_dur, endpoint.connect(upstream_addr, &connect_host)?).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(err)) => return Err(anyhow!(err)),
            Err(_) => return Err(anyhow!("extended CONNECT upstream connect timed out")),
        };
    let normalized_headers =
        normalize_qpx_upstream_connect_headers(req_head.uri(), sanitized_headers, proxy_name)?;
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(req_head.uri().clone())
        .body(())?;
    *request.headers_mut() = normalized_headers;
    qpx_h3::open_extended_connect_stream(
        endpoint,
        connection,
        request,
        Some(qpx_h3::Protocol::WebTransport),
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram,
            enable_webtransport: true,
            max_webtransport_sessions: 1,
            max_request_body_bytes: 16 * 1024 * 1024,
            max_concurrent_streams_per_connection: 64,
            read_timeout: timeout_dur,
            ..Default::default()
        },
        timeout_dur,
    )
    .await
}

async fn parse_qpx_extended_connect_upstream(
    uri: &http::Uri,
    upstream: Option<&str>,
) -> Result<(String, u16)> {
    if let Some(upstream) = upstream {
        if upstream.contains("://") {
            let parsed = url::Url::parse(upstream)?;
            match parsed.scheme() {
                "https" | "h3" => {}
                _ => return Err(anyhow!("extended CONNECT upstream requires https/h3 URL")),
            }
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow!("extended CONNECT upstream host missing"))?;
            let port = parsed.port().unwrap_or(443);
            return Ok((host.to_string(), port));
        }
        return crate::http::address::parse_authority_host_port(upstream, 443)
            .ok_or_else(|| anyhow!("invalid extended CONNECT upstream authority"));
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow!("extended CONNECT missing authority"))?;
    crate::http::address::parse_authority_host_port(authority.as_str(), 443)
        .ok_or_else(|| anyhow!("invalid extended CONNECT authority"))
}

fn finalize_qpx_connect_head_response(
    response: http::Response<()>,
    proxy_name: &str,
    header_control: Option<&CompiledHeaderControl>,
) -> Result<http::Response<()>> {
    let (parts, _) = response.into_parts();
    let mut downstream = Response::builder()
        .status(StatusCode::from_u16(parts.status.as_u16())?)
        .body(Body::empty())?;
    *downstream.headers_mut() = h1_headers_to_http(&parts.headers)?;
    let downstream = finalize_response_with_headers(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        downstream,
        header_control,
        false,
    );
    let status = http::StatusCode::from_u16(downstream.status().as_u16())?;
    let mut out = http::Response::builder().status(status).body(())?;
    *out.headers_mut() = http_headers_to_h1(downstream.headers())?;
    Ok(out)
}

fn upstream_qpx_extended_connect_error_response(
    response: http::Response<()>,
    upstream: qpx_h3::RequestStream,
    proxy_name: &str,
    header_control: Option<&CompiledHeaderControl>,
    body_read_timeout: Duration,
) -> Result<Response<Body>> {
    let (parts, _) = response.into_parts();
    let mut downstream = Response::builder()
        .status(StatusCode::from_u16(parts.status.as_u16())?)
        .body(body_from_upstream_qpx_stream(upstream, body_read_timeout))?;
    *downstream.headers_mut() = h1_headers_to_http(&parts.headers)?;
    Ok(finalize_response_with_headers(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        downstream,
        header_control,
        false,
    ))
}

fn body_from_upstream_qpx_stream(
    mut upstream: qpx_h3::RequestStream,
    body_read_timeout: Duration,
) -> Body {
    let (mut sender, body) = Body::channel();
    tokio::spawn(async move {
        loop {
            let next = tokio::select! {
                _ = sender.closed() => return,
                recv = timeout(body_read_timeout, upstream.recv_data()) => recv,
            };
            match next {
                Err(_) => {
                    warn!("extended CONNECT upstream error body timed out");
                    sender.abort();
                    return;
                }
                Ok(Ok(Some(chunk))) => {
                    if sender.send_data(chunk).await.is_err() {
                        return;
                    }
                }
                Ok(Ok(None)) => break,
                Ok(Err(err)) => {
                    warn!(error = ?err, "extended CONNECT upstream error body stream failed");
                    sender.abort();
                    return;
                }
            }
        }
        let trailers = tokio::select! {
            _ = sender.closed() => return,
            recv = timeout(body_read_timeout, upstream.recv_trailers()) => recv,
        };
        match trailers {
            Err(_) => {
                warn!("extended CONNECT upstream error trailers timed out");
                sender.abort();
            }
            Ok(Ok(Some(trailers))) => match h1_headers_to_http(&trailers) {
                Ok(trailers) => {
                    let _ = sender.send_trailers(trailers).await;
                }
                Err(err) => {
                    warn!(error = ?err, "extended CONNECT upstream trailers were invalid");
                }
            },
            Ok(Ok(None)) => {}
            Ok(Err(err)) => {
                warn!(error = ?err, "extended CONNECT upstream error trailers failed");
            }
        }
    });
    body
}
