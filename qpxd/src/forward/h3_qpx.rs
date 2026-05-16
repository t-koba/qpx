use super::policy::{ForwardPolicyDecision, evaluate_forward_policy};
#[cfg(feature = "auth-basic")]
use super::request::proxy_auth_required;
use crate::http::body::Body;
use crate::http::body_size::set_observed_request_size;
use crate::http::common::{
    blocked_response as blocked, forbidden_response as forbidden, http_version_label,
    too_many_requests_response as too_many_requests,
};
use crate::http::l7::{finalize_response_for_request, finalize_response_with_headers};
use crate::http::local_response::build_local_response;
use crate::http3::codec::{h1_headers_to_http, h3_request_to_hyper};
use crate::http3::quinn_socket::{
    NoopQuinnUdpIngressFilter, PreparedServerEndpointSocket, QuinnBrokerKind, QuinnBrokerStream,
    QuinnEndpointSocket, build_server_endpoint, prepare_server_endpoint_socket,
};
use crate::policy_context::{
    AuditRecord, ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode,
    apply_ext_authz_action_overrides, emit_audit_log, enforce_ext_authz, resolve_identity,
    sanitize_headers_for_policy, validate_ext_authz_allow_mode,
};
use crate::runtime::Runtime;
use crate::sidecar_control::SidecarControl;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use hyper::{Response, StatusCode};
use qpx_core::config::{ActionKind, ConnectUdpConfig, Http3IngressEdgeConfig, IngressEdgeConfig};
use qpx_core::rules::{CompiledHeaderControl, RuleMatchContext};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::{Duration, Instant, timeout};
use tracing::{info, warn};

#[path = "h3_connect_parse.rs"]
mod h3_connect_parse;
#[path = "h3_qpx_connect.rs"]
mod h3_qpx_connect;
#[path = "h3_qpx_connect_upstream.rs"]
mod h3_qpx_connect_upstream;
#[path = "h3_qpx_relay.rs"]
mod h3_qpx_relay;
#[path = "h3_qpx_response.rs"]
mod h3_qpx_response;
#[path = "h3_qpx_webtransport.rs"]
mod h3_qpx_webtransport;
#[path = "h3_qpx_webtransport_dispatch.rs"]
mod h3_qpx_webtransport_dispatch;

use self::h3_connect_parse::{
    H3ConnectProtocol, parse_connect_authority_required, parse_connect_udp_target,
    validate_h3_connect_pseudo_headers,
};
use self::h3_qpx_connect::handle_qpx_connect_stream;
use self::h3_qpx_connect_upstream::{
    OpenUpstreamQpxExtendedConnectInput, open_upstream_qpx_extended_connect_stream,
    validate_qpx_connect_head,
};
use self::h3_qpx_response::{
    QpxPolicyResponseContext, finalize_qpx_connect_head_response, send_qpx_policy_response,
    send_qpx_response_stream, send_qpx_static_response,
    upstream_qpx_extended_connect_error_response,
};
use self::h3_qpx_webtransport_dispatch::handle_qpx_webtransport_connect as dispatch_qpx_webtransport_connect;

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
    listener: IngressEdgeConfig,
    runtime: Runtime,
    http3_cfg: Http3IngressEdgeConfig,
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

    let tls_config = build_forward_tls_config(&listener, &runtime, listen_addr)?;
    let max_bidi = runtime
        .state()
        .plan
        .limits
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
    listener: &IngressEdgeConfig,
    runtime: &Runtime,
    listen_addr: SocketAddr,
) -> Result<quinn::rustls::ServerConfig> {
    let state = runtime.state();
    let ca = state
        .security
        .destination
        .tls
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
        let limits = state.plan.limits;
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: limits.max_h3_streams_per_connection.max(1) as u64,
            max_request_body_bytes: limits.max_h3_request_body_bytes,
            max_concurrent_streams_per_connection: limits.max_h3_streams_per_connection,
            read_timeout: Duration::from_millis(limits.h3_read_timeout_ms),
            datagram_channel_capacity: limits.datagram_channel_capacity,
            webtransport_datagram_channel_capacity: limits.webtransport_datagram_channel_capacity,
            webtransport_stream_channel_capacity: limits.webtransport_stream_channel_capacity,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        request: qpx_h3::Request,
        conn: qpx_h3::ConnectionInfo,
        req_stream: &mut qpx_h3::RequestStream,
    ) -> Result<()> {
        if request.head.method() == http::Method::CONNECT {
            return self
                .handle_connect(request, conn.remote_addr, req_stream)
                .await;
        }

        self.handle_http_request(request, conn.remote_addr, req_stream)
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
    async fn handle_http_request(
        &self,
        request: qpx_h3::Request,
        remote_addr: std::net::SocketAddr,
        req_stream: &mut qpx_h3::RequestStream,
    ) -> Result<()> {
        let request_headers = request.head.headers().clone();
        let grpc_protocol = crate::http::rpc::streaming_grpc_protocol(&request_headers, None);
        let grpc_started = Instant::now();
        let grpc_deadline = grpc_protocol.as_ref().map(|_| {
            grpc_started
                + Duration::from_millis(
                    self.runtime.state().plan.limits.max_grpc_stream_duration_ms,
                )
        });
        let declared_content_length =
            crate::http3::codec::parse_content_length_fields(request.head.headers())?;
        if let Some(content_length) = declared_content_length
            && content_length > self.runtime.state().plan.limits.max_h3_request_body_bytes as u64
        {
            return send_qpx_static_response(
                req_stream,
                StatusCode::PAYLOAD_TOO_LARGE,
                b"request payload too large",
            )
            .await;
        }

        let (sender, body) = Body::channel();
        let mut req = h3_request_to_hyper(request.head, body)?;
        if let Some(content_length) = declared_content_length {
            set_observed_request_size(&mut req, content_length);
        }
        let request_method = req.method().clone();
        let response_fut = async {
            let fut = crate::forward::request::handle_request_inner(
                req,
                self.runtime.clone(),
                self.listener_name.as_ref(),
                remote_addr,
            );
            if let Some(deadline) = grpc_deadline {
                tokio::time::timeout_at(deadline, fut)
                    .await
                    .map_err(|_| anyhow!("qpx-h3 gRPC stream duration exceeded configured limit"))?
            } else {
                fut.await
            }
        };
        let relay_fut = crate::http3::qpx_stream::relay_qpx_request_body_observed(
            req_stream,
            sender,
            crate::http3::qpx_stream::QpxRequestBodyRelayOptions {
                read_timeout: h3_body_read_timeout(&self.runtime),
                max_body_bytes: self.runtime.state().plan.limits.max_h3_request_body_bytes,
                declared_content_length,
                request_headers: &request_headers,
                listener_name: Some(self.listener_name.as_ref()),
                max_grpc_message_bytes: Some(
                    self.runtime.state().plan.limits.max_grpc_message_bytes,
                ),
                grpc_stream_deadline: grpc_deadline,
            },
        );
        let (relay_result, response) = tokio::join!(relay_fut, response_fut);
        let request_summary = match relay_result {
            Ok((_bytes, summary)) => summary,
            Err(err) => {
                warn!(error = ?err, "forward qpx-h3 request body relay failed");
                None
            }
        };
        let response = response?;
        let response_summary = crate::http3::qpx_stream::send_qpx_response_stream_observed(
            req_stream,
            response,
            &request_method,
            crate::http3::qpx_stream::QpxResponseSendOptions {
                max_body_bytes: self.runtime.state().plan.limits.max_h3_response_body_bytes,
                body_read_timeout: h3_body_read_timeout(&self.runtime),
                listener_name: Some(self.listener_name.as_ref()),
                fallback_grpc_protocol: grpc_protocol.as_deref(),
                max_grpc_message_bytes: Some(
                    self.runtime.state().plan.limits.max_grpc_message_bytes,
                ),
                grpc_stream_deadline: grpc_deadline,
            },
        )
        .await?;
        if let Some(protocol) = grpc_protocol.as_deref() {
            let streaming = crate::http::rpc::grpc_streaming_label(
                protocol,
                request_summary
                    .as_ref()
                    .map(|summary| summary.message_count()),
                response_summary
                    .as_ref()
                    .map(|summary| summary.message_count()),
            );
            crate::http::rpc::emit_grpc_stream_duration_metric(
                self.listener_name.as_ref(),
                protocol,
                streaming,
                grpc_started.elapsed(),
            );
        }
        Ok(())
    }

    async fn handle_connect(
        &self,
        request: qpx_h3::Request,
        remote_addr: std::net::SocketAddr,
        req_stream: &mut qpx_h3::RequestStream,
    ) -> Result<()> {
        match request.protocol {
            Some(qpx_h3::Protocol::ConnectUdp) => {
                self.handle_connect_udp(request, req_stream).await
            }
            Some(_) => {
                self.static_response(
                    req_stream,
                    http::Method::CONNECT,
                    StatusCode::NOT_IMPLEMENTED,
                    self.runtime.state().messages.proxy_error.clone(),
                )
                .await
            }
            None => {
                self.handle_http_request(request, remote_addr, req_stream)
                    .await
            }
        }
    }

    async fn handle_connect_udp(
        &self,
        request: qpx_h3::Request,
        req_stream: &mut qpx_h3::RequestStream,
    ) -> Result<()> {
        if !self.connect_udp.enabled {
            return self
                .static_response(
                    req_stream,
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
                    req_stream,
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
            self.runtime.state().plan.identity.proxy_name.as_ref(),
            response,
            false,
        );
        send_qpx_response_stream(
            req_stream,
            response,
            &http::Method::CONNECT,
            self.runtime.state().plan.limits.max_h3_response_body_bytes,
            h3_body_read_timeout(&self.runtime),
        )
        .await
    }

    async fn static_response(
        &self,
        req_stream: &mut qpx_h3::RequestStream,
        method: http::Method,
        status: StatusCode,
        body: String,
    ) -> Result<()> {
        let response = crate::http::l7::finalize_response_for_request(
            &method,
            http::Version::HTTP_3,
            self.runtime.state().plan.identity.proxy_name.as_ref(),
            Response::builder()
                .status(status)
                .body(crate::http::body::Body::from(body))?,
            false,
        );
        send_qpx_response_stream(
            req_stream,
            response,
            &method,
            self.runtime.state().plan.limits.max_h3_response_body_bytes,
            h3_body_read_timeout(&self.runtime),
        )
        .await
    }

    async fn handle_qpx_webtransport_connect(
        &self,
        req_head: http::Request<()>,
        req_stream: qpx_h3::RequestStream,
        conn: qpx_h3::ConnectionInfo,
        session: qpx_h3::WebTransportSession,
    ) -> Result<()> {
        dispatch_qpx_webtransport_connect(self, req_head, req_stream, conn, session).await
    }
}

fn h3_body_read_timeout(runtime: &Runtime) -> Duration {
    Duration::from_millis(runtime.state().plan.limits.h3_read_timeout_ms.max(1))
}
