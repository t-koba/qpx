use crate::http3::listener::{H3ConnInfo, H3ConnectKind, H3Limits, H3RequestHandler};
use crate::http3::quic::build_h3_server_config_from_tls;
use crate::runtime::Runtime;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hyper::{Body, Request, Response, StatusCode};
use qpx_core::config::{ConnectUdpConfig, Http3ListenerConfig, ListenerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::info;

pub(crate) async fn run_http3_listener(
    listener: ListenerConfig,
    runtime: Runtime,
    http3_cfg: Http3ListenerConfig,
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
    let quic_config = build_h3_server_config_from_tls(tls_config, max_bidi.max(1), 256)?;
    let endpoint = quinn::Endpoint::server(quic_config, listen_addr)?;

    let semaphore = runtime.state().connection_semaphore.clone();
    let handler = ForwardH3Handler {
        runtime,
        listener_name: Arc::<str>::from(listener.name.as_str()),
        connect_udp,
    };
    info!(
        listener = %listener.name,
        addr = %listen_addr,
        connect_udp = handler.connect_udp.enabled,
        "forward HTTP/3 listener starting"
    );
    crate::http3::listener::serve_endpoint(
        endpoint,
        listen_addr.port(),
        handler,
        "forward",
        semaphore,
    )
    .await
}

fn build_forward_tls_config(
    listener: &ListenerConfig,
    runtime: &Runtime,
    listen_addr: SocketAddr,
) -> Result<quinn::rustls::ServerConfig> {
    let state = runtime.state();
    let ca = state
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
pub(super) struct ForwardH3Handler {
    pub(super) runtime: Runtime,
    pub(super) listener_name: Arc<str>,
    pub(super) connect_udp: ConnectUdpConfig,
}

#[async_trait]
impl H3RequestHandler for ForwardH3Handler {
    fn limits(&self) -> H3Limits {
        let state = self.runtime.state();
        let limits = state.config.runtime.clone();
        H3Limits {
            max_request_body_bytes: limits.max_h3_request_body_bytes,
            max_response_body_bytes: limits.max_h3_response_body_bytes,
            max_concurrent_streams_per_connection: limits.max_h3_streams_per_connection,
            read_timeout: Duration::from_millis(limits.h3_read_timeout_ms),
            proxy_name: Arc::<str>::from(state.config.identity.proxy_name.as_str()),
            error_body: Arc::<str>::from(state.messages.proxy_error.as_str()),
        }
    }

    fn enable_extended_connect(&self) -> bool {
        true
    }

    fn enable_datagram(&self) -> bool {
        self.connect_udp.enabled
    }

    async fn handle_http(&self, req: Request<Body>, conn: H3ConnInfo) -> Response<Body> {
        let state = self.runtime.state();
        let request_method = req.method().clone();
        let request_version = req.version();
        match crate::forward::request::handle_request_inner(
            req,
            self.runtime.clone(),
            self.listener_name.as_ref(),
            conn.remote_addr,
        )
        .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::warn!(error = ?err, "forward HTTP/3 request handling failed");
                crate::http::l7::finalize_response_for_request(
                    &request_method,
                    request_version,
                    state.config.identity.proxy_name.as_str(),
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from(state.messages.proxy_error.clone()))
                        .unwrap(),
                    false,
                )
            }
        }
    }

    async fn handle_connect(
        &self,
        req_head: http1::Request<()>,
        req_stream: crate::http3::server::H3ServerRequestStream,
        conn: H3ConnInfo,
        kind: H3ConnectKind,
        datagrams: Option<crate::http3::datagram::H3StreamDatagrams>,
    ) -> Result<()> {
        match kind {
            H3ConnectKind::Connect => {
                let _ = datagrams;
                super::h3_connect::handle_h3_connect(req_head, req_stream, self.clone(), conn).await
            }
            H3ConnectKind::ConnectUdp => {
                super::h3_connect_udp::handle_h3_connect_udp(
                    req_head,
                    req_stream,
                    self.clone(),
                    conn,
                    datagrams,
                )
                .await
            }
        }
    }
}
