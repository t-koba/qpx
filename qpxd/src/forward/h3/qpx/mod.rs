use crate::http3::quinn_socket::{
    NoopQuinnUdpIngressFilter, PreparedServerEndpointSocket, QuinnBrokerKind, QuinnBrokerStream,
    QuinnEndpointSocket, build_server_endpoint, prepare_server_endpoint_socket,
};
use crate::runtime::Runtime;
use crate::server::control::SidecarControl;
use anyhow::{Result, anyhow};
use qpx_core::config::{ConnectUdpConfig, Http3IngressEdgeConfig, IngressEdgeConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{info, warn};

mod connect;
mod connect_upstream;
mod handler;
mod relay;
mod response;
mod webtransport;
mod webtransport_dispatch;

pub(super) use self::handler::{ForwardQpxHandler, h3_body_read_timeout};

pub(crate) fn configure_qpx_h3_upstream_session_pool(
    max_sessions_per_key: usize,
    max_inflight_streams_per_session: usize,
) {
    connect_upstream::configure_qpx_h3_upstream_session_pool(
        max_sessions_per_key,
        max_inflight_streams_per_session,
    );
}

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
        .h3
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
