use super::server_tls::build_forward_tls_config;
use crate::http3::qpx_listener::serve_qpx_h3_endpoint;
use crate::http3::quinn_socket::{QuinnEndpointSocket, build_server_endpoint};
use crate::runtime::Runtime;
use crate::server::control::SidecarControl;
use anyhow::Result;
use bytes::Bytes;
use qpx_core::config::{
    ConnectIpConfig, ConnectUdpConfig, Http3IngressEdgeConfig, IngressEdgeConfig,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::info;

mod connect;
mod connect_upstream;
mod handler;
mod relay;
mod response;
mod webtransport;
mod webtransport_dispatch;

async fn recv_stream_datagram(datagrams: &mut Option<qpx_h3::StreamDatagrams>) -> Option<Bytes> {
    if let Some(datagrams) = datagrams.as_mut() {
        datagrams.receiver.recv().await
    } else {
        std::future::pending::<Option<Bytes>>().await
    }
}

pub(crate) use self::connect_upstream::QpxH3UpstreamSessionPool;
pub(super) use self::handler::{ForwardQpxHandler, h3_body_read_timeout};

pub(crate) async fn run_http3_listener(
    listener: IngressEdgeConfig,
    runtime: Runtime,
    http3_cfg: Http3IngressEdgeConfig,
    shutdown: watch::Receiver<SidecarControl>,
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
    let connect_ip = http3_cfg.connect_ip.unwrap_or(ConnectIpConfig {
        enabled: false,
        uri_template: "https://invalid/.well-known/masque/ip/{target}/{ipproto}/".to_owned(),
        allowed_source_cidrs: Vec::new(),
        allowed_destination_cidrs: Vec::new(),
        mtu: 1280,
        idle_timeout_secs: 30,
        max_capsule_buffer_bytes: 256 * 1024,
        device: None,
        wintun_dll: None,
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
        connect_ip,
    };
    let connection_semaphore = handler.runtime.state().connection_semaphore.clone();

    info!(
        listener = %listener.name,
        addr = %listen_addr,
        connect_udp = handler.connect_udp.enabled,
        connect_ip = handler.connect_ip.enabled,
        "forward HTTP/3 listener starting (qpx-h3)"
    );
    // The h3 backend logs this same line when its listener starts, with the
    // same field, so a reader can compare the two backends.
    info!(label = "forward", "HTTP/3 listener starting");

    serve_qpx_h3_endpoint(
        endpoint,
        listen_addr,
        handler,
        connection_semaphore,
        shutdown,
        "forward HTTP/3 qpx-h3 connection failed",
    )
    .await
}
