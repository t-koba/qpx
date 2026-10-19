use super::super::ReloadableReverse;
pub(crate) use super::terminate_socket::prepare_reverse_terminate_socket;
use crate::http3::quinn_socket::QuinnEndpointSocket;
use crate::server::control::SidecarControl;
use anyhow::{Result, anyhow};
use qpx_core::config::ReverseEdgeConfig;
use std::net::SocketAddr;
use tokio::sync::watch;

pub(crate) async fn run_http3_terminate(
    _reverse: ReverseEdgeConfig,
    _listen_addr: SocketAddr,
    _reverse_rt: ReloadableReverse,
    _shutdown: watch::Receiver<SidecarControl>,
    _endpoint_socket: QuinnEndpointSocket,
) -> Result<()> {
    Err(anyhow!("invalid HTTP/3 backend feature selection"))
}

pub(crate) fn build_reverse_tls_config(
    _reverse: &ReverseEdgeConfig,
) -> Result<quinn::rustls::ServerConfig> {
    Err(anyhow!("invalid HTTP/3 backend feature selection"))
}
