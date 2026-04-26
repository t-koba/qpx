use crate::sidecar_control::SidecarControl;
use crate::udp_session_handoff::{ReversePassthroughListenerRestore, UdpSessionRestoreState};
use anyhow::{anyhow, Result};
use qpx_core::config::ReverseHttp3Config;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
use tokio::time::Duration;

pub(crate) struct Http3PassthroughRuntime {
    pub(crate) reverse: super::ReloadableReverse,
    pub(crate) upstream_resolve_timeout: Duration,
    pub(crate) shutdown: watch::Receiver<SidecarControl>,
    pub(crate) listener_socket: std::net::UdpSocket,
    pub(crate) restore: Option<ReversePassthroughListenerRestore>,
    pub(crate) export_sink: Arc<Mutex<UdpSessionRestoreState>>,
}

pub(crate) async fn run_http3_passthrough(
    _listen_addr: SocketAddr,
    _upstreams: Vec<String>,
    _cfg: &ReverseHttp3Config,
    _runtime: Http3PassthroughRuntime,
) -> Result<()> {
    Err(anyhow!("invalid HTTP/3 backend feature selection"))
}
