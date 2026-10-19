use crate::http3::quinn_socket::QuinnEndpointSocket;
use crate::runtime::Runtime;
use crate::server::control::SidecarControl;
use anyhow::{Result, anyhow};
use qpx_core::config::{Http3IngressEdgeConfig, IngressEdgeConfig};
use tokio::sync::watch;

pub(crate) async fn run_http3_listener(
    _listener: IngressEdgeConfig,
    _runtime: Runtime,
    _http3_cfg: Http3IngressEdgeConfig,
    _shutdown: watch::Receiver<SidecarControl>,
    _endpoint_socket: QuinnEndpointSocket,
) -> Result<()> {
    Err(anyhow!("invalid HTTP/3 backend feature selection"))
}
