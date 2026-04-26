use crate::http3::quinn_socket::{
    prepare_server_endpoint_socket, NoopQuinnUdpIngressFilter, PreparedServerEndpointSocket,
    QuinnBrokerKind, QuinnBrokerStream, QuinnEndpointSocket,
};
use crate::runtime::Runtime;
use crate::sidecar_control::SidecarControl;
use anyhow::{anyhow, Result};
use qpx_core::config::{Http3ListenerConfig, ListenerConfig};
use std::sync::Arc;
use tokio::sync::watch;

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
    _listener: ListenerConfig,
    _runtime: Runtime,
    _http3_cfg: Http3ListenerConfig,
    _shutdown: watch::Receiver<SidecarControl>,
    _endpoint_socket: QuinnEndpointSocket,
) -> Result<()> {
    Err(anyhow!("invalid HTTP/3 backend feature selection"))
}
