use super::broker::{
    LocalQuinnBrokerHandle, QuinnBrokerKind, new_local_broker_socket, new_remote_broker_socket,
};
use super::stream::QuinnBrokerStream;
use anyhow::Result;
use quinn::AsyncUdpSocket;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct QuinnEndpointSocket {
    socket: Arc<dyn AsyncUdpSocket>,
}

impl QuinnEndpointSocket {
    pub(super) fn new(socket: Arc<dyn AsyncUdpSocket>) -> Self {
        Self { socket }
    }

    pub(crate) fn as_async_socket(&self) -> Arc<dyn AsyncUdpSocket> {
        self.socket.clone()
    }
}

pub(crate) struct PreparedServerEndpointSocket {
    pub(crate) endpoint_socket: QuinnEndpointSocket,
    pub(crate) local_broker_handle: Option<LocalQuinnBrokerHandle>,
}

pub(crate) trait QuinnUdpIngressFilter: Send + Sync + 'static {
    fn allow(&self, remote_addr: SocketAddr, packet: &[u8]) -> bool;
}

#[derive(Default)]
pub(crate) struct NoopQuinnUdpIngressFilter;

impl QuinnUdpIngressFilter for NoopQuinnUdpIngressFilter {
    fn allow(&self, _remote_addr: SocketAddr, _packet: &[u8]) -> bool {
        true
    }
}

pub(crate) fn prepare_server_endpoint_socket(
    name: &str,
    kind: QuinnBrokerKind,
    std_socket: std::net::UdpSocket,
    inherited_stream: Option<QuinnBrokerStream>,
    filter: Arc<dyn QuinnUdpIngressFilter>,
) -> Result<PreparedServerEndpointSocket> {
    if let Some(stream) = inherited_stream {
        return Ok(PreparedServerEndpointSocket {
            endpoint_socket: new_remote_broker_socket(std_socket, stream, filter)?,
            local_broker_handle: None,
        });
    }

    let (endpoint_socket, local_broker_handle) =
        new_local_broker_socket(name, kind, std_socket, filter)?;
    Ok(PreparedServerEndpointSocket {
        endpoint_socket,
        local_broker_handle: Some(local_broker_handle),
    })
}

#[cfg(feature = "http3")]
pub(crate) fn build_server_endpoint(
    socket: QuinnEndpointSocket,
    server_config: quinn::ServerConfig,
) -> Result<quinn::Endpoint> {
    Ok(quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket.as_async_socket(),
        Arc::new(quinn::TokioRuntime),
    )?)
}
