use crate::http3::quinn_socket::{
    PreparedServerEndpointSocket, QuinnBrokerKind, QuinnBrokerStream, QuinnEndpointSocket,
    QuinnUdpIngressFilter, prepare_server_endpoint_socket,
};
use crate::sidecar_control::SidecarControl;
use anyhow::{Result, anyhow};
use qpx_core::config::ReverseEdgeConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

pub(crate) fn prepare_reverse_terminate_socket(
    reverse_name: &str,
    reverse_rt: super::ReloadableReverse,
    std_socket: std::net::UdpSocket,
    inherited_broker: Option<QuinnBrokerStream>,
) -> Result<PreparedServerEndpointSocket> {
    let local_port = std_socket.local_addr()?.port();
    prepare_server_endpoint_socket(
        reverse_name,
        QuinnBrokerKind::ReverseTerminate,
        std_socket,
        inherited_broker,
        Arc::new(ReverseQuicPacketFilter {
            reverse: reverse_rt,
            local_port,
        }),
    )
}

pub(crate) async fn run_http3_terminate(
    _reverse: ReverseEdgeConfig,
    _listen_addr: SocketAddr,
    _reverse_rt: super::ReloadableReverse,
    _shutdown: watch::Receiver<SidecarControl>,
    _endpoint_socket: QuinnEndpointSocket,
) -> Result<()> {
    Err(anyhow!("invalid HTTP/3 backend feature selection"))
}

struct ReverseQuicPacketFilter {
    reverse: super::ReloadableReverse,
    local_port: u16,
}

impl QuinnUdpIngressFilter for ReverseQuicPacketFilter {
    fn allow(&self, remote_addr: SocketAddr, packet: &[u8]) -> bool {
        match super::reverse_quic_connection_filter_match(
            &self.reverse,
            remote_addr,
            self.local_port,
            packet,
        ) {
            Some((stage, matched_rule, sni)) => {
                super::record_reverse_connection_filter_block(
                    &self.reverse,
                    remote_addr,
                    self.local_port,
                    stage,
                    matched_rule.as_str(),
                    sni.as_deref(),
                );
                false
            }
            None => true,
        }
    }
}

pub(super) fn build_reverse_tls_config(
    _reverse: &ReverseEdgeConfig,
) -> Result<quinn::rustls::ServerConfig> {
    Err(anyhow!("invalid HTTP/3 backend feature selection"))
}
