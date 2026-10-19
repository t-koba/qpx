use super::super::{
    ReloadableReverse, record_reverse_connection_filter_block, reverse_quic_connection_filter_match,
};
use crate::http3::quinn_socket::{
    PreparedServerEndpointSocket, QuinnBrokerKind, QuinnBrokerStream, QuinnUdpIngressFilter,
    prepare_server_endpoint_socket,
};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;

pub(crate) fn prepare_reverse_terminate_socket(
    reverse_name: &str,
    reverse_rt: ReloadableReverse,
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

struct ReverseQuicPacketFilter {
    reverse: ReloadableReverse,
    local_port: u16,
}

impl QuinnUdpIngressFilter for ReverseQuicPacketFilter {
    fn allow(&self, remote_addr: SocketAddr, packet: &[u8]) -> bool {
        match reverse_quic_connection_filter_match(
            &self.reverse,
            remote_addr,
            self.local_port,
            packet,
        ) {
            Some((stage, matched_rule, sni)) => {
                record_reverse_connection_filter_block(
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
