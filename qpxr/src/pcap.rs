use anyhow::Result;
use byteorder_slice::LittleEndian;
use pcap_file::pcapng::Block;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::blocks::section_header::{SectionHeaderBlock, SectionHeaderOption};
use pcap_file::{DataLink, Endianness};
use qpx_core::exporter::{CaptureDirection, CaptureEvent, CapturePlane};
use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

#[derive(Clone, Copy)]
pub(super) struct Endpoint {
    pub(super) ip: Ipv4Addr,
    pub(super) port: u16,
}

pub(super) fn encode_enhanced_packet(
    interface_id: u32,
    timestamp_unix_nanos: u64,
    packet: Vec<u8>,
) -> Result<Vec<u8>> {
    let block = EnhancedPacketBlock {
        interface_id,
        timestamp: Duration::from_nanos(timestamp_unix_nanos),
        original_len: packet.len() as u32,
        data: Cow::Owned(packet),
        options: vec![],
    };
    let mut out = Vec::with_capacity(block.data.len() + 128);
    Block::EnhancedPacket(block).write_to::<LittleEndian, _>(&mut out)?;
    Ok(out)
}

pub(crate) fn build_pcap_preface() -> Result<Vec<u8>> {
    let section = SectionHeaderBlock {
        endianness: Endianness::Little,
        major_version: 1,
        minor_version: 0,
        section_length: -1,
        options: vec![SectionHeaderOption::UserApplication(Cow::Borrowed("qpxr"))],
    };

    let mut out = Vec::new();
    Block::SectionHeader(section).write_to::<LittleEndian, _>(&mut out)?;
    for iface in [
        ("client-proxy-tls", "Client <-> Proxy encrypted bytes"),
        ("proxy-server-tls", "Proxy <-> Server encrypted bytes"),
        ("client-server", "Decrypted plaintext (client <-> server)"),
    ]
    .into_iter()
    .map(|(name, desc)| InterfaceDescriptionBlock {
        linktype: DataLink::IPV4,
        snaplen: 0xFFFF,
        options: vec![
            InterfaceDescriptionOption::IfName(Cow::Borrowed(name)),
            InterfaceDescriptionOption::IfDescription(Cow::Borrowed(desc)),
            // Timestamps are nanosecond counts: without this readers assume
            // the PCAPNG default of microseconds and scale time by 1000.
            InterfaceDescriptionOption::IfTsResol(9),
        ],
    }) {
        Block::InterfaceDescription(iface).write_to::<LittleEndian, _>(&mut out)?;
    }
    Ok(out)
}

pub(super) fn interface_id(plane: CapturePlane) -> u32 {
    match plane {
        CapturePlane::ClientProxyEncrypted => 0,
        CapturePlane::ProxyServerEncrypted => 1,
        CapturePlane::ClientServerPlaintext => 2,
    }
}

pub(super) fn endpoints_for_event(event: &CaptureEvent) -> (Endpoint, Endpoint) {
    let default_server_port = match event.plane {
        CapturePlane::ClientServerPlaintext => 80,
        _ => 443,
    };
    let client = parse_endpoint(event.client.as_str(), 49152, "client");
    let server = parse_endpoint(event.server.as_str(), default_server_port, "server");
    match event.direction {
        CaptureDirection::ClientToServer => (client, server),
        CaptureDirection::ServerToClient => (server, client),
    }
}

fn parse_endpoint(input: &str, default_port: u16, label: &str) -> Endpoint {
    if let Ok(addr) = input.parse::<SocketAddr>() {
        return Endpoint {
            ip: to_ipv4(addr.ip(), input),
            port: addr.port(),
        };
    }

    let (host, port) = if let Some((host, raw_port)) = input.rsplit_once(':') {
        match raw_port.parse::<u16>() {
            Ok(port) => (host, port),
            Err(_) => (input, default_port),
        }
    } else {
        (input, default_port)
    };

    if let Ok(ip) = host.parse::<IpAddr>() {
        Endpoint {
            ip: to_ipv4(ip, input),
            port,
        }
    } else {
        Endpoint {
            ip: synthetic_ipv4(format!("{}:{}", label, host).as_str()),
            port,
        }
    }
}

fn to_ipv4(ip: IpAddr, seed: &str) -> Ipv4Addr {
    match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => synthetic_ipv4(seed),
    }
}

fn synthetic_ipv4(seed: &str) -> Ipv4Addr {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    Ipv4Addr::new(
        198,
        18,
        ((hasher.finish() >> 8) & 0xff) as u8,
        ((hasher.finish() >> 16) & 0xff) as u8,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_endpoint_supports_socket_addr() {
        let endpoint = parse_endpoint("127.0.0.1:8443", 80, "server");
        assert_eq!(endpoint.ip, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(endpoint.port, 8443);
    }
}

#[cfg(test)]
mod tsresol_tests {
    use super::*;
    use pcap_file::pcapng::PcapNgReader;

    #[test]
    fn preface_advertises_nanosecond_resolution_on_every_interface() {
        let preface = build_pcap_preface().expect("preface builds");
        let mut reader = PcapNgReader::new(&preface[..]).expect("preface parses");
        let mut interfaces = 0;
        while let Some(block) = reader.next_block() {
            let Block::InterfaceDescription(iface) = block.expect("block parses") else {
                continue;
            };
            interfaces += 1;
            assert!(
                iface
                    .options
                    .contains(&InterfaceDescriptionOption::IfTsResol(9)),
                "interface {interfaces} must advertise nanoseconds"
            );
        }
        assert_eq!(interfaces, 3);
    }

    #[test]
    fn enhanced_packet_counter_is_nanoseconds() {
        let bytes = encode_enhanced_packet(0, 1_000_000_000, vec![0xAA]).expect("packet encodes");
        let high = u32::from_le_bytes(bytes[12..16].try_into().expect("ts high")) as u64;
        let low = u32::from_le_bytes(bytes[16..20].try_into().expect("ts low")) as u64;
        assert_eq!((high << 32) | low, 1_000_000_000u64);
    }
}
