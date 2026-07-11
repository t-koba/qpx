//! RFC 9484 CONNECT-IP capsule payload codecs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

pub const ADDRESS_ASSIGN_CAPSULE: u64 = 0x01;
pub const ADDRESS_REQUEST_CAPSULE: u64 = 0x02;
pub const ROUTE_ADVERTISEMENT_CAPSULE: u64 = 0x03;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPrefixRecord {
    pub request_id: u64,
    pub address: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRouteRecord {
    pub start: IpAddr,
    pub end: IpAddr,
    pub protocol: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConnectIpCodecError {
    #[error("CONNECT-IP payload is truncated")]
    Truncated,
    #[error("CONNECT-IP payload contains an invalid QUIC variable-length integer")]
    InvalidVarInt,
    #[error("CONNECT-IP address family is invalid or inconsistent")]
    InvalidAddressFamily,
    #[error("CONNECT-IP prefix length or host bits are invalid")]
    InvalidPrefix,
    #[error("CONNECT-IP ADDRESS_REQUEST must contain nonzero request identifiers")]
    InvalidRequestId,
    #[error("CONNECT-IP route start exceeds route end")]
    InvalidRouteOrder,
    #[error("CONNECT-IP packet exceeds the configured MTU")]
    MtuExceeded,
    #[error("CONNECT-IP packet has an invalid IP header or length")]
    InvalidPacket,
    #[error("CONNECT-IP packet source or destination is outside the configured policy")]
    PolicyDenied,
}

#[derive(Debug, Clone)]
pub struct ConnectIpPacketPolicy {
    source_cidrs: Vec<cidr::IpCidr>,
    destination_cidrs: Vec<cidr::IpCidr>,
    mtu: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedIpPacket {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub length: usize,
}

impl ConnectIpPacketPolicy {
    pub fn new(
        source_cidrs: Vec<cidr::IpCidr>,
        destination_cidrs: Vec<cidr::IpCidr>,
        mtu: usize,
    ) -> Result<Self, ConnectIpCodecError> {
        if source_cidrs.is_empty() || destination_cidrs.is_empty() || mtu < 1280 {
            return Err(ConnectIpCodecError::PolicyDenied);
        }
        Ok(Self {
            source_cidrs,
            destination_cidrs,
            mtu,
        })
    }

    pub fn validate(&self, packet: &[u8]) -> Result<ValidatedIpPacket, ConnectIpCodecError> {
        if packet.len() > self.mtu {
            return Err(ConnectIpCodecError::MtuExceeded);
        }
        let validated = parse_ip_packet(packet)?;
        if !self
            .source_cidrs
            .iter()
            .any(|cidr| cidr.contains(&validated.source))
            || !self
                .destination_cidrs
                .iter()
                .any(|cidr| cidr.contains(&validated.destination))
        {
            return Err(ConnectIpCodecError::PolicyDenied);
        }
        Ok(validated)
    }

    pub fn allows_source(&self, address: IpAddr) -> bool {
        self.source_cidrs.iter().any(|cidr| cidr.contains(&address))
    }

    pub fn allows_source_prefix(&self, address: IpAddr, prefix_len: u8) -> bool {
        self.source_cidrs.iter().any(|cidr| {
            cidr.contains(&address)
                && prefix_len >= cidr.network_length()
                && cidr.first_address().is_ipv4() == address.is_ipv4()
        })
    }

    pub fn allows_destination(&self, address: IpAddr) -> bool {
        self.destination_cidrs
            .iter()
            .any(|cidr| cidr.contains(&address))
    }

    pub fn allows_destination_range(&self, start: IpAddr, end: IpAddr) -> bool {
        self.destination_cidrs
            .iter()
            .any(|cidr| cidr.contains(&start) && cidr.contains(&end))
    }
}

fn parse_ip_packet(packet: &[u8]) -> Result<ValidatedIpPacket, ConnectIpCodecError> {
    let version = packet.first().ok_or(ConnectIpCodecError::InvalidPacket)? >> 4;
    match version {
        4 => {
            if packet.len() < 20 {
                return Err(ConnectIpCodecError::InvalidPacket);
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if header_len < 20 || total_len < header_len || total_len != packet.len() {
                return Err(ConnectIpCodecError::InvalidPacket);
            }
            Ok(ValidatedIpPacket {
                source: IpAddr::V4(Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15],
                )),
                destination: IpAddr::V4(Ipv4Addr::new(
                    packet[16], packet[17], packet[18], packet[19],
                )),
                protocol: packet[9],
                length: total_len,
            })
        }
        6 => {
            if packet.len() < 40 {
                return Err(ConnectIpCodecError::InvalidPacket);
            }
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            let total_len = 40usize
                .checked_add(payload_len)
                .ok_or(ConnectIpCodecError::InvalidPacket)?;
            if total_len != packet.len() {
                return Err(ConnectIpCodecError::InvalidPacket);
            }
            Ok(ValidatedIpPacket {
                source: IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&packet[8..24])
                        .map_err(|_| ConnectIpCodecError::InvalidPacket)?,
                )),
                destination: IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&packet[24..40])
                        .map_err(|_| ConnectIpCodecError::InvalidPacket)?,
                )),
                protocol: packet[6],
                length: total_len,
            })
        }
        _ => Err(ConnectIpCodecError::InvalidPacket),
    }
}

pub fn encode_ip_prefix_records(
    records: &[IpPrefixRecord],
) -> Result<Vec<u8>, ConnectIpCodecError> {
    let mut out = Vec::new();
    for record in records {
        encode_varint(record.request_id, &mut out)?;
        let (version, bytes, width) = address_bytes(record.address);
        validate_prefix(&bytes, record.prefix_len, width)?;
        out.push(version);
        out.extend_from_slice(&bytes);
        out.push(record.prefix_len);
    }
    Ok(out)
}

pub fn decode_ip_prefix_records(
    payload: &[u8],
    address_request: bool,
) -> Result<Vec<IpPrefixRecord>, ConnectIpCodecError> {
    let mut offset = 0;
    let mut records = Vec::new();
    while offset < payload.len() {
        let (request_id, consumed) = decode_varint(&payload[offset..])?;
        offset += consumed;
        if address_request && request_id == 0 {
            return Err(ConnectIpCodecError::InvalidRequestId);
        }
        let version = *payload.get(offset).ok_or(ConnectIpCodecError::Truncated)?;
        offset += 1;
        let len = match version {
            4 => 4,
            6 => 16,
            _ => return Err(ConnectIpCodecError::InvalidAddressFamily),
        };
        let bytes = payload
            .get(offset..offset + len)
            .ok_or(ConnectIpCodecError::Truncated)?;
        offset += len;
        let prefix_len = *payload.get(offset).ok_or(ConnectIpCodecError::Truncated)?;
        offset += 1;
        validate_prefix(bytes, prefix_len, (len * 8) as u8)?;
        records.push(IpPrefixRecord {
            request_id,
            address: decode_address(version, bytes),
            prefix_len,
        });
    }
    if address_request && records.is_empty() {
        return Err(ConnectIpCodecError::InvalidRequestId);
    }
    Ok(records)
}

pub fn encode_ip_routes(routes: &[IpRouteRecord]) -> Result<Vec<u8>, ConnectIpCodecError> {
    let mut out = Vec::new();
    for route in routes {
        match (route.start, route.end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                if u32::from(start) > u32::from(end) {
                    return Err(ConnectIpCodecError::InvalidRouteOrder);
                }
                out.push(4);
                out.extend_from_slice(&start.octets());
                out.extend_from_slice(&end.octets());
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                if u128::from(start) > u128::from(end) {
                    return Err(ConnectIpCodecError::InvalidRouteOrder);
                }
                out.push(6);
                out.extend_from_slice(&start.octets());
                out.extend_from_slice(&end.octets());
            }
            _ => return Err(ConnectIpCodecError::InvalidAddressFamily),
        }
        out.push(route.protocol);
    }
    Ok(out)
}

pub fn decode_ip_routes(payload: &[u8]) -> Result<Vec<IpRouteRecord>, ConnectIpCodecError> {
    let mut offset = 0;
    let mut routes = Vec::new();
    while offset < payload.len() {
        let version = payload[offset];
        offset += 1;
        let len = match version {
            4 => 4,
            6 => 16,
            _ => return Err(ConnectIpCodecError::InvalidAddressFamily),
        };
        let start = payload
            .get(offset..offset + len)
            .ok_or(ConnectIpCodecError::Truncated)?;
        offset += len;
        let end = payload
            .get(offset..offset + len)
            .ok_or(ConnectIpCodecError::Truncated)?;
        offset += len;
        let protocol = *payload.get(offset).ok_or(ConnectIpCodecError::Truncated)?;
        offset += 1;
        let route = IpRouteRecord {
            start: decode_address(version, start),
            end: decode_address(version, end),
            protocol,
        };
        encode_ip_routes(std::slice::from_ref(&route))?;
        routes.push(route);
    }
    Ok(routes)
}

fn address_bytes(address: IpAddr) -> (u8, Vec<u8>, u8) {
    match address {
        IpAddr::V4(address) => (4, address.octets().to_vec(), 32),
        IpAddr::V6(address) => (6, address.octets().to_vec(), 128),
    }
}

fn decode_address(version: u8, bytes: &[u8]) -> IpAddr {
    if version == 4 {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).expect("validated IPv6 length"),
        ))
    }
}

fn validate_prefix(bytes: &[u8], prefix_len: u8, width: u8) -> Result<(), ConnectIpCodecError> {
    if prefix_len > width {
        return Err(ConnectIpCodecError::InvalidPrefix);
    }
    let full = usize::from(prefix_len / 8);
    let partial = prefix_len % 8;
    if partial != 0 {
        let mask = (1_u8 << (8 - partial)) - 1;
        if bytes[full] & mask != 0 {
            return Err(ConnectIpCodecError::InvalidPrefix);
        }
    }
    if bytes[full + usize::from(partial != 0)..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(ConnectIpCodecError::InvalidPrefix);
    }
    Ok(())
}

fn encode_varint(value: u64, out: &mut Vec<u8>) -> Result<(), ConnectIpCodecError> {
    let width = if value <= 63 {
        1
    } else if value <= 16_383 {
        2
    } else if value <= 1_073_741_823 {
        4
    } else if value <= 4_611_686_018_427_387_903 {
        8
    } else {
        return Err(ConnectIpCodecError::InvalidVarInt);
    };
    let tagged = value
        | match width {
            1 => 0,
            2 => 1 << 14,
            4 => 2 << 30,
            8 => 3 << 62,
            _ => unreachable!(),
        };
    out.extend_from_slice(&tagged.to_be_bytes()[8 - width..]);
    Ok(())
}

fn decode_varint(input: &[u8]) -> Result<(u64, usize), ConnectIpCodecError> {
    let first = *input.first().ok_or(ConnectIpCodecError::Truncated)?;
    let width = 1_usize << (first >> 6);
    let bytes = input.get(..width).ok_or(ConnectIpCodecError::Truncated)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, width))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_records_round_trip_and_reject_host_bits() {
        let records = vec![
            IpPrefixRecord {
                request_id: 7,
                address: "192.0.2.0".parse().unwrap(),
                prefix_len: 24,
            },
            IpPrefixRecord {
                request_id: 8,
                address: "2001:db8::".parse().unwrap(),
                prefix_len: 32,
            },
        ];
        let encoded = encode_ip_prefix_records(&records).unwrap();
        assert_eq!(decode_ip_prefix_records(&encoded, true).unwrap(), records);
        assert!(
            encode_ip_prefix_records(&[IpPrefixRecord {
                request_id: 1,
                address: "192.0.2.1".parse().unwrap(),
                prefix_len: 24
            }])
            .is_err()
        );
    }

    #[test]
    fn route_records_round_trip_and_validate_ranges() {
        let routes = vec![IpRouteRecord {
            start: "192.0.2.1".parse().unwrap(),
            end: "192.0.2.254".parse().unwrap(),
            protocol: 6,
        }];
        let encoded = encode_ip_routes(&routes).unwrap();
        assert_eq!(decode_ip_routes(&encoded).unwrap(), routes);
        assert!(
            encode_ip_routes(&[IpRouteRecord {
                start: "2001:db8::1".parse().unwrap(),
                end: "192.0.2.1".parse().unwrap(),
                protocol: 0
            }])
            .is_err()
        );
    }

    #[test]
    fn packet_policy_enforces_ip_lengths_mtu_and_cidrs() {
        let policy = ConnectIpPacketPolicy::new(
            vec!["192.0.2.0/24".parse().unwrap()],
            vec!["198.51.100.0/24".parse().unwrap()],
            1280,
        )
        .unwrap();
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 20]);
        let validated = policy.validate(&packet).unwrap();
        assert_eq!(validated.source, "192.0.2.10".parse::<IpAddr>().unwrap());
        assert_eq!(
            validated.destination,
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
        packet[16..20].copy_from_slice(&[203, 0, 113, 1]);
        assert_eq!(
            policy.validate(&packet),
            Err(ConnectIpCodecError::PolicyDenied)
        );
        packet[2..4].copy_from_slice(&21u16.to_be_bytes());
        assert_eq!(
            policy.validate(&packet),
            Err(ConnectIpCodecError::InvalidPacket)
        );
    }
}
