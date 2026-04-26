use anyhow::{anyhow, Result};
use qpx_core::config::{UpstreamDiscoveryConfig, UpstreamDiscoveryKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
#[cfg(feature = "http3")]
use tokio::net::lookup_host;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use super::{dispatch::default_port_for_scheme, parse_origin_target, OriginEndpoint};

pub(super) const DNS_TYPE_A: u16 = 1;
pub(super) const DNS_TYPE_AAAA: u16 = 28;
pub(super) const DNS_TYPE_SRV: u16 = 33;
const DNS_CLASS_IN: u16 = 1;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(1);

#[derive(Debug, Clone)]
struct DnsARecord {
    addr: IpAddr,
    ttl_secs: u32,
}

#[derive(Debug, Clone)]
struct DnsSrvRecord {
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
    ttl_secs: u32,
}

pub(crate) async fn discover_origin_endpoints(
    base_upstream: &str,
    config: &UpstreamDiscoveryConfig,
) -> Result<(Vec<OriginEndpoint>, Duration)> {
    let nameservers = system_nameservers()?;
    discover_origin_endpoints_with_nameservers(base_upstream, config, nameservers.as_slice()).await
}

pub(super) async fn discover_origin_endpoints_with_nameservers(
    base_upstream: &str,
    config: &UpstreamDiscoveryConfig,
    nameservers: &[SocketAddr],
) -> Result<(Vec<OriginEndpoint>, Duration)> {
    let base = parse_origin_target(base_upstream)?;
    let logical_host = base.host.clone();
    let logical_port = base.port.unwrap_or_else(|| {
        base.scheme
            .as_deref()
            .map(default_port_for_scheme)
            .unwrap_or(443)
    });
    let connect_port = config.port.unwrap_or(logical_port);

    match config.kind {
        UpstreamDiscoveryKind::Dns => {
            let (records, delay) = resolve_host_records(logical_host.as_str(), nameservers).await?;
            let endpoints = records
                .into_iter()
                .map(|record| {
                    OriginEndpoint::discovered(
                        base_upstream,
                        record.addr.to_string(),
                        connect_port,
                        logical_host.clone(),
                        logical_port,
                        logical_host.clone(),
                    )
                })
                .collect::<Vec<_>>();
            Ok((endpoints, clamp_refresh_delay(delay, config)))
        }
        UpstreamDiscoveryKind::Srv => {
            let name = config
                .name
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(logical_host.as_str());
            let (srv_records, srv_delay) = query_srv_records(name, nameservers).await?;
            let mut endpoints = Vec::new();
            let mut ttl = Some(srv_delay);
            let mut ordered = srv_records;
            ordered.sort_by_key(|record| (record.priority, std::cmp::Reverse(record.weight)));
            for record in ordered {
                let port = config.port.unwrap_or(record.port);
                let (records, delay) =
                    resolve_host_records(record.target.as_str(), nameservers).await?;
                ttl = Some(match ttl {
                    Some(current) => current.min(delay),
                    None => delay,
                });
                for address in records {
                    endpoints.push(OriginEndpoint::discovered(
                        base_upstream,
                        address.addr.to_string(),
                        port,
                        logical_host.clone(),
                        logical_port,
                        logical_host.clone(),
                    ));
                }
            }
            Ok((
                endpoints,
                clamp_refresh_delay(ttl.unwrap_or_else(|| Duration::from_secs(30)), config),
            ))
        }
    }
}

#[cfg(feature = "http3")]
pub(crate) async fn resolve_upstream_socket_addr(
    upstream: &str,
    default_port: u16,
    resolve_timeout: Duration,
) -> Result<SocketAddr> {
    let parsed = parse_origin_target(upstream)?;
    let port = parsed
        .port
        .or_else(|| parsed.scheme.as_deref().map(default_port_for_scheme))
        .unwrap_or(default_port);
    let mut addrs = timeout(resolve_timeout, lookup_host((parsed.host.as_str(), port))).await??;
    addrs
        .next()
        .ok_or_else(|| anyhow!("failed to resolve upstream address: {}", upstream))
}

fn clamp_refresh_delay(delay: Duration, config: &UpstreamDiscoveryConfig) -> Duration {
    delay.clamp(
        Duration::from_millis(config.min_ttl_ms.max(1)),
        Duration::from_millis(config.max_ttl_ms.max(config.min_ttl_ms.max(1))),
    )
}

async fn resolve_host_records(
    host: &str,
    nameservers: &[SocketAddr],
) -> Result<(Vec<DnsARecord>, Duration)> {
    let mut records = Vec::new();
    let mut ttl = None::<Duration>;
    for qtype in [DNS_TYPE_A, DNS_TYPE_AAAA] {
        let resolved = query_dns_records(host, qtype, nameservers).await?;
        for record in resolved {
            ttl = Some(match ttl {
                Some(current) => current.min(Duration::from_secs(record.ttl_secs as u64)),
                None => Duration::from_secs(record.ttl_secs as u64),
            });
            records.push(record);
        }
    }
    Ok((records, ttl.unwrap_or_else(|| Duration::from_secs(30))))
}

async fn query_srv_records(
    name: &str,
    nameservers: &[SocketAddr],
) -> Result<(Vec<DnsSrvRecord>, Duration)> {
    let mut ttl = None::<Duration>;
    let mut records = Vec::new();
    for record in query_dns_srv_records(name, nameservers).await? {
        ttl = Some(match ttl {
            Some(current) => current.min(Duration::from_secs(record.ttl_secs as u64)),
            None => Duration::from_secs(record.ttl_secs as u64),
        });
        records.push(record);
    }
    Ok((records, ttl.unwrap_or_else(|| Duration::from_secs(30))))
}

async fn query_dns_records(
    name: &str,
    qtype: u16,
    nameservers: &[SocketAddr],
) -> Result<Vec<DnsARecord>> {
    let response = query_raw_dns(name, qtype, nameservers).await?;
    parse_address_records(response.as_slice(), qtype)
}

async fn query_dns_srv_records(
    name: &str,
    nameservers: &[SocketAddr],
) -> Result<Vec<DnsSrvRecord>> {
    let response = query_raw_dns(name, DNS_TYPE_SRV, nameservers).await?;
    parse_srv_records(response.as_slice())
}

async fn query_raw_dns(name: &str, qtype: u16, nameservers: &[SocketAddr]) -> Result<Vec<u8>> {
    let mut request = Vec::with_capacity(256);
    let id = DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed);
    request.extend_from_slice(&id.to_be_bytes());
    request.extend_from_slice(&0x0100u16.to_be_bytes());
    request.extend_from_slice(&1u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    encode_dns_name(name, &mut request)?;
    request.extend_from_slice(&qtype.to_be_bytes());
    request.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    let bind_addr: SocketAddr = "0.0.0.0:0".parse().expect("socket addr");
    let socket = UdpSocket::bind(bind_addr).await?;
    let mut buf = [0u8; 2048];
    for nameserver in nameservers {
        socket.send_to(request.as_slice(), nameserver).await?;
        let (len, _) = match timeout(DNS_QUERY_TIMEOUT, socket.recv_from(&mut buf)).await {
            Ok(result) => result?,
            Err(_) => continue,
        };
        if len < 12 {
            continue;
        }
        if u16::from_be_bytes([buf[0], buf[1]]) != id {
            continue;
        }
        return Ok(buf[..len].to_vec());
    }
    Err(anyhow!("DNS query timed out for {}", name))
}

fn parse_address_records(response: &[u8], qtype: u16) -> Result<Vec<DnsARecord>> {
    let answers = parse_answer_records(response)?;
    let mut records = Vec::new();
    for answer in answers {
        if answer.qtype != qtype || answer.class != DNS_CLASS_IN {
            continue;
        }
        match qtype {
            DNS_TYPE_A if answer.rdata.len() == 4 => records.push(DnsARecord {
                addr: IpAddr::V4(Ipv4Addr::new(
                    answer.rdata[0],
                    answer.rdata[1],
                    answer.rdata[2],
                    answer.rdata[3],
                )),
                ttl_secs: answer.ttl,
            }),
            DNS_TYPE_AAAA if answer.rdata.len() == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(answer.rdata.as_slice());
                records.push(DnsARecord {
                    addr: IpAddr::V6(Ipv6Addr::from(octets)),
                    ttl_secs: answer.ttl,
                });
            }
            _ => {}
        }
    }
    Ok(records)
}

fn parse_srv_records(response: &[u8]) -> Result<Vec<DnsSrvRecord>> {
    let answers = parse_answer_records(response)?;
    let mut records = Vec::new();
    for answer in answers {
        if answer.qtype != DNS_TYPE_SRV || answer.class != DNS_CLASS_IN || answer.rdata.len() < 6 {
            continue;
        }
        let priority = u16::from_be_bytes([answer.rdata[0], answer.rdata[1]]);
        let weight = u16::from_be_bytes([answer.rdata[2], answer.rdata[3]]);
        let port = u16::from_be_bytes([answer.rdata[4], answer.rdata[5]]);
        let (target, _) = parse_dns_name(answer.rdata.as_slice(), 6)?;
        records.push(DnsSrvRecord {
            priority,
            weight,
            port,
            target,
            ttl_secs: answer.ttl,
        });
    }
    Ok(records)
}

struct AnswerRecord {
    qtype: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

fn parse_answer_records(response: &[u8]) -> Result<Vec<AnswerRecord>> {
    if response.len() < 12 {
        return Err(anyhow!("DNS response too short"));
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut offset = 12usize;
    for _ in 0..qdcount {
        let (_, next) = parse_dns_name(response, offset)?;
        if next + 4 > response.len() {
            return Err(anyhow!("DNS question truncated"));
        }
        offset = next + 4;
    }

    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (_, next) = parse_dns_name(response, offset)?;
        if next + 10 > response.len() {
            return Err(anyhow!("DNS answer truncated"));
        }
        let qtype = u16::from_be_bytes([response[next], response[next + 1]]);
        let class = u16::from_be_bytes([response[next + 2], response[next + 3]]);
        let ttl = u32::from_be_bytes([
            response[next + 4],
            response[next + 5],
            response[next + 6],
            response[next + 7],
        ]);
        let rdlength = u16::from_be_bytes([response[next + 8], response[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > response.len() {
            return Err(anyhow!("DNS answer rdata truncated"));
        }
        answers.push(AnswerRecord {
            qtype,
            class,
            ttl,
            rdata: response[rdata_start..rdata_end].to_vec(),
        });
        offset = rdata_end;
    }
    Ok(answers)
}

pub(super) fn parse_dns_name(buf: &[u8], offset: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut consumed = None::<usize>;
    let mut jumps = 0usize;

    loop {
        if pos >= buf.len() {
            return Err(anyhow!("DNS name out of bounds"));
        }
        let len = buf[pos];
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= buf.len() {
                return Err(anyhow!("DNS compression pointer truncated"));
            }
            let pointer = (((len as u16 & 0x3f) << 8) | buf[pos + 1] as u16) as usize;
            if consumed.is_none() {
                consumed = Some(pos + 2);
            }
            pos = pointer;
            jumps += 1;
            if jumps > 16 {
                return Err(anyhow!("DNS compression pointer loop"));
            }
            continue;
        }
        if len == 0 {
            let next = consumed.unwrap_or(pos + 1);
            return Ok((labels.join("."), next));
        }
        if len & 0xc0 != 0 {
            return Err(anyhow!("invalid DNS label length"));
        }
        let label_len = len as usize;
        let start = pos + 1;
        let end = start + label_len;
        if end > buf.len() {
            return Err(anyhow!("DNS label truncated"));
        }
        labels.push(std::str::from_utf8(&buf[start..end])?.to_string());
        pos = end;
    }
}

pub(super) fn encode_dns_name(name: &str, out: &mut Vec<u8>) -> Result<()> {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(anyhow!("DNS label too long"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn system_nameservers() -> Result<Vec<SocketAddr>> {
    let mut out = Vec::new();
    let resolv = std::fs::read_to_string("/etc/resolv.conf")?;
    for line in resolv.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let host = rest.trim();
            let addr = if host.contains(':') {
                format!("[{}]:53", host)
            } else {
                format!("{}:53", host)
            };
            if let Ok(addr) = addr.parse() {
                out.push(addr);
            }
        }
    }
    if out.is_empty() {
        return Err(anyhow!("no DNS nameservers found in /etc/resolv.conf"));
    }
    Ok(out)
}
