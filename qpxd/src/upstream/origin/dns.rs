use anyhow::{Result, anyhow};
use qpx_core::config::{UpstreamDiscoveryConfig, UpstreamDiscoveryKind};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "http3")]
use tokio::net::lookup_host;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Duration, Instant, timeout};

use super::{OriginEndpoint, dispatch::default_port_for_scheme, parse_origin_target};

pub(super) const DNS_TYPE_A: u16 = 1;
pub(super) const DNS_TYPE_AAAA: u16 = 28;
pub(super) const DNS_TYPE_SRV: u16 = 33;
pub(super) const DNS_TYPE_HTTPS: u16 = 65;
const DNS_CLASS_IN: u16 = 1;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const SYSTEM_NAMESERVER_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct CachedSystemNameservers {
    loaded_at: Instant,
    nameservers: Vec<SocketAddr>,
}

static SYSTEM_NAMESERVER_CACHE: OnceLock<Mutex<Option<CachedSystemNameservers>>> = OnceLock::new();

pub(crate) async fn discover_origin_endpoints(
    base_upstream: &str,
    config: &UpstreamDiscoveryConfig,
) -> Result<(Vec<OriginEndpoint>, Duration)> {
    let nameservers = system_nameservers().await?;
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
            let mut endpoints = records
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
            let mut next_delay = delay;
            if matches!(base.scheme.as_deref(), Some("https" | "h3"))
                && let Ok((mut h3_endpoints, h3_delay)) = resolve_https_h3_endpoints(
                    logical_host.as_str(),
                    logical_port,
                    config.port,
                    nameservers,
                )
                .await
            {
                endpoints.append(&mut h3_endpoints);
                next_delay = next_delay.min(h3_delay);
            }
            Ok((endpoints, clamp_refresh_delay(next_delay, config)))
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
            for record in order_srv_records(srv_records) {
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

fn order_srv_records(mut records: Vec<DnsSrvRecord>) -> Vec<DnsSrvRecord> {
    records.sort_by_key(|record| record.priority);
    let mut ordered = Vec::with_capacity(records.len());
    let mut offset = 0usize;
    while offset < records.len() {
        let priority = records[offset].priority;
        let mut end = offset + 1;
        while end < records.len() && records[end].priority == priority {
            end += 1;
        }
        ordered.extend(weighted_srv_priority_group(records[offset..end].to_vec()));
        offset = end;
    }
    ordered
}

fn weighted_srv_priority_group(mut group: Vec<DnsSrvRecord>) -> Vec<DnsSrvRecord> {
    let mut ordered = Vec::with_capacity(group.len());
    while !group.is_empty() {
        let total = group.iter().map(|record| record.weight as u32).sum::<u32>();
        let index = if total == 0 {
            0
        } else {
            let mut cursor = random_mod(total);
            group
                .iter()
                .position(|record| {
                    let weight = record.weight as u32;
                    if cursor < weight {
                        true
                    } else {
                        cursor = cursor.saturating_sub(weight);
                        false
                    }
                })
                .unwrap_or(0)
        };
        ordered.push(group.remove(index));
    }
    ordered
}

fn random_mod(upper_exclusive: u32) -> u32 {
    let mut bytes = [0u8; 4];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return 0;
    }
    u32::from_be_bytes(bytes) % upper_exclusive.max(1)
}

async fn resolve_host_records(
    host: &str,
    nameservers: &[SocketAddr],
) -> Result<(Vec<DnsARecord>, Duration)> {
    let mut records = Vec::new();
    let mut ttl = None::<Duration>;
    let (a_records, aaaa_records) = tokio::try_join!(
        query_dns_records(host, DNS_TYPE_A, nameservers),
        query_dns_records(host, DNS_TYPE_AAAA, nameservers)
    )?;
    for resolved in [a_records, aaaa_records] {
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

async fn resolve_https_h3_endpoints(
    logical_host: &str,
    logical_port: u16,
    configured_port: Option<u16>,
    nameservers: &[SocketAddr],
) -> Result<(Vec<OriginEndpoint>, Duration)> {
    let mut records = query_dns_https_records(logical_host, nameservers).await?;
    let mut alias_ttl = records
        .iter()
        .filter(|record| record.priority == 0)
        .map(|record| Duration::from_secs(record.ttl_secs as u64))
        .min();
    let mut followed_aliases = HashSet::new();
    for _ in 0..4 {
        let aliases = records
            .iter()
            .filter(|record| record.priority == 0)
            .filter_map(|record| record.target.as_deref())
            .filter(|target| followed_aliases.insert(normalize_dns_name(target)))
            .map(str::to_string)
            .collect::<Vec<_>>();
        if aliases.is_empty() {
            break;
        }
        for alias in aliases {
            let alias_records = query_dns_https_records(alias.as_str(), nameservers).await?;
            for record in &alias_records {
                if record.priority == 0 {
                    alias_ttl = Some(match alias_ttl {
                        Some(current) => current.min(Duration::from_secs(record.ttl_secs as u64)),
                        None => Duration::from_secs(record.ttl_secs as u64),
                    });
                }
            }
            records.extend(alias_records);
        }
    }
    let mut endpoints = Vec::new();
    let mut ttl = alias_ttl;
    let mut service_records = records
        .into_iter()
        .filter(|record| record.priority != 0)
        .collect::<Vec<_>>();
    service_records.sort_by_key(|record| record.priority);
    for record in service_records {
        if !record
            .alpn
            .iter()
            .any(|alpn| alpn.eq_ignore_ascii_case("h3") || alpn.starts_with("h3-"))
        {
            continue;
        }
        let connect_port = configured_port.or(record.port).unwrap_or(logical_port);
        let target = record
            .target
            .as_deref()
            .unwrap_or(record.owner_name.as_str());
        let h3_upstream = h3_upstream_for_logical_origin(logical_host, logical_port);
        ttl = Some(match ttl {
            Some(current) => current.min(Duration::from_secs(record.ttl_secs as u64)),
            None => Duration::from_secs(record.ttl_secs as u64),
        });
        if record.ipv4_hints.is_empty() && record.ipv6_hints.is_empty() {
            let (addresses, address_delay) = resolve_host_records(target, nameservers).await?;
            ttl = Some(ttl.unwrap_or(address_delay).min(address_delay));
            endpoints.extend(addresses.into_iter().map(|address| {
                OriginEndpoint::discovered(
                    h3_upstream.as_str(),
                    address.addr.to_string(),
                    connect_port,
                    logical_host.to_string(),
                    logical_port,
                    logical_host.to_string(),
                )
            }));
        } else {
            endpoints.extend(record.ipv4_hints.iter().map(|addr| {
                OriginEndpoint::discovered(
                    h3_upstream.as_str(),
                    addr.to_string(),
                    connect_port,
                    logical_host.to_string(),
                    logical_port,
                    logical_host.to_string(),
                )
            }));
            endpoints.extend(record.ipv6_hints.iter().map(|addr| {
                OriginEndpoint::discovered(
                    h3_upstream.as_str(),
                    addr.to_string(),
                    connect_port,
                    logical_host.to_string(),
                    logical_port,
                    logical_host.to_string(),
                )
            }));
        }
    }
    Ok((endpoints, ttl.unwrap_or_else(|| Duration::from_secs(30))))
}

async fn query_dns_https_records(
    name: &str,
    nameservers: &[SocketAddr],
) -> Result<Vec<DnsHttpsRecord>> {
    let response = query_raw_dns(name, DNS_TYPE_HTTPS, nameservers).await?;
    parse_https_records(response.as_slice())
}

async fn query_raw_dns(name: &str, qtype: u16, nameservers: &[SocketAddr]) -> Result<Vec<u8>> {
    let mut request = Vec::with_capacity(256);
    let id = random_dns_query_id()?;
    request.extend_from_slice(&id.to_be_bytes());
    request.extend_from_slice(&0x0100u16.to_be_bytes());
    request.extend_from_slice(&1u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    encode_dns_name_inner(name, &mut request)?;
    request.extend_from_slice(&qtype.to_be_bytes());
    request.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

    if nameservers.is_empty() {
        return Err(anyhow!("no DNS nameservers configured"));
    }
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let socket = UdpSocket::bind(bind_addr).await?;
    let mut buf = [0u8; 2048];
    let mut last_rcode = None;
    let mut pending = HashSet::new();
    let mut last_send_err = None;
    for nameserver in nameservers.iter().copied() {
        match socket.send_to(request.as_slice(), nameserver).await {
            Ok(_) => {
                pending.insert(nameserver);
            }
            Err(err) => {
                last_send_err = Some(err);
            }
        }
    }
    if pending.is_empty() {
        if let Some(err) = last_send_err {
            return Err(err.into());
        }
        return Err(anyhow!("DNS query timed out for {}", name));
    }

    let deadline = Instant::now() + DNS_QUERY_TIMEOUT;
    while !pending.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(now);
        let (len, peer) = match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(result) => result?,
            Err(_) => break,
        };
        if !pending.contains(&peer) {
            continue;
        }
        if dns_response_is_truncated_match(&buf[..len], id, name, qtype).unwrap_or(false) {
            return query_raw_dns_tcp(request.as_slice(), id, name, qtype, peer).await;
        }
        match dns_response_query_status(&buf[..len], id, name, qtype) {
            Ok(DnsResponseStatus::Success) => return Ok(buf[..len].to_vec()),
            Ok(DnsResponseStatus::ErrorRcode(rcode)) => {
                last_rcode = Some(rcode);
                pending.remove(&peer);
            }
            Ok(DnsResponseStatus::Mismatch) | Err(_) => continue,
        }
    }
    if let Some(rcode) = last_rcode {
        return Err(anyhow!("DNS query failed for {name} with RCODE {rcode}"));
    }
    Err(anyhow!("DNS query timed out for {}", name))
}

async fn query_raw_dns_tcp(
    request: &[u8],
    id: u16,
    name: &str,
    qtype: u16,
    nameserver: SocketAddr,
) -> Result<Vec<u8>> {
    let mut stream = timeout(DNS_QUERY_TIMEOUT, TcpStream::connect(nameserver)).await??;
    let len = u16::try_from(request.len()).map_err(|_| anyhow!("DNS request too large"))?;
    let mut framed = Vec::with_capacity(request.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(request);
    timeout(DNS_QUERY_TIMEOUT, stream.write_all(framed.as_slice())).await??;

    let mut len_buf = [0u8; 2];
    timeout(DNS_QUERY_TIMEOUT, stream.read_exact(&mut len_buf)).await??;
    let response_len = u16::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; response_len];
    timeout(
        DNS_QUERY_TIMEOUT,
        stream.read_exact(response.as_mut_slice()),
    )
    .await??;
    match dns_response_query_status(response.as_slice(), id, name, qtype)? {
        DnsResponseStatus::Success => return Ok(response),
        DnsResponseStatus::ErrorRcode(rcode) => {
            return Err(anyhow!(
                "DNS TCP query failed for {name} with RCODE {rcode}"
            ));
        }
        DnsResponseStatus::Mismatch => {}
    }
    Err(anyhow!("DNS TCP response did not match query for {}", name))
}

fn random_dns_query_id() -> Result<u16> {
    let mut bytes = [0u8; 2];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("failed to generate DNS query id"))?;
    Ok(u16::from_be_bytes(bytes))
}

mod parser;
use self::parser::{
    DnsARecord, DnsHttpsRecord, DnsResponseStatus, DnsSrvRecord, dns_response_is_truncated_match,
    dns_response_query_status, encode_dns_name as encode_dns_name_inner,
    h3_upstream_for_logical_origin, normalize_dns_name, parse_address_records, parse_https_records,
    parse_srv_records,
};
#[cfg(test)]
pub(super) use self::parser::{dns_response_matches_query, encode_dns_name, parse_dns_name};

async fn system_nameservers() -> Result<Vec<SocketAddr>> {
    let now = Instant::now();
    let cache = SYSTEM_NAMESERVER_CACHE.get_or_init(|| Mutex::new(None));
    if let Some(cached) = cache
        .lock()
        .map_err(|_| anyhow!("system nameserver cache lock poisoned"))?
        .as_ref()
        .filter(|cached| now.duration_since(cached.loaded_at) < SYSTEM_NAMESERVER_CACHE_TTL)
        .cloned()
    {
        return Ok(cached.nameservers);
    }

    let nameservers = tokio::task::spawn_blocking(parse_system_nameservers)
        .await
        .map_err(|err| anyhow!("system nameserver loader task failed: {err}"))??;
    *cache
        .lock()
        .map_err(|_| anyhow!("system nameserver cache lock poisoned"))? =
        Some(CachedSystemNameservers {
            loaded_at: Instant::now(),
            nameservers: nameservers.clone(),
        });
    Ok(nameservers)
}

fn parse_system_nameservers() -> Result<Vec<SocketAddr>> {
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
