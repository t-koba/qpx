use anyhow::{Result, anyhow};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::time::{Duration, timeout};

#[cfg(test)]
pub(super) fn redirect_host_is_private_ip(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    host.parse::<IpAddr>()
        .is_ok_and(ip_is_non_global_for_subrequest)
}

pub(super) async fn redirect_host_resolves_to_private_ip(
    uri: &http::Uri,
    host: &str,
    timeout_dur: Duration,
) -> Result<bool> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(false);
    }
    let port = default_port(uri);
    let mut addrs = timeout(timeout_dur, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| anyhow!("subrequest redirect Location DNS lookup timed out"))?
        .map_err(|err| anyhow!("subrequest redirect Location DNS lookup failed: {err}"))?;
    Ok(addrs.any(|addr| redirect_ip_is_private(addr.ip())))
}

pub(super) fn redirect_ip_is_private(ip: IpAddr) -> bool {
    ip_is_non_global_for_subrequest(ip)
}

pub(super) fn host_is_non_global_ip(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    host.parse::<IpAddr>()
        .is_ok_and(ip_is_non_global_for_subrequest)
}

pub(super) async fn resolve_public_subrequest_addr(
    uri: &http::Uri,
    host: &str,
    timeout_dur: Duration,
) -> Result<Option<SocketAddr>> {
    let port = default_port(uri);
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        if ip_is_non_global_for_subrequest(ip) {
            return Err(anyhow!("target points to a private IP"));
        }
        return Ok(Some(SocketAddr::new(ip, port)));
    }
    let addrs = timeout(timeout_dur, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| anyhow!("target DNS lookup timed out"))?
        .map_err(|err| anyhow!("target DNS lookup failed: {err}"))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(anyhow!("target DNS lookup returned no addresses"));
    }
    if addrs
        .iter()
        .any(|addr| ip_is_non_global_for_subrequest(addr.ip()))
    {
        return Err(anyhow!("target resolves to a private IP"));
    }
    Ok(addrs.into_iter().next())
}

fn default_port(uri: &http::Uri) -> u16 {
    uri.port_u16()
        .or_else(|| match uri.scheme_str() {
            Some("https") => Some(443),
            Some("http") => Some(80),
            _ => None,
        })
        .unwrap_or(80)
}

fn ip_is_non_global_for_subrequest(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ipv4_is_non_global_for_subrequest(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return ipv4_is_non_global_for_subrequest(mapped);
            }
            if let Some(mapped) = ipv6_embedded_nat64_ipv4(ip)
                && ipv4_is_non_global_for_subrequest(mapped)
            {
                return true;
            }
            ipv6_is_non_global_for_subrequest(ip)
        }
    }
}

fn ipv6_embedded_nat64_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = ip.octets();
    let well_known_96 = octets[..12] == [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
    if well_known_96 {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    let local_use_48 = octets[..6] == [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01];
    if local_use_48 {
        return Some(Ipv4Addr::new(octets[6], octets[7], octets[8], octets[9]));
    }
    None
}

fn ipv4_is_non_global_for_subrequest(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (18..=19).contains(&b))
        || (a == 192 && b == 0)
}

fn ipv6_is_non_global_for_subrequest(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}
