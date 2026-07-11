use crate::runtime::CompiledForwardedPolicy;
use anyhow::{Result, anyhow};
use http::HeaderMap;
use qpx_core::config::UntrustedForwardedChainPolicy;
use qpx_http::forwarded::{ForwardedElement, parse_forwarded, serialize_forwarded};
use std::net::IpAddr;

pub(crate) fn apply_forwarded_policy(
    headers: &mut HeaderMap,
    policy: Option<&CompiledForwardedPolicy>,
    peer_ip: IpAddr,
    scheme: &str,
    host: Option<&str>,
) -> Result<()> {
    let Some(policy) = policy else {
        return Ok(());
    };
    let trusted = policy
        .trusted_peers
        .iter()
        .any(|network| network.contains(&peer_ip));
    let mut chain = if trusted {
        parse_forwarded(headers)
            .map_err(|error| anyhow!("invalid trusted Forwarded chain: {error}"))?
    } else {
        if headers.contains_key("forwarded")
            && policy.untrusted_chain == UntrustedForwardedChainPolicy::Reject
        {
            return Err(anyhow!("untrusted peer supplied a Forwarded chain"));
        }
        Vec::new()
    };
    headers.remove("forwarded");
    for legacy in [
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
    ] {
        headers.remove(legacy);
    }

    let mut parameters = vec![
        ("for".to_string(), format_forwarded_node(peer_ip)),
        ("by".to_string(), policy.by.to_string()),
        ("proto".to_string(), scheme.to_ascii_lowercase()),
    ];
    if let Some(host) = host.filter(|host| !host.is_empty()) {
        parameters.push(("host".to_string(), host.to_string()));
    }
    chain.push(
        ForwardedElement::new(parameters)
            .map_err(|error| anyhow!("cannot construct Forwarded element: {error}"))?,
    );
    let value = serialize_forwarded(&chain)
        .map_err(|error| anyhow!("cannot serialize Forwarded chain: {error}"))?;
    headers.insert("forwarded", value);
    Ok(())
}

fn format_forwarded_node(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn policy(mode: UntrustedForwardedChainPolicy) -> CompiledForwardedPolicy {
        CompiledForwardedPolicy {
            trusted_peers: Arc::from(["10.0.0.0/8".parse().expect("CIDR")]),
            by: Arc::from("qpx-edge"),
            untrusted_chain: mode,
        }
    }

    #[test]
    fn discards_untrusted_chain_and_appends_current_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("forwarded", "for=192.0.2.4".parse().expect("header"));
        headers.insert("x-forwarded-for", "192.0.2.4".parse().expect("header"));
        apply_forwarded_policy(
            &mut headers,
            Some(&policy(UntrustedForwardedChainPolicy::Discard)),
            "203.0.113.8".parse().expect("IP"),
            "https",
            Some("example.com"),
        )
        .expect("apply policy");
        assert_eq!(
            headers.get("forwarded").expect("Forwarded"),
            "for=203.0.113.8;by=qpx-edge;proto=https;host=example.com"
        );
        assert!(!headers.contains_key("x-forwarded-for"));
    }

    #[test]
    fn preserves_only_strict_chain_from_trusted_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("forwarded", "for=192.0.2.4".parse().expect("header"));
        apply_forwarded_policy(
            &mut headers,
            Some(&policy(UntrustedForwardedChainPolicy::Reject)),
            "10.0.0.8".parse().expect("IP"),
            "http",
            None,
        )
        .expect("trusted peer");
        assert_eq!(
            headers.get("forwarded").expect("Forwarded"),
            "for=192.0.2.4, for=10.0.0.8;by=qpx-edge;proto=http"
        );
    }

    #[test]
    fn rejects_untrusted_chain_when_configured() {
        let mut headers = HeaderMap::new();
        headers.insert("forwarded", "for=192.0.2.4".parse().expect("header"));
        let error = apply_forwarded_policy(
            &mut headers,
            Some(&policy(UntrustedForwardedChainPolicy::Reject)),
            "203.0.113.8".parse().expect("IP"),
            "http",
            None,
        )
        .expect_err("untrusted chain must fail");
        assert!(error.to_string().contains("untrusted peer"));
    }
}
