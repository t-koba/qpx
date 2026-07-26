use crate::runtime::{CompiledForwardedHop, CompiledForwardedHopCache, CompiledForwardedPolicy};
use anyhow::{Result, anyhow};
use http::{HeaderMap, HeaderValue, header::HeaderName};
use qpx_core::config::UntrustedForwardedChainPolicy;
use qpx_http::forwarded::{FORWARDED, ForwardedElement, parse_forwarded, serialize_forwarded};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;

static FORWARDED_CHAIN_HEADERS: [HeaderName; 5] = [
    HeaderName::from_static("forwarded"),
    HeaderName::from_static("x-forwarded-for"),
    HeaderName::from_static("x-forwarded-host"),
    HeaderName::from_static("x-forwarded-proto"),
    HeaderName::from_static("x-forwarded-port"),
];

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
    let has_forwarded_chain = headers.contains_key(&FORWARDED);
    let mut chain = if trusted && has_forwarded_chain {
        parse_forwarded(headers)
            .map_err(|error| anyhow!("invalid trusted Forwarded chain: {error}"))?
    } else {
        if headers.contains_key(&FORWARDED)
            && policy.untrusted_chain == UntrustedForwardedChainPolicy::Reject
        {
            return Err(anyhow!("untrusted peer supplied a Forwarded chain"));
        }
        Vec::new()
    };
    for name in &FORWARDED_CHAIN_HEADERS {
        headers.remove(name);
    }

    if chain.is_empty() {
        headers.reserve(1);
        headers.insert(
            FORWARDED.clone(),
            cached_current_hop(policy, peer_ip, scheme, host)?,
        );
        return Ok(());
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
    headers.insert(FORWARDED.clone(), value);
    Ok(())
}

fn cached_current_hop(
    policy: &CompiledForwardedPolicy,
    peer_ip: IpAddr,
    scheme: &str,
    host: Option<&str>,
) -> Result<HeaderValue> {
    let host = host.filter(|value| !value.is_empty());
    let current = policy.current_hops.load();
    if let Some(entry) = current.entries.iter().find(|entry| {
        entry.peer_ip == peer_ip && entry.scheme.as_ref() == scheme && entry.host.as_deref() == host
    }) {
        return Ok(entry.value.clone());
    }
    drop(current);
    let value = serialize_current_hop(peer_ip, policy.by.as_ref(), scheme, host)?;
    let entry = CompiledForwardedHop {
        peer_ip,
        scheme: Arc::from(scheme),
        host: host.map(Arc::from),
        value: value.clone(),
    };
    policy.current_hops.rcu(|current| {
        let mut entries = Vec::with_capacity(32);
        entries.push(entry.clone());
        entries.extend(
            current
                .entries
                .iter()
                .filter(|candidate| {
                    candidate.peer_ip != entry.peer_ip
                        || candidate.scheme != entry.scheme
                        || candidate.host != entry.host
                })
                .take(31)
                .cloned(),
        );
        CompiledForwardedHopCache { entries }
    });
    Ok(value)
}

fn serialize_current_hop(
    peer_ip: IpAddr,
    by: &str,
    scheme: &str,
    host: Option<&str>,
) -> Result<HeaderValue> {
    let mut output =
        String::with_capacity(72 + by.len() + scheme.len() + host.map(str::len).unwrap_or(0));
    output.push_str("for=");
    push_forwarded_node(&mut output, peer_ip);
    output.push_str(";by=");
    push_forwarded_value(&mut output, by);
    output.push_str(";proto=");
    push_forwarded_value(&mut output, scheme);
    if let Some(host) = host.filter(|host| !host.is_empty()) {
        output.push_str(";host=");
        push_forwarded_value(&mut output, host);
    }
    HeaderValue::from_str(&output)
        .map_err(|error| anyhow!("cannot serialize Forwarded hop: {error}"))
}

fn push_forwarded_node(output: &mut String, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            let _ = write!(output, "{ip}");
        }
        IpAddr::V6(ip) => {
            output.push_str("\"[");
            let _ = write!(output, "{ip}");
            output.push_str("]\"");
        }
    }
}

fn push_forwarded_value(output: &mut String, value: &str) {
    if is_forwarded_token(value) {
        output.push_str(value);
        return;
    }
    output.push('"');
    for character in value.chars() {
        if character == '"' || character == '\\' {
            output.push('\\');
        }
        output.push(character);
    }
    output.push('"');
}

fn is_forwarded_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
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

    fn policy(mode: UntrustedForwardedChainPolicy) -> CompiledForwardedPolicy {
        CompiledForwardedPolicy {
            trusted_peers: Arc::from(["10.0.0.0/8".parse().expect("CIDR")]),
            by: Arc::from("qpx-edge"),
            untrusted_chain: mode,
            current_hops: Arc::new(arc_swap::ArcSwap::from_pointee(Default::default())),
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
