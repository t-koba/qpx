use hyper::Uri;

pub fn parse_authority_host_port(input: &str, default_port: u16) -> Option<(String, u16)> {
    parse_authority_host_port_with_default(input, Some(default_port))
}

pub fn parse_authority_host_port_with_default(
    input: &str,
    default_port: Option<u16>,
) -> Option<(String, u16)> {
    let authority = normalize_strict_authority(input, default_port)?;

    let uri = Uri::builder()
        .scheme("http")
        .authority(authority.as_str())
        .path_and_query("/")
        .build()
        .ok()?;
    let auth = uri.authority()?;
    let port = auth.port_u16().or(default_port)?;
    let host = normalize_authority_host(auth.host());
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

fn normalize_authority_host(host: &str) -> String {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_string()
}

fn normalize_strict_authority(input: &str, default_port: Option<u16>) -> Option<String> {
    let input = input.trim();
    if input.is_empty()
        || input.contains('@')
        || input.contains("://")
        || input.contains('/')
        || input.contains('?')
        || input.contains('#')
    {
        return None;
    }

    if input.starts_with('[') {
        let close = input.find(']')?;
        let rest = &input[close + 1..];
        return match rest {
            "" => default_port.map(|port| format!("{input}:{port}")),
            _ if rest.starts_with(':') && rest.len() > 1 => Some(input.to_string()),
            _ => None,
        };
    }

    match input
        .as_bytes()
        .iter()
        .filter(|&&byte| byte == b':')
        .count()
    {
        0 => default_port.map(|port| format!("{input}:{port}")),
        1 if !input.starts_with(':') && !input.ends_with(':') => Some(input.to_string()),
        _ => None,
    }
}

pub fn format_authority_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::address::*;

    #[test]
    fn authority_parser_rejects_userinfo_and_absolute_form() {
        assert!(parse_authority_host_port("user@example.com:443", 443).is_none());
        assert!(parse_authority_host_port("https://example.com:443", 443).is_none());
        assert!(parse_authority_host_port("example.com:443/path", 443).is_none());
    }

    #[test]
    fn authority_parser_handles_default_port_and_ipv6_literals() {
        assert_eq!(
            parse_authority_host_port("example.com", 443),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            parse_authority_host_port("[2001:db8::1]", 443),
            Some(("2001:db8::1".to_string(), 443))
        );
        assert_eq!(
            parse_authority_host_port("[2001:db8::1]:8443", 443),
            Some(("2001:db8::1".to_string(), 8443))
        );
        assert!(parse_authority_host_port("2001:db8::1", 443).is_none());
    }

    #[test]
    fn authority_parser_requires_explicit_port_without_default() {
        assert!(parse_authority_host_port_with_default("example.com", None).is_none());
        assert_eq!(
            parse_authority_host_port_with_default("example.com:8443", None),
            Some(("example.com".to_string(), 8443))
        );
    }
}
