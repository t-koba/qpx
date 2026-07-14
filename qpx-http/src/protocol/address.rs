use http::uri::Authority;

pub fn parse_authority_host_port(input: &str, default_port: u16) -> Option<(String, u16)> {
    parse_authority_host_port_with_default(input, Some(default_port))
}

pub fn parse_authority_host_port_with_default(
    input: &str,
    default_port: Option<u16>,
) -> Option<(String, u16)> {
    let (authority, port) = parse_authority_with_default_port(input, default_port)?;
    let host = normalize_authority_host(authority.host());
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

pub fn parse_authority_with_default_port(
    input: &str,
    default_port: Option<u16>,
) -> Option<(Authority, u16)> {
    let input = validate_strict_authority(input)?;
    let authority = input.parse::<Authority>().ok()?;
    let explicit_port = has_explicit_port(input);
    let port = match (explicit_port, authority.port_u16()) {
        (true, Some(port)) => port,
        (true, None) => return None,
        (false, _) => default_port?,
    };
    if authority.host().is_empty() {
        return None;
    }
    Some((authority, port))
}

fn normalize_authority_host(host: &str) -> String {
    let mut host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_string();
    host.make_ascii_lowercase();
    host
}

fn validate_strict_authority(input: &str) -> Option<&str> {
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
            "" => Some(input),
            _ if rest.starts_with(':') && rest.len() > 1 => Some(input),
            _ => None,
        };
    }

    match input
        .as_bytes()
        .iter()
        .filter(|&&byte| byte == b':')
        .count()
    {
        0 => Some(input),
        1 if !input.starts_with(':') && !input.ends_with(':') => Some(input),
        _ => None,
    }
}

fn has_explicit_port(authority: &str) -> bool {
    authority
        .strip_prefix('[')
        .and_then(|value| value.find(']').map(|close| &value[close + 1..]))
        .map_or_else(|| authority.contains(':'), |suffix| suffix.starts_with(':'))
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
        assert_eq!(
            parse_authority_host_port("EXAMPLE.COM:8443", 443),
            Some(("example.com".to_string(), 8443))
        );
        assert!(parse_authority_host_port("example.com:http", 443).is_none());
        assert!(parse_authority_host_port("[2001:db8::1]:https", 443).is_none());
    }

    #[test]
    fn authority_parser_requires_explicit_port_without_default() {
        assert!(parse_authority_host_port_with_default("example.com", None).is_none());
        assert_eq!(
            parse_authority_host_port_with_default("example.com:8443", None),
            Some(("example.com".to_string(), 8443))
        );
    }

    #[test]
    fn authority_parser_can_retain_the_validated_authority() {
        let (authority, port) =
            parse_authority_with_default_port("EXAMPLE.COM:8443", Some(443)).expect("authority");

        assert_eq!(authority.host(), "EXAMPLE.COM");
        assert_eq!(authority.port_u16(), Some(8443));
        assert_eq!(port, 8443);
        assert!(parse_authority_with_default_port("example.com:http", Some(443)).is_none());
    }
}
