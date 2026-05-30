use anyhow::{Result, anyhow};
use percent_encoding::percent_decode_str;
use qpx_core::uri_template::UriTemplate;

#[cfg(feature = "http3")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::forward) enum H3ConnectProtocol {
    Plain,
    ConnectUdp,
    Extended,
}

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(super) fn validate_h3_connect_head(
    req_head: &::http::Request<()>,
    headers: &http::HeaderMap,
    authority_host: &str,
    authority_port: u16,
    allow_extended_connect: bool,
) -> Result<()> {
    crate::http::protocol::semantics::validate_h2_h3_connect_headers(headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    crate::http::protocol::semantics::validate_expect_header(headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    let protocol = if allow_extended_connect {
        match req_head.extensions().get::<::h3::ext::Protocol>().copied() {
            Some(::h3::ext::Protocol::CONNECT_UDP) => H3ConnectProtocol::ConnectUdp,
            Some(_) => H3ConnectProtocol::Extended,
            None => return Err(anyhow!("extended CONNECT protocol required")),
        }
    } else {
        H3ConnectProtocol::Plain
    };
    validate_h3_connect_pseudo_headers(req_head, headers, authority_host, authority_port, protocol)
}

#[cfg(feature = "http3")]
pub(in crate::forward) fn validate_h3_connect_pseudo_headers(
    req_head: &::http::Request<()>,
    headers: &http::HeaderMap,
    authority_host: &str,
    authority_port: u16,
    protocol: H3ConnectProtocol,
) -> Result<()> {
    if req_head.method() != ::http::Method::CONNECT {
        return Err(anyhow!("CONNECT method required"));
    }

    match protocol {
        H3ConnectProtocol::ConnectUdp => {
            // RFC 9298 section 3.4: :scheme and :path are derived from the expanded URI
            // template and MUST be present (non-empty). Unlike CONNECT, :authority is the
            // proxy authority.
            validate_extended_connect_target(req_head, "CONNECT-UDP")?;
            let capsule_protocol = headers
                .get("capsule-protocol")
                .and_then(|v| v.to_str().ok())
                .map(str::trim);
            if capsule_protocol != Some("?1") {
                return Err(anyhow!("CONNECT-UDP requires Capsule-Protocol: ?1"));
            }
        }
        H3ConnectProtocol::Extended => {
            validate_extended_connect_target(req_head, "extended CONNECT")?;
        }
        H3ConnectProtocol::Plain => {
            if req_head.uri().scheme_str().is_some() || req_head.uri().path_and_query().is_some() {
                return Err(anyhow!(
                    "CONNECT request target must be authority-form without scheme/path"
                ));
            }
        }
    }

    let host_values: Vec<_> = headers.get_all(http::header::HOST).iter().collect();
    if host_values.len() > 1 {
        return Err(anyhow!("multiple Host headers are not allowed"));
    }
    if let Some(value) = host_values.first() {
        let raw = value
            .to_str()
            .map_err(|_| anyhow!("invalid Host header"))?
            .trim();
        if raw.is_empty() {
            return Err(anyhow!("Host header must not be empty"));
        }
        let (host_name, host_port) =
            crate::http::protocol::address::parse_authority_host_port(raw, authority_port)
                .ok_or_else(|| anyhow!("invalid Host header"))?;
        if host_port != authority_port || !host_name.eq_ignore_ascii_case(authority_host) {
            return Err(anyhow!("Host header does not match CONNECT authority"));
        }
    }
    Ok(())
}

#[cfg(feature = "http3")]
fn validate_extended_connect_target(
    req_head: &::http::Request<()>,
    label: &'static str,
) -> Result<()> {
    let scheme = req_head
        .uri()
        .scheme_str()
        .ok_or_else(|| anyhow!("{label} requires :scheme"))?;
    if scheme.trim().is_empty() {
        return Err(anyhow!("{label} :scheme must not be empty"));
    }
    let path = req_head
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .ok_or_else(|| anyhow!("{label} requires :path"))?;
    if path.trim().is_empty() {
        return Err(anyhow!("{label} :path must not be empty"));
    }
    Ok(())
}

#[cfg(feature = "http3")]
pub(in crate::forward) fn parse_connect_authority_with_default(
    authority: &str,
    default_port: Option<u16>,
) -> Result<(String, u16)> {
    crate::http::protocol::address::parse_authority_host_port_with_default(authority, default_port)
        .ok_or_else(|| anyhow!("invalid CONNECT authority"))
}

#[cfg(feature = "http3")]
pub(in crate::forward) fn default_connect_port_for_scheme(scheme: Option<&str>) -> Option<u16> {
    match scheme {
        Some("http") => Some(80),
        Some("https") | Some("wss") | Some("h3") | None => Some(443),
        Some(_) => None,
    }
}

pub(in crate::forward) fn parse_connect_udp_target(
    uri: &::http::Uri,
    uri_template: Option<&str>,
) -> Result<(String, u16)> {
    if let Some(template) = uri_template {
        // Strict mode: when a template is configured, only that template is accepted.
        return parse_connect_udp_target_from_template(uri, template);
    }

    let path_and_query = uri
        .path_and_query()
        .ok_or_else(|| anyhow!("CONNECT-UDP requires :path"))?;

    // RFC 9298 default template: /.well-known/masque/udp/{target_host}/{target_port}/
    let path = path_and_query.path();
    let segments = path.split('/').collect::<Vec<_>>();
    if segments.len() == 7
        && segments[0].is_empty()
        && segments[1] == ".well-known"
        && segments[2] == "masque"
        && segments[3] == "udp"
        && segments[6].is_empty()
    {
        if path_and_query.query().is_some() {
            return Err(anyhow!(
                "CONNECT-UDP default URI template does not accept a query component"
            ));
        }
        let host = percent_decode_str(segments[4])
            .decode_utf8()
            .map_err(|_| anyhow!("invalid CONNECT-UDP target_host encoding"))?;
        let host = validate_connect_udp_host(host.as_ref())?;
        let port: u16 = segments[5]
            .parse()
            .map_err(|_| anyhow!("invalid CONNECT-UDP target_port"))?;
        if port == 0 {
            return Err(anyhow!(
                "CONNECT-UDP target_port must be in range 1..=65535"
            ));
        }
        return Ok((host, port));
    }

    // Query-based templates:
    // - ...?target_host=...&target_port=...
    // - ...?h=...&p=...
    if let Some(query) = path_and_query.query() {
        let mut target_host: Option<String> = None;
        let mut target_port: Option<u16> = None;
        if let Some(host) = query_get_single(query, "target_host")? {
            target_host = Some(decode_connect_udp_host(host)?);
        } else if let Some(host) = query_get_single(query, "h")? {
            target_host = Some(decode_connect_udp_host(host)?);
        }
        if let Some(port) = query_get_single(query, "target_port")? {
            target_port = Some(parse_connect_udp_port(port)?);
        } else if let Some(port) = query_get_single(query, "p")? {
            target_port = Some(parse_connect_udp_port(port)?);
        }
        if let (Some(h), Some(p)) = (target_host, target_port) {
            return Ok((h, p));
        }
    }

    Err(anyhow!("unsupported CONNECT-UDP request target"))
}

pub(in crate::forward) fn validate_connect_udp_scheme<'a>(
    uri: &'a ::http::Uri,
    uri_template: Option<&str>,
) -> Result<&'a str> {
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow!("CONNECT-UDP requires :scheme"))?;
    if let Some(template) = uri_template {
        let template = split_connect_udp_uri_template(template)?;
        if let Some((template_scheme, _)) = template.absolute {
            if scheme.eq_ignore_ascii_case(template_scheme) {
                return Ok(scheme);
            }
            return Err(anyhow!("CONNECT-UDP uri_template scheme mismatch"));
        }
    }
    if scheme.eq_ignore_ascii_case("https") {
        return Ok(scheme);
    }
    Err(anyhow!("CONNECT-UDP :scheme must be https"))
}

fn parse_connect_udp_target_from_template(
    uri: &::http::Uri,
    template: &str,
) -> Result<(String, u16)> {
    let template = split_connect_udp_uri_template(template)?;
    if let Some((template_scheme, template_authority)) = template.absolute {
        let req_scheme = uri
            .scheme_str()
            .ok_or_else(|| anyhow!("CONNECT-UDP requires :scheme"))?;
        if !req_scheme.eq_ignore_ascii_case(template_scheme) {
            return Err(anyhow!("CONNECT-UDP uri_template scheme mismatch"));
        }
        let req_authority = uri
            .authority()
            .ok_or_else(|| anyhow!("CONNECT-UDP requires :authority"))?;
        let default_port = default_port_for_scheme(template_scheme);
        let (template_host, template_port) =
            crate::http::protocol::address::parse_authority_host_port(
                template_authority,
                default_port,
            )
            .ok_or_else(|| anyhow!("invalid CONNECT-UDP uri_template authority"))?;
        let (req_host, req_port) = crate::http::protocol::address::parse_authority_host_port(
            req_authority.as_str(),
            default_port,
        )
        .ok_or_else(|| anyhow!("invalid CONNECT-UDP :authority"))?;
        if template_port != req_port || !template_host.eq_ignore_ascii_case(req_host.as_str()) {
            return Err(anyhow!("CONNECT-UDP uri_template authority mismatch"));
        }
    }

    let path_and_query = uri
        .path_and_query()
        .ok_or_else(|| anyhow!("CONNECT-UDP requires :path"))?;
    let parser = UriTemplate::parse(template.path_query)?;
    let matched = parser.match_scalars(path_and_query.as_str())?;
    let host = matched
        .get("target_host")
        .ok_or_else(|| anyhow!("unsupported CONNECT-UDP request target"))?;
    let port = matched
        .get("target_port")
        .ok_or_else(|| anyhow!("unsupported CONNECT-UDP request target"))?;
    Ok((
        validate_connect_udp_host(host.as_str())?,
        parse_connect_udp_port(port.as_str())?,
    ))
}

#[derive(Clone, Copy)]
struct ConnectUdpUriTemplateParts<'a> {
    absolute: Option<(&'a str, &'a str)>,
    path_query: &'a str,
}

fn split_connect_udp_uri_template(template: &str) -> Result<ConnectUdpUriTemplateParts<'_>> {
    let (absolute, path_query) = if template.starts_with('/') {
        (None, template)
    } else {
        let scheme_end = template
            .find("://")
            .ok_or_else(|| anyhow!("invalid CONNECT-UDP uri_template"))?;
        let scheme = &template[..scheme_end];
        let rest = &template[scheme_end + 3..];
        let slash = rest
            .find('/')
            .ok_or_else(|| anyhow!("CONNECT-UDP uri_template must include a path"))?;
        let authority = &rest[..slash];
        if authority.is_empty() {
            return Err(anyhow!("CONNECT-UDP uri_template authority is empty"));
        }
        (Some((scheme, authority)), &rest[slash..])
    };
    Ok(ConnectUdpUriTemplateParts {
        absolute,
        path_query,
    })
}

fn query_get_single<'a>(query: &'a str, key: &str) -> Result<Option<&'a str>> {
    let mut found = None::<&'a str>;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            if found.is_some() {
                return Err(anyhow!("duplicate query parameter: {}", key));
            }
            found = Some(v);
        }
    }
    Ok(found)
}

fn decode_connect_udp_host(raw: &str) -> Result<String> {
    let host = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| anyhow!("invalid CONNECT-UDP target_host encoding"))?;
    validate_connect_udp_host(host.as_ref())
}

fn validate_connect_udp_host(raw: &str) -> Result<String> {
    let host = raw.trim();
    if host.is_empty() {
        return Err(anyhow!("CONNECT-UDP target_host must not be empty"));
    }
    if host.contains('@') {
        return Err(anyhow!("CONNECT-UDP target_host must not contain userinfo"));
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.to_string());
    }
    let uri: ::http::Uri = format!("http://{host}/")
        .parse()
        .map_err(|_| anyhow!("invalid CONNECT-UDP target_host"))?;
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow!("invalid CONNECT-UDP target_host"))?;
    if authority.port().is_some() {
        return Err(anyhow!("CONNECT-UDP target_host must not include a port"));
    }
    let normalized_host = normalize_connect_udp_authority_host(authority.host())?;
    if normalized_host.is_empty() {
        return Err(anyhow!("CONNECT-UDP target_host must not be empty"));
    }
    Ok(normalized_host)
}

fn normalize_connect_udp_authority_host(host: &str) -> Result<String> {
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        if inner.parse::<std::net::IpAddr>().is_ok() {
            return Ok(inner.to_string());
        }
        return Err(anyhow!("invalid CONNECT-UDP target_host"));
    }
    Ok(host.to_string())
}

fn parse_connect_udp_port(raw: &str) -> Result<u16> {
    let port: u16 = raw
        .parse()
        .map_err(|_| anyhow!("invalid CONNECT-UDP target_port"))?;
    if port == 0 {
        return Err(anyhow!(
            "CONNECT-UDP target_port must be in range 1..=65535"
        ));
    }
    Ok(port)
}

pub(super) fn default_port_for_scheme(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("http") {
        80
    } else {
        443
    }
}

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(super) fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

#[cfg(test)]
mod tests {
    use crate::forward::h3::connect::parse::*;

    #[test]
    fn connect_udp_path_template_requires_https_scheme() {
        let uri: ::http::Uri = "http://proxy.example/.well-known/masque/udp/example.com/443/"
            .parse()
            .expect("uri");
        assert!(validate_connect_udp_scheme(&uri, None).is_err());

        let uri: ::http::Uri = "https://proxy.example/.well-known/masque/udp/example.com/443/"
            .parse()
            .expect("uri");
        validate_connect_udp_scheme(&uri, None).expect("https default template");
    }

    #[test]
    fn connect_udp_absolute_template_scheme_must_match() {
        let uri: ::http::Uri = "http://proxy.example/masque/example.com/443"
            .parse()
            .expect("uri");
        assert!(
            validate_connect_udp_scheme(
                &uri,
                Some("https://proxy.example/masque/{target_host}/{target_port}")
            )
            .is_err()
        );
    }
}
