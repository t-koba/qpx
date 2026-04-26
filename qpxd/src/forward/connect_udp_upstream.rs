use anyhow::{anyhow, Result};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use qpx_core::uri_template::UriTemplate;
use url::Url;

const TARGET_HOST_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b':')
    .add(b'%')
    .add(b'/')
    .add(b'?')
    .add(b'#')
    .add(b'[')
    .add(b']');

pub(super) fn build_upstream_connect_udp_uri(
    upstream: &str,
    target_host: &str,
    target_port: u16,
) -> Result<(String, u16, http::Uri)> {
    let encoded_host = utf8_percent_encode(target_host, TARGET_HOST_ENCODE_SET).to_string();

    if upstream.contains('{') || upstream.contains('}') {
        let (scheme, authority, path_query_tmpl) = split_uri_template(upstream)?;
        match scheme {
            "https" | "h3" => {}
            _ => {
                return Err(anyhow!(
                    "CONNECT-UDP upstream URI template requires https/h3 scheme"
                ))
            }
        }
        let (connect_host, connect_port) =
            crate::http::address::parse_authority_host_port(authority, 443)
                .ok_or_else(|| anyhow!("invalid CONNECT-UDP upstream authority"))?;
        let request_scheme = if scheme == "h3" { "https" } else { scheme };
        let path_and_query = UriTemplate::parse(path_query_tmpl)?.expand(|name| match name {
            "target_host" => Some(target_host.to_string()),
            "target_port" => Some(target_port.to_string()),
            _ => None,
        })?;
        let uri = http::Uri::builder()
            .scheme(request_scheme)
            .authority(authority)
            .path_and_query(path_and_query.as_str())
            .build()?;
        return Ok((connect_host, connect_port, uri));
    }

    if upstream.contains("://") {
        let parsed = Url::parse(upstream)?;
        match parsed.scheme() {
            "https" | "h3" => {}
            _ => {
                return Err(anyhow!(
                    "CONNECT-UDP upstream chain requires https/h3 proxy URL"
                ))
            }
        }
        if parsed.path() != "/" || parsed.query().is_some() {
            return Err(anyhow!(
                "CONNECT-UDP upstream URL must be a URI template when it includes path/query"
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("CONNECT-UDP upstream host missing"))?
            .to_string();
        let port = parsed.port().unwrap_or(443);
        let authority = format_proxy_authority(host.as_str(), port);
        let path_and_query = format!("/.well-known/masque/udp/{encoded_host}/{target_port}/");
        let uri = http::Uri::builder()
            .scheme("https")
            .authority(authority.as_str())
            .path_and_query(path_and_query.as_str())
            .build()?;
        return Ok((host, port, uri));
    }

    let (host, port) = crate::http::address::parse_authority_host_port(upstream, 443)
        .ok_or_else(|| anyhow!("invalid CONNECT-UDP upstream authority"))?;
    let authority = format_proxy_authority(host.as_str(), port);
    let path_and_query = format!("/.well-known/masque/udp/{encoded_host}/{target_port}/");
    let uri = http::Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query(path_and_query.as_str())
        .build()?;
    Ok((host, port, uri))
}

#[cfg(any(
    test,
    all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx"))
))]
pub(super) fn parse_connect_udp_upstream(upstream: &str) -> Result<(String, u16)> {
    if upstream.contains('{') || upstream.contains('}') {
        let (scheme, authority, _path) = split_uri_template(upstream)?;
        match scheme {
            "https" | "h3" => {}
            _ => {
                return Err(anyhow!(
                    "CONNECT-UDP upstream chain requires https/h3 proxy URL"
                ))
            }
        }
        return crate::http::address::parse_authority_host_port(authority, 443)
            .ok_or_else(|| anyhow!("invalid CONNECT-UDP upstream authority"));
    }
    if upstream.contains("://") {
        let parsed = Url::parse(upstream)?;
        match parsed.scheme() {
            "https" | "h3" => {}
            _ => {
                return Err(anyhow!(
                    "CONNECT-UDP upstream chain requires https/h3 proxy URL"
                ))
            }
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("CONNECT-UDP upstream host missing"))?;
        let port = parsed.port().unwrap_or(443);
        return Ok((host.to_string(), port));
    }

    crate::http::address::parse_authority_host_port(upstream, 443)
        .ok_or_else(|| anyhow!("invalid CONNECT-UDP upstream authority"))
}

fn split_uri_template(template: &str) -> Result<(&str, &str, &str)> {
    let scheme_end = template
        .find("://")
        .ok_or_else(|| anyhow!("CONNECT-UDP upstream URI template must be absolute"))?;
    let scheme = &template[..scheme_end];
    let rest = &template[scheme_end + 3..];
    let slash = rest
        .find('/')
        .ok_or_else(|| anyhow!("CONNECT-UDP upstream URI template must include a path"))?;
    let authority = &rest[..slash];
    if authority.is_empty() {
        return Err(anyhow!(
            "CONNECT-UDP upstream URI template authority is empty"
        ));
    }
    if authority.contains('{') || authority.contains('}') {
        return Err(anyhow!(
            "CONNECT-UDP upstream URI template must not contain variables in authority"
        ));
    }
    let path_query = &rest[slash..];
    if !path_query.starts_with('/') {
        return Err(anyhow!(
            "CONNECT-UDP upstream URI template path must start with '/'"
        ));
    }
    Ok((scheme, authority, path_query))
}

fn format_proxy_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else if port == 443 {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect_udp_upstream_accepts_h3_variants() {
        let (host, port) = parse_connect_udp_upstream("https://proxy.example:7443").expect("https");
        assert_eq!(host, "proxy.example");
        assert_eq!(port, 7443);

        let (host, port) = parse_connect_udp_upstream("h3://proxy.example").expect("h3");
        assert_eq!(host, "proxy.example");
        assert_eq!(port, 443);

        let (host, port) = parse_connect_udp_upstream("proxy.example:9443").expect("authority");
        assert_eq!(host, "proxy.example");
        assert_eq!(port, 9443);
    }

    #[test]
    fn parse_connect_udp_upstream_rejects_http_scheme() {
        assert!(parse_connect_udp_upstream("http://proxy.example:8080").is_err());
    }

    #[test]
    fn build_upstream_connect_udp_uri_supports_rfc6570_operators() {
        let (host, port, uri) = build_upstream_connect_udp_uri(
            "https://proxy.example/masque{/target_host}{;target_port}{?target_host,target_port}",
            "2001:db8::42",
            8443,
        )
        .expect("uri");
        assert_eq!(host, "proxy.example");
        assert_eq!(port, 443);
        assert_eq!(
            uri.to_string(),
            "https://proxy.example/masque/2001%3Adb8%3A%3A42;target_port=8443?target_host=2001%3Adb8%3A%3A42&target_port=8443"
        );
    }
}
