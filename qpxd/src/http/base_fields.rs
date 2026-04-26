use crate::http::address::parse_authority_host_port;
use crate::http::common::http_version_label;
use hyper::{Method, Request};
use qpx_core::rules::RuleMatchContext;
use std::net::IpAddr;

#[derive(Default)]
pub(crate) struct BaseRequestContext<'a> {
    pub(crate) peer_ip: Option<IpAddr>,
    pub(crate) dst_port: Option<u16>,
    pub(crate) host: Option<&'a str>,
    pub(crate) sni: Option<&'a str>,
    pub(crate) authority: Option<&'a str>,
    pub(crate) scheme: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub(crate) struct BaseRequestFields {
    pub(crate) peer_ip: Option<IpAddr>,
    pub(crate) dst_port: Option<u16>,
    pub(crate) host: Option<String>,
    pub(crate) sni: Option<String>,
    pub(crate) method: Method,
    pub(crate) path: Option<String>,
    pub(crate) query: Option<String>,
    pub(crate) authority: Option<String>,
    pub(crate) scheme: Option<String>,
    pub(crate) request_uri: String,
    pub(crate) http_version: &'static str,
}

impl BaseRequestFields {
    pub(crate) fn rule_match_context(&self) -> RuleMatchContext<'_> {
        RuleMatchContext {
            src_ip: self.peer_ip,
            dst_port: self.dst_port,
            host: self.host.as_deref(),
            sni: self.sni.as_deref(),
            method: Some(self.method.as_str()),
            path: self.path.as_deref(),
            query: self.query.as_deref(),
            authority: self.authority.as_deref(),
            scheme: self.scheme.as_deref(),
            http_version: Some(self.http_version),
            ..Default::default()
        }
    }
}

pub(crate) fn extract_base_request_fields<B>(
    req: &Request<B>,
    ctx: BaseRequestContext<'_>,
) -> BaseRequestFields {
    let scheme = ctx
        .scheme
        .map(str::to_string)
        .or_else(|| req.uri().scheme_str().map(str::to_string));
    let derived_authority = req
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| {
            req.headers()
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        });
    let (derived_host, derived_port) =
        extract_host_port(req, scheme.as_deref(), derived_authority.as_deref());

    BaseRequestFields {
        peer_ip: ctx.peer_ip,
        dst_port: ctx.dst_port.or(derived_port),
        host: ctx.host.map(str::to_string).or(derived_host),
        sni: ctx.sni.map(str::to_string),
        method: req.method().clone(),
        path: Some(req.uri().path().to_string()),
        query: req
            .uri()
            .path_and_query()
            .and_then(|value| value.query())
            .map(str::to_string),
        authority: ctx.authority.map(str::to_string).or(derived_authority),
        scheme,
        request_uri: req.uri().to_string(),
        http_version: http_version_label(req.version()),
    }
}

fn extract_host_port<B>(
    req: &Request<B>,
    scheme: Option<&str>,
    authority: Option<&str>,
) -> (Option<String>, Option<u16>) {
    let default_port = default_port_for_scheme(scheme.or_else(|| req.uri().scheme_str()));
    if let Some(authority) = authority {
        if let Some((host, port)) = parse_authority_host_port(authority, default_port) {
            return (Some(host), Some(port));
        }
        return (Some(authority.to_string()), None);
    }
    (None, None)
}

fn default_port_for_scheme(scheme: Option<&str>) -> u16 {
    match scheme {
        Some(value) if value.eq_ignore_ascii_case("https") || value.eq_ignore_ascii_case("wss") => {
            443
        }
        Some(value) if value.eq_ignore_ascii_case("ftp") => 21,
        _ => 80,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_base_request_fields_splits_path_and_query() {
        let req = Request::builder()
            .uri("https://example.com/foo/bar?a=1&b=2")
            .body(())
            .expect("request");

        let fields = extract_base_request_fields(
            &req,
            BaseRequestContext {
                peer_ip: Some("127.0.0.1".parse().expect("ip")),
                ..Default::default()
            },
        );

        assert_eq!(fields.path.as_deref(), Some("/foo/bar"));
        assert_eq!(fields.query.as_deref(), Some("a=1&b=2"));

        let ctx = fields.rule_match_context();
        assert_eq!(ctx.path, Some("/foo/bar"));
        assert_eq!(ctx.query, Some("a=1&b=2"));
    }
}
