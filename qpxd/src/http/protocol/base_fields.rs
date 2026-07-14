use crate::http::protocol::common::http_version_label;
use http::Method;
use http::uri::{Authority, Scheme};
use hyper::Request;
use qpx_core::rules::RuleMatchContext;
use qpx_http::protocol::address::parse_authority_with_default_port;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

#[derive(Default)]
pub(crate) struct BaseRequestContext<'a> {
    pub(crate) peer_ip: Option<IpAddr>,
    pub(crate) dst_port: Option<u16>,
    pub(crate) host: Option<&'a str>,
    pub(crate) sni: Option<&'a str>,
    pub(crate) shared_sni: Option<Arc<str>>,
    pub(crate) scheme: Option<Scheme>,
    pub(crate) validated_request: Option<qpx_http::protocol::semantics::ValidatedIncomingRequest>,
}

#[derive(Debug, Clone)]
enum BaseAuthority {
    Parsed(Authority),
    InvalidPort(Authority),
    InvalidHeader(String),
}

impl BaseAuthority {
    fn as_str(&self) -> &str {
        match self {
            Self::Parsed(authority) | Self::InvalidPort(authority) => authority.as_str(),
            Self::InvalidHeader(value) => value.as_str(),
        }
    }

    fn host(&self) -> &str {
        match self {
            Self::Parsed(authority) => authority.host(),
            Self::InvalidPort(authority) => authority.as_str(),
            Self::InvalidHeader(value) => value.as_str(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BaseRequestFields {
    pub(crate) peer_ip: Option<IpAddr>,
    pub(crate) dst_port: Option<u16>,
    host_override: Option<String>,
    normalized_host: Option<String>,
    pub(crate) sni: Option<Arc<str>>,
    pub(crate) method: Method,
    authority: Option<BaseAuthority>,
    pub(crate) scheme: Option<Scheme>,
    pub(crate) uri: http::Uri,
    request_uri: OnceLock<String>,
    pub(crate) http_version: &'static str,
}

impl BaseRequestFields {
    pub(crate) fn path(&self) -> Option<&str> {
        Some(self.uri.path())
    }

    pub(crate) fn query(&self) -> Option<&str> {
        self.uri.query()
    }

    pub(crate) fn request_uri(&self) -> &str {
        if self.uri.scheme().is_some()
            || (self.uri.authority().is_some() && self.uri.path_and_query().is_none())
        {
            return self.request_uri.get_or_init(|| self.uri.to_string());
        }
        self.uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("")
    }

    pub(crate) fn host(&self) -> Option<&str> {
        self.host_override
            .as_deref()
            .or(self.normalized_host.as_deref())
            .or_else(|| self.authority.as_ref().map(BaseAuthority::host))
    }

    pub(crate) fn authority(&self) -> Option<&str> {
        self.authority.as_ref().map(BaseAuthority::as_str)
    }

    pub(crate) fn rule_match_context(&self) -> RuleMatchContext<'_> {
        RuleMatchContext {
            src_ip: self.peer_ip,
            dst_port: self.dst_port,
            host: self.host(),
            sni: self.sni.as_deref(),
            method: Some(self.method.as_str()),
            path: self.path(),
            query: self.query(),
            authority: self.authority(),
            scheme: self.scheme.as_ref().map(Scheme::as_str),
            http_version: Some(self.http_version),
            ..Default::default()
        }
    }
}

pub(crate) fn extract_base_request_fields<B>(
    req: &Request<B>,
    ctx: BaseRequestContext<'_>,
) -> BaseRequestFields {
    let uri = req.uri().clone();
    let scheme = ctx.scheme.or_else(|| req.uri().scheme().cloned());
    let default_port = default_port_for_scheme(
        scheme
            .as_ref()
            .map(Scheme::as_str)
            .or_else(|| req.uri().scheme_str()),
    );
    let (derived_authority, derived_port) =
        extract_authority(req, default_port, ctx.validated_request);
    let normalized_host = ctx.host.is_none().then(|| {
        let host = derived_authority.as_ref()?.host();
        host.bytes()
            .any(|byte| byte.is_ascii_uppercase())
            .then(|| host.to_ascii_lowercase())
    });

    BaseRequestFields {
        peer_ip: ctx.peer_ip,
        dst_port: ctx.dst_port.or(derived_port),
        host_override: ctx.host.map(str::to_string),
        normalized_host: normalized_host.flatten(),
        sni: ctx.shared_sni.or_else(|| ctx.sni.map(Arc::<str>::from)),
        method: req.method().clone(),
        authority: derived_authority,
        scheme,
        uri,
        request_uri: OnceLock::new(),
        http_version: http_version_label(req.version()),
    }
}

fn extract_authority<B>(
    req: &Request<B>,
    default_port: u16,
    validated_request: Option<qpx_http::protocol::semantics::ValidatedIncomingRequest>,
) -> (Option<BaseAuthority>, Option<u16>) {
    if let Some(authority) = req.uri().authority() {
        if authority_has_explicit_port(authority.as_str()) && authority.port_u16().is_none() {
            return (Some(BaseAuthority::InvalidPort(authority.clone())), None);
        }
        let port = authority.port_u16().unwrap_or(default_port);
        return (Some(BaseAuthority::Parsed(authority.clone())), Some(port));
    }
    if let Some(authority) = validated_request.and_then(|validated| validated.into_authority()) {
        if authority_has_explicit_port(authority.as_str()) && authority.port_u16().is_none() {
            return (Some(BaseAuthority::InvalidPort(authority)), None);
        }
        let port = authority.port_u16().unwrap_or(default_port);
        return (Some(BaseAuthority::Parsed(authority)), Some(port));
    }
    let Some(value) = req.headers().get(http::header::HOST) else {
        return (None, None);
    };
    let Ok(raw) = value.to_str() else {
        return (None, None);
    };
    match parse_authority_with_default_port(raw, Some(default_port)) {
        Some((authority, port)) => (Some(BaseAuthority::Parsed(authority)), Some(port)),
        None => (Some(BaseAuthority::InvalidHeader(raw.to_owned())), None),
    }
}

fn authority_has_explicit_port(authority: &str) -> bool {
    if let Some(suffix) = authority
        .strip_prefix('[')
        .and_then(|value| value.find(']').map(|close| &value[close + 1..]))
    {
        return suffix.starts_with(':');
    }
    authority.contains(':')
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
    use crate::http::protocol::base_fields::*;

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

        assert_eq!(fields.path(), Some("/foo/bar"));
        assert_eq!(fields.query(), Some("a=1&b=2"));
        assert_eq!(fields.request_uri(), "https://example.com/foo/bar?a=1&b=2");
        assert_eq!(fields.host(), Some("example.com"));

        let ctx = fields.rule_match_context();
        assert_eq!(ctx.path, Some("/foo/bar"));
        assert_eq!(ctx.query, Some("a=1&b=2"));
        assert_eq!(ctx.authority, Some("example.com"));
        assert_eq!(ctx.scheme, Some("https"));
    }

    #[test]
    fn origin_form_request_uri_borrows_path_and_query() {
        let req = Request::builder()
            .uri("/foo/bar?a=1&b=2")
            .body(())
            .expect("request");

        let fields = extract_base_request_fields(&req, BaseRequestContext::default());

        assert!(fields.request_uri.get().is_none());
        assert_eq!(fields.request_uri(), "/foo/bar?a=1&b=2");
    }

    #[test]
    fn lowercase_host_does_not_require_normalized_storage() {
        let req = Request::builder()
            .uri("/")
            .header(http::header::HOST, "example.com:8080")
            .body(())
            .expect("request");

        let fields = extract_base_request_fields(&req, BaseRequestContext::default());

        assert_eq!(fields.host(), Some("example.com"));
        assert!(fields.normalized_host.is_none());
        assert_eq!(fields.dst_port, Some(8080));
    }

    #[test]
    fn uppercase_host_is_normalized_once() {
        let req = Request::builder()
            .uri("/")
            .header(http::header::HOST, "EXAMPLE.COM")
            .body(())
            .expect("request");

        let fields = extract_base_request_fields(&req, BaseRequestContext::default());

        assert_eq!(fields.host(), Some("example.com"));
        assert_eq!(fields.normalized_host.as_deref(), Some("example.com"));
    }

    #[test]
    fn uri_service_name_port_is_not_treated_as_the_default_numeric_port() {
        let req = Request::builder()
            .uri("http://example.com:http/resource")
            .body(())
            .expect("request");

        let fields = extract_base_request_fields(&req, BaseRequestContext::default());

        assert_eq!(fields.host(), Some("example.com:http"));
        assert_eq!(fields.dst_port, None);
    }

    #[test]
    fn extraction_reuses_preflight_authority_metadata() {
        let req = Request::builder()
            .version(http::Version::HTTP_11)
            .uri("/")
            .header(http::header::HOST, "example.com:http")
            .body(())
            .expect("request");
        let validated =
            qpx_http::protocol::semantics::validate_incoming_request_with_metadata(&req)
                .expect("validated request");
        let fields = extract_base_request_fields(
            &req,
            BaseRequestContext {
                validated_request: Some(validated),
                ..Default::default()
            },
        );

        assert!(matches!(
            fields.authority,
            Some(BaseAuthority::InvalidPort(_))
        ));
        assert_eq!(fields.host(), Some("example.com:http"));
        assert_eq!(fields.dst_port, None);
    }
}
