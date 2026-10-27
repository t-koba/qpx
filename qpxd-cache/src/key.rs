use super::types::CacheRequestKey;
use anyhow::Result;
use hyper::Method;
use qpx_core::http_message::{OrdinaryHeaderName, Request as OwnerRequest};
use qpx_http::protocol::address::format_authority_host_port;
use std::cell::RefCell;
use std::sync::Arc;
use url::Url;

fn host_name() -> OrdinaryHeaderName {
    OrdinaryHeaderName::try_from("host").expect("host is ordinary")
}

struct CachedRequestKey {
    method: Method,
    uri: http::Uri,
    host: Option<http::HeaderValue>,
    default_scheme: String,
    key: Option<CacheRequestKey>,
    primary_hash: Option<Arc<str>>,
}

thread_local! {
    static CACHED_REQUEST_KEY: RefCell<Option<CachedRequestKey>> = const { RefCell::new(None) };
}

impl CacheRequestKey {
    pub fn for_lookup(req: &OwnerRequest<()>, default_scheme: &str) -> Result<Option<Self>> {
        Self::for_target(req, default_scheme)
    }

    pub fn for_target(req: &OwnerRequest<()>, default_scheme: &str) -> Result<Option<Self>> {
        let host_name = host_name();
        let host = req.headers().get(&host_name);
        if let Some(key) = CACHED_REQUEST_KEY.with_borrow(|cached| {
            cached
                .as_ref()
                .filter(|cached| {
                    cached.method == *req.method()
                        && cached.uri == *req.uri()
                        && cached.host.as_ref() == host
                        && cached.default_scheme == default_scheme
                })
                .map(|cached| cached.key.clone())
        }) {
            return Ok(key);
        }
        let key = Self::for_target_uncached(req, default_scheme)?;
        let primary_hash = key
            .as_ref()
            .map(|key| Arc::from(key.compute_primary_hash()));
        CACHED_REQUEST_KEY.with_borrow_mut(|cached| {
            *cached = Some(CachedRequestKey {
                method: req.method().clone(),
                uri: req.uri().clone(),
                host: host.cloned(),
                default_scheme: default_scheme.to_string(),
                key: key.clone(),
                primary_hash,
            });
        });
        Ok(key)
    }

    fn for_target_uncached(req: &OwnerRequest<()>, default_scheme: &str) -> Result<Option<Self>> {
        let scheme = req
            .uri()
            .scheme_str()
            .unwrap_or(default_scheme)
            .trim()
            .to_ascii_lowercase();
        let authority = req
            .uri()
            .authority()
            .and_then(|a| normalize_authority(a.as_str(), scheme.as_str()))
            .or_else(|| {
                req.headers()
                    .get(&host_name())
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| normalize_authority(v, scheme.as_str()))
            });

        let Some(authority) = authority.filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        Ok(Some(Self::from_parts(
            Arc::from(cache_method_group(req.method())),
            Arc::from(scheme),
            Arc::from(authority),
            Arc::from(path_and_query),
        )))
    }

    /// Builds a lookup key from components that already satisfy the same
    /// normalization rules as `for_target_uncached`: a lowercased scheme, the
    /// output of `normalize_authority` for the authority, and the origin-form
    /// path-and-query. Callers that already hold pre-parsed request data use
    /// this to skip a redundant URI parse on hot paths.
    pub fn from_normalized_parts(
        method: &'static str,
        scheme: &'static str,
        authority: String,
        path_and_query: String,
    ) -> Self {
        Self::from_parts(
            std::sync::Arc::from(method),
            std::sync::Arc::from(scheme),
            std::sync::Arc::from(authority),
            std::sync::Arc::from(path_and_query),
        )
    }

    pub fn primary_hash(&self) -> String {
        self.primary_hash_arc().to_string()
    }

    pub fn absolute_url(&self) -> Option<Url> {
        Url::parse(
            format!(
                "{}://{}{}",
                self.scheme, self.authority, self.path_and_query
            )
            .as_str(),
        )
        .ok()
    }

    pub fn with_method_group(&self, method: impl Into<String>) -> Self {
        Self {
            method: Arc::from(method.into()),
            scheme: self.scheme.clone(),
            authority: self.authority.clone(),
            path_and_query: self.path_and_query.clone(),
            content_digest: self.content_digest.clone(),
            primary_index_storage_key: Arc::new(std::sync::OnceLock::new()),
            primary_default_variant_storage_key: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub fn with_content_digest(&self, digest: impl Into<String>) -> Self {
        let mut key = self.clone();
        key.content_digest = Some(std::sync::Arc::from(digest.into()));
        key
    }

    pub(crate) fn from_parts(
        method: Arc<str>,
        scheme: Arc<str>,
        authority: Arc<str>,
        path_and_query: Arc<str>,
    ) -> Self {
        Self {
            method,
            scheme,
            authority,
            path_and_query,
            content_digest: None,
            primary_index_storage_key: Arc::new(std::sync::OnceLock::new()),
            primary_default_variant_storage_key: Arc::new(std::sync::OnceLock::new()),
        }
    }

    pub(crate) fn primary_hash_arc(&self) -> Arc<str> {
        if let Some(primary_hash) = CACHED_REQUEST_KEY.with_borrow(|cached| {
            cached.as_ref().and_then(|cached| {
                cached
                    .key
                    .as_ref()
                    .filter(|key| self.same_primary_key(key))
                    .and(cached.primary_hash.clone())
            })
        }) {
            return primary_hash;
        }
        Arc::from(self.compute_primary_hash())
    }

    pub(crate) fn primary_index_storage_key_arc(&self) -> Arc<str> {
        self.primary_index_storage_key
            .get_or_init(|| {
                Arc::from(super::vary::index_storage_key(
                    self.primary_hash_arc().as_ref(),
                ))
            })
            .clone()
    }

    /// Storage key of the primary variant index, computed once per key.
    pub fn primary_index_storage_key(&self) -> Arc<str> {
        self.primary_index_storage_key_arc()
    }

    /// Storage key of the canonical Vary-less variant. Vary-less responses
    /// publish no variant index, so lookups probe this deterministic key.
    pub fn primary_default_variant_storage_key(&self) -> Arc<str> {
        self.primary_default_variant_storage_key
            .get_or_init(|| {
                Arc::from(super::vary::variant_storage_key(
                    self.primary_hash_arc().as_ref(),
                    &[],
                ))
            })
            .clone()
    }

    fn compute_primary_hash(&self) -> String {
        super::hash::sha256_hex_parts(&[
            self.method.as_bytes(),
            b"|",
            self.scheme.as_bytes(),
            b"|",
            self.authority.as_bytes(),
            b"|",
            self.path_and_query.as_bytes(),
        ])
    }

    fn same_primary_key(&self, other: &Self) -> bool {
        self.method == other.method
            && self.scheme == other.scheme
            && self.authority == other.authority
            && self.path_and_query == other.path_and_query
    }
}

pub fn cache_method_group(method: &Method) -> String {
    if *method == Method::GET {
        "GET".to_string()
    } else if *method == Method::HEAD {
        "HEAD".to_string()
    } else {
        method.as_str().to_ascii_uppercase()
    }
}

pub fn normalize_authority(raw: &str, scheme: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let normalized_scheme = if scheme.eq_ignore_ascii_case("https") {
        "https"
    } else {
        "http"
    };
    // Fast path for plain registrable names without a port or IPv6 brackets.
    // The accepted character set is a strict subset of the URI authority
    // grammar, so anything this accepts is also what the full validation
    // below would return; everything else falls back to that path.
    if !raw.contains(':')
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
    {
        return Some(raw.to_ascii_lowercase());
    }
    let uri = http::Uri::builder()
        .scheme(normalized_scheme)
        .authority(raw)
        .path_and_query("/")
        .build()
        .ok()?;
    let authority = uri.authority()?;
    let host = normalize_host(authority.host());

    if let Some(port) = authority.port_u16() {
        let default_port = match normalized_scheme {
            "https" => 443,
            _ => 80,
        };
        if port == default_port {
            return Some(host);
        }
        return Some(format_authority_host_port(host.as_str(), port));
    }
    Some(host)
}

fn normalize_host(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    if host.starts_with('[') && host.ends_with(']') {
        host
    } else if host.contains(':') {
        format!("[{}]", host)
    } else {
        host
    }
}

pub fn normalize_url_authority(url: &Url) -> Option<String> {
    let host = normalize_host(url.host_str()?);
    let default_port = match url.scheme() {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    match url.port() {
        Some(port) if port != default_port => Some(format_authority_host_port(host.as_str(), port)),
        _ => Some(host),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qpx_core::http_message::OrdinaryHeaderName;

    fn owner_request(method: Method, uri: &str, host: Option<&str>) -> OwnerRequest<()> {
        let mut req = OwnerRequest::new(());
        *req.method_mut() = method;
        *req.uri_mut() = uri.parse().expect("uri");
        if let Some(host) = host {
            req.headers_mut().insert(
                OrdinaryHeaderName::try_from("host").expect("host"),
                host.parse().expect("host value"),
            );
        }
        req
    }

    fn owner_request_with_extra_host(
        method: Method,
        uri: &str,
        first_host: &str,
        extra_host: &str,
    ) -> OwnerRequest<()> {
        let mut req = owner_request(method, uri, Some(first_host));
        req.headers_mut().append(
            OrdinaryHeaderName::try_from("host").expect("host"),
            extra_host.parse().expect("host value"),
        );
        req
    }

    #[test]
    fn query_content_digest_selects_variant_without_fragmenting_primary_index() {
        let request = owner_request(Method::QUERY, "https://example.com/search", None);
        let key = CacheRequestKey::for_lookup(&request, "https")
            .unwrap()
            .unwrap();
        let first = key.with_content_digest("sha-256:first");
        let second = key.with_content_digest("sha-256:second");
        assert_eq!(first.primary_hash(), second.primary_hash());
        assert_ne!(first.content_digest, second.content_digest);
    }

    #[test]
    fn repeated_request_key_reuses_normalized_components_without_cross_host_aliasing() {
        let first_request = owner_request(Method::GET, "/asset", Some("Example.COM:80"));
        let first = CacheRequestKey::for_lookup(&first_request, "http")
            .unwrap()
            .unwrap();
        let second = CacheRequestKey::for_lookup(&first_request, "http")
            .unwrap()
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(&first.method, &second.method));
        assert!(std::sync::Arc::ptr_eq(&first.scheme, &second.scheme));
        assert!(std::sync::Arc::ptr_eq(&first.authority, &second.authority));
        assert!(std::sync::Arc::ptr_eq(
            &first.path_and_query,
            &second.path_and_query
        ));
        assert!(std::sync::Arc::ptr_eq(
            &first.primary_hash_arc(),
            &second.primary_hash_arc()
        ));
        assert!(std::sync::Arc::ptr_eq(
            &first.primary_index_storage_key_arc(),
            &second.primary_index_storage_key_arc()
        ));
        assert!(std::sync::Arc::ptr_eq(
            &first.primary_index_storage_key_arc(),
            &first
                .with_content_digest("sha-256:body")
                .primary_index_storage_key_arc()
        ));
        assert!(!std::sync::Arc::ptr_eq(
            &first.primary_index_storage_key_arc(),
            &first
                .with_method_group("HEAD")
                .primary_index_storage_key_arc()
        ));

        let other_host = owner_request(Method::GET, "/asset", Some("other.example"));
        let other = CacheRequestKey::for_lookup(&other_host, "http")
            .unwrap()
            .unwrap();
        assert_eq!(other.authority.as_ref(), "other.example");
        assert_ne!(first.authority, other.authority);
    }

    #[test]
    fn ipv6_authority_normalization_preserves_uri_and_host_semantics() {
        let absolute_request = owner_request(
            Method::GET,
            "https://[2001:db8::1]:443/absolute?q=1",
            Some("other.example"),
        );
        let absolute = CacheRequestKey::for_target(&absolute_request, "http")
            .unwrap()
            .unwrap();
        assert_eq!(absolute.scheme.as_ref(), "https");
        assert_eq!(absolute.authority.as_ref(), "[2001:db8::1]");
        assert_eq!(absolute.path_and_query.as_ref(), "/absolute?q=1");
        let absolute_url = absolute.absolute_url().unwrap();
        assert_eq!(absolute_url.as_str(), "https://[2001:db8::1]/absolute?q=1");
        assert_eq!(absolute_url.port(), None);
        assert_eq!(
            normalize_url_authority(&absolute_url).as_deref(),
            Some("[2001:db8::1]")
        );
        assert_eq!(absolute_url.path(), "/absolute");
        assert_eq!(absolute_url.query(), Some("q=1"));

        let host_fallback_request = owner_request_with_extra_host(
            Method::GET,
            "/host-fallback",
            "[2001:db8::1]:443",
            "other.example",
        );
        let host_fallback = CacheRequestKey::for_target(&host_fallback_request, "https")
            .unwrap()
            .unwrap();
        assert_eq!(host_fallback.authority.as_ref(), "[2001:db8::1]");
        assert_eq!(host_fallback.path_and_query.as_ref(), "/host-fallback");
        assert_eq!(
            host_fallback.absolute_url().unwrap().as_str(),
            "https://[2001:db8::1]/host-fallback"
        );

        assert_eq!(
            normalize_authority("[2001:db8::1]:8443", "https").as_deref(),
            Some("[2001:db8::1]:8443")
        );
        assert_eq!(
            normalize_url_authority(&Url::parse("https://[2001:db8::1]:8443/").unwrap()).as_deref(),
            Some("[2001:db8::1]:8443")
        );
        assert_eq!(
            normalize_authority("Example.COM:80", "http").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_authority("192.0.2.1:8080", "http").as_deref(),
            Some("192.0.2.1:8080")
        );
    }
}
