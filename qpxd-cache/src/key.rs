use super::types::CacheRequestKey;
use anyhow::Result;
use http::header::HOST;
use hyper::{Method, Request};
use qpx_http::body::Body;
use qpx_http::protocol::address::format_authority_host_port;
use std::cell::RefCell;
use url::Url;

struct CachedRequestKey {
    method: Method,
    uri: http::Uri,
    host: Option<http::HeaderValue>,
    default_scheme: String,
    key: Option<CacheRequestKey>,
}

thread_local! {
    static CACHED_REQUEST_KEY: RefCell<Option<CachedRequestKey>> = const { RefCell::new(None) };
}

impl CacheRequestKey {
    pub fn for_lookup(req: &Request<Body>, default_scheme: &str) -> Result<Option<Self>> {
        Self::for_target(req, default_scheme)
    }

    pub fn for_target(req: &Request<Body>, default_scheme: &str) -> Result<Option<Self>> {
        let host = req.headers().get(HOST);
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
        CACHED_REQUEST_KEY.with_borrow_mut(|cached| {
            *cached = Some(CachedRequestKey {
                method: req.method().clone(),
                uri: req.uri().clone(),
                host: host.cloned(),
                default_scheme: default_scheme.to_string(),
                key: key.clone(),
            });
        });
        Ok(key)
    }

    fn for_target_uncached(req: &Request<Body>, default_scheme: &str) -> Result<Option<Self>> {
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
                    .get(HOST)
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

        Ok(Some(Self {
            method: std::sync::Arc::from(cache_method_group(req.method())),
            scheme: std::sync::Arc::from(scheme),
            authority: std::sync::Arc::from(authority),
            path_and_query: std::sync::Arc::from(path_and_query),
            content_digest: None,
        }))
    }

    pub fn primary_hash(&self) -> String {
        let raw = format!(
            "{}|{}|{}|{}",
            self.method, self.scheme, self.authority, self.path_and_query
        );
        super::hash::sha256_hex(raw.as_bytes())
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
            method: std::sync::Arc::from(method.into()),
            scheme: self.scheme.clone(),
            authority: self.authority.clone(),
            path_and_query: self.path_and_query.clone(),
            content_digest: self.content_digest.clone(),
        }
    }

    pub fn with_content_digest(&self, digest: impl Into<String>) -> Self {
        let mut key = self.clone();
        key.content_digest = Some(std::sync::Arc::from(digest.into()));
        key
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
    let uri = http::Uri::builder()
        .scheme(normalized_scheme)
        .authority(raw)
        .path_and_query("/")
        .build()
        .ok()?;
    let authority = uri.authority()?;
    let host = authority.host().to_ascii_lowercase();
    let host = if host.contains(':') {
        format!("[{}]", host)
    } else {
        host
    };

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

pub fn normalize_url_authority(url: &Url) -> Option<String> {
    let host = url.host_str()?.to_ascii_lowercase();
    let host = if host.contains(':') {
        format!("[{}]", host)
    } else {
        host
    };
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

    #[test]
    fn query_content_digest_selects_variant_without_fragmenting_primary_index() {
        let request = Request::builder()
            .method("QUERY")
            .uri("https://example.com/search")
            .body(Body::empty())
            .unwrap();
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
        let first_request = Request::builder()
            .method(Method::GET)
            .uri("/asset")
            .header(HOST, "Example.COM:80")
            .body(Body::empty())
            .unwrap();
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

        let other_host = Request::builder()
            .method(Method::GET)
            .uri("/asset")
            .header(HOST, "other.example")
            .body(Body::empty())
            .unwrap();
        let other = CacheRequestKey::for_lookup(&other_host, "http")
            .unwrap()
            .unwrap();
        assert_eq!(other.authority.as_ref(), "other.example");
        assert_ne!(first.authority, other.authority);
    }
}
