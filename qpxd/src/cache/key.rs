use super::types::CacheRequestKey;
use crate::http::address::format_authority_host_port;
use crate::http::body::Body;
use anyhow::Result;
use http::header::HOST;
use hyper::{Method, Request};
use url::Url;

impl CacheRequestKey {
    pub fn for_lookup(req: &Request<Body>, default_scheme: &str) -> Result<Option<Self>> {
        Self::for_target(req, default_scheme)
    }

    pub fn for_target(req: &Request<Body>, default_scheme: &str) -> Result<Option<Self>> {
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
            method: cache_method_group(req.method()),
            scheme,
            authority,
            path_and_query,
        }))
    }

    pub(super) fn primary_hash(&self) -> String {
        let raw = format!(
            "{}|{}|{}|{}",
            self.method, self.scheme, self.authority, self.path_and_query
        );
        super::hash::sha256_hex(raw.as_bytes())
    }

    pub(super) fn absolute_url(&self) -> Option<Url> {
        Url::parse(
            format!(
                "{}://{}{}",
                self.scheme, self.authority, self.path_and_query
            )
            .as_str(),
        )
        .ok()
    }

    pub(super) fn with_method_group(&self, method: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            scheme: self.scheme.clone(),
            authority: self.authority.clone(),
            path_and_query: self.path_and_query.clone(),
        }
    }
}

pub(super) fn cache_method_group(method: &Method) -> String {
    if *method == Method::GET {
        "GET".to_string()
    } else if *method == Method::HEAD {
        "HEAD".to_string()
    } else {
        method.as_str().to_ascii_uppercase()
    }
}

pub(super) fn normalize_authority(raw: &str, scheme: &str) -> Option<String> {
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

pub(super) fn normalize_url_authority(url: &Url) -> Option<String> {
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
