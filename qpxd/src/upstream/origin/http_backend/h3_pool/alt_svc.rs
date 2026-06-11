use super::{OriginEndpoint, content_length_is_zero_or_absent};
use anyhow::Result;
use http::HeaderMap;
use hyper::Request;
use qpx_http::body::Body;
use std::collections::HashMap;
use std::sync::LazyLock;
use tokio::time::{Duration, Instant};

const H3_ALT_SVC_CACHE_SHARDS: usize = 64;
const MAX_H3_ALT_SVC_CACHE_KEYS: usize = 1024;
pub(super) const MAX_H3_ALT_SVC_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

static H3_ALT_SVC_CACHE: LazyLock<ShardedAltSvcCache> = LazyLock::new(ShardedAltSvcCache::new);

struct ShardedAltSvcCache {
    shards: qpx_http::sharding::AsyncShardMap<String, AltSvcH3Endpoint>,
}

impl ShardedAltSvcCache {
    fn new() -> Self {
        Self {
            shards: qpx_http::sharding::AsyncShardMap::new(H3_ALT_SVC_CACHE_SHARDS),
        }
    }

    async fn get(&self, key: &str) -> Option<AltSvcH3Endpoint> {
        let mut cache = self.shards.lock(key).await;
        prune_alt_svc_cache(&mut cache);
        let entry = cache.get(key).cloned()?;
        if entry.expires_at <= Instant::now() {
            cache.remove(key);
            return None;
        }
        Some(entry)
    }

    async fn insert(&self, key: String, endpoint: AltSvcH3Endpoint) {
        let mut cache = self.shards.lock(&key).await;
        prune_alt_svc_cache(&mut cache);
        evict_alt_svc_cache_if_full(&mut cache, key.as_str(), self.max_keys_per_shard());
        cache.insert(key, endpoint);
    }

    async fn remove(&self, key: &str) {
        self.shards.lock(key).await.remove(key);
    }

    fn max_keys_per_shard(&self) -> usize {
        MAX_H3_ALT_SVC_CACHE_KEYS
            .div_ceil(H3_ALT_SVC_CACHE_SHARDS)
            .max(1)
    }
}

#[derive(Debug, Clone)]
pub(super) struct AltSvcH3Endpoint {
    pub(super) connect_host: Option<String>,
    pub(super) connect_port: u16,
    pub(super) expires_at: Instant,
}

pub(in crate::upstream::origin::http_backend) async fn cached_alt_svc_h3_endpoint(
    origin: &OriginEndpoint,
) -> Result<Option<OriginEndpoint>> {
    let key = alt_svc_cache_key(origin)?;
    let Some(entry) = H3_ALT_SVC_CACHE.get(&key).await else {
        return Ok(None);
    };
    let default_port = origin.default_port_hint();
    let (logical_host, logical_port) = origin.logical_parts(default_port)?;
    let tls_name = origin.tls_server_name()?;
    Ok(Some(OriginEndpoint::discovered(
        origin.upstream.as_str(),
        entry.connect_host.unwrap_or_else(|| logical_host.clone()),
        entry.connect_port,
        logical_host,
        logical_port,
        tls_name,
    )))
}

pub(in crate::upstream::origin::http_backend) async fn record_h3_alt_svc(
    origin: &OriginEndpoint,
    headers: &HeaderMap,
) {
    let alt_svc = http::header::HeaderName::from_static("alt-svc");
    let key = match alt_svc_cache_key(origin) {
        Ok(key) => key,
        Err(_) => return,
    };
    let default_port = origin.default_port_hint();
    let Ok((logical_host, _logical_port)) = origin.logical_parts(default_port) else {
        return;
    };
    for value in headers.get_all(alt_svc).iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        if value.trim().eq_ignore_ascii_case("clear") {
            H3_ALT_SVC_CACHE.remove(&key).await;
            return;
        }
        if let Some(endpoint) = parse_h3_alt_svc(value)
            && alt_svc_endpoint_matches_same_origin_host(&endpoint, logical_host.as_str())
        {
            H3_ALT_SVC_CACHE.insert(key, endpoint).await;
            return;
        }
    }
}

pub(in crate::upstream::origin::http_backend) async fn forget_alt_svc_h3_endpoint(
    origin: &OriginEndpoint,
) {
    if let Ok(key) = alt_svc_cache_key(origin) {
        H3_ALT_SVC_CACHE.remove(&key).await;
    }
}

pub(in crate::upstream::origin::http_backend) fn request_can_use_alt_svc_h3(
    req: &Request<Body>,
) -> bool {
    matches!(
        *req.method(),
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS | http::Method::TRACE
    ) && req.headers().get(http::header::TRANSFER_ENCODING).is_none()
        && http_body::Body::is_end_stream(req.body())
        && content_length_is_zero_or_absent(req.headers())
}

fn alt_svc_cache_key(origin: &OriginEndpoint) -> Result<String> {
    let default_port = origin.default_port_hint();
    Ok(origin
        .host_header_authority(default_port)?
        .to_ascii_lowercase())
}

pub(super) fn parse_h3_alt_svc(value: &str) -> Option<AltSvcH3Endpoint> {
    for alternative in split_alt_svc_values(value) {
        let mut parts = alternative.split(';').map(str::trim);
        let first = parts.next()?;
        let (alpn, authority) = first.split_once('=')?;
        let alpn = alpn.trim().trim_matches('"');
        if !alpn.eq_ignore_ascii_case("h3") && !alpn.to_ascii_lowercase().starts_with("h3-") {
            continue;
        }
        let authority = authority.trim().trim_matches('"');
        let (connect_host, connect_port) = parse_alt_svc_authority(authority)?;
        let mut max_age = MAX_H3_ALT_SVC_MAX_AGE;
        for param in parts {
            let Some((name, raw)) = param.split_once('=') else {
                continue;
            };
            if name.trim().eq_ignore_ascii_case("ma")
                && let Ok(seconds) = raw.trim().trim_matches('"').parse::<u64>()
            {
                max_age = Duration::from_secs(seconds).min(MAX_H3_ALT_SVC_MAX_AGE);
            }
        }
        if max_age.is_zero() {
            return None;
        }
        let expires_at = Instant::now().checked_add(max_age)?;
        return Some(AltSvcH3Endpoint {
            connect_host,
            connect_port,
            expires_at,
        });
    }
    None
}

pub(super) fn alt_svc_endpoint_matches_same_origin_host(
    endpoint: &AltSvcH3Endpoint,
    logical_host: &str,
) -> bool {
    endpoint
        .connect_host
        .as_deref()
        .map(|host| normalize_alt_svc_host(host) == normalize_alt_svc_host(logical_host))
        .unwrap_or(true)
}

fn normalize_alt_svc_host(host: &str) -> String {
    host.trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn prune_alt_svc_cache(cache: &mut HashMap<String, AltSvcH3Endpoint>) {
    let now = Instant::now();
    cache.retain(|_, endpoint| endpoint.expires_at > now);
}

fn evict_alt_svc_cache_if_full(
    cache: &mut HashMap<String, AltSvcH3Endpoint>,
    inserting_key: &str,
    max_keys: usize,
) {
    if cache.contains_key(inserting_key) || cache.len() < max_keys {
        return;
    }
    let Some(oldest_key) = cache
        .iter()
        .min_by_key(|(_, endpoint)| endpoint.expires_at)
        .map(|(key, _)| key.clone())
    else {
        return;
    };
    cache.remove(&oldest_key);
}

fn split_alt_svc_values(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    for (idx, ch) in value.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(value[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    out.push(value[start..].trim());
    out
}

fn parse_alt_svc_authority(authority: &str) -> Option<(Option<String>, u16)> {
    if authority.is_empty() {
        return None;
    }
    let authority = authority.strip_prefix("//").unwrap_or(authority);
    if let Some(port) = authority.strip_prefix(':') {
        return port.parse::<u16>().ok().map(|port| (None, port));
    }
    let (host, port) = authority.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    port.parse::<u16>()
        .ok()
        .map(|port| (Some(host.trim_matches(['[', ']']).to_string()), port))
}
