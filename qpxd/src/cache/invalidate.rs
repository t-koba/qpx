use super::key::normalize_url_authority;
use super::types::{CacheBackend, CacheRequestKey};
use super::util::{cache_namespace, load_variant_index};
use super::vary::index_storage_key;
use anyhow::Result;
use http::header::{CONTENT_LOCATION, LOCATION};
use hyper::{Method, StatusCode};
use qpx_core::config::CachePolicyConfig;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use url::Url;

pub async fn maybe_invalidate(
    request_method: &Method,
    response_status: StatusCode,
    response_headers: &http::HeaderMap,
    target_key: Option<&CacheRequestKey>,
    policy: &CachePolicyConfig,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<()> {
    if !policy.enabled
        || !is_unsafe_method(request_method)
        || !is_invalidation_status(response_status)
    {
        return Ok(());
    }
    let Some(key) = target_key else {
        return Ok(());
    };
    let Some(backend) = backends.get(policy.backend.as_str()) else {
        return Ok(());
    };

    let namespace = cache_namespace(policy, "default");
    let mut keys = vec![key.clone()];
    keys.extend(collect_invalidation_targets(key, response_headers));
    let mut seen = HashSet::new();
    for k in keys {
        let primary = k.primary_hash();
        if !seen.insert(primary.clone()) {
            continue;
        }
        invalidate_primary(backend.as_ref(), namespace.as_str(), primary.as_str()).await?;
    }
    Ok(())
}

pub(super) async fn invalidate_primary(
    backend: &dyn CacheBackend,
    namespace: &str,
    primary: &str,
) -> Result<()> {
    let index = load_variant_index(backend, namespace, primary).await?;
    for variant in index.variants {
        let _ = backend.delete(namespace, variant.as_str()).await;
    }
    let _ = backend
        .delete(namespace, index_storage_key(primary).as_str())
        .await;
    Ok(())
}

fn is_unsafe_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    )
}

fn is_invalidation_status(status: StatusCode) -> bool {
    status.is_success() || status.is_redirection()
}

fn collect_invalidation_targets(
    request_target: &CacheRequestKey,
    response_headers: &http::HeaderMap,
) -> Vec<CacheRequestKey> {
    let Some(request_url) = request_target.absolute_url() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for header in [LOCATION, CONTENT_LOCATION] {
        for value in response_headers.get_all(header).iter() {
            let Ok(value) = value.to_str() else {
                continue;
            };
            let Ok(url) = request_url.join(value.trim()) else {
                continue;
            };
            if !same_authority(&request_url, &url) {
                continue;
            }
            let key = CacheRequestKey {
                scheme: url.scheme().to_ascii_lowercase(),
                authority: normalize_url_authority(&url).unwrap_or_default(),
                path_and_query: match url.query() {
                    Some(query) => format!("{}?{}", url.path(), query),
                    None => url.path().to_string(),
                },
            };
            if !key.authority.is_empty() {
                out.push(key);
            }
        }
    }
    out
}

fn same_authority(a: &Url, b: &Url) -> bool {
    a.scheme().eq_ignore_ascii_case(b.scheme())
        && a.host_str()
            .zip(b.host_str())
            .map(|(ah, bh)| ah.eq_ignore_ascii_case(bh))
            .unwrap_or(false)
        && a.port_or_known_default() == b.port_or_known_default()
}
