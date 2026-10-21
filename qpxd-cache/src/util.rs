use super::types::{CacheBackend, MAX_VARIANTS_PER_PRIMARY, ResponseDirectives, VariantIndex};
use super::vary::index_storage_key;
use anyhow::Result;
#[cfg(test)]
use http::header::TRANSFER_ENCODING;
use qpx_core::config::CachePolicyConfig;
pub use qpx_http::now_millis;
use std::collections::HashSet;
use tracing::warn;

pub fn sanitize_cached_headers_for_storage(
    headers: &http::HeaderMap,
    directives: &ResponseDirectives,
) -> Vec<(String, String)> {
    let mut stripped = HashSet::new();
    stripped.extend(directives.no_cache_fields.iter().cloned());
    stripped.extend(directives.private_fields.iter().cloned());

    headers
        .iter()
        .filter_map(|(name, value)| {
            if stripped.contains(name.as_str()) {
                return None;
            }
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect()
}

#[cfg(test)]
pub fn cacheable_content_length(headers: &http::HeaderMap) -> Option<u64> {
    if headers.contains_key(TRANSFER_ENCODING) {
        return None;
    }
    qpx_core::http_content_length::declared_content_length(headers)
        .ok()
        .flatten()
}

pub fn upsert_variant_with_cap(index: &mut VariantIndex, variant_key: &str) -> Vec<String> {
    if let Some(pos) = index.variants.iter().position(|v| v == variant_key) {
        index.variants.remove(pos);
    }
    index.variants.push(variant_key.to_string());
    let mut evicted = Vec::new();
    while index.variants.len() > MAX_VARIANTS_PER_PRIMARY {
        if index.variants.is_empty() {
            break;
        }
        evicted.push(index.variants.remove(0));
    }
    evicted
}

pub async fn load_variant_index(
    backend: &dyn CacheBackend,
    namespace: &str,
    primary: &str,
) -> Result<VariantIndex> {
    let raw = backend
        .get(namespace, index_storage_key(primary).as_str())
        .await?;
    let Some(raw) = raw else {
        return Ok(VariantIndex::default());
    };
    let parsed = match serde_json::from_slice::<VariantIndex>(&raw) {
        Ok(parsed) => parsed,
        Err(err) => {
            warn!(
                error = ?err,
                namespace = %namespace,
                primary = %primary,
                "cache variant index parse failed"
            );
            return Err(err.into());
        }
    };
    Ok(parsed)
}

pub fn cache_namespace<'a>(policy: &'a CachePolicyConfig, fallback: &'a str) -> &'a str {
    policy
        .namespace
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(fallback)
}
