use super::types::{CacheBackend, ResponseDirectives, VariantIndex, MAX_VARIANTS_PER_PRIMARY};
use super::vary::index_storage_key;
use anyhow::Result;
use http::header::{CONTENT_LENGTH, ETAG, LAST_MODIFIED, TRANSFER_ENCODING};
use qpx_core::config::CachePolicyConfig;
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(super) fn has_validators(headers: &[(String, String)]) -> bool {
    header_value(headers, ETAG.as_str()).is_some()
        || header_value(headers, LAST_MODIFIED.as_str()).is_some()
}

pub(super) fn header_value(headers: &[(String, String)], key: &str) -> Option<String> {
    headers
        .iter()
        .rev()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.clone())
}

pub(super) fn sanitize_cached_headers_for_storage(
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

pub(super) fn cacheable_content_length(headers: &http::HeaderMap) -> Option<u64> {
    if headers.contains_key(TRANSFER_ENCODING) {
        return None;
    }
    let mut parsed: Option<u64> = None;
    for value in headers.get_all(CONTENT_LENGTH).iter() {
        let raw = value.to_str().ok()?;
        for part in raw.split(',') {
            let current = part.trim().parse::<u64>().ok()?;
            if let Some(prev) = parsed {
                if prev != current {
                    return None;
                }
            } else {
                parsed = Some(current);
            }
        }
    }
    parsed
}

pub(super) fn upsert_variant_with_cap(index: &mut VariantIndex, variant_key: &str) -> Vec<String> {
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

pub(super) async fn load_variant_index(
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
    let parsed = serde_json::from_slice::<VariantIndex>(&raw).unwrap_or_default();
    Ok(parsed)
}

pub(super) fn cache_namespace(policy: &CachePolicyConfig, fallback: &str) -> String {
    policy
        .namespace
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

pub(super) fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}
