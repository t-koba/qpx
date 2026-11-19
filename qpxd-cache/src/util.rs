use super::types::{CacheBackend, MAX_VARIANTS_PER_PRIMARY, VariantIndex};
use super::vary::index_storage_key;
use anyhow::{Result, anyhow};
#[cfg(test)]
use http::header::TRANSFER_ENCODING;
use qpx_core::config::CachePolicyConfig;
#[cfg(test)]
use qpx_core::http_message::Headers as OwnedHeaders;
pub use qpx_http::now_millis;
use std::time::Duration;
use tracing::warn;

/// Timer resolution we can reliably schedule for a heartbeat. A one-third
/// cadence needs at least three such ticks in the TTL, so 30 ms is the
/// smallest accepted writer lease; shorter ones are rejected rather than
/// silently allowed to expire before their first renewal.
pub const MIN_WRITER_LEASE_TTL_MS: u64 = 30;
const LEASE_TIMER_TICK_MS: u64 = 10;

pub(crate) fn writer_lease_renewal_interval(ttl_ms: u64) -> Result<Duration> {
    if ttl_ms < MIN_WRITER_LEASE_TTL_MS {
        return Err(anyhow!(
            "writer_lease_ttl_ms must be at least {} (one third of the TTL must be a schedulable {} ms heartbeat tick); got {}",
            MIN_WRITER_LEASE_TTL_MS,
            LEASE_TIMER_TICK_MS,
            ttl_ms
        ));
    }
    Ok(Duration::from_millis(ttl_ms / 3))
}

#[cfg(test)]
pub fn cacheable_content_length(headers: &OwnedHeaders) -> Option<u64> {
    if headers.contains_key(&ord(TRANSFER_ENCODING.as_str())) {
        return None;
    }
    headers.declared_content_length().ok().flatten()
}

pub fn upsert_variant_with_cap(index: &mut VariantIndex, variant_key: &str) -> Vec<String> {
    // Superseded generations are no longer discoverable. Do not delete their
    // objects here: an already-open remote body producer may still need them.
    // They retain the TTL assigned by their writer.
    index
        .variants
        .retain(|v| super::vary::variant_identity(v) != super::vary::variant_identity(variant_key));
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

#[cfg(test)]
fn ord(name: &str) -> qpx_core::http_message::OrdinaryHeaderName {
    qpx_core::http_message::OrdinaryHeaderName::try_from(name).expect("ordinary header name")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_renewal_interval_has_headroom_for_every_accepted_ttl() {
        assert_eq!(
            writer_lease_renewal_interval(MIN_WRITER_LEASE_TTL_MS).unwrap(),
            Duration::from_millis(10)
        );
        assert_eq!(
            writer_lease_renewal_interval(5_000).unwrap(),
            Duration::from_millis(1_666)
        );
        for ttl in MIN_WRITER_LEASE_TTL_MS..2_000 {
            let interval = writer_lease_renewal_interval(ttl).unwrap();
            assert!(interval >= Duration::from_millis(10));
            assert!(interval * 3 <= Duration::from_millis(ttl));
        }
        let err = writer_lease_renewal_interval(MIN_WRITER_LEASE_TTL_MS - 1)
            .expect_err("sub-resolution lease must be rejected");
        assert!(err.to_string().contains("at least 30"), "{err}");
    }
}
