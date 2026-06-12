use anyhow::Result;
use qpxd_cache::CacheBackend;
use std::collections::HashMap;
use std::sync::Arc;

use super::RuntimeResources;

#[derive(Clone)]
pub struct CacheRuntime {
    pub backends: HashMap<String, Arc<dyn CacheBackend>>,
    /// Per-runtime request-collapse registry (replaces the former process-global).
    pub(crate) request_collapse: Arc<qpxd_cache::InFlightLookups>,
    /// Per-runtime background-revalidation dedupe registry.
    pub(crate) background_revalidations: Arc<qpxd_cache::InFlightRevalidations>,
}

impl CacheRuntime {
    pub(super) fn build(config: &RuntimeResources) -> Result<Self> {
        let backends = qpxd_cache::build_backends(
            &config.operational.caches,
            config.operational.identity.generated_user_agent.as_deref(),
        )?;
        Ok(Self {
            backends,
            request_collapse: Arc::new(qpxd_cache::InFlightLookups::with_default_shards()),
            background_revalidations: Arc::new(
                qpxd_cache::InFlightRevalidations::with_default_shards(),
            ),
        })
    }

    /// Joins the request-collapse group for `key` on this runtime's registry.
    pub(crate) fn begin_request_collapse(
        &self,
        key: &qpxd_cache::CacheRequestKey,
    ) -> qpxd_cache::RequestCollapseJoin {
        self.request_collapse.begin(key)
    }
}
