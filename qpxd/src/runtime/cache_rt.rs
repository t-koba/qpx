use crate::cache::CacheBackend;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

use super::RuntimeResources;

#[derive(Clone)]
pub struct CacheRuntime {
    pub backends: HashMap<String, Arc<dyn CacheBackend>>,
}

impl CacheRuntime {
    pub(super) fn build(config: &RuntimeResources) -> Result<Self> {
        let backends = crate::cache::build_backends(
            &config.operational.caches,
            config.operational.identity.generated_user_agent.as_deref(),
        )?;
        Ok(Self { backends })
    }
}
