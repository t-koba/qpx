use crate::cache::CacheBackend;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

use super::ConfigRuntime;

#[derive(Clone)]
pub struct CacheRuntime {
    pub backends: HashMap<String, Arc<dyn CacheBackend>>,
}

impl CacheRuntime {
    pub(super) fn build(config: &ConfigRuntime) -> Result<Self> {
        let backends = crate::cache::build_backends(
            &config.cache.backends,
            config.identity.generated_user_agent.as_deref(),
        )?;
        Ok(Self { backends })
    }
}
