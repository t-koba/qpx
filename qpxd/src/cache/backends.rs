use super::types::CacheBackend;
use anyhow::{anyhow, Result};
use qpx_core::config::CacheBackendConfig;
use std::collections::HashMap;
use std::sync::Arc;

pub fn build_backends(
    configs: &[CacheBackendConfig],
    generated_user_agent: Option<&str>,
) -> Result<HashMap<String, Arc<dyn CacheBackend>>> {
    let mut out = HashMap::with_capacity(configs.len());
    for cfg in configs {
        let backend: Arc<dyn CacheBackend> = match cfg.kind.as_str() {
            "http" => Arc::new(super::backend_http::HttpCacheBackend::new(
                cfg.clone(),
                generated_user_agent,
            )?),
            "redis" => Arc::new(super::backend_redis::RedisCacheBackend::new(cfg.clone())?),
            other => {
                return Err(anyhow!(
                    "unsupported cache backend kind {} for {}",
                    other,
                    cfg.name
                ));
            }
        };
        out.insert(cfg.name.clone(), backend);
    }
    Ok(out)
}
