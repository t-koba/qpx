use super::types::CacheBackend;
use anyhow::{Result, anyhow};
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
            "disk" => Arc::new(super::backend_disk::DiskCacheBackend::new(cfg.clone())?),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_shared_mode_is_rejected_even_without_config_validation() {
        for (kind, endpoint) in [
            ("http", "http://localhost:1"),
            ("redis", "redis://localhost:1"),
        ] {
            let cfg: CacheBackendConfig = serde_json::from_value(serde_json::json!({
                "name": "test", "kind": kind, "endpoint": endpoint, "writer_mode": "shared"
            }))
            .unwrap();
            let error = if kind == "http" {
                super::super::backend_http::HttpCacheBackend::new(cfg, None)
                    .err()
                    .unwrap()
            } else {
                super::super::backend_redis::RedisCacheBackend::new(cfg)
                    .err()
                    .unwrap()
            };
            assert!(error.to_string().contains("shared"));
        }
    }
}
