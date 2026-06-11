use super::{CgiRequest, Execution, Executor};
use crate::config::WasmBackendConfig;
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub struct WasmExecutor {
    instances: Vec<Arc<qpx_wasm::WasmExecutor>>,
    semaphore: Arc<Semaphore>,
    next: AtomicUsize,
}

impl WasmExecutor {
    pub fn new(config: &WasmBackendConfig) -> Result<Self> {
        let pool = config.pool.as_ref();
        let max_instances = pool.map(|pool| pool.max_instances).unwrap_or(1).max(1);
        let min_idle = pool
            .map(|pool| pool.min_idle)
            .unwrap_or(1)
            .clamp(1, max_instances);
        let precompile = config.precompile || pool.map(|pool| pool.prewarm).unwrap_or(false);
        let mut instances = Vec::with_capacity(min_idle);
        let max_memory_bytes = config
            .max_memory_mb
            .checked_mul(1024)
            .and_then(|value| value.checked_mul(1024))
            .ok_or_else(|| anyhow::anyhow!("wasm max_memory_mb is too large"))?;
        for _ in 0..min_idle {
            instances.push(Arc::new(qpx_wasm::WasmExecutor::new(
                qpx_wasm::WasmExecutorConfig {
                    module: config.module.clone(),
                    precompile,
                    max_module_bytes: config.max_module_bytes,
                    max_memory_bytes,
                    timeout_ms: config.timeout_ms,
                    env: config.env.clone(),
                    max_stdin_bytes: config.max_stdin_bytes,
                    max_stdout_bytes: config.max_stdout_bytes,
                    max_stderr_bytes: config.max_stderr_bytes,
                    idle_instances: if precompile { 1 } else { 0 },
                },
            )?));
        }
        Ok(Self {
            instances,
            semaphore: Arc::new(Semaphore::new(max_instances)),
            next: AtomicUsize::new(0),
        })
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit> {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("WASM executor pool closed"))
    }

    fn pick_instance(&self) -> Arc<qpx_wasm::WasmExecutor> {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.instances.len();
        self.instances[idx].clone()
    }

    #[cfg(test)]
    fn prewarmed_instances(&self) -> usize {
        self.instances.len()
    }
}

#[async_trait]
impl Executor for WasmExecutor {
    async fn start(&self, req: CgiRequest) -> Result<Execution> {
        let permit = self.acquire().await?;
        let exec = self
            .pick_instance()
            .start(qpx_wasm::WasmRequest {
                script_name: req.script_name,
                path_info: req.path_info,
                query_string: req.query_string,
                request_method: req.request_method,
                content_type: req.content_type,
                content_length: req.content_length,
                server_protocol: req.server_protocol,
                server_name: req.server_name,
                server_port: req.server_port,
                remote_addr: req.remote_addr,
                remote_port: req.remote_port,
                http_headers: req.http_headers,
            })
            .await?;
        let done = tokio::spawn(async move {
            let result = exec.done.await.map_err(|err| anyhow::anyhow!(err))?;
            drop(permit);
            result.map_err(anyhow::Error::from)
        });
        Ok(Execution {
            stdin: exec.stdin,
            stdout: exec.stdout,
            stderr: exec.stderr,
            abort: exec.abort,
            done,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WasmPoolConfig;
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[tokio::test]
    async fn wasm_pool_prewarms_min_idle_instances() {
        let module = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("config/usecases/12-ipc-gateway/assets/wasm/echo.wat");
        let executor = WasmExecutor::new(&WasmBackendConfig {
            module,
            precompile: false,
            pool: Some(WasmPoolConfig {
                min_idle: 2,
                max_instances: 3,
                prewarm: true,
            }),
            max_module_bytes: 1024 * 1024,
            max_memory_mb: 16,
            timeout_ms: 1000,
            env: HashMap::new(),
            max_stdin_bytes: 1024,
            max_stdout_bytes: 1024,
            max_stderr_bytes: 1024,
        })
        .expect("wasm executor");

        assert_eq!(executor.prewarmed_instances(), 2);
    }

    #[tokio::test]
    async fn wasm_executor_rejects_invalid_module_during_prewarm() {
        let module = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("Cargo.toml");
        let result = WasmExecutor::new(&WasmBackendConfig {
            module,
            precompile: true,
            pool: Some(WasmPoolConfig {
                min_idle: 1,
                max_instances: 1,
                prewarm: true,
            }),
            max_module_bytes: 1024 * 1024,
            max_memory_mb: 16,
            timeout_ms: 1000,
            env: HashMap::new(),
            max_stdin_bytes: 1024,
            max_stdout_bytes: 1024,
            max_stderr_bytes: 1024,
        });
        let err = match result {
            Ok(_) => panic!("invalid module should fail during executor construction"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("WASM")
                || err.to_string().contains("wasm")
                || err.to_string().contains("module"),
            "{err:?}"
        );
    }
}
