use super::{CgiRequest, Execution, Executor};
use crate::config::WasmBackendConfig;
use anyhow::Result;
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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
        for _ in 0..min_idle {
            instances.push(Arc::new(qpx_wasm::WasmExecutor::new(
                qpx_wasm::WasmExecutorConfig {
                    module: config.module.clone(),
                    precompile,
                    max_module_bytes: config.max_module_bytes,
                    max_memory_bytes: config.max_memory_mb * 1024 * 1024,
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
            result
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
