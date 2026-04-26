use super::{CgiRequest, Execution, Executor};
use crate::config::WasmBackendConfig;
use anyhow::Result;
use async_trait::async_trait;

pub struct WasmExecutor {
    inner: qpx_wasm::WasmExecutor,
}

impl WasmExecutor {
    pub fn new(config: &WasmBackendConfig) -> Result<Self> {
        Ok(Self {
            inner: qpx_wasm::WasmExecutor::new(qpx_wasm::WasmExecutorConfig {
                module: config.module.clone(),
                precompile: config.precompile,
                max_module_bytes: config.max_module_bytes,
                max_memory_bytes: config.max_memory_mb * 1024 * 1024,
                timeout_ms: config.timeout_ms,
                env: config.env.clone(),
                max_stdin_bytes: config.max_stdin_bytes,
                max_stdout_bytes: config.max_stdout_bytes,
                max_stderr_bytes: config.max_stderr_bytes,
            })?,
        })
    }
}

#[async_trait]
impl Executor for WasmExecutor {
    async fn start(&self, req: CgiRequest) -> Result<Execution> {
        let exec = self
            .inner
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
        Ok(Execution {
            stdin: exec.stdin,
            stdout: exec.stdout,
            stderr: exec.stderr,
            abort: exec.abort,
            done: exec.done,
        })
    }
}
