use super::{CgiRequest, CgiResponse, Execution, Executor};
use crate::config::WasmBackendConfig;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, OnceCell};
use tracing::info;
use wasmtime::*;
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::{I32Exit, WasiCtxBuilder};

pub struct WasmExecutor {
    engine: Engine,
    module_path: PathBuf,
    module: Arc<OnceCell<Module>>,
    linker: Arc<Linker<WasmStoreData>>,
    instance_pre: Arc<OnceCell<InstancePre<WasmStoreData>>>,
    max_memory_bytes: u64,
    timeout_ms: u64,
    env: HashMap<String, String>,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
    /// Background epoch ticker handle; dropped on executor drop.
    _epoch_ticker: tokio::task::JoinHandle<()>,
}

impl WasmExecutor {
    pub fn new(config: &WasmBackendConfig) -> Result<Self> {
        let mut wasm_config = Config::new();
        wasm_config.async_support(true);
        wasm_config.epoch_interruption(true);

        let engine = Engine::new(&wasm_config)?;

        // Start a single global epoch ticker that increments every 10ms.
        // Individual stores set their deadline relative to this ticker.
        let ticker_engine = engine.clone();
        let epoch_ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(10));
            loop {
                interval.tick().await;
                ticker_engine.increment_epoch();
            }
        });

        if !config.module.exists() {
            return Err(anyhow!(
                "WASM module not found: {}",
                config.module.display()
            ));
        }

        let module = Arc::new(OnceCell::new());
        if config.precompile {
            let compiled = Module::from_file(&engine, &config.module)?;
            let _ = module.set(compiled);
            info!(module = %config.module.display(), "WASM module loaded (precompiled)");
        }

        let mut linker = Linker::<WasmStoreData>::new(&engine);
        p1::add_to_linker_async(&mut linker, |ctx| &mut ctx.wasi)?;
        let linker = Arc::new(linker);
        let instance_pre = Arc::new(OnceCell::new());

        Ok(Self {
            engine,
            module_path: config.module.clone(),
            module,
            linker,
            instance_pre,
            max_memory_bytes: config.max_memory_mb * 1024 * 1024,
            timeout_ms: config.timeout_ms,
            env: config.env.clone(),
            max_stdout_bytes: config.max_stdout_bytes,
            max_stderr_bytes: config.max_stderr_bytes,
            _epoch_ticker: epoch_ticker,
        })
    }
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-authentication-info"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn parse_connection_tokens(headers: &HashMap<String, String>) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(value) = headers.get("connection") else {
        return out;
    };
    for token in value.split(',') {
        let token = token.trim();
        if !token.is_empty() {
            out.insert(token.to_ascii_lowercase());
        }
    }
    out
}

/// Store data combining WASI context and resource limiter.
struct WasmStoreData {
    wasi: WasiP1Ctx,
    limiter: MemoryLimiter,
}

/// Simple memory limiter for WASM stores.
struct MemoryLimiter {
    max_memory: usize,
}

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool> {
        Ok(desired <= self.max_memory)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool> {
        // Allow table growth up to 100k entries.
        Ok(desired <= 100_000)
    }
}

#[async_trait]
impl Executor for WasmExecutor {
    async fn start(&self, req: CgiRequest) -> Result<Execution> {
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Bytes>(16);
        let (stdout_tx, stdout_rx) = mpsc::channel::<Bytes>(16);
        let (stderr_tx, stderr_rx) = mpsc::channel::<Bytes>(16);
        let (abort_tx, abort_rx) = oneshot::channel::<()>();

        let engine = self.engine.clone();
        let module_path = self.module_path.clone();
        let module = Arc::clone(&self.module);
        let linker = Arc::clone(&self.linker);
        let instance_pre = Arc::clone(&self.instance_pre);
        let max_memory_bytes = self.max_memory_bytes;
        let timeout_ms = self.timeout_ms;
        let env = self.env.clone();
        let max_stdout_bytes = self.max_stdout_bytes;
        let max_stderr_bytes = self.max_stderr_bytes;

        let done = tokio::spawn(async move {
            let mut abort_rx = abort_rx;

            // Collect stdin (WASI preview1 uses an in-memory stdin pipe).
            let mut stdin_data: Vec<u8> = Vec::new();
            loop {
                tokio::select! {
                    _ = &mut abort_rx => {
                        return Err(anyhow!("WASM request aborted"));
                    }
                    next = stdin_rx.recv() => {
                        match next {
                            Some(chunk) => stdin_data.extend_from_slice(&chunk),
                            None => break,
                        }
                    }
                }
            }

            fn build_wasi_ctx(
                req: &CgiRequest,
                extra_env: &HashMap<String, String>,
            ) -> WasiCtxBuilder {
                let mut builder = WasiCtxBuilder::new();
                builder.env("GATEWAY_INTERFACE", "CGI/1.1");
                builder.env("SERVER_PROTOCOL", &req.server_protocol);
                builder.env("SERVER_SOFTWARE", "qpxf/0.1");
                builder.env("REQUEST_METHOD", &req.request_method);
                builder.env("QUERY_STRING", &req.query_string);
                builder.env("SCRIPT_NAME", &req.script_name);
                builder.env("PATH_INFO", &req.path_info);
                builder.env("SERVER_NAME", &req.server_name);
                builder.env("SERVER_PORT", req.server_port.to_string());
                if let Some(addr) = req.remote_addr.as_ref() {
                    builder.env("REMOTE_ADDR", addr);
                }
                if let Some(port) = req.remote_port {
                    builder.env("REMOTE_PORT", port.to_string());
                }
                if !req.content_type.is_empty() {
                    builder.env("CONTENT_TYPE", &req.content_type);
                }
                if req.content_length > 0 {
                    builder.env("CONTENT_LENGTH", req.content_length.to_string());
                }
                let connection_tokens = parse_connection_tokens(&req.http_headers);
                for (key, value) in &req.http_headers {
                    let lower = key.to_ascii_lowercase();
                    if is_hop_by_hop_header(&lower) || connection_tokens.contains(lower.as_str()) {
                        continue;
                    }
                    let env_key = format!("HTTP_{}", key.to_uppercase().replace('-', "_"));
                    builder.env(&env_key, value);
                }
                for (key, value) in extra_env {
                    builder.env(key, value);
                }
                builder
            }

            // Build WASI ctx and pipes.
            let mut wasi_builder = build_wasi_ctx(&req, &env);
            wasi_builder.stdin(MemoryInputPipe::new(Bytes::from(stdin_data)));

            let stdout_pipe = MemoryOutputPipe::new(max_stdout_bytes);
            let stdout_pipe_clone = stdout_pipe.clone();
            wasi_builder.stdout(stdout_pipe);

            let stderr_pipe = MemoryOutputPipe::new(max_stderr_bytes);
            let stderr_pipe_clone = stderr_pipe.clone();
            wasi_builder.stderr(stderr_pipe);

            let wasi_ctx = wasi_builder.build_p1();

            let module = module
                .get_or_try_init(|| async {
                    let engine = engine.clone();
                    let module_path = module_path.clone();
                    tokio::task::spawn_blocking(move || Module::from_file(&engine, &module_path))
                        .await
                        .map_err(|e| anyhow!("WASM compile join failed: {}", e))?
                        .map_err(|e| anyhow!("WASM compile failed: {}", e))
                })
                .await?;

            let instance_pre = instance_pre
                .get_or_try_init(|| async {
                    // `instantiate_pre` is synchronous; the async wrapper is just for OnceCell.
                    linker
                        .instantiate_pre(module)
                        .map_err(|e| anyhow!("WASM instantiate_pre failed: {}", e))
                })
                .await?;

            let store_data = WasmStoreData {
                wasi: wasi_ctx,
                limiter: MemoryLimiter {
                    max_memory: max_memory_bytes as usize,
                },
            };
            let mut store = Store::new(&engine, store_data);
            store.limiter(|data| &mut data.limiter);
            let ticks = std::cmp::max(1, timeout_ms / 10);
            store.set_epoch_deadline(ticks);

            let instance = instance_pre.instantiate_async(&mut store).await?;
            let func = instance
                .get_typed_func::<(), ()>(&mut store, "_start")
                .map_err(|e| anyhow!("WASM module missing _start: {}", e))?;

            let result = func.call_async(&mut store, ()).await;
            drop(store);

            let stderr_data: Vec<u8> = stderr_pipe_clone
                .try_into_inner()
                .map(|b| b.to_vec())
                .unwrap_or_default();
            for chunk in stderr_data.chunks(8192) {
                if stderr_tx.send(Bytes::copy_from_slice(chunk)).await.is_err() {
                    break;
                }
            }

            let stdout_data: Vec<u8> = stdout_pipe_clone
                .try_into_inner()
                .map(|b| b.to_vec())
                .unwrap_or_default();

            let output = match result {
                Ok(()) => Bytes::from(stdout_data),
                Err(e) => {
                    if let Some(trap) = e.downcast_ref::<Trap>() {
                        if *trap == Trap::Interrupt {
                            CgiResponse {
                                status: 504,
                                headers: vec![("Content-Type".into(), "text/plain".into())],
                                body: Bytes::from_static(b"WASM execution timed out"),
                            }
                            .to_cgi_output()
                        } else {
                            return Err(anyhow!("WASM execution failed: {}", e));
                        }
                    } else if let Some(I32Exit(0)) = e.downcast_ref::<I32Exit>() {
                        Bytes::from(stdout_data)
                    } else if let Some(I32Exit(code)) = e.downcast_ref::<I32Exit>() {
                        CgiResponse {
                            status: 502,
                            headers: vec![("Content-Type".into(), "text/plain".into())],
                            body: Bytes::from(format!("WASM module exited with code {}", code)),
                        }
                        .to_cgi_output()
                    } else {
                        return Err(anyhow!("WASM execution failed: {}", e));
                    }
                }
            };

            for chunk in output.chunks(8192) {
                if stdout_tx.send(Bytes::copy_from_slice(chunk)).await.is_err() {
                    break;
                }
            }
            Ok(())
        });

        Ok(Execution {
            stdin: stdin_tx,
            stdout: stdout_rx,
            stderr: stderr_rx,
            abort: abort_tx,
            done,
        })
    }
}
