use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex, OnceCell};
use tracing::info;
use wasmtime::*;
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::{I32Exit, WasiCtxBuilder};

const DEFAULT_MAX_MODULE_BYTES: u64 = 134_217_728; // 128 MiB

#[derive(Debug, Clone)]
pub struct WasmExecutorConfig {
    pub module: PathBuf,
    pub precompile: bool,
    pub max_module_bytes: u64,
    pub max_memory_bytes: u64,
    pub timeout_ms: u64,
    pub env: HashMap<String, String>,
    pub max_stdin_bytes: usize,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub idle_instances: usize,
}

struct PreparedInstance {
    store: Store<WasmStoreData>,
    instance: Instance,
}

#[derive(Debug, Clone)]
pub struct WasmRequest {
    pub script_name: String,
    pub path_info: String,
    pub query_string: String,
    pub request_method: String,
    pub content_type: String,
    pub content_length: usize,
    pub server_protocol: String,
    pub server_name: String,
    pub server_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub http_headers: HashMap<String, String>,
}

pub struct WasmExecution {
    pub stdin: mpsc::Sender<Bytes>,
    pub stdout: mpsc::Receiver<Bytes>,
    pub stderr: mpsc::Receiver<Bytes>,
    pub abort: oneshot::Sender<()>,
    pub done: tokio::task::JoinHandle<Result<()>>,
}

#[derive(Debug, Clone)]
pub struct WasmResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl WasmResponse {
    pub fn to_cgi_output(&self) -> Bytes {
        let header_size: usize = self
            .headers
            .iter()
            .map(|(k, v)| k.len() + v.len() + 4)
            .sum::<usize>()
            + 20;
        let mut out = String::with_capacity(header_size);
        use std::fmt::Write as _;
        let _ = write!(out, "Status: {}\r\n", self.status);
        for (k, v) in &self.headers {
            let _ = write!(out, "{}: {}\r\n", k, v);
        }
        out.push_str("\r\n");
        let mut bytes = Vec::with_capacity(out.len() + self.body.len());
        bytes.extend_from_slice(out.as_bytes());
        bytes.extend_from_slice(&self.body);
        Bytes::from(bytes)
    }
}

pub struct WasmExecutor {
    engine: Engine,
    module_path: PathBuf,
    module: Arc<OnceCell<Module>>,
    linker: Arc<Linker<WasmStoreData>>,
    instance_pre: Arc<OnceCell<InstancePre<WasmStoreData>>>,
    idle_instances: Arc<Mutex<Vec<PreparedInstance>>>,
    max_idle_instances: usize,
    max_module_bytes: u64,
    max_memory_bytes: u64,
    timeout_ms: u64,
    env: HashMap<String, String>,
    max_stdin_bytes: usize,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
    _epoch_ticker: tokio::task::JoinHandle<()>,
}

impl WasmExecutor {
    pub fn new(config: WasmExecutorConfig) -> Result<Self> {
        let mut wasm_config = Config::new();
        wasm_config.epoch_interruption(true);

        let engine =
            Engine::new(&wasm_config).map_err(|e| anyhow!("WASM engine init failed: {e}"))?;
        if !config.module.exists() {
            return Err(anyhow!(
                "WASM module not found: {}",
                config.module.display()
            ));
        }
        let max_module_bytes = if config.max_module_bytes == 0 {
            DEFAULT_MAX_MODULE_BYTES
        } else {
            config.max_module_bytes
        };
        enforce_module_size(&config.module, max_module_bytes)?;

        let mut linker = Linker::<WasmStoreData>::new(&engine);
        p1::add_to_linker_async(&mut linker, |ctx| &mut ctx.wasi)
            .map_err(|e| anyhow!("WASM linker init failed: {e}"))?;

        let module = Arc::new(OnceCell::new());
        let instance_pre = Arc::new(OnceCell::new());
        if config.precompile {
            let compiled = Module::from_file(&engine, &config.module)
                .map_err(|e| anyhow!("WASM precompile failed: {}", e))?;
            let pre = linker
                .instantiate_pre(&compiled)
                .map_err(|e| anyhow!("WASM instantiate_pre failed: {e}"))?;
            let _ = module.set(compiled);
            let _ = instance_pre.set(pre);
            info!(module = %config.module.display(), "WASM module loaded (precompiled)");
        }

        let ticker_engine = engine.clone();
        let epoch_ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(10));
            loop {
                interval.tick().await;
                ticker_engine.increment_epoch();
            }
        });

        let idle_instances = Arc::new(Mutex::new(Vec::with_capacity(config.idle_instances)));
        if config.precompile && config.idle_instances > 0 {
            schedule_idle_replenish(
                Arc::clone(&idle_instances),
                config.idle_instances,
                engine.clone(),
                Arc::clone(&instance_pre),
                config.max_memory_bytes,
                config.timeout_ms,
            );
        }

        Ok(Self {
            engine,
            module_path: config.module,
            module,
            linker: Arc::new(linker),
            instance_pre,
            idle_instances,
            max_idle_instances: config.idle_instances,
            max_module_bytes,
            max_memory_bytes: config.max_memory_bytes,
            timeout_ms: config.timeout_ms,
            env: config.env,
            max_stdin_bytes: config.max_stdin_bytes,
            max_stdout_bytes: config.max_stdout_bytes,
            max_stderr_bytes: config.max_stderr_bytes,
            _epoch_ticker: epoch_ticker,
        })
    }

    pub async fn start(&self, req: WasmRequest) -> Result<WasmExecution> {
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Bytes>(16);
        let (stdout_tx, stdout_rx) = mpsc::channel::<Bytes>(16);
        let (stderr_tx, stderr_rx) = mpsc::channel::<Bytes>(16);
        let (abort_tx, abort_rx) = oneshot::channel::<()>();

        let engine = self.engine.clone();
        let module_path = self.module_path.clone();
        let module = Arc::clone(&self.module);
        let linker = Arc::clone(&self.linker);
        let instance_pre = Arc::clone(&self.instance_pre);
        let idle_instances = Arc::clone(&self.idle_instances);
        let max_idle_instances = self.max_idle_instances;
        let max_module_bytes = self.max_module_bytes;
        let max_memory_bytes = self.max_memory_bytes;
        let timeout_ms = self.timeout_ms;
        let env = self.env.clone();
        let max_stdin_bytes = self.max_stdin_bytes;
        let max_stdout_bytes = self.max_stdout_bytes;
        let max_stderr_bytes = self.max_stderr_bytes;

        let done = tokio::spawn(async move {
            let mut abort_rx = abort_rx;
            let timeout = tokio::time::Duration::from_millis(timeout_ms.max(1));
            let operation = async move {
                let mut stdin_data = Vec::new();
                while let Some(chunk) = stdin_rx.recv().await {
                    let next_len = stdin_data
                        .len()
                        .checked_add(chunk.len())
                        .ok_or_else(|| anyhow!("WASM stdin too large"))?;
                    if next_len > max_stdin_bytes {
                        return Err(anyhow!(
                            "WASM stdin exceeded max_stdin_bytes={}",
                            max_stdin_bytes
                        ));
                    }
                    stdin_data.extend_from_slice(&chunk);
                }

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
                        enforce_module_size(&module_path, max_module_bytes)?;
                        let engine = engine.clone();
                        let module_path = module_path.clone();
                        tokio::task::spawn_blocking(move || {
                            Module::from_file(&engine, &module_path)
                        })
                        .await
                        .map_err(|e| anyhow!("WASM compile join failed: {}", e))?
                        .map_err(|e| anyhow!("WASM compile failed: {}", e))
                    })
                    .await?;

                let instance_template = instance_pre
                    .get_or_try_init(|| async {
                        linker
                            .instantiate_pre(module)
                            .map_err(|e| anyhow!("WASM instantiate_pre failed: {}", e))
                    })
                    .await?;

                let mut prepared = idle_instances.lock().await.pop();
                let (mut store, instance) = match prepared.take() {
                    Some(mut prepared) => {
                        prepared.store.data_mut().wasi = wasi_ctx;
                        prepared.store.data_mut().limiter.max_memory = max_memory_bytes as usize;
                        prepared
                            .store
                            .set_epoch_deadline(std::cmp::max(1, timeout_ms / 10));
                        (prepared.store, prepared.instance)
                    }
                    None => {
                        let store_data = WasmStoreData {
                            wasi: wasi_ctx,
                            limiter: MemoryLimiter {
                                max_memory: max_memory_bytes as usize,
                            },
                        };
                        let mut store = Store::new(&engine, store_data);
                        store.limiter(|data| &mut data.limiter);
                        store.set_epoch_deadline(std::cmp::max(1, timeout_ms / 10));

                        let instance = instance_template
                            .instantiate_async(&mut store)
                            .await
                            .map_err(|e| anyhow!("WASM instantiate failed: {e}"))?;
                        (store, instance)
                    }
                };
                schedule_idle_replenish(
                    Arc::clone(&idle_instances),
                    max_idle_instances,
                    engine.clone(),
                    Arc::clone(&instance_pre),
                    max_memory_bytes,
                    timeout_ms,
                );
                let func = instance
                    .get_typed_func::<(), ()>(&mut store, "_start")
                    .map_err(|e| anyhow!("WASM module missing _start: {}", e))?;

                let result = func.call_async(&mut store, ()).await;
                drop(store);

                let stderr_data = stderr_pipe_clone
                    .try_into_inner()
                    .map(|b| b.to_vec())
                    .unwrap_or_default();
                for chunk in stderr_data.chunks(8192) {
                    if stderr_tx.send(Bytes::copy_from_slice(chunk)).await.is_err() {
                        break;
                    }
                }

                let stdout_data = stdout_pipe_clone
                    .try_into_inner()
                    .map(|b| b.to_vec())
                    .unwrap_or_default();
                let output = match result {
                    Ok(()) => Bytes::from(stdout_data),
                    Err(e) => build_error_output(e, stdout_data)?,
                };

                for chunk in output.chunks(8192) {
                    if stdout_tx.send(Bytes::copy_from_slice(chunk)).await.is_err() {
                        break;
                    }
                }
                Ok(())
            };

            tokio::select! {
                _ = &mut abort_rx => Err(anyhow!("WASM request aborted")),
                result = tokio::time::timeout(timeout, operation) => match result {
                    Ok(result) => result,
                    Err(_) => Err(anyhow!("WASM execution timed out after {}ms", timeout_ms.max(1))),
                },
            }
        });

        Ok(WasmExecution {
            stdin: stdin_tx,
            stdout: stdout_rx,
            stderr: stderr_rx,
            abort: abort_tx,
            done,
        })
    }
}

fn schedule_idle_replenish(
    idle_instances: Arc<Mutex<Vec<PreparedInstance>>>,
    max_idle_instances: usize,
    engine: Engine,
    instance_pre: Arc<OnceCell<InstancePre<WasmStoreData>>>,
    max_memory_bytes: u64,
    timeout_ms: u64,
) {
    if max_idle_instances == 0 || instance_pre.get().is_none() {
        return;
    }
    tokio::spawn(async move {
        loop {
            {
                let idle = idle_instances.lock().await;
                if idle.len() >= max_idle_instances {
                    break;
                }
            }
            match prepare_idle_instance(
                &engine,
                &instance_pre,
                max_memory_bytes as usize,
                timeout_ms,
            )
            .await
            {
                Ok(instance) => idle_instances.lock().await.push(instance),
                Err(err) => {
                    tracing::warn!(error = ?err, "WASM idle instance prewarm failed");
                    break;
                }
            }
        }
    });
}

async fn prepare_idle_instance(
    engine: &Engine,
    instance_pre: &OnceCell<InstancePre<WasmStoreData>>,
    max_memory_bytes: usize,
    timeout_ms: u64,
) -> Result<PreparedInstance> {
    let instance_pre = instance_pre
        .get()
        .ok_or_else(|| anyhow!("WASM instance template missing"))?;
    let store_data = WasmStoreData {
        wasi: WasiCtxBuilder::new().build_p1(),
        limiter: MemoryLimiter {
            max_memory: max_memory_bytes,
        },
    };
    let mut store = Store::new(engine, store_data);
    store.limiter(|data| &mut data.limiter);
    store.set_epoch_deadline(std::cmp::max(1, timeout_ms / 10));
    let instance = instance_pre
        .instantiate_async(&mut store)
        .await
        .map_err(|e| anyhow!("WASM idle instantiate failed: {e}"))?;
    Ok(PreparedInstance { store, instance })
}

fn enforce_module_size(module: &PathBuf, max_module_bytes: u64) -> Result<()> {
    let size = std::fs::metadata(module)
        .map_err(|e| anyhow!("WASM module metadata failed: {}", e))?
        .len();
    if size > max_module_bytes {
        return Err(anyhow!(
            "WASM module {} exceeds max_module_bytes={}",
            module.display(),
            max_module_bytes
        ));
    }
    Ok(())
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

struct WasmStoreData {
    wasi: WasiP1Ctx,
    limiter: MemoryLimiter,
}

struct MemoryLimiter {
    max_memory: usize,
}

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmtime::Error> {
        Ok(desired <= self.max_memory)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmtime::Error> {
        Ok(desired <= 100_000)
    }
}

fn build_wasi_ctx(req: &WasmRequest, extra_env: &HashMap<String, String>) -> WasiCtxBuilder {
    let mut builder = WasiCtxBuilder::new();
    builder.env("GATEWAY_INTERFACE", "CGI/1.1");
    builder.env("SERVER_PROTOCOL", &req.server_protocol);
    builder.env(
        "SERVER_SOFTWARE",
        concat!("qpxf/", env!("CARGO_PKG_VERSION")),
    );
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

fn build_error_output(err: wasmtime::Error, stdout_data: Vec<u8>) -> Result<Bytes> {
    if let Some(trap) = err.downcast_ref::<Trap>() {
        if *trap == Trap::Interrupt {
            return Ok(WasmResponse {
                status: 504,
                headers: vec![("Content-Type".into(), "text/plain".into())],
                body: Bytes::from_static(b"WASM execution timed out"),
            }
            .to_cgi_output());
        }
        return Err(anyhow!("WASM execution failed: {}", err));
    }
    if let Some(I32Exit(0)) = err.downcast_ref::<I32Exit>() {
        return Ok(Bytes::from(stdout_data));
    }
    if let Some(I32Exit(code)) = err.downcast_ref::<I32Exit>() {
        return Ok(WasmResponse {
            status: 502,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: Bytes::from(format!("WASM module exited with code {}", code)),
        }
        .to_cgi_output());
    }
    Err(anyhow!("WASM execution failed: {}", err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_file(name: &str, bytes: &[u8]) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("qpx-wasm-test-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("write temp wasm");
        path
    }

    fn test_config(module: PathBuf, precompile: bool) -> WasmExecutorConfig {
        WasmExecutorConfig {
            module,
            precompile,
            max_module_bytes: DEFAULT_MAX_MODULE_BYTES,
            max_memory_bytes: 16 * 1024 * 1024,
            timeout_ms: 1_000,
            env: HashMap::new(),
            max_stdin_bytes: 1024,
            max_stdout_bytes: 1024,
            max_stderr_bytes: 1024,
            idle_instances: if precompile { 1 } else { 0 },
        }
    }

    async fn wait_for_idle(executor: &WasmExecutor, expected: usize) {
        for _ in 0..50 {
            if executor.idle_instances.lock().await.len() >= expected {
                return;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        panic!("idle WASM instance pool did not reach {expected}");
    }

    #[tokio::test]
    async fn precompile_true_rejects_invalid_module_at_startup() {
        let module = temp_file("invalid.wasm", b"not a wasm module");
        let err = match WasmExecutor::new(test_config(module, true)) {
            Ok(_) => panic!("invalid wasm unexpectedly loaded"),
            Err(err) => err,
        };
        assert!(
            err.chain()
                .any(|cause| cause.to_string().contains("WASM precompile failed")),
            "unexpected error chain: {err:?}"
        );
    }

    #[tokio::test]
    async fn precompile_false_defers_invalid_module_until_request() {
        let module = temp_file("deferred-invalid.wasm", b"not a wasm module");
        let executor =
            WasmExecutor::new(test_config(module, false)).expect("lazy invalid wasm config loads");
        let execution = executor
            .start(WasmRequest {
                script_name: "/test".into(),
                path_info: String::new(),
                query_string: String::new(),
                request_method: "GET".into(),
                content_type: String::new(),
                content_length: 0,
                server_protocol: "HTTP/1.1".into(),
                server_name: "localhost".into(),
                server_port: 80,
                remote_addr: None,
                remote_port: None,
                http_headers: HashMap::new(),
            })
            .await
            .expect("start execution");
        drop(execution.stdin);
        let err = execution
            .done
            .await
            .expect("join lazy invalid wasm")
            .expect_err("lazy compile fails on request");
        assert!(
            err.chain()
                .any(|cause| cause.to_string().contains("WASM compile failed")),
            "unexpected error chain: {err:?}"
        );
    }

    #[tokio::test]
    async fn precompile_true_prewarms_and_replenishes_idle_instance() {
        let module = temp_file("empty.wat", br#"(module (func (export "_start")))"#);
        let mut config = test_config(module, true);
        config.idle_instances = 1;
        let executor = WasmExecutor::new(config).expect("precompiled wasm config loads");
        wait_for_idle(&executor, 1).await;

        let execution = executor
            .start(WasmRequest {
                script_name: "/test".into(),
                path_info: String::new(),
                query_string: String::new(),
                request_method: "GET".into(),
                content_type: String::new(),
                content_length: 0,
                server_protocol: "HTTP/1.1".into(),
                server_name: "localhost".into(),
                server_port: 80,
                remote_addr: None,
                remote_port: None,
                http_headers: HashMap::new(),
            })
            .await
            .expect("start execution");
        drop(execution.stdin);
        execution
            .done
            .await
            .expect("join empty wasm")
            .expect("empty wasm succeeds");

        wait_for_idle(&executor, 1).await;
    }
}
