use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

mod load;
mod validate;

#[cfg(test)]
mod tests;

pub use load::load_config;

/// Top-level qpxf configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QpxfConfig {
    /// Listen address — prefer Unix sockets ("unix:///var/run/qpxf.sock").
    /// TCP listeners are opt-in with `allow_insecure_tcp=true`.
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Maximum concurrent request executions (CGI/WASM combined).
    #[serde(default = "default_workers")]
    pub workers: usize,

    /// Maximum concurrent client connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Maximum number of requests per connection (keep-alive cap).
    #[serde(default = "default_max_requests_per_connection")]
    pub max_requests_per_connection: usize,

    /// Allow binding to non-loopback TCP addresses without auth/TLS.
    ///
    /// qpxf provides an execution surface; exposing it to an untrusted network is unsafe.
    #[serde(default)]
    pub allow_insecure_tcp: bool,

    /// Maximum PARAMS buffer size per request (bytes). Protects against DoS.
    #[serde(default = "default_max_params_bytes")]
    pub max_params_bytes: usize,

    /// Maximum STDIN body size per request (bytes). Protects against DoS.
    #[serde(default = "default_max_stdin_bytes")]
    pub max_stdin_bytes: usize,

    /// Maximum time to wait between request records while reading PARAMS/STDIN (ms).
    #[serde(default = "default_input_idle_timeout_ms")]
    pub input_idle_timeout_ms: u64,

    /// Idle timeout for keep-alive connections with no in-flight requests (ms).
    #[serde(default = "default_conn_idle_timeout_ms")]
    pub conn_idle_timeout_ms: u64,

    /// Handler routing rules.
    #[serde(default)]
    pub handlers: Vec<HandlerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandlerConfig {
    pub r#match: MatchConfig,
    pub backend: BackendConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchConfig {
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub path_regex: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum BackendConfig {
    #[serde(rename = "cgi")]
    Cgi(CgiBackendConfig),
    #[serde(rename = "wasm")]
    Wasm(WasmBackendConfig),
    #[serde(rename = "fastcgi")]
    FastCgi(FastCgiBackendConfig),
    #[serde(rename = "scgi")]
    Scgi(ScgiBackendConfig),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CgiBackendConfig {
    pub root: PathBuf,
    #[serde(default = "default_cgi_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    /// Maximum CGI stdout size (bytes).
    #[serde(default = "default_max_stdout_bytes")]
    pub max_stdout_bytes: usize,
    /// Maximum CGI stderr size (bytes).
    #[serde(default = "default_max_stderr_bytes")]
    pub max_stderr_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmBackendConfig {
    pub module: PathBuf,
    #[serde(default)]
    pub precompile: bool,
    #[serde(default)]
    pub pool: Option<WasmPoolConfig>,
    /// Maximum WASM module file size accepted by the executor (bytes).
    #[serde(default = "default_wasm_max_module_bytes")]
    pub max_module_bytes: u64,
    #[serde(default = "default_wasm_max_memory_mb")]
    pub max_memory_mb: u64,
    #[serde(default = "default_wasm_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Maximum WASM stdin size accepted by the executor (bytes).
    #[serde(default = "default_max_stdin_bytes")]
    pub max_stdin_bytes: usize,
    /// Maximum WASM stdout capture size (bytes).
    #[serde(default = "default_max_stdout_bytes")]
    pub max_stdout_bytes: usize,
    /// Maximum WASM stderr capture size (bytes).
    #[serde(default = "default_max_stderr_bytes")]
    pub max_stderr_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmPoolConfig {
    #[serde(default)]
    pub min_idle: usize,
    #[serde(default = "default_wasm_pool_max_instances")]
    pub max_instances: usize,
    #[serde(default)]
    pub prewarm: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FastCgiBackendConfig {
    pub address: String,
    #[serde(default = "default_persistent_backend_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub script_name_prefixes: Vec<String>,
    #[serde(default)]
    pub pool: FastCgiPoolConfig,
    #[serde(default = "default_max_stdin_bytes")]
    pub max_stdin_bytes: usize,
    #[serde(default = "default_max_stdout_bytes")]
    pub max_stdout_bytes: usize,
    #[serde(default = "default_max_stderr_bytes")]
    pub max_stderr_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FastCgiPoolConfig {
    #[serde(default = "default_persistent_backend_max_concurrency")]
    pub max_concurrency: usize,
    #[serde(default = "default_fastcgi_pool_max_idle")]
    pub max_idle: usize,
}

impl Default for FastCgiPoolConfig {
    fn default() -> Self {
        Self {
            max_concurrency: default_persistent_backend_max_concurrency(),
            max_idle: default_fastcgi_pool_max_idle(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScgiBackendConfig {
    pub address: String,
    #[serde(default = "default_persistent_backend_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub script_name_prefixes: Vec<String>,
    #[serde(default = "default_persistent_backend_max_concurrency")]
    pub max_concurrency: usize,
    #[serde(default = "default_max_stdin_bytes")]
    pub max_stdin_bytes: usize,
    #[serde(default = "default_max_stdout_bytes")]
    pub max_stdout_bytes: usize,
    #[serde(default = "default_max_stderr_bytes")]
    pub max_stderr_bytes: usize,
}

fn default_listen() -> String {
    #[cfg(unix)]
    {
        let path = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .or_else(|| dirs_next::home_dir().map(|home| home.join(".qpxf").join("run")))
            .unwrap_or_else(|| {
                let user = std::env::var("USER").unwrap_or_else(|_| "local-user".to_string());
                std::env::temp_dir().join(format!("qpxf-{user}"))
            })
            .join("qpxf.sock");
        format!("unix://{}", path.display())
    }
    #[cfg(not(unix))]
    {
        "127.0.0.1:9000".to_string()
    }
}

fn default_workers() -> usize {
    4
}

fn default_max_connections() -> usize {
    64
}

fn default_max_requests_per_connection() -> usize {
    64
}

fn default_cgi_timeout_ms() -> u64 {
    30_000
}

fn default_wasm_max_memory_mb() -> u64 {
    128
}

fn default_wasm_max_module_bytes() -> u64 {
    134_217_728 // 128 MiB
}

fn default_wasm_timeout_ms() -> u64 {
    10_000
}

fn default_wasm_pool_max_instances() -> usize {
    1
}

fn default_persistent_backend_timeout_ms() -> u64 {
    30_000
}

fn default_persistent_backend_max_concurrency() -> usize {
    128
}

fn default_fastcgi_pool_max_idle() -> usize {
    16
}

fn default_max_params_bytes() -> usize {
    1_048_576 // 1 MiB
}

fn default_max_stdin_bytes() -> usize {
    33_554_432 // 32 MiB
}

fn default_input_idle_timeout_ms() -> u64 {
    30_000
}

fn default_conn_idle_timeout_ms() -> u64 {
    60_000
}

fn default_max_stdout_bytes() -> usize {
    33_554_432 // 32 MiB
}

fn default_max_stderr_bytes() -> usize {
    1_048_576 // 1 MiB
}
