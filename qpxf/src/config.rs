use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Top-level qpxf configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QpxfConfig {
    /// Listen address — TCP ("127.0.0.1:9000") or Unix socket ("unix:///var/run/qpxf.sock").
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
    #[serde(default = "default_wasm_max_memory_mb")]
    pub max_memory_mb: u64,
    #[serde(default = "default_wasm_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Maximum WASM stdout capture size (bytes).
    #[serde(default = "default_max_stdout_bytes")]
    pub max_stdout_bytes: usize,
    /// Maximum WASM stderr capture size (bytes).
    #[serde(default = "default_max_stderr_bytes")]
    pub max_stderr_bytes: usize,
}

fn default_listen() -> String {
    "127.0.0.1:9000".to_string()
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

fn default_wasm_timeout_ms() -> u64 {
    10_000
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

impl QpxfConfig {
    pub fn validate(&self) -> Result<()> {
        if self.workers == 0 {
            return Err(anyhow!("workers must be >= 1"));
        }
        if self.max_connections == 0 {
            return Err(anyhow!("max_connections must be >= 1"));
        }
        if self.max_requests_per_connection == 0 {
            return Err(anyhow!("max_requests_per_connection must be >= 1"));
        }
        if self.max_params_bytes == 0 {
            return Err(anyhow!("max_params_bytes must be >= 1"));
        }
        if self.max_stdin_bytes == 0 {
            return Err(anyhow!("max_stdin_bytes must be >= 1"));
        }
        if self.input_idle_timeout_ms == 0 {
            return Err(anyhow!("input_idle_timeout_ms must be >= 1"));
        }
        if self.conn_idle_timeout_ms == 0 {
            return Err(anyhow!("conn_idle_timeout_ms must be >= 1"));
        }

        if self.listen.starts_with("unix://") {
            return Ok(());
        }

        let addr: SocketAddr = self
            .listen
            .parse()
            .map_err(|e| anyhow!("invalid listen address '{}': {}", self.listen, e))?;
        if !addr.ip().is_loopback() && !self.allow_insecure_tcp {
            return Err(anyhow!(
                "refusing to bind qpxf to non-loopback address '{}' without allow_insecure_tcp=true",
                self.listen
            ));
        }
        Ok(())
    }
}

pub fn load_config(path: &Path) -> anyhow::Result<QpxfConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: QpxfConfig = serde_yaml::from_str(&content)?;
    Ok(config)
}
