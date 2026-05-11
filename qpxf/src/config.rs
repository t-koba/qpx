use anyhow::{Result, anyhow};
use qpx_core::envsubst::expand_env;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

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
        for (idx, handler) in self.handlers.iter().enumerate() {
            match &handler.backend {
                BackendConfig::FastCgi(config) => {
                    validate_persistent_backend(PersistentBackendValidation {
                        kind: "fastcgi",
                        handler_idx: idx,
                        address: config.address.as_str(),
                        timeout_ms: config.timeout_ms,
                        max_concurrency: config.pool.max_concurrency,
                        max_stdin_bytes: config.max_stdin_bytes,
                        max_stdout_bytes: config.max_stdout_bytes,
                        max_stderr_bytes: config.max_stderr_bytes,
                    })?;
                    if config.pool.max_idle == 0 {
                        return Err(anyhow!(
                            "handlers[{idx}] fastcgi pool.max_idle must be >= 1"
                        ));
                    }
                }
                BackendConfig::Scgi(config) => {
                    validate_persistent_backend(PersistentBackendValidation {
                        kind: "scgi",
                        handler_idx: idx,
                        address: config.address.as_str(),
                        timeout_ms: config.timeout_ms,
                        max_concurrency: config.max_concurrency,
                        max_stdin_bytes: config.max_stdin_bytes,
                        max_stdout_bytes: config.max_stdout_bytes,
                        max_stderr_bytes: config.max_stderr_bytes,
                    })?;
                }
                BackendConfig::Wasm(config) => {
                    if let Some(pool) = config.pool.as_ref() {
                        if pool.max_instances == 0 {
                            return Err(anyhow!(
                                "handlers[{idx}] wasm pool.max_instances must be >= 1"
                            ));
                        }
                        if pool.min_idle > pool.max_instances {
                            return Err(anyhow!(
                                "handlers[{idx}] wasm pool.min_idle must be <= pool.max_instances"
                            ));
                        }
                    }
                    if config.max_stdin_bytes == 0
                        || config.max_stdout_bytes == 0
                        || config.max_stderr_bytes == 0
                    {
                        return Err(anyhow!("handlers[{idx}] wasm byte limits must be >= 1"));
                    }
                }
                BackendConfig::Cgi(_) => {}
            }
        }

        if self.listen.starts_with("unix://") {
            return Ok(());
        }

        let _addr: SocketAddr = self
            .listen
            .parse()
            .map_err(|e| anyhow!("invalid listen address '{}': {}", self.listen, e))?;
        if !self.allow_insecure_tcp {
            return Err(anyhow!(
                "refusing to bind qpxf to TCP address '{}' without allow_insecure_tcp=true; use a unix:// socket instead",
                self.listen
            ));
        }
        Ok(())
    }
}

struct PersistentBackendValidation<'a> {
    kind: &'a str,
    handler_idx: usize,
    address: &'a str,
    timeout_ms: u64,
    max_concurrency: usize,
    max_stdin_bytes: usize,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

fn validate_persistent_backend(input: PersistentBackendValidation<'_>) -> Result<()> {
    let PersistentBackendValidation {
        kind,
        handler_idx,
        address,
        timeout_ms,
        max_concurrency,
        max_stdin_bytes,
        max_stdout_bytes,
        max_stderr_bytes,
    } = input;
    if address.trim().is_empty() {
        return Err(anyhow!(
            "handlers[{handler_idx}] {kind} address must not be empty"
        ));
    }
    if !address.starts_with("unix://") {
        let _: SocketAddr = address
            .parse()
            .map_err(|err| anyhow!("handlers[{handler_idx}] {kind} address is invalid: {err}"))?;
    }
    if timeout_ms == 0 {
        return Err(anyhow!(
            "handlers[{handler_idx}] {kind} timeout_ms must be >= 1"
        ));
    }
    if max_concurrency == 0 {
        return Err(anyhow!(
            "handlers[{handler_idx}] {kind} max_concurrency must be >= 1"
        ));
    }
    if max_stdin_bytes == 0 || max_stdout_bytes == 0 || max_stderr_bytes == 0 {
        return Err(anyhow!(
            "handlers[{handler_idx}] {kind} byte limits must be >= 1"
        ));
    }
    Ok(())
}

pub fn load_config(path: &Path) -> anyhow::Result<QpxfConfig> {
    let content = std::fs::read_to_string(path)?;
    let expanded = expand_env(&content)?;
    let config: QpxfConfig = serde_yaml::from_str(&expanded)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    #[test]
    fn default_listen_uses_private_user_scoped_socket_path() {
        let listen = default_listen();
        assert!(listen.starts_with("unix://"));
        assert!(listen.ends_with("/qpxf.sock"));
        assert!(!listen.contains("unix:///tmp/qpxf.sock"));
    }

    fn minimal_config(listen: String) -> QpxfConfig {
        QpxfConfig {
            listen,
            workers: 1,
            max_connections: 1,
            max_requests_per_connection: 1,
            allow_insecure_tcp: false,
            max_params_bytes: 1024,
            max_stdin_bytes: 1024,
            input_idle_timeout_ms: 1000,
            conn_idle_timeout_ms: 1000,
            handlers: Vec::new(),
        }
    }

    #[test]
    fn validate_rejects_tcp_without_explicit_opt_in() {
        let err = minimal_config("127.0.0.1:9000".to_string())
            .validate()
            .expect_err("tcp should require explicit opt-in");
        assert!(err.to_string().contains("allow_insecure_tcp=true"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_accepts_unix_socket_default() {
        let cfg = minimal_config(default_listen());
        cfg.validate().expect("unix socket should be accepted");
    }

    #[cfg(unix)]
    #[test]
    fn load_config_expands_env_variables() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("qpxf-config-{unique}.yaml"));
        fs::write(
            &path,
            "listen: \"unix://${QPXF_TEST_RUNTIME_DIR:-/tmp/qpxf-runtime}/qpxf.sock\"\nhandlers: []\n",
        )
        .expect("write config");
        let cfg = load_config(&path).expect("config");
        let _ = fs::remove_file(&path);
        assert_eq!(cfg.listen, "unix:///tmp/qpxf-runtime/qpxf.sock");
    }
}
