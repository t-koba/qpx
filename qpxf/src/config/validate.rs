use anyhow::{Result, anyhow};
use std::net::SocketAddr;

use super::{BackendConfig, QpxfConfig};

const MAX_WASM_MODULE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_WASM_MEMORY_MB: u64 = 4096;

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
                        script_name_prefixes: &config.script_name_prefixes,
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
                        script_name_prefixes: &config.script_name_prefixes,
                    })?;
                }
                BackendConfig::Wasm(config) => {
                    if config.timeout_ms == 0 {
                        return Err(anyhow!("handlers[{idx}] wasm timeout_ms must be >= 1"));
                    }
                    if config.max_module_bytes == 0 {
                        return Err(anyhow!(
                            "handlers[{idx}] wasm max_module_bytes must be >= 1"
                        ));
                    }
                    if config.max_module_bytes > MAX_WASM_MODULE_BYTES {
                        return Err(anyhow!(
                            "handlers[{idx}] wasm max_module_bytes must be <= {MAX_WASM_MODULE_BYTES}"
                        ));
                    }
                    if config.max_memory_mb > MAX_WASM_MEMORY_MB {
                        return Err(anyhow!(
                            "handlers[{idx}] wasm max_memory_mb must be <= {MAX_WASM_MEMORY_MB}"
                        ));
                    }
                    let max_memory_bytes = config
                        .max_memory_mb
                        .checked_mul(1024)
                        .and_then(|value| value.checked_mul(1024))
                        .ok_or_else(|| {
                            anyhow!(
                                "handlers[{idx}] wasm max_memory_mb is too large to convert to bytes"
                            )
                        })?;
                    if max_memory_bytes == 0 {
                        return Err(anyhow!("handlers[{idx}] wasm max_memory_mb must be >= 1"));
                    }
                    if max_memory_bytes > usize::MAX as u64 {
                        return Err(anyhow!(
                            "handlers[{idx}] wasm max_memory_mb exceeds this platform's addressable memory limit"
                        ));
                    }
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
                    for key in config.env.keys() {
                        if key.trim().is_empty() {
                            return Err(anyhow!("handlers[{idx}] wasm env keys must not be empty"));
                        }
                        if crate::executor::cgi::cgi_env_passthrough_is_reserved(key) {
                            return Err(anyhow!(
                                "handlers[{idx}] wasm env must not include CGI reserved variable {key}"
                            ));
                        }
                    }
                }
                BackendConfig::Cgi(config) => {
                    if config.timeout_ms == 0 {
                        return Err(anyhow!("handlers[{idx}] cgi timeout_ms must be >= 1"));
                    }
                    if config.max_stdout_bytes == 0 || config.max_stderr_bytes == 0 {
                        return Err(anyhow!("handlers[{idx}] cgi byte limits must be >= 1"));
                    }
                    for var in &config.env_passthrough {
                        if crate::executor::cgi::cgi_env_passthrough_is_reserved(var) {
                            return Err(anyhow!(
                                "handlers[{idx}] cgi env_passthrough must not include CGI reserved variable {var}"
                            ));
                        }
                    }
                }
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
    script_name_prefixes: &'a [String],
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
        script_name_prefixes,
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
    for (prefix_idx, prefix) in script_name_prefixes.iter().enumerate() {
        if prefix.is_empty() || !prefix.starts_with('/') || prefix.ends_with('/') {
            return Err(anyhow!(
                "handlers[{handler_idx}] {kind} script_name_prefixes[{prefix_idx}] must start with '/' and must not end with '/'"
            ));
        }
    }
    Ok(())
}
