use crate::config::{BackendConfig, QpxfConfig};
use crate::executor::cgi::CgiExecutor;
#[cfg(feature = "wasm")]
use crate::executor::wasm::WasmExecutor;
use crate::executor::Executor;
#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use regex::Regex;
use std::sync::Arc;

struct CompiledHandler {
    path_prefix: Option<String>,
    path_regex: Option<Regex>,
    host: Option<String>,
    executor: Arc<dyn Executor>,
}

pub struct Router {
    handlers: Vec<CompiledHandler>,
}

impl Router {
    pub fn new(config: &QpxfConfig) -> Result<Self> {
        let mut handlers = Vec::new();
        for h in &config.handlers {
            let executor: Arc<dyn Executor> = match &h.backend {
                BackendConfig::Cgi(cgi_config) => Arc::new(CgiExecutor::new(cgi_config)?),
                #[cfg(feature = "wasm")]
                BackendConfig::Wasm(wasm_config) => Arc::new(WasmExecutor::new(wasm_config)?),
                #[cfg(not(feature = "wasm"))]
                BackendConfig::Wasm(_) => {
                    return Err(anyhow!(
                        "WASM backend requires the 'wasm' feature to be enabled"
                    ));
                }
            };

            let path_regex = h
                .r#match
                .path_regex
                .as_ref()
                .map(|p| Regex::new(p))
                .transpose()?;

            handlers.push(CompiledHandler {
                path_prefix: h.r#match.path_prefix.clone(),
                path_regex,
                host: h.r#match.host.clone(),
                executor,
            });
        }
        Ok(Self { handlers })
    }

    /// Route a request and return the matched executor and the matched prefix (if any).
    pub fn route(
        &self,
        script_name: &str,
        host: Option<&str>,
    ) -> Option<(Arc<dyn Executor>, Option<String>)> {
        for h in &self.handlers {
            if let Some(prefix) = &h.path_prefix {
                let prefix = prefix.as_str();
                let boundary_ok = script_name == prefix
                    || (script_name.starts_with(prefix)
                        && (prefix.ends_with('/')
                            || script_name.as_bytes().get(prefix.len()) == Some(&b'/')));
                if !boundary_ok {
                    continue;
                }
            }
            if let Some(regex) = &h.path_regex {
                if !regex.is_match(script_name) {
                    continue;
                }
            }
            if let Some(expected_host) = &h.host {
                match host {
                    Some(actual) if actual.eq_ignore_ascii_case(expected_host) => {}
                    _ => continue,
                }
            }
            return Some((Arc::clone(&h.executor), h.path_prefix.clone()));
        }
        None
    }
}
