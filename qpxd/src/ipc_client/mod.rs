mod backend;
mod meta;
mod pool;
mod proxy;
mod shm;

#[cfg(test)]
mod tests;

use anyhow::Result;
use qpx_core::config::{IpcMode, IpcUpstreamConfig};
use std::time::Duration;

use backend::{IpcBackend, parse_ipc_address};

pub(crate) use pool::IpcConnectionPool;
pub(crate) use proxy::{proxy_ipc, proxy_ipc_upstream};

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ClientConnInfo {
    pub remote_addr: Option<std::net::SocketAddr>,
}

#[derive(Debug, Clone)]
pub(crate) struct IpcUpstream {
    mode: IpcMode,
    backend: IpcBackend,
    timeout: Duration,
    max_request_bytes: Option<usize>,
    max_response_bytes: Option<usize>,
}

impl IpcUpstream {
    pub(crate) fn from_config(cfg: &IpcUpstreamConfig) -> Result<Self> {
        Ok(Self {
            mode: cfg.mode.clone(),
            backend: parse_ipc_address(cfg.address.as_str())?,
            timeout: Duration::from_millis(cfg.timeout_ms),
            max_request_bytes: cfg.body.max_request_bytes,
            max_response_bytes: cfg.body.max_response_bytes,
        })
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(crate) fn endpoint_label(&self) -> String {
        self.backend.pool_key()
    }

    fn effective_timeout(&self, route_timeout: Duration) -> Duration {
        std::cmp::min(route_timeout, self.timeout)
    }
}
