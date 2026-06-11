//! Per-runtime registry of connection pools.
//!
//! Pools are process-lived connection caches that must survive config reloads, but
//! they are owned by [`crate::runtime::RuntimeState`] (not process-global statics)
//! so they are explicit, test-isolatable, and reconfigurable. The registry instance
//! is carried across reloads by [`crate::runtime::Runtime::swap`]; only the
//! configured limits are re-applied on reload.

use crate::ipc_client::IpcConnectionPool;
use crate::upstream::origin::DirectOriginPools;
use crate::upstream::pool::UpstreamProxyPool;
use std::sync::Arc;

/// Holds the runtime's connection pools.
pub(crate) struct PoolRegistry {
    /// HTTP/1 upstream-proxy sender pool (forward proxy chaining).
    pub(crate) upstream_proxy: UpstreamProxyPool,
    /// Direct origin connection pools (plain HTTP/1 + HTTPS H1/H2).
    pub(crate) direct_origin: DirectOriginPools,
    /// IPC connection pool (reverse `ipc:` routes / function executor). `Arc` so
    /// the response-relay task can retain it to check the connection back in.
    pub(crate) ipc: Arc<IpcConnectionPool>,
    /// HTTP/3 origin connection pool (upstream `h3://` and Alt-Svc).
    #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
    pub(crate) h3_origin: crate::upstream::origin::H3OriginPool,
    /// qpx-h3 upstream CONNECT session pool (datagram / WebTransport relay).
    #[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
    pub(crate) qpx_h3: crate::forward::h3::QpxH3UpstreamSessionPool,
}

/// Pool limits sourced from runtime configuration.
#[derive(Clone, Copy)]
pub(crate) struct PoolLimits {
    pub(crate) upstream_proxy_max_concurrent_per_endpoint: usize,
    pub(crate) h3_origin_max_connections_per_origin: usize,
    pub(crate) h3_origin_max_inflight_streams_per_connection: usize,
}

impl Default for PoolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PoolRegistry {
    pub(crate) fn new() -> Self {
        Self {
            upstream_proxy: UpstreamProxyPool::new(),
            direct_origin: DirectOriginPools::new(),
            ipc: Arc::new(IpcConnectionPool::new()),
            #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
            h3_origin: crate::upstream::origin::H3OriginPool::new(),
            #[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
            qpx_h3: crate::forward::h3::QpxH3UpstreamSessionPool::new(),
        }
    }

    /// Applies pool limits from runtime configuration. Called on initial build and,
    /// via [`PoolRegistry::copy_limits_from`], on reload.
    pub(crate) fn apply_limits(&self, limits: PoolLimits) {
        self.upstream_proxy
            .set_max_concurrent_per_endpoint(limits.upstream_proxy_max_concurrent_per_endpoint);
        #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
        self.h3_origin.set_limits(
            limits.h3_origin_max_connections_per_origin,
            limits.h3_origin_max_inflight_streams_per_connection,
        );
        #[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
        self.qpx_h3.set_limits(
            limits.h3_origin_max_connections_per_origin,
            limits.h3_origin_max_inflight_streams_per_connection,
        );
        #[cfg(not(feature = "http3"))]
        {
            let _ = (
                limits.h3_origin_max_connections_per_origin,
                limits.h3_origin_max_inflight_streams_per_connection,
            );
        }
    }

    /// Copies the configured limits from a freshly-built registry into this carried-over
    /// one, so a reload adopts new limits without discarding live pooled connections.
    pub(crate) fn copy_limits_from(&self, other: &PoolRegistry) {
        self.upstream_proxy
            .set_max_concurrent_per_endpoint(other.upstream_proxy.max_concurrent_per_endpoint());
        #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
        self.h3_origin.set_limits(
            other.h3_origin.max_connections_per_origin(),
            other.h3_origin.max_inflight_streams_per_connection(),
        );
        #[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
        self.qpx_h3.set_limits(
            other.qpx_h3.max_sessions_per_key(),
            other.qpx_h3.max_inflight_streams_per_session(),
        );
    }
}
