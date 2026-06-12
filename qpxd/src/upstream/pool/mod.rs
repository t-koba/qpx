mod cluster;
mod metrics;
mod resolved;
mod send;
mod sender_pool;

#[cfg(test)]
mod tests;

pub(crate) trait ConnectionPool<T> {
    type Acquire;
    type Error;

    fn acquire_connection(&self, request: Self::Acquire) -> std::result::Result<T, Self::Error>;
}

pub(crate) use cluster::UpstreamProxyCluster;
pub(crate) use resolved::{ResolvedUpstreamProxy, build_named_upstream_proxies};
pub(crate) use send::{send_via_upstream_proxy, send_via_upstream_proxy_with_interim};
pub(crate) use sender_pool::UpstreamProxyPool;
