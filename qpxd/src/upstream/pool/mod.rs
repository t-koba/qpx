mod cluster;
mod resolved;
mod send;
mod sender_pool;

#[cfg(test)]
mod tests;

pub(crate) use cluster::UpstreamProxyCluster;
pub(crate) use resolved::{ResolvedUpstreamProxy, build_named_upstream_proxies};
pub(crate) use send::{send_via_upstream_proxy, send_via_upstream_proxy_with_interim};
pub(crate) use sender_pool::set_upstream_proxy_max_concurrent_per_endpoint;
