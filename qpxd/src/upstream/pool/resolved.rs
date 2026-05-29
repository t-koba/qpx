use super::cluster::UpstreamProxyCluster;
use super::cluster::{ManagedUpstreamEndpoint, PassiveFailureKind, PassiveHealthPolicy};
use crate::tls::CompiledUpstreamTlsTrust;
use crate::upstream::http1::{UpstreamProxyEndpoint, parse_upstream_proxy_endpoint};
use anyhow::Result;
use hyper::StatusCode;
use qpx_core::config::UpstreamConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::time::Duration;
use url::Url;

pub(super) struct EndpointConcurrencyPermit {
    pub(super) endpoint: Arc<ManagedUpstreamEndpoint>,
}

impl Drop for EndpointConcurrencyPermit {
    fn drop(&mut self) {
        self.endpoint.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) struct ResolvedUpstreamProxy {
    pub(super) key: Arc<str>,
    pub(super) endpoint: Arc<ManagedUpstreamEndpoint>,
    pub(super) trust: Option<Arc<CompiledUpstreamTlsTrust>>,
    pub(super) passive_health: Option<PassiveHealthPolicy>,
    pub(super) _permit: Option<EndpointConcurrencyPermit>,
}

impl ResolvedUpstreamProxy {
    pub(crate) fn direct(raw: &str) -> Result<Self> {
        Ok(Self {
            key: Arc::<str>::from(raw),
            endpoint: Arc::new(ManagedUpstreamEndpoint::new(parse_upstream_proxy_endpoint(
                raw,
            )?)),
            trust: None,
            passive_health: None,
            _permit: None,
        })
    }

    pub(crate) fn key(&self) -> &str {
        self.key.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn label(&self) -> &str {
        self.key.as_ref()
    }

    pub(crate) fn endpoint(&self) -> &UpstreamProxyEndpoint {
        &self.endpoint.endpoint
    }

    pub(crate) fn trust(&self) -> Option<&CompiledUpstreamTlsTrust> {
        self.trust.as_deref()
    }

    pub(crate) fn mark_success(&self) {
        if self.passive_health.is_some() {
            self.endpoint.mark_passive_success();
        }
    }

    pub(crate) fn mark_http_response(&self, status: StatusCode, elapsed: Duration) {
        if status.is_server_error() {
            self.endpoint
                .mark_passive_failure(self.passive_health.as_ref(), PassiveFailureKind::Http5xx);
            return;
        }
        self.endpoint.mark_passive_success();
        self.endpoint
            .mark_passive_latency(self.passive_health.as_ref(), elapsed);
    }

    pub(crate) fn mark_timeout(&self) {
        self.endpoint
            .mark_passive_failure(self.passive_health.as_ref(), PassiveFailureKind::Timeout);
    }

    pub(crate) fn mark_connect_error(&self) {
        self.endpoint.mark_passive_failure(
            self.passive_health.as_ref(),
            PassiveFailureKind::ConnectError,
        );
    }

    pub(crate) fn mark_reset(&self) {
        self.endpoint
            .mark_passive_failure(self.passive_health.as_ref(), PassiveFailureKind::Reset);
    }
}

pub(crate) fn build_named_upstream_proxies(
    upstreams: &[UpstreamConfig],
) -> Result<HashMap<String, Arc<UpstreamProxyCluster>>> {
    let mut clusters = HashMap::new();
    for cfg in upstreams {
        let scheme = Url::parse(cfg.url.as_str())
            .ok()
            .map(|url| url.scheme().to_ascii_lowercase())
            .unwrap_or_default();
        if scheme != "http" && scheme != "https" {
            continue;
        }
        clusters.insert(cfg.name.clone(), UpstreamProxyCluster::from_config(cfg)?);
    }
    Ok(clusters)
}
