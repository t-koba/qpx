use crate::exporter::ExporterSink;
use anyhow::{anyhow, Result};
use std::sync::OnceLock;

use super::ConfigRuntime;

#[derive(Clone)]
pub struct ObsRuntime {
    pub metric_names: MetricNames,
    pub exporter: Option<ExporterSink>,
}

impl ObsRuntime {
    pub(super) fn build(config: &ConfigRuntime) -> Result<Self> {
        let metric_names = MetricNames::from_prefix(config.identity.metrics_prefix.as_str());
        register_metric_names(metric_names.clone())?;
        let exporter = match &config.exporter {
            Some(cfg) if cfg.enabled => Some(ExporterSink::from_config(cfg)?),
            _ => None,
        };
        Ok(Self {
            metric_names,
            exporter,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MetricNames {
    pub forward_requests_total: String,
    pub forward_latency_ms: String,
    pub forward_upstream_proxy_ejections_total: String,
    pub forward_upstream_proxy_probe_success_total: String,
    pub header_regex_replace_invalid_total: String,
    pub reverse_local_response_total: String,
    pub reverse_path_rewrite_invalid_total: String,
    pub reverse_retry_budget_exhausted_total: String,
    pub reverse_upstream_latency_ms: String,
    pub reverse_upstream_probe_success_total: String,
    pub reverse_upstream_ejections_total: String,
    pub reverse_upstreams_draining: String,
    pub reverse_requests_total: String,
    pub reverse_upstreams_unhealthy: String,
    pub transparent_requests_total: String,
    pub transparent_latency_ms: String,
}

impl MetricNames {
    fn from_prefix(prefix: &str) -> Self {
        Self {
            forward_requests_total: format!("{}_forward_requests_total", prefix),
            forward_latency_ms: format!("{}_forward_latency_ms", prefix),
            forward_upstream_proxy_ejections_total: format!(
                "{}_forward_upstream_proxy_ejections_total",
                prefix
            ),
            forward_upstream_proxy_probe_success_total: format!(
                "{}_forward_upstream_proxy_probe_success_total",
                prefix
            ),
            header_regex_replace_invalid_total: format!(
                "{}_header_regex_replace_invalid_total",
                prefix
            ),
            reverse_local_response_total: format!("{}_reverse_local_response_total", prefix),
            reverse_path_rewrite_invalid_total: format!(
                "{}_reverse_path_rewrite_invalid_total",
                prefix
            ),
            reverse_retry_budget_exhausted_total: format!(
                "{}_reverse_retry_budget_exhausted_total",
                prefix
            ),
            reverse_upstream_latency_ms: format!("{}_reverse_upstream_latency_ms", prefix),
            reverse_upstream_probe_success_total: format!(
                "{}_reverse_upstream_probe_success_total",
                prefix
            ),
            reverse_upstream_ejections_total: format!(
                "{}_reverse_upstream_ejections_total",
                prefix
            ),
            reverse_upstreams_draining: format!("{}_reverse_upstreams_draining", prefix),
            reverse_requests_total: format!("{}_reverse_requests_total", prefix),
            reverse_upstreams_unhealthy: format!("{}_reverse_upstreams_unhealthy", prefix),
            transparent_requests_total: format!("{}_transparent_requests_total", prefix),
            transparent_latency_ms: format!("{}_transparent_latency_ms", prefix),
        }
    }
}

fn metric_names_registry() -> &'static OnceLock<MetricNames> {
    static METRIC_NAMES: OnceLock<MetricNames> = OnceLock::new();
    &METRIC_NAMES
}

fn register_metric_names(names: MetricNames) -> Result<()> {
    let registry = metric_names_registry();
    if let Some(existing) = registry.get() {
        if existing != &names {
            return Err(anyhow!("identity.metrics_prefix changed; restart required"));
        }
        return Ok(());
    }
    let _ = registry.set(names);
    Ok(())
}

pub(crate) fn metric_names() -> &'static MetricNames {
    metric_names_registry().get().unwrap_or_else(|| {
        static DEFAULT_METRIC_NAMES: OnceLock<MetricNames> = OnceLock::new();
        DEFAULT_METRIC_NAMES.get_or_init(|| MetricNames::from_prefix("qpx"))
    })
}
