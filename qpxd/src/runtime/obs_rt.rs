use crate::exporter::ExporterSink;
use anyhow::{Result, anyhow};
use std::sync::OnceLock;

use super::RuntimeResources;

#[derive(Clone)]
pub struct ObsRuntime {
    pub metric_names: MetricNames,
    pub exporter: Option<ExporterSink>,
}

impl ObsRuntime {
    pub(super) fn build(config: &RuntimeResources) -> Result<Self> {
        let metric_names =
            MetricNames::from_prefix(config.operational.identity.metrics_prefix.as_str());
        register_metric_names(metric_names.clone())?;
        let exporter = match &config.operational.telemetry.exporter {
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
    pub datagram_received_total: String,
    pub datagram_received_bytes_total: String,
    pub datagram_sent_total: String,
    pub datagram_sent_bytes_total: String,
    pub datagram_dropped_total: String,
    pub datagram_channel_utilization: String,
    pub grpc_messages_total: String,
    pub grpc_message_bytes_total: String,
    pub grpc_status_total: String,
    pub grpc_stream_duration_seconds: String,
    pub tunnel_bytes_total: String,
    pub tunnel_duration_seconds: String,
    pub tunnel_close_total: String,
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
            datagram_received_total: format!("{}_datagram_received_total", prefix),
            datagram_received_bytes_total: format!("{}_datagram_received_bytes_total", prefix),
            datagram_sent_total: format!("{}_datagram_sent_total", prefix),
            datagram_sent_bytes_total: format!("{}_datagram_sent_bytes_total", prefix),
            datagram_dropped_total: format!("{}_datagram_dropped_total", prefix),
            datagram_channel_utilization: format!("{}_datagram_channel_utilization", prefix),
            grpc_messages_total: format!("{}_grpc_messages_total", prefix),
            grpc_message_bytes_total: format!("{}_grpc_message_bytes_total", prefix),
            grpc_status_total: format!("{}_grpc_status_total", prefix),
            grpc_stream_duration_seconds: format!("{}_grpc_stream_duration_seconds", prefix),
            tunnel_bytes_total: format!("{}_tunnel_bytes_total", prefix),
            tunnel_duration_seconds: format!("{}_tunnel_duration_seconds", prefix),
            tunnel_close_total: format!("{}_tunnel_close_total", prefix),
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
