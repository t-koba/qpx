use super::{DispatchOutcome, ProxyKind};
use metrics::{Histogram, counter, histogram};
use std::sync::OnceLock;
use std::time::Duration;

pub(super) fn record_dispatch_outcome(kind: ProxyKind, outcome: DispatchOutcome) {
    if !qpx_observability::metrics_enabled() {
        return;
    }
    let kind_label = kind.as_str();
    match outcome.as_str() {
        "http_guard_reject" => {
            counter!("qpx_http_guard_reject_total", "kind" => kind_label).increment(1);
        }
        "rate_limited" | "concurrency_limited" => {
            counter!("qpx_rate_limited_total", "kind" => kind_label).increment(1);
        }
        "decision_service_deny" | "decision_service_local_response" => {
            counter!("qpx_decision_service_deny_total", "kind" => kind_label).increment(1);
        }
        "cache_hit" => record_cache_lookup_result(kind, "hit"),
        "cache_stale" => record_cache_lookup_result(kind, "stale"),
        "cache_collapsed_hit" => record_cache_lookup_result(kind, "collapsed_hit"),
        "cache_collapsed_stale" => record_cache_lookup_result(kind, "collapsed_stale"),
        "cache_only_if_cached_miss" => record_cache_lookup_result(kind, "only_if_cached_miss"),
        "response_local_response" | "response_rule_local_response" => {
            record_response_policy_action(kind, "local_response");
        }
        "block" => record_response_policy_action(kind, "block"),
        _ => {}
    }
}

pub(crate) fn record_cache_lookup_duration(kind: ProxyKind, duration: Duration) {
    histogram!("qpx_cache_lookup_duration_seconds", "kind" => kind.as_str())
        .record(duration.as_secs_f64());
}

pub(crate) fn record_cache_lookup_result(kind: ProxyKind, result: &'static str) {
    counter!("qpx_cache_lookup_total", "kind" => kind.as_str(), "result" => result).increment(1);
}

pub(crate) fn record_upstream_request_duration(kind: ProxyKind, duration: Duration) {
    struct UpstreamDurationHistograms {
        forward: Histogram,
        reverse: Histogram,
        transparent: Histogram,
        #[cfg(feature = "mitm")]
        mitm: Histogram,
    }
    static HISTOGRAMS: OnceLock<UpstreamDurationHistograms> = OnceLock::new();
    let histograms = HISTOGRAMS.get_or_init(|| UpstreamDurationHistograms {
        forward: histogram!("qpx_upstream_request_duration_seconds", "kind" => "forward"),
        reverse: histogram!("qpx_upstream_request_duration_seconds", "kind" => "reverse"),
        transparent: histogram!("qpx_upstream_request_duration_seconds", "kind" => "transparent"),
        #[cfg(feature = "mitm")]
        mitm: histogram!("qpx_upstream_request_duration_seconds", "kind" => "mitm"),
    });
    let histogram = match kind {
        ProxyKind::Forward => &histograms.forward,
        ProxyKind::Reverse => &histograms.reverse,
        ProxyKind::Transparent => &histograms.transparent,
        #[cfg(feature = "mitm")]
        ProxyKind::Mitm => &histograms.mitm,
    };
    histogram.record(duration.as_secs_f64());
}

pub(crate) fn record_response_policy_action(kind: ProxyKind, action: &'static str) {
    counter!("qpx_response_policy_action_total", "kind" => kind.as_str(), "action" => action)
        .increment(1);
}
