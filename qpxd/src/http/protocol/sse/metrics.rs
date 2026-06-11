use super::SseStreamSummary;
use metrics::{Counter, Gauge, Histogram, counter, gauge, histogram};
use std::time::Duration;

pub(crate) fn emit_sse_reconnect(listener: &str, route: &str) {
    counter!(
        "qpx_sse_reconnections_total",
        "listener" => listener.to_string(),
        "route" => route.to_string()
    )
    .increment(1);
}

pub(crate) fn emit_slow_upstream_body(listener: &str) {
    counter!(
        "qpx_upstream_slow_body_total",
        "listener" => listener.to_string()
    )
    .increment(1);
}

pub(crate) struct SseActiveGuard {
    active: Gauge,
}

impl Drop for SseActiveGuard {
    fn drop(&mut self) {
        self.active.decrement(1.0);
    }
}

#[derive(Clone)]
pub(crate) struct SseMetricHandles {
    events: Counter,
    bytes: Counter,
    idle_disconnects: Counter,
    idle_timeouts: Counter,
    max_duration_exceeded: Counter,
    active: Gauge,
    stream_duration: Histogram,
    first_event_latency: Histogram,
    inter_event_latency: Histogram,
}

impl SseMetricHandles {
    pub(crate) fn new(listener: &str, route: &str) -> Self {
        let listener = listener.to_string();
        let route = route.to_string();
        Self {
            events: counter!("qpx_sse_events_total", "listener" => listener.clone(), "route" => route.clone()),
            bytes: counter!("qpx_sse_bytes_total", "listener" => listener.clone(), "route" => route.clone()),
            idle_disconnects: counter!("qpx_sse_idle_disconnects_total", "listener" => listener.clone(), "route" => route.clone()),
            idle_timeouts: counter!("qpx_sse_idle_timeouts_total", "listener" => listener.clone(), "route" => route.clone()),
            max_duration_exceeded: counter!("qpx_sse_max_duration_exceeded_total", "listener" => listener.clone(), "route" => route.clone()),
            active: gauge!("qpx_sse_streams_active", "listener" => listener.clone(), "route" => route.clone()),
            stream_duration: histogram!("qpx_sse_stream_duration_seconds", "listener" => listener.clone(), "route" => route.clone()),
            first_event_latency: histogram!("qpx_sse_first_event_latency_seconds", "listener" => listener.clone(), "route" => route.clone()),
            inter_event_latency: histogram!("qpx_sse_inter_event_latency_seconds", "listener" => listener, "route" => route),
        }
    }

    pub(crate) fn active_guard(&self) -> SseActiveGuard {
        self.active.increment(1.0);
        SseActiveGuard {
            active: self.active.clone(),
        }
    }

    pub(crate) fn record_summary(&self, summary: &SseStreamSummary, duration: Duration) {
        self.events.increment(summary.event_count);
        self.bytes.increment(summary.byte_count);
        self.stream_duration.record(duration.as_secs_f64());
    }

    pub(crate) fn record_first_event_latency(&self, duration: Duration) {
        self.first_event_latency.record(duration.as_secs_f64());
    }

    pub(crate) fn record_inter_event_latency(&self, duration: Duration) {
        self.inter_event_latency.record(duration.as_secs_f64());
    }

    pub(crate) fn record_idle_disconnect(&self) {
        self.idle_disconnects.increment(1);
        self.idle_timeouts.increment(1);
    }

    pub(crate) fn record_max_duration_exceeded(&self) {
        self.max_duration_exceeded.increment(1);
    }
}
