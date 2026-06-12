use crate::http::protocol::sse::{SseActiveGuard, SseEventObserver, SseMetricHandles};
use http::HeaderMap;
use tokio::time::Instant;

pub(crate) struct H3SseResponseObserver {
    observer: Option<SseEventObserver>,
    metrics: Option<SseMetricHandles>,
    _active: Option<SseActiveGuard>,
    started: Instant,
    first_event_seen: bool,
    last_event_at: Option<Instant>,
}

impl H3SseResponseObserver {
    pub(crate) fn new(
        headers: &HeaderMap,
        listener_name: Option<&str>,
        policy: Option<qpx_core::config::SseStreamingPolicy>,
    ) -> Self {
        let observer = listener_name
            .filter(|_| crate::http::modules::is_event_stream_headers(headers))
            .map(|_| SseEventObserver::with_policy(policy.unwrap_or_default()));
        let metrics = observer
            .as_ref()
            .and_then(|_| listener_name.map(|listener| SseMetricHandles::new(listener, "unknown")));
        Self {
            observer,
            _active: metrics.as_ref().map(SseMetricHandles::active_guard),
            metrics,
            started: Instant::now(),
            first_event_seen: false,
            last_event_at: None,
        }
    }

    pub(crate) fn record_read_error(&self, err: &anyhow::Error) {
        let Some(metrics) = self.metrics.as_ref() else {
            return;
        };
        if err.to_string().contains("duration exceeded") {
            metrics.record_max_duration_exceeded();
        } else {
            metrics.record_idle_disconnect();
        }
    }

    pub(crate) fn feed_chunk(&mut self, chunk: &[u8]) {
        let Some(observer) = self.observer.as_mut() else {
            return;
        };
        let feed = observer.feed(chunk);
        if feed.events == 0 {
            return;
        }
        let Some(metrics) = self.metrics.as_ref() else {
            return;
        };
        let now = Instant::now();
        if !self.first_event_seen {
            metrics.record_first_event_latency(now.duration_since(self.started));
            self.first_event_seen = true;
        }
        if let Some(previous) = self.last_event_at {
            metrics.record_inter_event_latency(now.duration_since(previous));
        }
        self.last_event_at = Some(now);
    }

    pub(crate) fn finish(&self) {
        if let (Some(metrics), Some(observer)) = (self.metrics.as_ref(), self.observer.as_ref()) {
            metrics.record_summary(&observer.summary(), self.started.elapsed());
        }
    }
}
