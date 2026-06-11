use http::HeaderMap;
use qpx_core::config::SseStreamingPolicy;

#[path = "sse/metrics.rs"]
mod metrics;
pub(crate) use metrics::{
    SseActiveGuard, SseMetricHandles, emit_slow_upstream_body, emit_sse_reconnect,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SseStreamSummary {
    pub(crate) event_count: u64,
    pub(crate) byte_count: u64,
    pub(crate) last_event_id: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SseFeedResult {
    pub(crate) events: u64,
    pub(crate) bytes: u64,
}

#[derive(Debug)]
pub(crate) struct SseEventObserver {
    line: Vec<u8>,
    line_truncated: bool,
    in_event: bool,
    max_line_bytes: usize,
    max_event_id_bytes: usize,
    summary: SseStreamSummary,
}

impl Default for SseEventObserver {
    fn default() -> Self {
        Self {
            line: Vec::new(),
            line_truncated: false,
            in_event: false,
            max_line_bytes: SseStreamingPolicy::default().max_line_bytes,
            max_event_id_bytes: SseStreamingPolicy::default().max_event_id_bytes,
            summary: SseStreamSummary::default(),
        }
    }
}

impl SseEventObserver {
    pub(crate) fn new() -> Self {
        Self::with_policy(SseStreamingPolicy::default())
    }

    pub(crate) fn with_policy(policy: SseStreamingPolicy) -> Self {
        Self {
            max_line_bytes: policy.max_line_bytes,
            max_event_id_bytes: policy.max_event_id_bytes,
            ..Self::default()
        }
    }

    pub(crate) fn feed(&mut self, chunk: &[u8]) -> SseFeedResult {
        let before = self.summary.event_count;
        self.summary.byte_count = self.summary.byte_count.saturating_add(chunk.len() as u64);
        for byte in chunk {
            if self.line.len() < self.max_line_bytes {
                self.line.push(*byte);
            } else {
                self.line_truncated = true;
            }
            if *byte == b'\n' {
                self.process_line();
            }
        }
        SseFeedResult {
            events: self.summary.event_count.saturating_sub(before),
            bytes: chunk.len() as u64,
        }
    }

    pub(crate) fn summary(&self) -> SseStreamSummary {
        self.summary.clone()
    }

    fn process_line(&mut self) {
        if self.line_truncated {
            self.line.clear();
            self.line_truncated = false;
            return;
        }
        while self
            .line
            .last()
            .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
        {
            self.line.pop();
        }
        if self.line.is_empty() {
            if self.in_event {
                self.summary.event_count = self.summary.event_count.saturating_add(1);
                self.in_event = false;
            }
            return;
        }
        if self.line.first() == Some(&b':') {
            self.line.clear();
            return;
        }
        self.in_event = true;
        if let Some(value) = self.line.strip_prefix(b"id:") {
            let value = value.strip_prefix(b" ").unwrap_or(value);
            let value = &value[..value.len().min(self.max_event_id_bytes)];
            self.summary.last_event_id = Some(String::from_utf8_lossy(value).into_owned());
        }
        self.line.clear();
    }
}

pub(crate) fn is_sse_reconnect(headers: &HeaderMap) -> bool {
    headers.contains_key("last-event-id")
}

#[cfg(test)]
mod tests {
    use crate::http::protocol::sse::*;

    #[test]
    fn sse_event_observer_counts_events_across_chunks_and_tracks_id() {
        let mut observer = SseEventObserver::new();
        assert_eq!(
            observer.feed(b"id: 1\ndata: he"),
            SseFeedResult {
                events: 0,
                bytes: 14
            }
        );
        assert_eq!(observer.feed(b"llo\n\nid: 2\ndata: next\n\n").events, 2);
        let summary = observer.summary();
        assert_eq!(summary.event_count, 2);
        assert_eq!(summary.last_event_id.as_deref(), Some("2"));
    }

    #[test]
    fn sse_event_observer_caps_line_and_event_id_storage() {
        let mut observer = SseEventObserver::new();
        let defaults = qpx_core::config::SseStreamingPolicy::default();
        let long_line = vec![b'a'; defaults.max_line_bytes + 32];
        observer.feed(long_line.as_slice());
        observer.feed(b"\n\n");
        let summary = observer.summary();
        assert_eq!(summary.event_count, 0);

        let mut observer = SseEventObserver::new();
        let mut id = b"id: ".to_vec();
        id.extend(std::iter::repeat_n(b'x', defaults.max_event_id_bytes + 32));
        id.extend_from_slice(b"\ndata: ok\n\n");
        observer.feed(id.as_slice());
        let summary = observer.summary();
        assert_eq!(summary.event_count, 1);
        assert_eq!(
            summary.last_event_id.as_ref().map(String::len),
            Some(defaults.max_event_id_bytes)
        );
    }
}
