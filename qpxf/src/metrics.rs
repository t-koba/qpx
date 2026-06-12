use metrics::{counter, gauge, histogram};
use std::time::Duration;

pub(crate) struct BackendActiveGuard {
    kind: &'static str,
}

impl BackendActiveGuard {
    pub(crate) fn new(kind: &'static str) -> Self {
        gauge!("qpxf_backend_connections_active", "kind" => kind).increment(1.0);
        Self { kind }
    }
}

impl Drop for BackendActiveGuard {
    fn drop(&mut self) {
        gauge!("qpxf_backend_connections_active", "kind" => self.kind).decrement(1.0);
    }
}

pub(crate) fn backend_request(kind: &'static str, result: &'static str) {
    counter!("qpxf_backend_requests_total", "kind" => kind, "result" => result).increment(1);
}

pub(crate) fn pool_reuse(kind: &'static str) {
    counter!("qpxf_backend_pool_reuse_total", "kind" => kind).increment(1);
}

pub(crate) fn pool_discard(kind: &'static str, reason: &'static str) {
    counter!("qpxf_backend_pool_discard_total", "kind" => kind, "reason" => reason).increment(1);
}

pub(crate) fn response_wait(kind: &'static str, duration: Duration) {
    histogram!("qpxf_backend_response_wait_seconds", "kind" => kind).record(duration.as_secs_f64());
}

pub(crate) fn broken_response(kind: &'static str, reason: &'static str) {
    counter!("qpxf_backend_broken_responses_total", "kind" => kind, "reason" => reason)
        .increment(1);
}

pub(crate) fn timeout(kind: &'static str, phase: &'static str) {
    counter!("qpxf_backend_timeouts_total", "kind" => kind, "phase" => phase).increment(1);
}
