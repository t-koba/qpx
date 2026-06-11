use crate::runtime::RuntimeState;
use metrics::{counter, histogram};
use std::time::Duration;

pub(super) fn retry_budget_exhausted(state: &RuntimeState) {
    let names = &state.observability.metric_names;
    counter!(names.reverse_retry_budget_exhausted_total.clone()).increment(1);
}

pub(super) fn reverse_result(state: &RuntimeState, result: &'static str) {
    let names = &state.observability.metric_names;
    counter!(
        names.reverse_requests_total.clone(),
        "result" => result
    )
    .increment(1);
}

pub(super) fn upstream_latency(state: &RuntimeState, elapsed: Duration) {
    let names = &state.observability.metric_names;
    histogram!(names.reverse_upstream_latency_ms.clone()).record(elapsed.as_secs_f64() * 1000.0);
}

pub(super) fn local_response(state: &RuntimeState) {
    let names = &state.observability.metric_names;
    counter!(names.reverse_local_response_total.clone()).increment(1);
}

pub(super) fn path_rewrite_invalid() {
    counter!(
        crate::runtime::metric_names()
            .reverse_path_rewrite_invalid_total
            .clone()
    )
    .increment(1);
}

pub(super) fn mirror_dropped(target: &str, reason: &'static str) {
    counter!(
        "qpx_reverse_mirror_dropped_total",
        "target" => target.to_owned(),
        "reason" => reason
    )
    .increment(1);
}
