use crate::runtime::RuntimeState;
use metrics::{Counter, Histogram, counter, histogram};
use std::sync::OnceLock;
use std::time::Duration;

struct ReverseResultCounters {
    ok: Counter,
    error: Counter,
    timeout: Counter,
}

pub(super) enum ReverseResult {
    Ok,
    Error,
    Timeout,
}

fn reverse_result_counters(state: &RuntimeState) -> &'static ReverseResultCounters {
    static COUNTERS: OnceLock<ReverseResultCounters> = OnceLock::new();
    COUNTERS.get_or_init(|| {
        let name = state
            .observability
            .metric_names
            .reverse_requests_total
            .clone();
        ReverseResultCounters {
            ok: counter!(name.clone(), "result" => "ok"),
            error: counter!(name.clone(), "result" => "error"),
            timeout: counter!(name, "result" => "timeout"),
        }
    })
}

pub(super) fn retry_budget_exhausted(state: &RuntimeState) {
    let names = &state.observability.metric_names;
    counter!(names.reverse_retry_budget_exhausted_total.clone()).increment(1);
}

pub(super) fn reverse_result(state: &RuntimeState, result: ReverseResult) {
    let counters = reverse_result_counters(state);
    match result {
        ReverseResult::Ok => counters.ok.increment(1),
        ReverseResult::Error => counters.error.increment(1),
        ReverseResult::Timeout => counters.timeout.increment(1),
    }
}

pub(super) fn upstream_latency(state: &RuntimeState, elapsed: Duration) {
    static HISTOGRAM: OnceLock<Histogram> = OnceLock::new();
    let histogram = HISTOGRAM.get_or_init(|| {
        histogram!(
            state
                .observability
                .metric_names
                .reverse_upstream_latency_ms
                .clone()
        )
    });
    histogram.record(elapsed.as_secs_f64() * 1000.0);
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
