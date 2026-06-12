use super::OriginKey;
use metrics::{counter, gauge, histogram};
use std::time::Duration;

pub(super) fn origin_label(key: &OriginKey) -> &str {
    key.server_name.as_str()
}

pub(super) fn inflight(origin: &str, count: usize) {
    gauge!("qpx_h3_origin_pool_inflight", "origin" => origin.to_owned()).set(count as f64);
}

pub(super) fn open_queue_depth(origin: &str, count: usize) {
    gauge!("qpx_h3_origin_pool_open_queue_depth", "origin" => origin.to_owned()).set(count as f64);
}

pub(super) fn open_queue_rejected(origin: &str) {
    counter!("qpx_h3_origin_pool_open_queue_rejected_total", "origin" => origin.to_owned())
        .increment(1);
}

pub(super) fn request_open(origin: &str, elapsed: Duration) {
    histogram!("qpx_h3_origin_pool_request_open_seconds", "origin" => origin.to_owned())
        .record(elapsed.as_secs_f64());
}

pub(super) fn connections(key: &OriginKey, count: usize) {
    gauge!(
        "qpx_h3_origin_pool_connections",
        "origin" => origin_label(key).to_owned(),
        "state" => "open"
    )
    .set(count as f64);
}

pub(super) fn wait(key: &OriginKey, elapsed: Duration) {
    histogram!("qpx_h3_origin_pool_wait_seconds", "origin" => origin_label(key).to_owned())
        .record(elapsed.as_secs_f64());
}

pub(super) fn reuse(key: &OriginKey) {
    counter!("qpx_h3_origin_pool_reuse_total", "origin" => origin_label(key).to_owned())
        .increment(1);
}

pub(super) fn eviction(key: &OriginKey, reason: &'static str) {
    counter!(
        "qpx_h3_origin_pool_evictions_total",
        "origin" => origin_label(key).to_owned(),
        "reason" => reason
    )
    .increment(1);
}

pub(super) fn connection_error(key: &OriginKey, reason: &'static str) {
    counter!(
        "qpx_h3_origin_pool_connection_errors_total",
        "origin" => origin_label(key).to_owned(),
        "reason" => reason
    )
    .increment(1);
}
