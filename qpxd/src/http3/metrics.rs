use metrics::counter;

#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) fn h3_datagram_channel_utilization(tx: &tokio::sync::mpsc::Sender<bytes::Bytes>) {
    let max = tx.max_capacity();
    if max == 0 {
        return;
    }
    let used = max.saturating_sub(tx.capacity());
    metrics::histogram!(
        "qpx_datagram_channel_utilization",
        "transport" => "h3",
        "listener" => "unknown"
    )
    .record(used as f64 / max as f64);
    metrics::gauge!(
        "qpx_datagram_queue_depth",
        "protocol" => "h3",
        "listener" => "unknown",
        "route" => "unknown"
    )
    .set(used as f64);
}

#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) fn h3_datagram_received(len: u64) {
    counter!(
        "qpx_datagrams_total",
        "protocol" => "h3",
        "listener" => "unknown",
        "route" => "unknown",
        "direction" => "downstream"
    )
    .increment(1);
    counter!(
        "qpx_datagram_bytes_total",
        "protocol" => "h3",
        "listener" => "unknown",
        "route" => "unknown",
        "direction" => "downstream"
    )
    .increment(len);
}

#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) fn h3_datagram_drop(reason: &'static str) {
    counter!(
        "qpx_datagrams_dropped_total",
        "protocol" => "h3",
        "listener" => "unknown",
        "route" => "unknown",
        "reason" => reason
    )
    .increment(1);
    if reason == "channel_full" {
        counter!(
            "qpx_datagram_queue_overflows_total",
            "protocol" => "h3",
            "listener" => "unknown",
            "route" => "unknown",
            "policy" => "drop_newest"
        )
        .increment(1);
    }
}

pub(crate) fn h3_response_send_error(backend: &'static str, stage: &'static str) {
    counter!(
        "qpx_h3_response_send_errors_total",
        "backend" => backend,
        "stage" => stage,
        "reason" => "error",
    )
    .increment(1);
}

#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) const DRAIN_STARTED: &str = "qpx_h3_request_body_drains_started_total";
#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) const DRAIN_COMPLETED: &str = "qpx_h3_request_body_drains_completed_total";
#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) const DRAIN_ABORTED: &str = "qpx_h3_request_body_drains_aborted_total";
#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) const DRAIN_LIMITED: &str = "qpx_h3_request_body_drains_limited_total";

#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) fn drain_completed(listener: &str, route: &str, reason: &str, seconds: f64) {
    drain(DRAIN_COMPLETED, listener, route, reason);
    metrics::histogram!(
        "qpx_h3_request_body_drain_duration_seconds",
        "listener" => listener.to_string(),
        "route" => route.to_string(),
        "reason" => reason.to_string(),
    )
    .record(seconds);
}

#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) fn drain(metric: &'static str, listener: &str, route: &str, reason: &str) {
    counter!(
        metric,
        "listener" => listener.to_string(),
        "route" => route.to_string(),
        "reason" => reason.to_string(),
    )
    .increment(1);
}
