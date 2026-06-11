use metrics::counter;

pub fn buffering(direction: &'static str, reason: &'static str, bytes: usize, spooled: usize) {
    counter!(
        "qpx_body_buffering_events_total",
        "direction" => direction,
        "reason" => reason
    )
    .increment(1);
    counter!(
        "qpx_body_buffering_bytes_total",
        "direction" => direction,
        "reason" => reason
    )
    .increment(bytes as u64);
    if spooled > 0 {
        counter!(
            "qpx_body_spooled_bytes_total",
            "direction" => direction,
            "reason" => reason
        )
        .increment(spooled as u64);
    }
}

pub fn spool_error(direction: &'static str, reason: &'static str, error: &'static str) {
    counter!(
        "qpx_body_spool_errors_total",
        "direction" => direction,
        "reason" => reason,
        "error" => error
    )
    .increment(1);
}

pub fn spool_cleanup_error() {
    counter!(
        "qpx_body_spool_cleanup_errors_total",
        "direction" => "unknown",
        "reason" => "observed_body",
        "error" => "remove"
    )
    .increment(1);
}

pub fn mirror_drop(mirror: &'static str, reason: &'static str) {
    counter!(
        "qpx_body_mirror_drops_total",
        "mirror" => mirror,
        "reason" => reason,
    )
    .increment(1);
}
