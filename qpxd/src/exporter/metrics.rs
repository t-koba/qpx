use metrics::counter;

pub(super) const EVENTS_DROPPED: &str = "qpx_exporter_events_dropped_total";
pub(super) const EVENTS_ENQUEUED: &str = "qpx_exporter_events_enqueued_total";
pub(super) const EVENTS_SENT: &str = "qpx_exporter_events_sent_total";
pub(super) const BYTES_SENT: &str = "qpx_exporter_bytes_sent_total";
pub(super) const WRITE_BLOCKED: &str = "qpx_exporter_write_blocked_total";

pub(super) fn increment(name: &'static str) {
    counter!(name).increment(1);
}

pub(super) fn increment_by(name: &'static str, value: u64) {
    counter!(name).increment(value);
}
