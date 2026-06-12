use bytes::Bytes;
use metrics::{counter, histogram};
use tokio::sync::mpsc;

pub(super) fn datagram_sent(payload_len: usize) {
    counter!(
        "qpx_datagram_sent_total",
        "transport" => "qpx_h3",
        "listener" => "unknown"
    )
    .increment(1);
    counter!(
        "qpx_datagram_sent_bytes_total",
        "transport" => "qpx_h3",
        "listener" => "unknown"
    )
    .increment(payload_len as u64);
}

pub(super) fn datagram_prefix_copy(payload_len: usize) {
    counter!(
        "qpx_datagram_prefix_copy_bytes_total",
        "transport" => "qpx_h3",
    )
    .increment(payload_len as u64);
    histogram!(
        "qpx_datagram_prefix_copy_payload_bytes",
        "transport" => "qpx_h3",
    )
    .record(payload_len as f64);
}

pub(super) fn datagram_received(len: u64) {
    counter!(
        "qpx_datagram_received_total",
        "transport" => "qpx_h3",
        "listener" => "unknown"
    )
    .increment(1);
    counter!(
        "qpx_datagram_received_bytes_total",
        "transport" => "qpx_h3",
        "listener" => "unknown"
    )
    .increment(len);
}

pub(super) fn datagram_dropped(reason: &'static str) {
    counter!(
        "qpx_datagram_dropped_total",
        "transport" => "qpx_h3",
        "listener" => "unknown",
        "reason" => reason
    )
    .increment(1);
}

pub(super) fn datagram_channel_utilization(tx: &mpsc::Sender<Bytes>) {
    let max = tx.max_capacity();
    if max == 0 {
        return;
    }
    let used = max.saturating_sub(tx.capacity());
    histogram!(
        "qpx_datagram_channel_utilization",
        "transport" => "qpx_h3",
        "listener" => "unknown"
    )
    .record(used as f64 / max as f64);
}
