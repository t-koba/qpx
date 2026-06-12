use metrics::{counter, histogram};

pub(super) fn dropped_datagram(queue: &'static str, reason: &'static str) {
    counter!(
        "qpx_quic_broker_dropped_datagrams_total",
        "queue" => queue,
        "reason" => reason,
    )
    .increment(1);
}

pub(super) fn packet_pool_event(event: &'static str, bucket: &'static str) {
    counter!(
        "qpx_quic_broker_packet_pool_events_total",
        "event" => event,
        "bucket" => bucket,
    )
    .increment(1);
}

pub(super) fn packet_copy(payload_len: usize, bucket: &'static str) {
    counter!(
        "qpx_quic_broker_packet_copy_bytes_total",
        "bucket" => bucket,
    )
    .increment(payload_len as u64);
    histogram!(
        "qpx_quic_broker_packet_size_bytes",
        "bucket" => bucket,
    )
    .record(payload_len as f64);
}
