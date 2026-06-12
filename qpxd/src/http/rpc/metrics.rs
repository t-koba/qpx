// Extracted from rpc/mod.rs; keep public re-exports in mod.rs.
use super::frame::FramedBodySummary;
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
use super::protocol::{extract_grpc_status_and_message, normalize_connect_code};
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
use http::HeaderMap;
use metrics::counter;
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
use metrics::histogram;
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
use std::time::Duration;

pub(crate) fn emit_inspected_body_metrics(
    direction: &'static str,
    listener: &str,
    protocol: &str,
    summary: &FramedBodySummary,
) {
    counter!(
        "qpx_grpc_messages_total",
        "direction" => direction,
        "listener" => listener.to_string(),
        "protocol" => protocol.to_string()
    )
    .increment(summary.message_count as u64);
    counter!(
        "qpx_grpc_message_bytes_total",
        "direction" => direction,
        "listener" => listener.to_string(),
        "protocol" => protocol.to_string()
    )
    .increment(summary.message_bytes);
}

pub(crate) fn emit_inspected_status(listener: &str, protocol: &str, status: &str) {
    counter!(
        "qpx_grpc_status_total",
        "listener" => listener.to_string(),
        "protocol" => protocol.to_string(),
        "status" => status.to_string()
    )
    .increment(1);
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn emit_grpc_deadline_exceeded_metric(listener: &str, protocol: &str) {
    let status = if protocol == "connect" {
        "deadline_exceeded"
    } else {
        "4"
    };
    counter!(
        "qpx_grpc_status_total",
        "listener" => listener.to_string(),
        "protocol" => protocol.to_string(),
        "status" => status
    )
    .increment(1);
    counter!(
        "qpx_rpc_status_total",
        "listener" => listener.to_string(),
        "protocol" => protocol.to_string(),
        "status" => status
    )
    .increment(1);
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn emit_grpc_body_metrics(
    direction: &'static str,
    listener: &str,
    protocol: &str,
    summary: &FramedBodySummary,
) {
    counter!(
        "qpx_grpc_messages_total",
        "direction" => direction,
        "listener" => listener.to_string(),
        "protocol" => protocol.to_string()
    )
    .increment(summary.message_count as u64);
    counter!(
        "qpx_rpc_messages_total",
        "direction" => direction,
        "listener" => listener.to_string(),
        "protocol" => protocol.to_string()
    )
    .increment(summary.message_count as u64);
    counter!(
        "qpx_grpc_message_bytes_total",
        "direction" => direction,
        "listener" => listener.to_string(),
        "protocol" => protocol.to_string()
    )
    .increment(summary.message_bytes);
    counter!(
        "qpx_rpc_message_bytes_total",
        "direction" => direction,
        "listener" => listener.to_string(),
        "protocol" => protocol.to_string()
    )
    .increment(summary.message_bytes);
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn emit_grpc_status_metric(
    listener: &str,
    protocol: &str,
    headers: &HeaderMap,
    trailers: Option<&HeaderMap>,
) {
    let (status, _) = if protocol == "connect" {
        extract_connect_stream_status_and_message(trailers)
    } else {
        extract_grpc_status_and_message(headers, trailers)
    };
    if let Some(status) = status {
        counter!(
            "qpx_grpc_status_total",
            "listener" => listener.to_string(),
            "protocol" => protocol.to_string(),
            "status" => status.clone()
        )
        .increment(1);
        counter!(
            "qpx_rpc_status_total",
            "listener" => listener.to_string(),
            "protocol" => protocol.to_string(),
            "status" => status
        )
        .increment(1);
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
fn extract_connect_stream_status_and_message(
    trailers: Option<&HeaderMap>,
) -> (Option<String>, Option<String>) {
    let status = trailers
        .and_then(|headers| headers.get("connect-code"))
        .and_then(|value| value.to_str().ok())
        .map(normalize_connect_code);
    let message = trailers
        .and_then(|headers| headers.get("connect-message"))
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    (status, message)
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn emit_grpc_stream_duration_metric(
    listener: &str,
    protocol: &str,
    streaming: &str,
    duration: Duration,
) {
    histogram!(
        "qpx_grpc_stream_duration_seconds",
        "listener" => listener.to_string(),
        "protocol" => protocol.to_string(),
        "streaming" => streaming.to_string()
    )
    .record(duration.as_secs_f64());
    histogram!(
        "qpx_rpc_stream_duration_seconds",
        "listener" => listener.to_string(),
        "protocol" => protocol.to_string(),
        "streaming" => streaming.to_string()
    )
    .record(duration.as_secs_f64());
}
