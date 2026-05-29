// Extracted from rpc/mod.rs; keep public re-exports in mod.rs.
use super::local_response::build_rpc_local_response;
use crate::http::body::Body;
use anyhow::Result;
use http::{HeaderMap, Response};
use qpx_core::config::RpcLocalResponseConfig;
use std::time::Duration;
use tokio::time::Instant;

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RpcDeadlineProtocol {
    Grpc,
    GrpcWeb,
    Connect,
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
impl RpcDeadlineProtocol {
    fn from_name(protocol: &str) -> Self {
        match protocol {
            "connect" => Self::Connect,
            "grpc_web" => Self::GrpcWeb,
            _ => Self::Grpc,
        }
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResolvedGrpcDeadline {
    deadline: Instant,
    protocol: RpcDeadlineProtocol,
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
impl ResolvedGrpcDeadline {
    pub(crate) fn instant(self) -> Instant {
        self.deadline
    }

    pub(crate) fn protocol(self) -> RpcDeadlineProtocol {
        self.protocol
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn parse_grpc_timeout(value: &str) -> Option<Duration> {
    let value = value.trim();
    if !(2..=9).contains(&value.len()) {
        return None;
    }
    let (digits, unit) = value.split_at(value.len() - 1);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = digits.parse::<u64>().ok()?;
    match unit {
        "H" => n.checked_mul(3_600).map(Duration::from_secs),
        "M" => n.checked_mul(60).map(Duration::from_secs),
        "S" => Some(Duration::from_secs(n)),
        "m" => Some(Duration::from_millis(n)),
        "u" => Some(Duration::from_micros(n)),
        "n" => Some(Duration::from_nanos(n)),
        _ => None,
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn parse_connect_timeout_ms(value: &str) -> Option<Duration> {
    let millis = value.trim().parse::<u64>().ok()?;
    Some(Duration::from_millis(millis))
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn resolve_rpc_deadline(
    request_headers: &HeaderMap,
    protocol: &str,
    proxy_max_duration: Duration,
    started: Instant,
) -> ResolvedGrpcDeadline {
    let max_duration = Duration::from_millis(qpx_core::config::MAX_GRPC_STREAM_DURATION_MS);
    let proxy_max_duration = proxy_max_duration.min(max_duration);
    let proxy_deadline = started.checked_add(proxy_max_duration).unwrap_or(started);
    let deadline_protocol = RpcDeadlineProtocol::from_name(protocol);
    let client_duration = match deadline_protocol {
        RpcDeadlineProtocol::Connect => request_headers
            .get("connect-timeout-ms")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_connect_timeout_ms),
        RpcDeadlineProtocol::Grpc | RpcDeadlineProtocol::GrpcWeb => request_headers
            .get("grpc-timeout")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_grpc_timeout),
    };
    let client_deadline =
        client_duration.and_then(|duration| started.checked_add(duration.min(proxy_max_duration)));
    ResolvedGrpcDeadline {
        deadline: client_deadline.map_or(proxy_deadline, |deadline| deadline.min(proxy_deadline)),
        protocol: deadline_protocol,
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn format_grpc_timeout(duration: Duration) -> String {
    const MAX_DIGITS: u128 = 99_999_999;
    if duration.is_zero() {
        return "1n".to_string();
    }
    let nanos = duration.as_nanos().max(1);
    for (unit, quantum) in [
        ("m", 1_000_000_u128),
        ("u", 1_000_u128),
        ("n", 1_u128),
        ("S", 1_000_000_000_u128),
        ("M", 60_000_000_000_u128),
        ("H", 3_600_000_000_000_u128),
    ] {
        let value = nanos.div_ceil(quantum).max(1);
        if value <= MAX_DIGITS {
            return format!("{value}{unit}");
        }
    }
    format!("{MAX_DIGITS}H")
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn apply_grpc_deadline_header(headers: &mut HeaderMap, deadline: ResolvedGrpcDeadline) {
    let remaining = deadline.instant().saturating_duration_since(Instant::now());
    match deadline.protocol() {
        RpcDeadlineProtocol::Connect => {
            headers.remove("grpc-timeout");
            let millis = remaining.as_millis().clamp(1, u128::from(u64::MAX));
            if let Ok(value) = http::HeaderValue::from_str(millis.to_string().as_str()) {
                headers.insert("connect-timeout-ms", value);
            }
        }
        RpcDeadlineProtocol::Grpc | RpcDeadlineProtocol::GrpcWeb => {
            headers.remove("connect-timeout-ms");
            if let Ok(value) = http::HeaderValue::from_str(format_grpc_timeout(remaining).as_str())
            {
                headers.insert("grpc-timeout", value);
            }
        }
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn build_grpc_deadline_exceeded_response(protocol: &str) -> Result<Response<Body>> {
    let config = RpcLocalResponseConfig {
        protocol: protocol.to_string(),
        status: Some(match protocol {
            "connect" => "deadline_exceeded".to_string(),
            _ => "4".to_string(),
        }),
        message: Some("deadline exceeded at proxy".to_string()),
        http_status: Some(if protocol == "connect" { 504 } else { 200 }),
        headers: Default::default(),
        trailers: Default::default(),
    };
    build_rpc_local_response(&config, &[])
}
