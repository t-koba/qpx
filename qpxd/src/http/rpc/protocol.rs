// Extracted from rpc/mod.rs; keep public re-exports in mod.rs.
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use percent_encoding::percent_decode_str;

pub(super) fn response_content_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(normalize_content_type)
}

pub(super) fn detect_rpc_protocol(headers: &HeaderMap, fallback: Option<&str>) -> Option<String> {
    let content_type = response_content_type(headers);
    let protocol = match content_type.as_deref() {
        Some(value) if value.starts_with("application/grpc-web") => Some("grpc_web"),
        Some(value) if value.starts_with("application/grpc") => Some("grpc"),
        Some(value) if value.starts_with("application/connect+") => Some("connect"),
        _ if headers.contains_key("connect-protocol-version") => Some("connect"),
        _ => fallback,
    };
    protocol.map(str::to_string)
}

fn normalize_content_type(raw: &str) -> String {
    raw.split(';')
        .next()
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase()
}

pub(super) fn extract_service_and_method(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_matches('/');
    let (service, method) = trimmed.split_once('/')?;
    if service.is_empty() || method.is_empty() || method.contains('/') {
        return None;
    }
    Some((service, method))
}

pub(super) fn parse_grpc_web_trailer_block(raw: &[u8]) -> Result<HeaderMap> {
    let block = std::str::from_utf8(raw)?;
    let mut headers = HeaderMap::new();
    for line in block.split("\r\n").filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(anyhow!("grpc-web trailer block line missing ':'"));
        };
        headers.insert(
            http::header::HeaderName::from_bytes(name.trim().as_bytes())?,
            http::HeaderValue::from_str(value.trim())?,
        );
    }
    Ok(headers)
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(super) fn parse_connect_end_stream_metadata(raw: &[u8]) -> Result<HeaderMap> {
    let value: serde_json::Value = serde_json::from_slice(raw)?;
    let mut headers = HeaderMap::new();
    if let Some(code) = value.get("code").and_then(|v| v.as_str()) {
        headers.insert(
            http::header::HeaderName::from_static("connect-code"),
            http::HeaderValue::from_str(code)?,
        );
    }
    if let Some(message) = value.get("message").and_then(|v| v.as_str()) {
        headers.insert(
            http::header::HeaderName::from_static("connect-message"),
            http::HeaderValue::from_str(message)?,
        );
    }
    Ok(headers)
}

pub(super) fn extract_rpc_status_and_message(
    protocol: Option<&str>,
    headers: &HeaderMap,
    trailers: Option<&HeaderMap>,
    body: Option<&Bytes>,
) -> (Option<String>, Option<String>) {
    match protocol {
        Some("grpc") | Some("grpc_web") => extract_grpc_status_and_message(headers, trailers),
        Some("connect") => extract_connect_status_and_message(body),
        _ => (None, None),
    }
}

pub(super) fn extract_grpc_status_and_message(
    headers: &HeaderMap,
    trailers: Option<&HeaderMap>,
) -> (Option<String>, Option<String>) {
    let source = trailers.unwrap_or(headers);
    let status = source
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .map(normalize_grpc_status);
    let message = source
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .map(|value| percent_decode_str(value).decode_utf8_lossy().to_string());
    (status, message)
}

pub(super) fn extract_connect_status_and_message(
    body: Option<&Bytes>,
) -> (Option<String>, Option<String>) {
    let Some(body) = body else {
        return (None, None);
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return (None, None);
    };
    let status = value
        .get("code")
        .and_then(|value| value.as_str())
        .map(normalize_connect_code);
    let message = value
        .get("message")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    (status, message)
}

pub(super) fn normalize_grpc_status(raw: &str) -> String {
    raw.parse::<u8>()
        .ok()
        .filter(|status| *status <= 16)
        .map(|status| status.to_string())
        .unwrap_or_else(|| "invalid".to_string())
}

pub(super) fn normalize_connect_code(raw: &str) -> String {
    match raw {
        "ok"
        | "canceled"
        | "unknown"
        | "invalid_argument"
        | "deadline_exceeded"
        | "not_found"
        | "already_exists"
        | "permission_denied"
        | "resource_exhausted"
        | "failed_precondition"
        | "aborted"
        | "out_of_range"
        | "unimplemented"
        | "internal"
        | "unavailable"
        | "data_loss"
        | "unauthenticated" => raw.to_string(),
        _ => "invalid".to_string(),
    }
}

pub(super) fn infer_request_streaming(
    protocol: Option<&str>,
    method: &str,
    request_messages: Option<usize>,
) -> Option<&'static str> {
    match protocol {
        Some("connect") if method.eq_ignore_ascii_case("GET") => Some("server"),
        Some("grpc") | Some("grpc_web") if request_messages.unwrap_or(0) > 1 => Some("client"),
        _ => None,
    }
}

pub(super) fn infer_response_streaming(
    protocol: Option<&str>,
    request_messages: Option<usize>,
    response_messages: Option<usize>,
) -> Option<&'static str> {
    match protocol {
        Some("grpc") | Some("grpc_web") => {
            let req_many = request_messages.unwrap_or(0) > 1;
            let resp_many = response_messages.unwrap_or(0) > 1;
            Some(match (req_many, resp_many) {
                (true, true) => "bidi",
                (true, false) => "client",
                (false, true) => "server",
                (false, false) => "unary",
            })
        }
        Some("connect") => None,
        _ => None,
    }
}
