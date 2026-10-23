// Extracted from rpc/mod.rs; keep public re-exports in mod.rs.
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use percent_encoding::percent_decode_str;

use crate::http::media_type::raw_media_type;

pub(super) fn response_content_type(headers: &HeaderMap) -> Option<String> {
    raw_media_type(headers).map(|media| media.to_ascii_lowercase())
}

pub(super) fn rpc_protocol_from_content_type(raw: &str) -> Option<&'static str> {
    if raw.starts_with("application/grpc-web") {
        Some("grpc_web")
    } else if raw.starts_with("application/grpc") {
        Some("grpc")
    } else if raw.starts_with("application/connect+") {
        Some("connect")
    } else {
        None
    }
}

pub(super) fn detect_rpc_protocol(headers: &HeaderMap, fallback: Option<&str>) -> Option<String> {
    let content_type = response_content_type(headers);
    if let Some(protocol) = content_type
        .as_deref()
        .and_then(rpc_protocol_from_content_type)
    {
        return Some(protocol.to_string());
    }
    if headers.contains_key("connect-protocol-version") {
        return Some("connect".to_string());
    }
    fallback.map(str::to_string)
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

/// Decodes a Connect streaming EndStreamResponse envelope.
///
/// Unlike the unary Error shape (`{"code","message"}` at top level), a
/// streaming envelope carries `{"error":{"code","message"},"metadata":{...}}`
/// and omits `error` entirely on success. User metadata keys map to repeated
/// trailer values; the reserved protocol names never come from metadata.
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(super) fn parse_connect_end_stream_metadata(raw: &[u8]) -> Result<HeaderMap> {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

    let value: serde_json::Value = serde_json::from_slice(raw)?;
    let mut headers = HeaderMap::new();
    match value.get("error") {
        None | Some(serde_json::Value::Null) => {
            headers.insert(
                http::header::HeaderName::from_static("connect-code"),
                http::HeaderValue::from_static("ok"),
            );
        }
        Some(error) => {
            if let Some(code) = error.get("code").and_then(|v| v.as_str()) {
                headers.insert(
                    http::header::HeaderName::from_static("connect-code"),
                    http::HeaderValue::from_str(code)?,
                );
            }
            if let Some(message) = error.get("message").and_then(|v| v.as_str()) {
                // Messages are free-form JSON strings and may carry newlines
                // or controls; store them with the same percent-encoding the
                // grpc-message boundary uses so any valid envelope observes.
                let encoded = utf8_percent_encode(message, NON_ALPHANUMERIC).to_string();
                headers.insert(
                    http::header::HeaderName::from_static("connect-message"),
                    http::HeaderValue::from_str(encoded.as_str())?,
                );
            }
        }
    }
    if let Some(metadata) = value.get("metadata").and_then(|v| v.as_object()) {
        for (name, values) in metadata {
            if name == "connect-code" || name == "connect-message" {
                continue;
            }
            // User metadata is telemetry only: entries that cannot be
            // represented as trailers are skipped rather than aborting the
            // whole observation and losing the protocol status.
            let Ok(name) = http::header::HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            if let Some(single) = values.as_str()
                && let Ok(value) = http::HeaderValue::from_str(single)
            {
                headers.append(name, value);
            } else if let Some(multiple) = values.as_array() {
                for item in multiple {
                    if let Some(item) = item.as_str()
                        && let Ok(value) = http::HeaderValue::from_str(item)
                    {
                        headers.append(name.clone(), value);
                    }
                }
            }
        }
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
        // Parsed end-stream trailers win when present; otherwise the body is
        // a unary JSON error.
        Some("connect") if trailers.is_some_and(|t| t.contains_key("connect-code")) => {
            extract_connect_stream_status_and_message(trailers)
        }
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

/// Extracts Connect status from parsed end-stream trailers.
///
/// Reading the decoded trailer form keeps buffered and streaming observation
/// on one path; the message is stored percent-encoded at the trailer
/// boundary, mirroring `grpc-message`.
pub(super) fn extract_connect_stream_status_and_message(
    trailers: Option<&HeaderMap>,
) -> (Option<String>, Option<String>) {
    let status = trailers
        .and_then(|headers| headers.get("connect-code"))
        .and_then(|value| value.to_str().ok())
        .map(normalize_connect_code);
    let message = trailers
        .and_then(|headers| headers.get("connect-message"))
        .and_then(|value| value.to_str().ok())
        .map(|value| percent_decode_str(value).decode_utf8_lossy().to_string());
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
        // Connect GET is a unary variant, never server streaming.
        Some("connect") if method.eq_ignore_ascii_case("GET") => Some("unary"),
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
