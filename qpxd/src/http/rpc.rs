use crate::http::body::Body;
use crate::http::body_size::{
    observed_request_bytes, observed_request_size, observed_request_trailers,
    observed_response_bytes, observed_response_size, observed_response_trailers,
};
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use percent_encoding::percent_decode_str;
use qpx_core::config::RpcLocalResponseConfig;
use serde_json::json;

#[derive(Debug, Clone, Default)]
pub(crate) struct RpcMatchContext {
    pub(crate) protocol: Option<String>,
    pub(crate) service: Option<String>,
    pub(crate) method: Option<String>,
    pub(crate) streaming: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) message_size: Option<u64>,
    pub(crate) message: Option<String>,
    pub(crate) trailers: Option<HeaderMap>,
    pub(crate) request_message_count: Option<usize>,
}

#[derive(Debug, Clone, Default)]
struct FramedBodySummary {
    message_count: usize,
    message_bytes: u64,
    trailers: Option<HeaderMap>,
}

pub(crate) fn inspect_request(req: &Request<Body>) -> RpcMatchContext {
    let protocol = detect_rpc_protocol(req.headers(), None);
    let (service, method) = extract_service_and_method(req.uri().path())
        .map(|(service, method)| (Some(service.to_string()), Some(method.to_string())))
        .unwrap_or((None, None));
    let message_size = observed_request_bytes(req)
        .and_then(|body| request_body_summary(protocol.as_deref(), req.headers(), body).ok())
        .map(|summary| summary.message_bytes)
        .filter(|size| *size > 0)
        .or_else(|| observed_request_size(req));
    let request_message_count = observed_request_bytes(req)
        .and_then(|body| request_body_summary(protocol.as_deref(), req.headers(), body).ok())
        .map(|summary| summary.message_count);
    let streaming = infer_request_streaming(
        protocol.as_deref(),
        req.method().as_str(),
        request_message_count,
    )
    .map(str::to_string);
    RpcMatchContext {
        protocol,
        service,
        method,
        streaming,
        message_size,
        trailers: observed_request_trailers(req).cloned(),
        request_message_count,
        ..Default::default()
    }
}

pub(crate) fn inspect_response(
    request: &RpcMatchContext,
    response: &Response<Body>,
) -> RpcMatchContext {
    let protocol = detect_rpc_protocol(response.headers(), request.protocol.as_deref())
        .or_else(|| request.protocol.clone());
    let content_type = response_content_type(response.headers());
    let body_summary = observed_response_bytes(response).and_then(|body| {
        response_body_summary(protocol.as_deref(), content_type.as_deref(), body).ok()
    });
    let trailers = observed_response_trailers(response).cloned().or_else(|| {
        body_summary
            .as_ref()
            .and_then(|summary| summary.trailers.clone())
    });

    let (status, message) = extract_rpc_status_and_message(
        protocol.as_deref(),
        response.headers(),
        trailers.as_ref(),
        observed_response_bytes(response),
    );
    let streaming = infer_response_streaming(
        protocol.as_deref(),
        request.request_message_count,
        body_summary.as_ref().map(|summary| summary.message_count),
    )
    .map(str::to_string)
    .or_else(|| request.streaming.clone());
    let message_size = body_summary
        .as_ref()
        .map(|summary| summary.message_bytes)
        .filter(|size| *size > 0)
        .or_else(|| observed_response_size(response));

    RpcMatchContext {
        protocol,
        service: request.service.clone(),
        method: request.method.clone(),
        streaming,
        status,
        message_size,
        message,
        trailers,
        request_message_count: request.request_message_count,
    }
}

pub(crate) fn build_rpc_local_response(
    config: &RpcLocalResponseConfig,
    payload: &[u8],
) -> Result<Response<Body>> {
    match config.protocol.trim().to_ascii_lowercase().as_str() {
        "grpc" => build_grpc_local_response(config, payload),
        "grpc_web" => build_grpc_web_local_response(config, payload),
        "connect" => build_connect_local_response(config),
        other => Err(anyhow!("unsupported rpc local response protocol: {other}")),
    }
}

fn build_grpc_local_response(
    config: &RpcLocalResponseConfig,
    payload: &[u8],
) -> Result<Response<Body>> {
    let http_status = StatusCode::from_u16(config.http_status.unwrap_or(200))
        .map_err(|_| anyhow!("invalid grpc local response HTTP status"))?;
    let mut response = Response::builder()
        .status(http_status)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(build_grpc_body(config, payload)?)?;
    apply_rpc_headers(response.headers_mut(), &config.headers)?;
    Ok(response)
}

fn build_grpc_web_local_response(
    config: &RpcLocalResponseConfig,
    payload: &[u8],
) -> Result<Response<Body>> {
    let http_status = StatusCode::from_u16(config.http_status.unwrap_or(200))
        .map_err(|_| anyhow!("invalid grpc_web local response HTTP status"))?;
    let mut response = Response::builder()
        .status(http_status)
        .header(http::header::CONTENT_TYPE, "application/grpc-web+proto")
        .body(build_grpc_web_body(config, payload)?)?;
    apply_rpc_headers(response.headers_mut(), &config.headers)?;
    Ok(response)
}

fn build_connect_local_response(config: &RpcLocalResponseConfig) -> Result<Response<Body>> {
    let http_status = StatusCode::from_u16(config.http_status.unwrap_or(503))
        .map_err(|_| anyhow!("invalid connect local response HTTP status"))?;
    let mut body = serde_json::to_vec(&json!({
        "code": config.status.clone().unwrap_or_else(|| "unavailable".to_string()),
        "message": config.message.clone().unwrap_or_default(),
    }))?;
    if !config.trailers.is_empty() {
        return Err(anyhow!(
            "connect rpc local responses do not support trailers"
        ));
    }
    let mut response = Response::builder()
        .status(http_status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(std::mem::take(&mut body)))?;
    apply_rpc_headers(response.headers_mut(), &config.headers)?;
    Ok(response)
}

fn build_grpc_body(config: &RpcLocalResponseConfig, payload: &[u8]) -> Result<Body> {
    let mut trailers = HeaderMap::new();
    trailers.insert(
        http::header::HeaderName::from_static("grpc-status"),
        http::HeaderValue::from_str(config.status.as_deref().unwrap_or("0"))?,
    );
    if let Some(message) = config.message.as_deref() {
        let encoded =
            percent_encoding::utf8_percent_encode(message, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        trailers.insert(
            http::header::HeaderName::from_static("grpc-message"),
            http::HeaderValue::from_str(encoded.as_str())?,
        );
    }
    for (name, value) in &config.trailers {
        let header = http::header::HeaderName::from_bytes(name.as_bytes())?;
        let value = http::HeaderValue::from_str(value)?;
        trailers.insert(header, value);
    }

    let (mut sender, body) = Body::channel();
    let payload = Bytes::copy_from_slice(payload);
    tokio::spawn(async move {
        if !payload.is_empty() {
            let _ = sender.send_data(frame_grpc_message(payload).into()).await;
        }
        let _ = sender.send_trailers(trailers).await;
    });
    Ok(body)
}

fn build_grpc_web_body(config: &RpcLocalResponseConfig, payload: &[u8]) -> Result<Body> {
    let mut out = Vec::new();
    if !payload.is_empty() {
        out.extend_from_slice(&frame_grpc_message(Bytes::copy_from_slice(payload)));
    }

    let mut trailers = Vec::new();
    trailers.extend_from_slice(b"grpc-status: ");
    trailers.extend_from_slice(config.status.as_deref().unwrap_or("0").as_bytes());
    trailers.extend_from_slice(b"\r\n");
    if let Some(message) = config.message.as_deref() {
        let encoded =
            percent_encoding::utf8_percent_encode(message, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        trailers.extend_from_slice(b"grpc-message: ");
        trailers.extend_from_slice(encoded.as_bytes());
        trailers.extend_from_slice(b"\r\n");
    }
    for (name, value) in &config.trailers {
        trailers.extend_from_slice(name.as_bytes());
        trailers.extend_from_slice(b": ");
        trailers.extend_from_slice(value.as_bytes());
        trailers.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(&frame_grpc_web_trailers(&trailers));
    Ok(Body::from(out))
}

fn apply_rpc_headers(
    headers: &mut HeaderMap,
    custom: &std::collections::HashMap<String, String>,
) -> Result<()> {
    for (name, value) in custom {
        let header = http::header::HeaderName::from_bytes(name.as_bytes())?;
        let value = http::HeaderValue::from_str(value)?;
        headers.insert(header, value);
    }
    Ok(())
}

fn response_content_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(normalize_content_type)
}

fn detect_rpc_protocol(headers: &HeaderMap, fallback: Option<&str>) -> Option<String> {
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

fn extract_service_and_method(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_matches('/');
    let (service, method) = trimmed.split_once('/')?;
    if service.is_empty() || method.is_empty() || method.contains('/') {
        return None;
    }
    Some((service, method))
}

fn request_body_summary(
    protocol: Option<&str>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<FramedBodySummary> {
    match protocol {
        Some("grpc") => parse_grpc_frames(body),
        Some("grpc_web") => parse_grpc_web_frames(
            body,
            response_content_type(headers)
                .as_deref()
                .map(|value| value.starts_with("application/grpc-web-text"))
                .unwrap_or(false),
        ),
        _ => Ok(FramedBodySummary {
            message_count: usize::from(!body.is_empty()),
            message_bytes: body.len() as u64,
            trailers: None,
        }),
    }
}

fn response_body_summary(
    protocol: Option<&str>,
    content_type: Option<&str>,
    body: &Bytes,
) -> Result<FramedBodySummary> {
    match protocol {
        Some("grpc") => parse_grpc_frames(body),
        Some("grpc_web") => parse_grpc_web_frames(
            body,
            content_type
                .map(|value| value.starts_with("application/grpc-web-text"))
                .unwrap_or(false),
        ),
        Some("connect") => Ok(FramedBodySummary {
            message_count: usize::from(!body.is_empty()),
            message_bytes: body.len() as u64,
            trailers: None,
        }),
        _ => Ok(FramedBodySummary {
            message_count: usize::from(!body.is_empty()),
            message_bytes: body.len() as u64,
            trailers: None,
        }),
    }
}

fn parse_grpc_frames(body: &Bytes) -> Result<FramedBodySummary> {
    let mut cursor = 0usize;
    let mut summary = FramedBodySummary::default();
    while cursor + 5 <= body.len() {
        let frame_len = u32::from_be_bytes([
            body[cursor + 1],
            body[cursor + 2],
            body[cursor + 3],
            body[cursor + 4],
        ]) as usize;
        cursor += 5;
        if cursor + frame_len > body.len() {
            return Err(anyhow!("grpc frame length exceeds body length"));
        }
        summary.message_count += 1;
        summary.message_bytes += frame_len as u64;
        cursor += frame_len;
    }
    if cursor != body.len() {
        return Err(anyhow!("grpc body ended mid-frame"));
    }
    Ok(summary)
}

fn parse_grpc_web_frames(body: &Bytes, text: bool) -> Result<FramedBodySummary> {
    let decoded = if text {
        let filtered = body
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        Bytes::from(BASE64.decode(filtered)?)
    } else {
        body.clone()
    };
    let mut cursor = 0usize;
    let mut summary = FramedBodySummary::default();
    while cursor + 5 <= decoded.len() {
        let flags = decoded[cursor];
        let frame_len = u32::from_be_bytes([
            decoded[cursor + 1],
            decoded[cursor + 2],
            decoded[cursor + 3],
            decoded[cursor + 4],
        ]) as usize;
        cursor += 5;
        if cursor + frame_len > decoded.len() {
            return Err(anyhow!("grpc-web frame length exceeds body length"));
        }
        let payload = &decoded[cursor..cursor + frame_len];
        if (flags & 0x80) != 0 {
            summary.trailers = Some(parse_grpc_web_trailer_block(payload)?);
        } else {
            summary.message_count += 1;
            summary.message_bytes += frame_len as u64;
        }
        cursor += frame_len;
    }
    if cursor != decoded.len() {
        return Err(anyhow!("grpc-web body ended mid-frame"));
    }
    Ok(summary)
}

fn parse_grpc_web_trailer_block(raw: &[u8]) -> Result<HeaderMap> {
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

fn extract_rpc_status_and_message(
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

fn extract_grpc_status_and_message(
    headers: &HeaderMap,
    trailers: Option<&HeaderMap>,
) -> (Option<String>, Option<String>) {
    let source = trailers.unwrap_or(headers);
    let status = source
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let message = source
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .map(|value| percent_decode_str(value).decode_utf8_lossy().to_string());
    (status, message)
}

fn extract_connect_status_and_message(body: Option<&Bytes>) -> (Option<String>, Option<String>) {
    let Some(body) = body else {
        return (None, None);
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return (None, None);
    };
    let status = value
        .get("code")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let message = value
        .get("message")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    (status, message)
}

fn infer_request_streaming(
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

fn infer_response_streaming(
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

fn frame_grpc_message(bytes: Bytes) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + bytes.len());
    out.push(0);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&bytes);
    out
}

fn frame_grpc_web_trailers(trailers: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + trailers.len());
    out.push(0x80);
    out.extend_from_slice(&(trailers.len() as u32).to_be_bytes());
    out.extend_from_slice(trailers);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use qpx_core::config::RpcLocalResponseConfig;
    use std::collections::HashMap;

    #[test]
    fn parses_grpc_web_trailer_frame() {
        let body = Bytes::from(frame_grpc_web_trailers(
            b"grpc-status: 7\r\ngrpc-message: denied\r\n",
        ));
        let summary = parse_grpc_web_frames(&body, false).expect("summary");
        let trailers = summary.trailers.expect("trailers");
        assert_eq!(
            trailers
                .get("grpc-status")
                .and_then(|value| value.to_str().ok()),
            Some("7")
        );
        assert_eq!(summary.message_count, 0);
    }

    #[test]
    fn grpc_path_extracts_service_and_method() {
        assert_eq!(
            extract_service_and_method("/demo.Echo/Say"),
            Some(("demo.Echo", "Say"))
        );
        assert!(extract_service_and_method("/invalid").is_none());
    }

    #[tokio::test]
    async fn grpc_local_response_emits_trailers() {
        let response = build_rpc_local_response(
            &RpcLocalResponseConfig {
                protocol: "grpc".to_string(),
                status: Some("14".to_string()),
                message: Some("unavailable".to_string()),
                http_status: Some(200),
                headers: HashMap::new(),
                trailers: HashMap::new(),
            },
            b"",
        )
        .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        assert!(body.data().await.is_none());
        let trailers = body.trailers().await.expect("trailers").expect("present");
        assert_eq!(
            trailers
                .get("grpc-status")
                .and_then(|value| value.to_str().ok()),
            Some("14")
        );
    }

    #[tokio::test]
    async fn grpc_web_local_response_emits_trailer_frame() {
        let response = build_rpc_local_response(
            &RpcLocalResponseConfig {
                protocol: "grpc_web".to_string(),
                status: Some("7".to_string()),
                message: Some("denied".to_string()),
                http_status: Some(200),
                headers: HashMap::new(),
                trailers: HashMap::new(),
            },
            b"",
        )
        .expect("response");
        let bytes = crate::http::body::to_bytes(response.into_body())
            .await
            .expect("body");
        let summary = parse_grpc_web_frames(&bytes, false).expect("summary");
        assert_eq!(summary.message_count, 0);
        let trailers = summary.trailers.expect("trailers");
        assert_eq!(
            trailers
                .get("grpc-status")
                .and_then(|value| value.to_str().ok()),
            Some("7")
        );
    }
}
