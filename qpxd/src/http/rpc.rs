use crate::http::body::Body;
use crate::http::body_size::{
    observed_request_bytes, observed_request_size, observed_request_trailers,
    observed_response_bytes, observed_response_size, observed_response_trailers,
};
use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use metrics::counter;
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
use metrics::histogram;
use percent_encoding::percent_decode_str;
use qpx_core::config::RpcLocalResponseConfig;
use serde_json::json;
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
use std::time::Duration;

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
    pub(crate) response_message_count: Option<usize>,
    pub(crate) request_message_bytes: Option<u64>,
    pub(crate) response_message_bytes: Option<u64>,
    pub(crate) stream_duration_ms: Option<u64>,
}

impl RpcMatchContext {
    pub(crate) fn to_log_context(&self) -> qpx_observability::access_log::RpcLogContext {
        qpx_observability::access_log::RpcLogContext {
            protocol: self.protocol.clone(),
            service: self.service.clone(),
            method: self.method.clone(),
            streaming: self.streaming.clone(),
            status: self.status.clone(),
            message_size: self.message_size,
            message: self.message.clone(),
            request_message_count: self.request_message_count,
            response_message_count: self.response_message_count,
            request_message_bytes: self.request_message_bytes,
            response_message_bytes: self.response_message_bytes,
            stream_duration_ms: self.stream_duration_ms,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FramedBodySummary {
    message_count: usize,
    message_bytes: u64,
    trailers: Option<HeaderMap>,
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
impl FramedBodySummary {
    pub(crate) fn message_count(&self) -> usize {
        self.message_count
    }

    pub(crate) fn trailers(&self) -> Option<&HeaderMap> {
        self.trailers.as_ref()
    }
}

#[derive(Debug)]
pub(crate) enum GrpcFrameError {
    Invalid(anyhow::Error),
    MessageTooLarge { len: u64, max: u64 },
}

impl std::fmt::Display for GrpcFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(err) => write!(f, "{err}"),
            Self::MessageTooLarge { len, max } => {
                write!(f, "grpc message length {len} exceeds limit {max}")
            }
        }
    }
}

impl std::error::Error for GrpcFrameError {}

impl From<anyhow::Error> for GrpcFrameError {
    fn from(value: anyhow::Error) -> Self {
        Self::Invalid(value)
    }
}

#[derive(Debug)]
enum FrameParseState {
    Header {
        buf: [u8; 5],
        pos: usize,
    },
    Payload {
        remaining: usize,
        flags: u8,
        trailer: Option<Vec<u8>>,
    },
}

#[derive(Debug)]
pub(crate) struct GrpcFrameObserver {
    state: FrameParseState,
    summary: FramedBodySummary,
    max_message_bytes: Option<u64>,
    grpc_web: bool,
    grpc_web_text: bool,
    grpc_web_text_done: bool,
    text_buf: Vec<u8>,
}

impl GrpcFrameObserver {
    pub(crate) fn new(max_message_bytes: Option<u64>) -> Self {
        Self::for_protocol(false, false, max_message_bytes)
    }

    pub(crate) fn grpc_web(text: bool, max_message_bytes: Option<u64>) -> Self {
        Self::for_protocol(true, text, max_message_bytes)
    }

    fn for_protocol(grpc_web: bool, grpc_web_text: bool, max_message_bytes: Option<u64>) -> Self {
        Self {
            state: FrameParseState::Header {
                buf: [0; 5],
                pos: 0,
            },
            summary: FramedBodySummary::default(),
            max_message_bytes,
            grpc_web,
            grpc_web_text,
            grpc_web_text_done: false,
            text_buf: Vec::new(),
        }
    }

    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Result<(), GrpcFrameError> {
        if self.grpc_web_text {
            return self.feed_grpc_web_text(chunk);
        }
        self.feed_binary(chunk)
    }

    fn feed_grpc_web_text(&mut self, chunk: &[u8]) -> Result<(), GrpcFrameError> {
        for byte in chunk
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
        {
            if self.grpc_web_text_done {
                return Err(anyhow!("grpc-web-text data found after base64 padding").into());
            }
            self.text_buf.push(byte);
        }

        while self.text_buf.len() >= 4 {
            let quantum = [
                self.text_buf[0],
                self.text_buf[1],
                self.text_buf[2],
                self.text_buf[3],
            ];
            let padded = quantum.contains(&b'=');
            if padded && self.text_buf.len() > 4 {
                return Err(anyhow!("grpc-web-text data found after base64 padding").into());
            }
            let decoded = BASE64.decode(quantum).map_err(|err| anyhow!(err))?;
            self.feed_binary(&decoded)?;
            self.text_buf.drain(..4);
            if padded {
                self.grpc_web_text_done = true;
                break;
            }
        }
        Ok(())
    }

    fn feed_binary(&mut self, mut chunk: &[u8]) -> Result<(), GrpcFrameError> {
        while !chunk.is_empty() {
            match &mut self.state {
                FrameParseState::Header { buf, pos } => {
                    let take = (5 - *pos).min(chunk.len());
                    buf[*pos..*pos + take].copy_from_slice(&chunk[..take]);
                    *pos += take;
                    chunk = &chunk[take..];
                    if *pos == 5 {
                        let flags = buf[0];
                        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as u64;
                        if let Some(max) = self.max_message_bytes
                            && len > max
                        {
                            return Err(GrpcFrameError::MessageTooLarge { len, max });
                        }
                        let is_trailer = self.grpc_web && (flags & 0x80) != 0;
                        if is_trailer {
                            self.state = FrameParseState::Payload {
                                remaining: len as usize,
                                flags,
                                trailer: Some(Vec::with_capacity(len as usize)),
                            };
                        } else {
                            self.summary.message_count += 1;
                            self.summary.message_bytes =
                                self.summary.message_bytes.saturating_add(len);
                            self.state = FrameParseState::Payload {
                                remaining: len as usize,
                                flags,
                                trailer: None,
                            };
                        }
                    }
                }
                FrameParseState::Payload {
                    remaining,
                    flags,
                    trailer,
                } => {
                    let take = (*remaining).min(chunk.len());
                    if let Some(trailer) = trailer {
                        trailer.extend_from_slice(&chunk[..take]);
                    }
                    *remaining -= take;
                    chunk = &chunk[take..];
                    if *remaining == 0 {
                        let completed_trailer =
                            ((*flags & 0x80) != 0).then(|| trailer.take()).flatten();
                        self.state = FrameParseState::Header {
                            buf: [0; 5],
                            pos: 0,
                        };
                        if let Some(trailer) = completed_trailer {
                            self.summary.trailers = Some(parse_grpc_web_trailer_block(&trailer)?);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<FramedBodySummary, GrpcFrameError> {
        if self.grpc_web_text {
            if !self.text_buf.is_empty() {
                let decoded = BASE64
                    .decode(std::mem::take(&mut self.text_buf))
                    .map_err(|err| anyhow!(err))?;
                self.feed_binary(&decoded)?;
            }
            self.grpc_web_text = false;
        }
        match self.state {
            FrameParseState::Header { pos: 0, .. } => Ok(self.summary),
            _ => Err(anyhow!("grpc body ended mid-frame").into()),
        }
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[derive(Debug)]
pub(crate) struct StreamingGrpcObserver {
    protocol: String,
    inner: GrpcFrameObserver,
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
impl StreamingGrpcObserver {
    pub(crate) fn protocol(&self) -> &str {
        self.protocol.as_str()
    }

    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Result<(), GrpcFrameError> {
        self.inner.feed(chunk)
    }

    pub(crate) fn finish(self) -> Result<FramedBodySummary, GrpcFrameError> {
        self.inner.finish()
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn streaming_grpc_protocol(
    headers: &HeaderMap,
    fallback: Option<&str>,
) -> Option<String> {
    detect_rpc_protocol(headers, fallback)
        .filter(|protocol| matches!(protocol.as_str(), "grpc" | "grpc_web"))
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn streaming_grpc_observer(
    headers: &HeaderMap,
    fallback: Option<&str>,
    max_message_bytes: Option<u64>,
) -> Option<StreamingGrpcObserver> {
    let protocol = streaming_grpc_protocol(headers, fallback)?;
    let inner = match protocol.as_str() {
        "grpc" => GrpcFrameObserver::new(max_message_bytes),
        "grpc_web" => GrpcFrameObserver::grpc_web(
            response_content_type(headers)
                .as_deref()
                .map(|value| value.starts_with("application/grpc-web-text"))
                .unwrap_or(false),
            max_message_bytes,
        ),
        _ => return None,
    };
    Some(StreamingGrpcObserver { protocol, inner })
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
        "qpx_grpc_message_bytes_total",
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
    let (status, _) = extract_grpc_status_and_message(headers, trailers);
    if let Some(status) = status {
        counter!(
            "qpx_grpc_status_total",
            "listener" => listener.to_string(),
            "protocol" => protocol.to_string(),
            "status" => status
        )
        .increment(1);
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn grpc_streaming_label(
    protocol: &str,
    request_messages: Option<usize>,
    response_messages: Option<usize>,
) -> &'static str {
    infer_response_streaming(Some(protocol), request_messages, response_messages)
        .or_else(|| infer_request_streaming(Some(protocol), "POST", request_messages))
        .unwrap_or("unknown")
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
}

pub(crate) fn inspect_request(req: &Request<Body>) -> RpcMatchContext {
    let protocol = detect_rpc_protocol(req.headers(), None);
    let (service, method) = extract_service_and_method(req.uri().path())
        .map(|(service, method)| (Some(service.to_string()), Some(method.to_string())))
        .unwrap_or((None, None));
    let message_size = observed_request_bytes(req)
        .and_then(|body| summarize_request_body(protocol.as_deref(), req.headers(), body).ok())
        .map(|summary| summary.message_bytes)
        .filter(|size| *size > 0)
        .or_else(|| observed_request_size(req));
    let request_summary = observed_request_bytes(req)
        .and_then(|body| summarize_request_body(protocol.as_deref(), req.headers(), body).ok())
        .filter(|summary| summary.message_count > 0 || summary.message_bytes > 0);
    let request_message_count = request_summary
        .as_ref()
        .map(|summary| summary.message_count);
    let request_message_bytes = request_summary
        .as_ref()
        .map(|summary| summary.message_bytes);
    if let (Some(protocol), Some(summary)) = (protocol.as_deref(), request_summary.as_ref())
        && matches!(protocol, "grpc" | "grpc_web")
    {
        counter!(
            "qpx_grpc_messages_total",
            "direction" => "request",
            "listener" => "unknown",
            "protocol" => protocol.to_string()
        )
        .increment(summary.message_count as u64);
        counter!(
            "qpx_grpc_message_bytes_total",
            "direction" => "request",
            "listener" => "unknown",
            "protocol" => protocol.to_string()
        )
        .increment(summary.message_bytes);
    }
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
        request_message_bytes,
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
        summarize_response_body(protocol.as_deref(), content_type.as_deref(), body).ok()
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
    let response_message_count = body_summary.as_ref().map(|summary| summary.message_count);
    let response_message_bytes = body_summary.as_ref().map(|summary| summary.message_bytes);
    if let (Some(protocol), Some(summary)) = (protocol.as_deref(), body_summary.as_ref())
        && matches!(protocol, "grpc" | "grpc_web")
    {
        counter!(
            "qpx_grpc_messages_total",
            "direction" => "response",
            "listener" => "unknown",
            "protocol" => protocol.to_string()
        )
        .increment(summary.message_count as u64);
        counter!(
            "qpx_grpc_message_bytes_total",
            "direction" => "response",
            "listener" => "unknown",
            "protocol" => protocol.to_string()
        )
        .increment(summary.message_bytes);
    }
    if let (Some(protocol), Some(status)) = (protocol.as_deref(), status.as_deref())
        && matches!(protocol, "grpc" | "grpc_web")
    {
        counter!(
            "qpx_grpc_status_total",
            "listener" => "unknown",
            "protocol" => protocol.to_string(),
            "status" => status.to_string()
        )
        .increment(1);
    }

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
        response_message_count,
        request_message_bytes: request.request_message_bytes,
        response_message_bytes,
        stream_duration_ms: request.stream_duration_ms,
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

fn summarize_request_body(
    protocol: Option<&str>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<FramedBodySummary> {
    match protocol {
        Some("grpc") => observe_grpc_body(body, GrpcFrameObserver::new(None)),
        Some("grpc_web") => observe_grpc_body(
            body,
            GrpcFrameObserver::grpc_web(
                response_content_type(headers)
                    .as_deref()
                    .map(|value| value.starts_with("application/grpc-web-text"))
                    .unwrap_or(false),
                None,
            ),
        ),
        _ => Ok(FramedBodySummary {
            message_count: usize::from(!body.is_empty()),
            message_bytes: body.len() as u64,
            trailers: None,
        }),
    }
}

fn summarize_response_body(
    protocol: Option<&str>,
    content_type: Option<&str>,
    body: &Bytes,
) -> Result<FramedBodySummary> {
    match protocol {
        Some("grpc") => observe_grpc_body(body, GrpcFrameObserver::new(None)),
        Some("grpc_web") => observe_grpc_body(
            body,
            GrpcFrameObserver::grpc_web(
                content_type
                    .map(|value| value.starts_with("application/grpc-web-text"))
                    .unwrap_or(false),
                None,
            ),
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

fn observe_grpc_body(body: &Bytes, mut observer: GrpcFrameObserver) -> Result<FramedBodySummary> {
    observer.feed(body.as_ref())?;
    observer.finish().map_err(Into::into)
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
        let mut observer = GrpcFrameObserver::grpc_web(false, None);
        observer.feed(&body).expect("feed");
        let summary = observer.finish().expect("summary");
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
    fn parses_grpc_frame_across_chunk_boundaries() {
        let body = frame_grpc_message(Bytes::from_static(b"hello"));
        let mut observer = GrpcFrameObserver::new(None);
        for chunk in body.chunks(2) {
            observer.feed(chunk).expect("feed");
        }
        let summary = observer.finish().expect("summary");
        assert_eq!(summary.message_count, 1);
        assert_eq!(summary.message_bytes, 5);
    }

    #[test]
    fn grpc_observer_rejects_messages_over_limit() {
        let body = frame_grpc_message(Bytes::from_static(b"hello"));
        let mut observer = GrpcFrameObserver::new(Some(4));
        let err = observer.feed(&body[..5]).expect_err("too large");
        assert!(matches!(
            err,
            GrpcFrameError::MessageTooLarge { len: 5, max: 4 }
        ));
    }

    #[test]
    fn grpc_web_text_observer_decodes_incrementally() {
        let encoded = BASE64.encode(frame_grpc_message(Bytes::from_static(b"hello")));
        let mut observer = GrpcFrameObserver::grpc_web(true, None);
        for chunk in encoded.as_bytes().chunks(3) {
            observer.feed(chunk).expect("feed");
        }
        let summary = observer.finish().expect("summary");
        assert_eq!(summary.message_count, 1);
        assert_eq!(summary.message_bytes, 5);
    }

    #[test]
    fn grpc_web_text_observer_rejects_oversized_message_before_finish() {
        let encoded = BASE64.encode(frame_grpc_message(Bytes::from_static(b"hello")));
        let mut observer = GrpcFrameObserver::grpc_web(true, Some(4));
        observer
            .feed(&encoded.as_bytes()[..4])
            .expect("partial header");
        let err = observer
            .feed(&encoded.as_bytes()[4..8])
            .expect_err("frame header should reveal oversized message");
        assert!(matches!(
            err,
            GrpcFrameError::MessageTooLarge { len: 5, max: 4 }
        ));
    }

    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    #[test]
    fn streaming_observer_uses_response_fallback_protocol() {
        let headers = HeaderMap::new();
        let observer =
            streaming_grpc_observer(&headers, Some("grpc"), Some(1024)).expect("fallback observer");
        assert_eq!(observer.protocol(), "grpc");
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
        let mut observer = GrpcFrameObserver::grpc_web(false, None);
        observer.feed(&bytes).expect("feed");
        let summary = observer.finish().expect("summary");
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
