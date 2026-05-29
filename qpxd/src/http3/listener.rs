use crate::http::body::Body;
use crate::http::body::size::set_observed_request_size;
use crate::http3::codec::{h3_request_to_hyper, sanitize_interim_response_for_h3};
use crate::http3::datagram::{DatagramRegistration, H3DatagramDispatch, H3StreamDatagrams};
use crate::http3::server::{
    H3IncomingBodyCompletion, H3IncomingBodyOptions, H3ResponseSendOptions, H3ServerRequestStream,
    H3ServerSendStream, h3_incoming_body, send_h3_response, send_h3_response_observed,
    send_h3_static_response,
};
use crate::runtime::ResolvedStreamingLimits;
use anyhow::Result;
use async_trait::async_trait;
use hyper::{Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{Duration, Instant};
use tracing::warn;

mod connection;
mod scheduler;

pub(crate) use self::connection::serve_endpoint;
use self::scheduler::{ScheduledH3Stream, request_priority, run_priority_scheduler};

#[derive(Debug, Clone)]
pub(crate) struct H3Limits {
    pub(crate) listener_name: Arc<str>,
    pub(crate) max_concurrent_streams_per_connection: usize,
    pub(crate) datagram_channel_capacity: usize,
    pub(crate) streaming: ResolvedStreamingLimits,
    pub(crate) read_timeout: Duration,
    pub(crate) proxy_name: Arc<str>,
    pub(crate) error_body: Arc<str>,
}

#[derive(Debug, Clone)]
pub(crate) struct H3ConnInfo {
    pub(crate) remote_addr: SocketAddr,
    pub(crate) dst_port: u16,
    pub(crate) tls_sni: Option<Arc<str>>,
    pub(crate) peer_certificates: Option<Arc<Vec<Vec<u8>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum H3ConnectKind {
    Connect,
    ConnectUdp,
    Extended(::h3::ext::Protocol),
}

fn classify_h3_connect_kind(protocol: Option<::h3::ext::Protocol>) -> H3ConnectKind {
    match protocol {
        Some(::h3::ext::Protocol::CONNECT_UDP) => H3ConnectKind::ConnectUdp,
        Some(other) => H3ConnectKind::Extended(other),
        None => H3ConnectKind::Connect,
    }
}

pub(crate) struct H3HttpResponse {
    pub(crate) interim: Vec<::http::Response<()>>,
    pub(crate) response: Response<Body>,
}

type H3RequestBodyResult =
    std::result::Result<Option<crate::http::rpc::FramedBodySummary>, anyhow::Error>;

fn reject_malformed_h3_request(req_stream: &mut H3ServerRequestStream) {
    let code = ::h3::error::Code::H3_MESSAGE_ERROR;
    req_stream.stop_stream(code);
    req_stream.stop_sending(code);
}

fn reject_malformed_h3_response_stream(req_stream: &mut H3ServerSendStream) {
    req_stream.stop_stream(::h3::error::Code::H3_MESSAGE_ERROR);
}

async fn finish_h3_request_body(completion: H3IncomingBodyCompletion) -> H3RequestBodyResult {
    completion.finish().await.map(|(_bytes, summary)| summary)
}

fn take_finished_h3_request_body(
    request_body: &mut Option<H3IncomingBodyCompletion>,
) -> Option<H3RequestBodyResult> {
    let result = request_body.as_mut()?.try_take_result()?;
    request_body.take();
    Some(result.map(|(_bytes, summary)| summary))
}

async fn finish_h3_request_body_before_response(
    request_body: &mut Option<H3IncomingBodyCompletion>,
    request_summary: &mut Option<crate::http::rpc::FramedBodySummary>,
    send_stream: &mut H3ServerSendStream,
    message: &'static str,
) -> bool {
    let Some(completion) = request_body.take() else {
        return true;
    };
    match finish_h3_request_body(completion).await {
        Ok(summary) => {
            *request_summary = summary;
            true
        }
        Err(err) => {
            warn!(error = ?err, "{message}");
            reject_malformed_h3_response_stream(send_stream);
            false
        }
    }
}

impl H3HttpResponse {
    pub(crate) fn final_only(response: Response<Body>) -> Self {
        Self {
            interim: Vec::new(),
            response,
        }
    }
}

#[async_trait]
pub(crate) trait H3RequestHandler: Clone + Send + Sync + 'static {
    fn limits(&self) -> H3Limits;

    fn enable_extended_connect(&self) -> bool {
        false
    }

    fn enable_datagram(&self) -> bool {
        false
    }

    async fn handle_http(&self, req: Request<Body>, conn: H3ConnInfo) -> Response<Body>;

    async fn handle_http_with_interim(
        &self,
        req: Request<Body>,
        conn: H3ConnInfo,
    ) -> H3HttpResponse {
        H3HttpResponse::final_only(self.handle_http(req, conn).await)
    }

    async fn handle_connect(
        &self,
        req_head: ::http::Request<()>,
        req_stream: H3ServerRequestStream,
        conn: H3ConnInfo,
        kind: H3ConnectKind,
        datagrams: Option<H3StreamDatagrams>,
    ) -> Result<()>;
}

async fn handle_stream<H: H3RequestHandler>(
    req_head: ::http::Request<()>,
    mut req_stream: H3ServerRequestStream,
    conn_info: H3ConnInfo,
    handler: H,
    limits: H3Limits,
    datagrams: Option<H3StreamDatagrams>,
    disabled_datagram_registration: Option<DatagramRegistration>,
) {
    let _disabled_datagram_registration = disabled_datagram_registration;
    let request_method = req_head
        .method()
        .as_str()
        .parse::<http::Method>()
        .unwrap_or(http::Method::GET);

    if let Err(err) = crate::http::protocol::semantics::validate_h2_h3_request_headers(
        http::Version::HTTP_3,
        req_head.headers(),
    ) {
        warn!(error = ?err, "malformed HTTP/3 request headers");
        reject_malformed_h3_request(&mut req_stream);
        return;
    }
    let declared_content_length = match parse_content_length(req_head.headers()) {
        Ok(length) => length,
        Err(err) => {
            warn!(error = %err, "invalid HTTP/3 request content-length");
            reject_malformed_h3_request(&mut req_stream);
            return;
        }
    };

    if req_head.method() == ::http::Method::CONNECT {
        let kind =
            classify_h3_connect_kind(req_head.extensions().get::<::h3::ext::Protocol>().copied());
        if let Err(err) = handler
            .handle_connect(req_head, req_stream, conn_info, kind, datagrams)
            .await
        {
            warn!(error = ?err, "HTTP/3 CONNECT handling failed");
        }
        return;
    }

    match parse_expect_continue(req_head.headers()) {
        Ok(true) => {
            let continue_head = match ::http::Response::builder()
                .status(::http::StatusCode::CONTINUE)
                .body(())
            {
                Ok(head) => head,
                Err(err) => {
                    warn!(error = ?err, "failed to build HTTP/3 100-continue response");
                    return;
                }
            };
            let send_result =
                tokio::time::timeout(limits.read_timeout, req_stream.send_response(continue_head))
                    .await;
            if let Err(err) = send_result
                .map_err(|_| anyhow::anyhow!("HTTP/3 100-continue send timed out"))
                .and_then(|result| result.map_err(Into::into))
            {
                warn!(error = ?err, "failed to send HTTP/3 100-continue response");
                return;
            }
        }
        Ok(false) => {}
        Err(_) => {
            let _ = send_h3_static_response(
                &mut req_stream,
                ::http::StatusCode::EXPECTATION_FAILED,
                b"expectation failed",
                &request_method,
                limits.proxy_name.as_ref(),
                limits.streaming.max_response_body_bytes,
            )
            .await;
            return;
        }
    }

    if let Some(content_length) = declared_content_length
        && content_length > limits.streaming.max_request_body_bytes as u64
    {
        warn!(
            content_length,
            limit = limits.streaming.max_request_body_bytes,
            "HTTP/3 request content-length exceeds configured limit"
        );
        if let Err(err) = send_h3_static_response(
            &mut req_stream,
            ::http::StatusCode::PAYLOAD_TOO_LARGE,
            b"request payload too large",
            &request_method,
            limits.proxy_name.as_ref(),
            limits.streaming.max_response_body_bytes,
        )
        .await
        {
            warn!(error = ?err, "failed to send HTTP/3 payload-too-large response");
        }
        return;
    }

    let request_headers = req_head.headers().clone();
    if crate::http::protocol::sse::is_sse_reconnect(&request_headers) {
        crate::http::protocol::sse::emit_sse_reconnect(limits.listener_name.as_ref(), "unknown");
    }
    let grpc_protocol = crate::http::rpc::streaming_rpc_protocol(&request_headers, None);
    let grpc_started = Instant::now();
    let grpc_deadline = grpc_protocol.as_deref().map(|protocol| {
        crate::http::rpc::resolve_rpc_deadline(
            &request_headers,
            protocol,
            Duration::from_millis(limits.streaming.max_grpc_stream_duration_ms),
            grpc_started,
        )
    });

    let (mut send_stream, recv_stream) = req_stream.split();
    let request_read_timeout = Duration::from_millis(limits.streaming.body_read_timeout_ms);
    let max_request_body_bytes = limits.streaming.max_request_body_bytes;
    let listener_name = limits.listener_name.clone();
    let max_grpc_message_bytes = limits.streaming.max_grpc_message_bytes;
    let max_grpc_web_trailer_bytes = limits.streaming.max_grpc_web_trailer_bytes;
    let (body, request_body_completion) = h3_incoming_body(
        recv_stream,
        H3IncomingBodyOptions {
            read_timeout: request_read_timeout,
            max_body_bytes: max_request_body_bytes,
            declared_content_length,
            request_headers,
            listener_name,
            max_grpc_message_bytes: Some(max_grpc_message_bytes),
            max_grpc_web_trailer_bytes: Some(max_grpc_web_trailer_bytes),
            grpc_stream_deadline: grpc_deadline.map(|deadline| deadline.instant()),
            observe_grpc_messages: limits.streaming.observe_grpc_messages,
        },
    );
    let mut request_body = Some(request_body_completion);
    let mut req = match h3_request_to_hyper(req_head, body) {
        Ok(req) => req,
        Err(err) => {
            warn!(error = ?err, "invalid HTTP/3 request");
            reject_malformed_h3_response_stream(&mut send_stream);
            return;
        }
    };
    if let Some(content_length) = declared_content_length {
        set_observed_request_size(&mut req, content_length);
    }
    if let Some(deadline) = grpc_deadline {
        req.extensions_mut().insert(deadline);
    }
    if let Some(priority) = req
        .headers()
        .get("priority")
        .and_then(|value| value.to_str().ok())
        .map(crate::http3::priority::parse_priority)
    {
        req.extensions_mut().insert(priority);
    }
    let response = if let Some(deadline) = grpc_deadline {
        match tokio::time::timeout_at(
            deadline.instant(),
            handler.handle_http_with_interim(req, conn_info),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => {
                drop(request_body.take());
                warn!("HTTP/3 gRPC stream duration exceeded configured limit");
                if let Some(protocol) = grpc_protocol.as_deref() {
                    crate::http::rpc::emit_grpc_deadline_exceeded_metric(
                        limits.listener_name.as_ref(),
                        protocol,
                    );
                    match crate::http::rpc::build_grpc_deadline_exceeded_response(protocol) {
                        Ok(response) => {
                            if let Err(err) = send_h3_response(
                                response,
                                &request_method,
                                &mut send_stream,
                                limits.streaming.max_response_body_bytes,
                                Duration::from_secs(1),
                            )
                            .await
                            {
                                warn!(error = ?err, "failed to send HTTP/3 gRPC deadline response");
                            }
                        }
                        Err(err) => warn!(error = ?err, "failed to build gRPC deadline response"),
                    }
                }
                return;
            }
        }
    } else {
        handler.handle_http_with_interim(req, conn_info).await
    };
    let response_streaming = response_streaming_limits(&response.response, &limits);
    let mut request_summary = None;
    if let Some(body_result) = take_finished_h3_request_body(&mut request_body) {
        match body_result {
            Ok(summary) => request_summary = summary,
            Err(err) => {
                warn!(error = ?err, "HTTP/3 request body failed before response");
                reject_malformed_h3_response_stream(&mut send_stream);
                return;
            }
        }
    }
    for interim in response.interim {
        if let Some(body_result) = take_finished_h3_request_body(&mut request_body) {
            match body_result {
                Ok(summary) => request_summary = summary,
                Err(err) => {
                    warn!(error = ?err, "HTTP/3 request body failed before interim response");
                    reject_malformed_h3_response_stream(&mut send_stream);
                    return;
                }
            }
        }
        let interim = match sanitize_interim_response_for_h3(interim) {
            Ok(interim) => interim,
            Err(err) => {
                warn!(error = ?err, "invalid HTTP/3 interim response");
                return;
            }
        };
        if let Err(err) = tokio::time::timeout(
            Duration::from_millis(response_streaming.body_send_timeout_ms),
            send_stream.send_response(interim),
        )
        .await
        .map_err(|_| anyhow::anyhow!("HTTP/3 interim response send timed out"))
        .and_then(|result| result.map_err(Into::into))
        {
            warn!(error = ?err, "HTTP/3 interim response stream failed");
            return;
        }
    }
    if grpc_protocol.is_none()
        && !finish_h3_request_body_before_response(
            &mut request_body,
            &mut request_summary,
            &mut send_stream,
            "HTTP/3 request body failed before final response",
        )
        .await
    {
        return;
    }
    let response_result = send_h3_response_observed(
        response.response,
        &request_method,
        &mut send_stream,
        H3ResponseSendOptions {
            max_body_bytes: response_streaming.max_response_body_bytes,
            body_read_timeout: Duration::from_millis(response_streaming.body_read_timeout_ms),
            body_send_timeout: Duration::from_millis(response_streaming.body_send_timeout_ms),
            listener_name: Some(limits.listener_name.as_ref()),
            fallback_grpc_protocol: grpc_protocol.as_deref(),
            max_grpc_message_bytes: Some(response_streaming.max_grpc_message_bytes),
            max_grpc_web_trailer_bytes: Some(response_streaming.max_grpc_web_trailer_bytes),
            grpc_stream_deadline: grpc_deadline.map(|deadline| deadline.instant()),
            sse_policy: Some(response_streaming.sse),
            observe_grpc_messages: response_streaming.observe_grpc_messages,
        },
    )
    .await;
    if !finish_h3_request_body_before_response(
        &mut request_body,
        &mut request_summary,
        &mut send_stream,
        "HTTP/3 request body failed",
    )
    .await
    {
        return;
    }
    match response_result {
        Ok(response_summary) => {
            if response_streaming.observe_grpc_messages
                && let Some(protocol) = grpc_protocol.as_deref()
            {
                let streaming = crate::http::rpc::grpc_streaming_label(
                    protocol,
                    request_summary
                        .as_ref()
                        .map(|summary| summary.message_count()),
                    response_summary
                        .as_ref()
                        .map(|summary| summary.message_count()),
                );
                crate::http::rpc::emit_grpc_stream_duration_metric(
                    limits.listener_name.as_ref(),
                    protocol,
                    streaming,
                    grpc_started.elapsed(),
                );
            }
        }
        Err(err) => {
            warn!(error = ?err, "HTTP/3 response stream failed");
            if err.can_send_error_response() {
                let _ = send_h3_static_response(
                    &mut send_stream,
                    ::http::StatusCode::BAD_GATEWAY,
                    limits.error_body.as_bytes(),
                    &request_method,
                    limits.proxy_name.as_ref(),
                    limits.streaming.max_response_body_bytes,
                )
                .await;
            }
        }
    }
}

fn response_streaming_limits(
    response: &Response<Body>,
    fallback: &H3Limits,
) -> ResolvedStreamingLimits {
    response
        .extensions()
        .get::<ResolvedStreamingLimits>()
        .copied()
        .unwrap_or(fallback.streaming)
}

#[cfg(test)]
mod tests;

fn parse_content_length(headers: &http::HeaderMap) -> Result<Option<u64>, String> {
    let mut parsed: Option<u64> = None;
    for value in headers.get_all(http::header::CONTENT_LENGTH).iter() {
        let raw = value
            .to_str()
            .map_err(|err| format!("invalid Content-Length header: {err}"))?
            .trim();
        if raw.is_empty() {
            return Err("empty Content-Length header".to_string());
        }
        for part in raw.split(',') {
            let value = part
                .trim()
                .parse::<u64>()
                .map_err(|err| format!("invalid Content-Length value: {err}"))?;
            match parsed {
                Some(existing) if existing != value => {
                    return Err("conflicting Content-Length values".to_string());
                }
                Some(_) => {}
                None => parsed = Some(value),
            }
        }
    }
    Ok(parsed)
}

#[derive(Debug, Clone, Copy)]
struct InvalidExpectHeader;

fn parse_expect_continue(
    headers: &::http::HeaderMap,
) -> std::result::Result<bool, InvalidExpectHeader> {
    let mut saw_expect = false;
    for value in headers.get_all(::http::header::EXPECT).iter() {
        let raw = value.to_str().map_err(|_| InvalidExpectHeader)?;
        for token in raw.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            saw_expect = true;
            if !token.eq_ignore_ascii_case("100-continue") {
                return Err(InvalidExpectHeader);
            }
        }
    }
    if headers.contains_key(::http::header::EXPECT) && !saw_expect {
        return Err(InvalidExpectHeader);
    }
    Ok(saw_expect)
}
