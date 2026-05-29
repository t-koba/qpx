use crate::http::body::Body;
use crate::http::protocol::l7::finalize_response_for_request;
use crate::http3::codec::prepare_h3_response_head;
use crate::http3::stream_limits::timeout_or_deadline;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use hyper::Response;
use tokio::time::{Duration, Instant};

pub struct H3ResponseSendOptions<'a> {
    pub max_body_bytes: usize,
    pub body_read_timeout: Duration,
    pub body_send_timeout: Duration,
    pub listener_name: Option<&'a str>,
    pub fallback_grpc_protocol: Option<&'a str>,
    pub max_grpc_message_bytes: Option<u64>,
    pub max_grpc_web_trailer_bytes: Option<u64>,
    pub grpc_stream_deadline: Option<Instant>,
    pub sse_policy: Option<qpx_core::config::SseStreamingPolicy>,
    pub observe_grpc_messages: bool,
}

#[derive(Debug)]
pub enum H3ResponseSendError {
    BeforeResponseHead(anyhow::Error),
    AfterResponseHead(anyhow::Error),
}

impl H3ResponseSendError {
    pub fn can_send_error_response(&self) -> bool {
        matches!(self, Self::BeforeResponseHead(_))
    }

    pub fn into_inner(self) -> anyhow::Error {
        match self {
            Self::BeforeResponseHead(err) | Self::AfterResponseHead(err) => err,
        }
    }
}

impl std::fmt::Display for H3ResponseSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeResponseHead(err) => write!(f, "before response head: {err}"),
            Self::AfterResponseHead(err) => write!(f, "after response head: {err}"),
        }
    }
}

impl std::error::Error for H3ResponseSendError {}

impl H3ResponseSendOptions<'_> {
    fn unobserved(max_body_bytes: usize, body_read_timeout: Duration) -> Self {
        Self {
            max_body_bytes,
            body_read_timeout,
            body_send_timeout: body_read_timeout,
            listener_name: None,
            fallback_grpc_protocol: None,
            max_grpc_message_bytes: None,
            max_grpc_web_trailer_bytes: None,
            grpc_stream_deadline: None,
            sse_policy: None,
            observe_grpc_messages: false,
        }
    }
}

pub(crate) async fn send_h3_response<S>(
    response: Response<Body>,
    request_method: &http::Method,
    req_stream: &mut ::h3::server::RequestStream<S, Bytes>,
    max_h3_response_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<()>
where
    S: ::h3::quic::SendStream<Bytes>,
{
    send_h3_response_observed(
        response,
        request_method,
        req_stream,
        H3ResponseSendOptions::unobserved(max_h3_response_body_bytes, body_read_timeout),
    )
    .await
    .map(|_summary| ())
    .map_err(H3ResponseSendError::into_inner)
}

pub(crate) async fn send_h3_response_observed<S>(
    response: Response<Body>,
    request_method: &http::Method,
    req_stream: &mut ::h3::server::RequestStream<S, Bytes>,
    options: H3ResponseSendOptions<'_>,
) -> std::result::Result<Option<crate::http::rpc::FramedBodySummary>, H3ResponseSendError>
where
    S: ::h3::quic::SendStream<Bytes>,
{
    let (parts, mut body) = response.into_parts();
    let mut grpc_observer = options
        .observe_grpc_messages
        .then(|| {
            crate::http::rpc::streaming_rpc_observer(
                &parts.headers,
                options.fallback_grpc_protocol,
                options.max_grpc_message_bytes,
                options.max_grpc_web_trailer_bytes,
            )
        })
        .flatten();
    let grpc_protocol = grpc_observer
        .as_ref()
        .map(|observer| observer.protocol().to_string());
    let prepared = prepare_h3_response_head(&parts, request_method)
        .map_err(H3ResponseSendError::BeforeResponseHead)?;
    let (body_read_timeout, body_send_timeout, stream_deadline) = response_stream_timeouts(
        &parts.headers,
        options.body_read_timeout,
        options.body_send_timeout,
        options.grpc_stream_deadline,
        options.sse_policy,
    );
    let mut sse_observer = options
        .listener_name
        .filter(|_| crate::http::modules::is_event_stream_headers(&parts.headers))
        .map(|_| crate::http::protocol::sse::SseEventObserver::new());
    let sse_started = Instant::now();
    timeout_or_deadline(
        req_stream.send_response(prepared.head),
        body_send_timeout,
        stream_deadline,
        "HTTP/3 response HEADERS send timed out",
        "HTTP/3 gRPC stream duration exceeded configured limit",
    )
    .await
    .map_err(|err| {
        req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
        H3ResponseSendError::BeforeResponseHead(err)
    })?
    .map_err(|err| {
        req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
        H3ResponseSendError::BeforeResponseHead(err.into())
    })?;
    if !prepared.body_allowed {
        if options.observe_grpc_messages
            && let (Some(listener), Some(protocol)) =
                (options.listener_name, grpc_protocol.as_deref())
        {
            crate::http::rpc::emit_grpc_status_metric(listener, protocol, &parts.headers, None);
        }
        timeout_or_deadline(
            req_stream.finish(),
            body_send_timeout,
            stream_deadline,
            "HTTP/3 response finish timed out",
            "HTTP/3 gRPC stream duration exceeded configured limit",
        )
        .await
        .map_err(|err| {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            H3ResponseSendError::AfterResponseHead(err)
        })?
        .map_err(|err| {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            H3ResponseSendError::AfterResponseHead(err.into())
        })?;
        return Ok(None);
    }

    let mut bytes_sent = 0usize;
    loop {
        let read_started = Instant::now();
        let chunk = match timeout_or_deadline(
            body.data(),
            body_read_timeout,
            stream_deadline,
            "HTTP/3 response body read timed out",
            "HTTP/3 gRPC stream duration exceeded configured limit",
        )
        .await
        {
            Ok(chunk) => {
                if read_started.elapsed() >= body_read_timeout.mul_f64(0.8)
                    && let Some(listener) = options.listener_name
                {
                    crate::http::protocol::sse::emit_slow_upstream_body(listener);
                }
                chunk
            }
            Err(err) => {
                if sse_observer.is_some()
                    && let Some(listener) = options.listener_name
                {
                    crate::http::protocol::sse::emit_sse_idle_disconnect(listener, "unknown");
                }
                req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
                return Err(H3ResponseSendError::AfterResponseHead(err));
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                req_stream.stop_stream(::h3::error::Code::H3_MESSAGE_ERROR);
                return Err(H3ResponseSendError::AfterResponseHead(err.into()));
            }
        };
        let next = match bytes_sent.checked_add(chunk.len()) {
            Some(next) => next,
            None => {
                req_stream.stop_stream(::h3::error::Code::H3_MESSAGE_ERROR);
                return Err(H3ResponseSendError::AfterResponseHead(anyhow!(
                    "HTTP/3 response body length overflow"
                )));
            }
        };
        if next > options.max_body_bytes {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            return Err(H3ResponseSendError::AfterResponseHead(anyhow!(
                "HTTP/3 response body exceeds configured limit: {} bytes",
                options.max_body_bytes
            )));
        }
        if let Some(content_length) = prepared.content_length
            && next as u64 > content_length
        {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            return Err(H3ResponseSendError::AfterResponseHead(anyhow!(
                "HTTP/3 response body exceeds Content-Length"
            )));
        }
        if let Some(observer) = grpc_observer.as_mut()
            && let Err(err) = observer.feed(chunk.as_ref())
        {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            return Err(H3ResponseSendError::AfterResponseHead(anyhow!(err)));
        }
        if let Some(observer) = sse_observer.as_mut() {
            observer.feed(chunk.as_ref());
        }
        bytes_sent = next;
        timeout_or_deadline(
            req_stream.send_data(chunk),
            body_send_timeout,
            stream_deadline,
            "HTTP/3 response DATA send timed out",
            "HTTP/3 gRPC stream duration exceeded configured limit",
        )
        .await
        .map_err(|err| {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            H3ResponseSendError::AfterResponseHead(err)
        })?
        .map_err(|err| {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            H3ResponseSendError::AfterResponseHead(err.into())
        })?;
    }

    if let (Some(listener), Some(observer)) = (options.listener_name, sse_observer.as_ref()) {
        crate::http::protocol::sse::emit_sse_summary(
            listener,
            "unknown",
            &observer.summary(),
            sse_started.elapsed(),
        );
    }

    if let Some(content_length) = prepared.content_length
        && content_length != bytes_sent as u64
    {
        req_stream.stop_stream(::h3::error::Code::H3_MESSAGE_ERROR);
        return Err(H3ResponseSendError::AfterResponseHead(anyhow!(
            "HTTP/3 response Content-Length mismatch: expected {content_length}, got {bytes_sent}"
        )));
    }

    let trailers = timeout_or_deadline(
        body.trailers(),
        body_read_timeout,
        stream_deadline,
        "HTTP/3 response trailers read timed out",
        "HTTP/3 gRPC stream duration exceeded configured limit",
    )
    .await
    .map_err(|err| {
        req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
        H3ResponseSendError::AfterResponseHead(err)
    })?
    .map_err(|err| {
        req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
        H3ResponseSendError::AfterResponseHead(err.into())
    })?;
    let mut trailers_for_status = trailers.clone();
    if let Some(mut trailers) = trailers {
        crate::http::protocol::semantics::sanitize_response_trailers(&mut trailers);
        let trailers = crate::http3::codec::http_headers_to_h1(&trailers)
            .map_err(H3ResponseSendError::AfterResponseHead)?;
        timeout_or_deadline(
            req_stream.send_trailers(trailers),
            body_send_timeout,
            stream_deadline,
            "HTTP/3 response trailers send timed out",
            "HTTP/3 gRPC stream duration exceeded configured limit",
        )
        .await
        .map_err(|err| {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            H3ResponseSendError::AfterResponseHead(err)
        })?
        .map_err(|err| {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            H3ResponseSendError::AfterResponseHead(err.into())
        })?;
    }
    let summary = if let Some(observer) = grpc_observer {
        let protocol = observer.protocol().to_string();
        let summary = observer.finish().map_err(|err| {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            H3ResponseSendError::AfterResponseHead(anyhow!(err))
        })?;
        if trailers_for_status.is_none() {
            trailers_for_status = summary.trailers().cloned();
        }
        if options.observe_grpc_messages
            && let Some(listener) = options.listener_name
        {
            crate::http::rpc::emit_grpc_body_metrics(
                "response",
                listener,
                protocol.as_str(),
                &summary,
            );
            crate::http::rpc::emit_grpc_status_metric(
                listener,
                protocol.as_str(),
                &parts.headers,
                trailers_for_status.as_ref(),
            );
        }
        Some(summary)
    } else {
        None
    };
    timeout_or_deadline(
        req_stream.finish(),
        body_send_timeout,
        stream_deadline,
        "HTTP/3 response finish timed out",
        "HTTP/3 gRPC stream duration exceeded configured limit",
    )
    .await
    .map_err(|err| {
        req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
        H3ResponseSendError::AfterResponseHead(err)
    })?
    .map_err(|err| {
        req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
        H3ResponseSendError::AfterResponseHead(err.into())
    })?;
    Ok(summary)
}

fn response_stream_timeouts(
    headers: &HeaderMap,
    default_timeout: Duration,
    default_send_timeout: Duration,
    default_deadline: Option<Instant>,
    sse_policy: Option<qpx_core::config::SseStreamingPolicy>,
) -> (Duration, Duration, Option<Instant>) {
    let Some(policy) = sse_policy else {
        return (default_timeout, default_send_timeout, default_deadline);
    };
    if !crate::http::modules::is_event_stream_headers(headers) {
        return (default_timeout, default_send_timeout, default_deadline);
    }
    let idle = Duration::from_millis(policy.idle_timeout_ms.max(1));
    let deadline = if policy.max_stream_duration_ms == 0 {
        None
    } else {
        let duration_ms = policy
            .max_stream_duration_ms
            .min(qpx_core::config::MAX_SSE_STREAM_DURATION_MS);
        Instant::now().checked_add(Duration::from_millis(duration_ms))
    };
    (idle, default_send_timeout, deadline)
}

pub(crate) async fn send_h3_static_response<S>(
    req_stream: &mut ::h3::server::RequestStream<S, Bytes>,
    status: ::http::StatusCode,
    body: &[u8],
    request_method: &http::Method,
    proxy_name: &str,
    max_h3_response_body_bytes: usize,
) -> Result<()>
where
    S: ::h3::quic::SendStream<Bytes>,
{
    let response = finalize_response_for_request(
        request_method,
        http::Version::HTTP_3,
        proxy_name,
        Response::builder()
            .status(
                crate::http::protocol::semantics::validate_http_status_class(
                    status,
                    "HTTP/3 static response",
                )?,
            )
            .body(Body::from(body.to_vec()))?,
        false,
    );
    send_h3_response(
        response,
        request_method,
        req_stream,
        max_h3_response_body_bytes,
        Duration::from_secs(1),
    )
    .await
}
