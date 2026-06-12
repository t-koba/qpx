use crate::http::protocol::l7::finalize_response_for_request;
use crate::http3::codec::prepare_h3_response_head;
use crate::http3::response_error::{H3ResponseSendError, emit_h3_response_send_error};
use crate::http3::stream_limits::timeout_or_deadline;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use hyper::Response;
use qpx_http::body::Body;
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
    .map_err(|err| {
        emit_h3_response_send_error("h3", &err);
        err.into_inner()
    })
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
    let mut grpc_observer = crate::http3::response_rpc::H3ResponseRpcObserver::new(
        &parts.headers,
        options.fallback_grpc_protocol,
        options.max_grpc_message_bytes,
        options.max_grpc_web_trailer_bytes,
        options.observe_grpc_messages,
        options.listener_name,
    );
    let prepared = prepare_h3_response_head(&parts, request_method)
        .map_err(H3ResponseSendError::before_response_head)?;
    let (body_read_timeout, body_send_timeout, stream_deadline) = response_stream_timeouts(
        &parts.headers,
        options.body_read_timeout,
        options.body_send_timeout,
        options.grpc_stream_deadline,
        options.sse_policy,
    );
    let mut sse_observer = crate::http3::response_sse::H3SseResponseObserver::new(
        &parts.headers,
        options.listener_name,
        options.sse_policy,
    );
    macro_rules! stop_map_err {
        ($err:expr, $builder:expr) => {{
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            $builder($err)
        }};
    }
    timeout_or_deadline(
        req_stream.send_response(prepared.head),
        body_send_timeout,
        stream_deadline,
        "HTTP/3 response HEADERS send timed out",
        "HTTP/3 gRPC stream duration exceeded configured limit",
    )
    .await
    .map_err(|err| stop_map_err!(err, H3ResponseSendError::before_response_head))?
    .map_err(|err| stop_map_err!(err, H3ResponseSendError::before_response_head))?;
    if !prepared.body_allowed {
        grpc_observer.emit_status_without_body(&parts.headers);
        finish_h3_response_stream(req_stream, body_send_timeout, stream_deadline, false)
            .await
            .map_err(|err| stop_map_err!(err, H3ResponseSendError::after_response_head))?;
        return Ok(None);
    }

    let mut bytes_sent = 0usize;
    let mut body_started = false;
    macro_rules! stop_body_error {
        ($code:expr, $err:expr) => {{
            req_stream.stop_stream($code);
            return Err(h3_response_send_error_for_body(body_started, $err));
        }};
    }
    macro_rules! stop_body_map_err {
        ($err:expr) => {{
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            h3_response_send_error_for_body(body_started, $err)
        }};
    }
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
                sse_observer.record_read_error(&err);
                stop_body_error!(::h3::error::Code::H3_INTERNAL_ERROR, err);
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                stop_body_error!(::h3::error::Code::H3_MESSAGE_ERROR, err.into());
            }
        };
        let next = match bytes_sent.checked_add(chunk.len()) {
            Some(next) => next,
            None => {
                stop_body_error!(
                    ::h3::error::Code::H3_MESSAGE_ERROR,
                    anyhow!("HTTP/3 response body length overflow")
                );
            }
        };
        if next > options.max_body_bytes {
            stop_body_error!(
                ::h3::error::Code::H3_INTERNAL_ERROR,
                anyhow!(
                    "HTTP/3 response body exceeds configured limit: {} bytes",
                    options.max_body_bytes
                )
            );
        }
        if let Some(content_length) = prepared.content_length
            && next as u64 > content_length
        {
            stop_body_error!(
                ::h3::error::Code::H3_INTERNAL_ERROR,
                anyhow!("HTTP/3 response body exceeds Content-Length")
            );
        }
        if let Err(err) = grpc_observer.feed(chunk.as_ref()) {
            stop_body_error!(::h3::error::Code::H3_INTERNAL_ERROR, err);
        }
        sse_observer.feed_chunk(chunk.as_ref());
        bytes_sent = next;
        timeout_or_deadline(
            req_stream.send_data(chunk),
            body_send_timeout,
            stream_deadline,
            "HTTP/3 response DATA send timed out",
            "HTTP/3 gRPC stream duration exceeded configured limit",
        )
        .await
        .map_err(|err| stop_body_map_err!(err))?
        .map_err(|err| stop_body_map_err!(err.into()))?;
        body_started = true;
    }

    sse_observer.finish();

    if let Some(content_length) = prepared.content_length
        && content_length != bytes_sent as u64
    {
        stop_body_error!(
            ::h3::error::Code::H3_MESSAGE_ERROR,
            anyhow!(
                "HTTP/3 response Content-Length mismatch: expected {content_length}, got {bytes_sent}"
            )
        );
    }

    let trailers = timeout_or_deadline(
        body.trailers(),
        body_read_timeout,
        stream_deadline,
        "HTTP/3 response trailers read timed out",
        "HTTP/3 gRPC stream duration exceeded configured limit",
    )
    .await
    .map_err(|err| stop_map_err!(err, H3ResponseSendError::after_response_head))?
    .map_err(|err| stop_map_err!(err, H3ResponseSendError::after_response_head))?;
    let mut trailers_for_status = trailers.clone();
    let sent_trailers = trailers.is_some();
    if let Some(mut trailers) = trailers {
        qpx_http::protocol::semantics::sanitize_response_trailers(&mut trailers);
        let trailers = crate::http3::codec::http_headers_to_h1(&trailers)
            .map_err(H3ResponseSendError::after_trailers_started)?;
        timeout_or_deadline(
            req_stream.send_trailers(trailers),
            body_send_timeout,
            stream_deadline,
            "HTTP/3 response trailers send timed out",
            "HTTP/3 gRPC stream duration exceeded configured limit",
        )
        .await
        .map_err(|err| stop_map_err!(err, H3ResponseSendError::after_trailers_started))?
        .map_err(|err| stop_map_err!(err, H3ResponseSendError::after_trailers_started))?;
        tokio::task::yield_now().await;
    }
    let summary = grpc_observer
        .finish(&parts.headers, &mut trailers_for_status)
        .map_err(|err| stop_body_map_err!(err))?;
    finish_h3_response_stream(
        req_stream,
        body_send_timeout,
        stream_deadline,
        sent_trailers,
    )
    .await
    .map_err(|err| stop_body_map_err!(err))?;
    Ok(summary)
}

async fn finish_h3_response_stream<S>(
    req_stream: &mut ::h3::server::RequestStream<S, Bytes>,
    body_send_timeout: Duration,
    stream_deadline: Option<Instant>,
    sent_trailers: bool,
) -> Result<()>
where
    S: ::h3::quic::SendStream<Bytes>,
{
    if sent_trailers {
        tokio::task::yield_now().await;
    }
    timeout_or_deadline(
        req_stream.finish(),
        body_send_timeout,
        stream_deadline,
        "HTTP/3 response finish timed out",
        "HTTP/3 gRPC stream duration exceeded configured limit",
    )
    .await?
    .map_err(Into::into)
}

fn h3_response_send_error_for_body(
    body_started: bool,
    source: anyhow::Error,
) -> H3ResponseSendError {
    if body_started {
        H3ResponseSendError::after_body_started(source)
    } else {
        H3ResponseSendError::after_response_head(source)
    }
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
            .status(qpx_http::protocol::semantics::validate_http_status_class(
                status,
                "HTTP/3 static response",
            )?)
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
