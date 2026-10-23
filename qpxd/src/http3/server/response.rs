use crate::http::protocol::l7::finalize_response_for_request;
use crate::http3::codec::prepare_h3_response_head;
use crate::http3::response_error::{H3ResponseSendError, emit_h3_response_send_error};
use crate::http3::response_options::H3ResponseSendOptions;
use crate::http3::stream_limits::{response_stream_timeouts, timeout_or_deadline};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use hyper::Response;
use qpx_http::body::Body;
use tokio::time::{Duration, Instant};

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
            return Err(H3ResponseSendError::for_body(body_started, $err));
        }};
    }
    macro_rules! stop_body_map_err {
        ($err:expr) => {{
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            H3ResponseSendError::for_body(body_started, $err)
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
        // Trailer HEADERS terminate the HTTP/3 message; sending an additional FIN
        // after trailers is redundant and has caused clients to observe EOF before
        // the trailer block on some runtimes.
        return Ok(());
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
