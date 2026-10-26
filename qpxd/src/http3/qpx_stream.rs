use crate::http3::codec::{prepare_h3_response_head, sanitize_interim_response_for_h3};
use crate::http3::response_error::H3ResponseSendError;
use crate::http3::response_options::H3ResponseSendOptions;
use crate::http3::stream_limits::{response_stream_timeouts, timeout_or_deadline};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use hyper::Response;
use qpx_http::body::Body;
use std::future::Future;
use tokio::time::{Duration, Instant, timeout};

mod request_body;

pub(crate) use self::request_body::{
    QpxRequestBodyRelayOptions, relay_qpx_request_body_observed_from_recv,
};

pub(crate) async fn send_qpx_interim_response_to_send(
    req_stream: &mut qpx_h3::RequestSendStream,
    interim: crate::upstream::raw_http1::InterimResponseHead,
    send_timeout: Duration,
) -> Result<()> {
    send_qpx_interim_response_inner(QpxResponseWriter::Send(req_stream), interim, send_timeout)
        .await
}

enum QpxResponseWriter<'a> {
    Full(&'a mut qpx_h3::RequestStream),
    Send(&'a mut qpx_h3::RequestSendStream),
}

impl QpxResponseWriter<'_> {
    async fn send_response_head(&mut self, response: &http::Response<()>) -> Result<()> {
        match self {
            Self::Full(stream) => stream
                .send_response_head(response)
                .await
                .map_err(Into::into),
            Self::Send(stream) => stream
                .send_response_head(response)
                .await
                .map_err(Into::into),
        }
    }

    async fn send_data(&mut self, payload: Bytes) -> Result<()> {
        match self {
            Self::Full(stream) => stream.send_data(payload).await.map_err(Into::into),
            Self::Send(stream) => stream.send_data(payload).await.map_err(Into::into),
        }
    }

    async fn send_trailers(&mut self, trailers: &HeaderMap) -> Result<()> {
        match self {
            Self::Full(stream) => stream.send_trailers(trailers).await.map_err(Into::into),
            Self::Send(stream) => stream.send_trailers(trailers).await.map_err(Into::into),
        }
    }

    async fn finish(&mut self) -> Result<()> {
        match self {
            Self::Full(stream) => stream.finish().await.map_err(Into::into),
            Self::Send(stream) => stream.finish().await.map_err(Into::into),
        }
    }

    fn abort_message_stream(&mut self) {
        match self {
            Self::Full(stream) => stream.abort_message_stream(),
            Self::Send(stream) => stream.abort_message_stream(),
        }
    }
}

async fn send_qpx_interim_response_inner(
    mut req_stream: QpxResponseWriter<'_>,
    interim: crate::upstream::raw_http1::InterimResponseHead,
    send_timeout: Duration,
) -> Result<()> {
    let interim = sanitize_interim_response_for_h3(interim)?;
    if let Err(err) = timeout(send_timeout, req_stream.send_response_head(&interim))
        .await
        .map_err(|_| anyhow!("qpx-h3 interim response send timed out"))
        .and_then(|result| result)
    {
        req_stream.abort_message_stream();
        return Err(err);
    }
    Ok(())
}

pub(crate) async fn send_qpx_response_stream(
    req_stream: &mut qpx_h3::RequestStream,
    response: Response<Body>,
    request_method: &http::Method,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<()> {
    send_qpx_response_stream_observed(
        req_stream,
        response,
        request_method,
        H3ResponseSendOptions::unobserved(max_body_bytes, body_read_timeout),
    )
    .await
    .map(|_summary| ())
    .map_err(|err| {
        crate::http3::response_error::emit_h3_response_send_error("qpx_h3", &err);
        err.into_inner()
    })
}

pub(crate) async fn send_qpx_response_stream_observed(
    req_stream: &mut qpx_h3::RequestStream,
    response: Response<Body>,
    request_method: &http::Method,
    options: H3ResponseSendOptions<'_>,
) -> std::result::Result<Option<crate::http::rpc::FramedBodySummary>, H3ResponseSendError> {
    send_qpx_response_stream_observed_inner(
        QpxResponseWriter::Full(req_stream),
        response,
        request_method,
        options,
    )
    .await
}

pub(crate) async fn send_qpx_response_stream_observed_to_send(
    req_stream: &mut qpx_h3::RequestSendStream,
    response: Response<Body>,
    request_method: &http::Method,
    options: H3ResponseSendOptions<'_>,
) -> std::result::Result<Option<crate::http::rpc::FramedBodySummary>, H3ResponseSendError> {
    send_qpx_response_stream_observed_inner(
        QpxResponseWriter::Send(req_stream),
        response,
        request_method,
        options,
    )
    .await
}

async fn send_qpx_response_stream_observed_inner(
    mut req_stream: QpxResponseWriter<'_>,
    response: Response<Body>,
    request_method: &http::Method,
    options: H3ResponseSendOptions<'_>,
) -> std::result::Result<Option<crate::http::rpc::FramedBodySummary>, H3ResponseSendError> {
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
    if let Err(err) = qpx_timeout_result(
        req_stream.send_response_head(&prepared.head),
        body_send_timeout,
        stream_deadline,
        "qpx-h3 response head send timed out",
        "qpx-h3 gRPC stream duration exceeded configured limit",
    )
    .await
    {
        req_stream.abort_message_stream();
        return Err(H3ResponseSendError::before_response_head(err));
    }
    if !prepared.body_allowed {
        grpc_observer.emit_status_without_body(&parts.headers);
        if let Err(err) = qpx_timeout_result(
            req_stream.finish(),
            body_send_timeout,
            stream_deadline,
            "qpx-h3 response finish timed out",
            "qpx-h3 gRPC stream duration exceeded configured limit",
        )
        .await
        {
            req_stream.abort_message_stream();
            return Err(H3ResponseSendError::after_response_head(err));
        }
        return Ok(None);
    }

    let mut bytes_sent = 0usize;
    let mut body_started = false;
    macro_rules! abort_body_error {
        ($err:expr) => {{
            req_stream.abort_message_stream();
            return Err(H3ResponseSendError::for_body(body_started, $err));
        }};
    }
    loop {
        let read_started = Instant::now();
        let chunk = match timeout_or_deadline(
            body.data(),
            body_read_timeout,
            stream_deadline,
            "qpx-h3 response body read timed out",
            "qpx-h3 gRPC stream duration exceeded configured limit",
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
                abort_body_error!(err);
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                abort_body_error!(err.into());
            }
        };
        let next = match bytes_sent.checked_add(chunk.len()) {
            Some(next) => next,
            None => {
                abort_body_error!(anyhow!("qpx-h3 response body length overflow"));
            }
        };
        if next > options.max_body_bytes {
            abort_body_error!(anyhow!(
                "qpx-h3 response body exceeds configured limit: {} bytes",
                options.max_body_bytes
            ));
        }
        if let Some(content_length) = prepared.content_length
            && next as u64 > content_length
        {
            abort_body_error!(anyhow!("qpx-h3 response body exceeds Content-Length"));
        }
        if let Err(err) = grpc_observer.feed(chunk.as_ref()) {
            abort_body_error!(err);
        }
        sse_observer.feed_chunk(chunk.as_ref());
        bytes_sent = next;
        if let Err(err) = qpx_timeout_result(
            req_stream.send_data(chunk),
            body_send_timeout,
            stream_deadline,
            "qpx-h3 response body send timed out",
            "qpx-h3 gRPC stream duration exceeded configured limit",
        )
        .await
        {
            abort_body_error!(err);
        }
        body_started = true;
    }

    sse_observer.finish();

    if let Some(content_length) = prepared.content_length
        && content_length != bytes_sent as u64
    {
        abort_body_error!(anyhow!(
            "qpx-h3 response Content-Length mismatch: expected {content_length}, got {bytes_sent}"
        ));
    }

    let trailers = match qpx_timeout_result(
        body.trailers(),
        body_read_timeout,
        stream_deadline,
        "qpx-h3 response trailers read timed out",
        "qpx-h3 gRPC stream duration exceeded configured limit",
    )
    .await
    {
        Ok(trailers) => trailers,
        Err(err) => {
            abort_body_error!(err);
        }
    };
    let mut trailers_for_status = trailers.clone();
    let sent_trailers = trailers.is_some();
    if let Some(mut trailers) = trailers {
        qpx_http::protocol::semantics::sanitize_response_trailers(&mut trailers);
        if let Err(err) = qpx_timeout_result(
            req_stream.send_trailers(&trailers),
            body_send_timeout,
            stream_deadline,
            "qpx-h3 response trailers send timed out",
            "qpx-h3 gRPC stream duration exceeded configured limit",
        )
        .await
        {
            req_stream.abort_message_stream();
            return Err(H3ResponseSendError::after_trailers_started(err));
        }
    }
    let summary = match grpc_observer.finish(&parts.headers, &mut trailers_for_status) {
        Ok(summary) => summary,
        Err(err) => {
            abort_body_error!(err);
        }
    };
    if sent_trailers {
        // Trailer HEADERS terminate the HTTP/3 message; an extra FIN is redundant
        // and can race trailer delivery in some clients.
        return Ok(summary);
    }
    if let Err(err) = qpx_timeout_result(
        req_stream.finish(),
        body_send_timeout,
        stream_deadline,
        "qpx-h3 response finish timed out",
        "qpx-h3 gRPC stream duration exceeded configured limit",
    )
    .await
    {
        abort_body_error!(err);
    }
    Ok(summary)
}

async fn qpx_timeout_result<F, T, E>(
    future: F,
    operation_timeout: Duration,
    stream_deadline: Option<Instant>,
    timeout_message: &'static str,
    deadline_message: &'static str,
) -> Result<T>
where
    F: Future<Output = std::result::Result<T, E>>,
    E: Into<anyhow::Error>,
{
    timeout_or_deadline(
        future,
        operation_timeout,
        stream_deadline,
        timeout_message,
        deadline_message,
    )
    .await?
    .map_err(Into::into)
}
