use crate::http::body::Body;
use crate::http3::codec::{prepare_h3_response_head, sanitize_interim_response_for_h3};
use crate::http3::stream_limits::timeout_or_deadline;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use hyper::Response;
use std::future::Future;
use tokio::time::{Duration, Instant, timeout};

mod request_body;

pub(crate) use self::request_body::{
    QpxRequestBodyRelayOptions, relay_qpx_request_body_observed_from_recv,
};

pub(crate) struct QpxResponseSendOptions<'a> {
    pub(crate) max_body_bytes: usize,
    pub(crate) body_read_timeout: Duration,
    pub(crate) body_send_timeout: Duration,
    pub(crate) listener_name: Option<&'a str>,
    pub(crate) fallback_grpc_protocol: Option<&'a str>,
    pub(crate) max_grpc_message_bytes: Option<u64>,
    pub(crate) max_grpc_web_trailer_bytes: Option<u64>,
    pub(crate) grpc_stream_deadline: Option<Instant>,
    pub(crate) sse_policy: Option<qpx_core::config::SseStreamingPolicy>,
    pub(crate) observe_grpc_messages: bool,
}

impl QpxResponseSendOptions<'_> {
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

pub(crate) async fn send_qpx_interim_response_to_send(
    req_stream: &mut qpx_h3::RequestSendStream,
    interim: http::Response<()>,
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
            Self::Full(stream) => stream.send_response_head(response).await,
            Self::Send(stream) => stream.send_response_head(response).await,
        }
    }

    async fn send_data(&mut self, payload: Bytes) -> Result<()> {
        match self {
            Self::Full(stream) => stream.send_data(payload).await,
            Self::Send(stream) => stream.send_data(payload).await,
        }
    }

    async fn send_trailers(&mut self, trailers: &HeaderMap) -> Result<()> {
        match self {
            Self::Full(stream) => stream.send_trailers(trailers).await,
            Self::Send(stream) => stream.send_trailers(trailers).await,
        }
    }

    async fn finish(&mut self) -> Result<()> {
        match self {
            Self::Full(stream) => stream.finish().await,
            Self::Send(stream) => stream.finish().await,
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
    interim: http::Response<()>,
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
        QpxResponseSendOptions::unobserved(max_body_bytes, body_read_timeout),
    )
    .await
    .map(|_summary| ())
}

pub(crate) async fn send_qpx_response_stream_observed(
    req_stream: &mut qpx_h3::RequestStream,
    response: Response<Body>,
    request_method: &http::Method,
    options: QpxResponseSendOptions<'_>,
) -> Result<Option<crate::http::rpc::FramedBodySummary>> {
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
    options: QpxResponseSendOptions<'_>,
) -> Result<Option<crate::http::rpc::FramedBodySummary>> {
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
    options: QpxResponseSendOptions<'_>,
) -> Result<Option<crate::http::rpc::FramedBodySummary>> {
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
    let prepared = prepare_h3_response_head(&parts, request_method)?;
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
        return Err(err);
    }
    if !prepared.body_allowed {
        if options.observe_grpc_messages
            && let (Some(listener), Some(protocol)) =
                (options.listener_name, grpc_protocol.as_deref())
        {
            crate::http::rpc::emit_grpc_status_metric(listener, protocol, &parts.headers, None);
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
            req_stream.abort_message_stream();
            return Err(err);
        }
        return Ok(None);
    }

    let mut bytes_sent = 0usize;
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
                if sse_observer.is_some()
                    && let Some(listener) = options.listener_name
                {
                    crate::http::protocol::sse::emit_sse_idle_disconnect(listener, "unknown");
                }
                req_stream.abort_message_stream();
                return Err(err);
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                req_stream.abort_message_stream();
                return Err(err.into());
            }
        };
        let next = match bytes_sent.checked_add(chunk.len()) {
            Some(next) => next,
            None => {
                req_stream.abort_message_stream();
                return Err(anyhow!("qpx-h3 response body length overflow"));
            }
        };
        if next > options.max_body_bytes {
            req_stream.abort_message_stream();
            return Err(anyhow!(
                "qpx-h3 response body exceeds configured limit: {} bytes",
                options.max_body_bytes
            ));
        }
        if let Some(content_length) = prepared.content_length
            && next as u64 > content_length
        {
            req_stream.abort_message_stream();
            return Err(anyhow!("qpx-h3 response body exceeds Content-Length"));
        }
        if let Some(observer) = grpc_observer.as_mut()
            && let Err(err) = observer.feed(chunk.as_ref())
        {
            req_stream.abort_message_stream();
            return Err(anyhow!(err));
        }
        if let Some(observer) = sse_observer.as_mut() {
            observer.feed(chunk.as_ref());
        }
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
            req_stream.abort_message_stream();
            return Err(err);
        }
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
        req_stream.abort_message_stream();
        return Err(anyhow!(
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
            req_stream.abort_message_stream();
            return Err(err);
        }
    };
    let mut trailers_for_status = trailers.clone();
    if let Some(mut trailers) = trailers {
        crate::http::protocol::semantics::sanitize_response_trailers(&mut trailers);
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
            return Err(err);
        }
    }
    let summary = if let Some(observer) = grpc_observer {
        let protocol = observer.protocol().to_string();
        let summary = match observer.finish().map_err(|err| anyhow!(err)) {
            Ok(summary) => summary,
            Err(err) => {
                req_stream.abort_message_stream();
                return Err(err);
            }
        };
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
        return Err(err);
    }
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
