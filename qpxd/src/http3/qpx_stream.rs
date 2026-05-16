use crate::http::body::{Body, Sender};
use crate::http3::codec::{prepare_h3_response_head, sanitize_interim_response_for_h3};
use crate::http3::stream_limits::timeout_or_deadline;
use anyhow::{Result, anyhow};
use http::HeaderMap;
use hyper::Response;
use std::future::Future;
use tokio::time::{Duration, Instant, timeout};

pub(crate) struct QpxRequestBodyRelayOptions<'a> {
    pub(crate) read_timeout: Duration,
    pub(crate) max_body_bytes: usize,
    pub(crate) declared_content_length: Option<u64>,
    pub(crate) request_headers: &'a HeaderMap,
    pub(crate) listener_name: Option<&'a str>,
    pub(crate) max_grpc_message_bytes: Option<u64>,
    pub(crate) grpc_stream_deadline: Option<Instant>,
}

pub(crate) struct QpxResponseSendOptions<'a> {
    pub(crate) max_body_bytes: usize,
    pub(crate) body_read_timeout: Duration,
    pub(crate) listener_name: Option<&'a str>,
    pub(crate) fallback_grpc_protocol: Option<&'a str>,
    pub(crate) max_grpc_message_bytes: Option<u64>,
    pub(crate) grpc_stream_deadline: Option<Instant>,
}

impl QpxResponseSendOptions<'_> {
    fn unobserved(max_body_bytes: usize, body_read_timeout: Duration) -> Self {
        Self {
            max_body_bytes,
            body_read_timeout,
            listener_name: None,
            fallback_grpc_protocol: None,
            max_grpc_message_bytes: None,
            grpc_stream_deadline: None,
        }
    }
}

pub(crate) async fn relay_qpx_request_body_observed(
    req_stream: &mut qpx_h3::RequestStream,
    mut sender: Sender,
    options: QpxRequestBodyRelayOptions<'_>,
) -> Result<(u64, Option<crate::http::rpc::FramedBodySummary>)> {
    let mut grpc_observer = crate::http::rpc::streaming_grpc_observer(
        options.request_headers,
        None,
        options.max_grpc_message_bytes,
    );
    let mut bytes_read = 0usize;
    loop {
        let chunk = tokio::select! {
            _ = sender.closed() => {
                req_stream.stop_receiving_request_body();
                return Ok((bytes_read as u64, None));
            }
            chunk = timeout_or_deadline(
                req_stream.recv_data(),
                options.read_timeout,
                options.grpc_stream_deadline,
                "qpx-h3 request body read timed out",
                "qpx-h3 gRPC stream duration exceeded configured limit",
            ) => chunk,
        };
        let chunk = match chunk {
            Ok(chunk) => chunk?,
            Err(err) => {
                sender.abort();
                req_stream.abort_message_stream();
                return Err(err);
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        let next = match bytes_read.checked_add(chunk.len()) {
            Some(next) => next,
            None => {
                sender.abort();
                req_stream.abort_message_stream();
                return Err(anyhow!("qpx-h3 request body length overflow"));
            }
        };
        if next > options.max_body_bytes {
            sender.abort();
            req_stream.abort_message_stream();
            return Err(anyhow!(
                "qpx-h3 request body exceeds configured limit: {} bytes",
                options.max_body_bytes
            ));
        }
        if let Some(content_length) = options.declared_content_length
            && next as u64 > content_length
        {
            sender.abort();
            req_stream.abort_message_stream();
            return Err(anyhow!("qpx-h3 request body exceeds Content-Length"));
        }
        if let Some(observer) = grpc_observer.as_mut()
            && let Err(err) = observer.feed(chunk.as_ref())
        {
            sender.abort();
            req_stream.abort_message_stream();
            return Err(anyhow!(err));
        }
        bytes_read = next;
        if sender.send_data(chunk).await.is_err() {
            req_stream.stop_receiving_request_body();
            return Ok((bytes_read as u64, None));
        }
    }

    if let Some(content_length) = options.declared_content_length
        && content_length != bytes_read as u64
    {
        sender.abort();
        req_stream.abort_message_stream();
        return Err(anyhow!(
            "qpx-h3 request Content-Length mismatch: expected {content_length}, got {bytes_read}"
        ));
    }

    let trailers = tokio::select! {
        _ = sender.closed() => {
            req_stream.stop_receiving_request_body();
            return Ok((bytes_read as u64, None));
        }
        trailers = timeout_or_deadline(
            req_stream.recv_trailers(),
            options.read_timeout,
            options.grpc_stream_deadline,
            "qpx-h3 request trailers read timed out",
            "qpx-h3 gRPC stream duration exceeded configured limit",
        ) => trailers,
    };
    let trailers = match trailers {
        Ok(trailers) => trailers?,
        Err(err) => {
            sender.abort();
            req_stream.abort_message_stream();
            return Err(err);
        }
    };
    if let Some(trailers) = trailers {
        if let Err(err) = crate::http::semantics::validate_request_trailers(&trailers) {
            sender.abort();
            req_stream.abort_message_stream();
            return Err(anyhow!("invalid qpx-h3 request trailers: {err}"));
        }
        if sender.send_trailers(trailers).await.is_err() {
            req_stream.stop_receiving_request_body();
            return Ok((bytes_read as u64, None));
        }
    }
    let summary = if let Some(observer) = grpc_observer {
        let protocol = observer.protocol().to_string();
        let summary = match observer.finish().map_err(|err| anyhow!(err)) {
            Ok(summary) => summary,
            Err(err) => {
                sender.abort();
                req_stream.abort_message_stream();
                return Err(err);
            }
        };
        if let Some(listener) = options.listener_name {
            crate::http::rpc::emit_grpc_body_metrics(
                "request",
                listener,
                protocol.as_str(),
                &summary,
            );
        }
        Some(summary)
    } else {
        None
    };
    Ok((bytes_read as u64, summary))
}

pub(crate) async fn send_qpx_interim_response(
    req_stream: &mut qpx_h3::RequestStream,
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
    let (parts, mut body) = response.into_parts();
    let mut grpc_observer = crate::http::rpc::streaming_grpc_observer(
        &parts.headers,
        options.fallback_grpc_protocol,
        options.max_grpc_message_bytes,
    );
    let grpc_protocol = grpc_observer
        .as_ref()
        .map(|observer| observer.protocol().to_string());
    let prepared = prepare_h3_response_head(&parts, request_method)?;
    if let Err(err) = qpx_timeout_result(
        req_stream.send_response_head(&prepared.head),
        options.body_read_timeout,
        options.grpc_stream_deadline,
        "qpx-h3 response head send timed out",
        "qpx-h3 gRPC stream duration exceeded configured limit",
    )
    .await
    {
        req_stream.abort_message_stream();
        return Err(err);
    }
    if !prepared.body_allowed {
        if let (Some(listener), Some(protocol)) = (options.listener_name, grpc_protocol.as_deref())
        {
            crate::http::rpc::emit_grpc_status_metric(listener, protocol, &parts.headers, None);
        }
        if let Err(err) = qpx_timeout_result(
            req_stream.finish(),
            options.body_read_timeout,
            options.grpc_stream_deadline,
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
        let Some(chunk) = (match timeout_or_deadline(
            body.data(),
            options.body_read_timeout,
            options.grpc_stream_deadline,
            "qpx-h3 response body read timed out",
            "qpx-h3 gRPC stream duration exceeded configured limit",
        )
        .await
        {
            Ok(chunk) => chunk,
            Err(err) => {
                req_stream.abort_message_stream();
                return Err(err);
            }
        }) else {
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
        bytes_sent = next;
        if let Err(err) = qpx_timeout_result(
            req_stream.send_data(chunk),
            options.body_read_timeout,
            options.grpc_stream_deadline,
            "qpx-h3 response body send timed out",
            "qpx-h3 gRPC stream duration exceeded configured limit",
        )
        .await
        {
            req_stream.abort_message_stream();
            return Err(err);
        }
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
        options.body_read_timeout,
        options.grpc_stream_deadline,
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
        crate::http::semantics::sanitize_response_trailers(&mut trailers);
        if let Err(err) = qpx_timeout_result(
            req_stream.send_trailers(&trailers),
            options.body_read_timeout,
            options.grpc_stream_deadline,
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
        if let Some(listener) = options.listener_name {
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
        options.body_read_timeout,
        options.grpc_stream_deadline,
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
