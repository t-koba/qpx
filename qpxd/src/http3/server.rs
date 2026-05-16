use crate::http::body::{Body, Sender};
use crate::http::l7::finalize_response_for_request;
use crate::http3::codec::{h1_headers_to_http, prepare_h3_response_head};
use crate::http3::stream_limits::timeout_or_deadline;
use anyhow::{Result, anyhow};
use bytes::{Buf, Bytes};
use http::HeaderMap;
use hyper::{Response, StatusCode};
use std::sync::Arc;
use tokio::time::{Duration, Instant};

pub type H3ServerRequestStream = ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
pub type H3ServerSendStream = ::h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub type H3ServerRecvStream = ::h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

pub struct H3RequestBodyRelayOptions {
    pub read_timeout: Duration,
    pub max_body_bytes: usize,
    pub declared_content_length: Option<u64>,
    pub request_headers: HeaderMap,
    pub listener_name: Arc<str>,
    pub max_grpc_message_bytes: Option<u64>,
    pub grpc_stream_deadline: Option<Instant>,
}

pub struct H3ResponseSendOptions<'a> {
    pub max_body_bytes: usize,
    pub body_read_timeout: Duration,
    pub listener_name: Option<&'a str>,
    pub fallback_grpc_protocol: Option<&'a str>,
    pub max_grpc_message_bytes: Option<u64>,
    pub grpc_stream_deadline: Option<Instant>,
}

impl H3ResponseSendOptions<'_> {
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

pub async fn relay_h3_request_body_observed(
    mut recv_stream: H3ServerRecvStream,
    mut sender: Sender,
    options: H3RequestBodyRelayOptions,
) -> Result<(u64, Option<crate::http::rpc::FramedBodySummary>)> {
    let mut grpc_observer = crate::http::rpc::streaming_grpc_observer(
        &options.request_headers,
        None,
        options.max_grpc_message_bytes,
    );
    let mut bytes_read = 0usize;
    loop {
        let recv = tokio::select! {
            _ = sender.closed() => {
                recv_stream.stop_sending(::h3::error::Code::H3_REQUEST_CANCELLED);
                return Ok((bytes_read as u64, None));
            }
            recv = timeout_or_deadline(
                recv_stream.recv_data(),
                options.read_timeout,
                options.grpc_stream_deadline,
                "HTTP/3 request body read timed out",
                "HTTP/3 gRPC stream duration exceeded configured limit",
            ) => recv
        };
        let recv = match recv {
            Ok(recv) => recv?,
            Err(err) => {
                sender.abort();
                return Err(err);
            }
        };
        let Some(chunk) = recv else {
            break;
        };
        let mut chunk = chunk;
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        let next = match bytes_read.checked_add(bytes.len()) {
            Some(next) => next,
            None => {
                sender.abort();
                recv_stream.stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
                return Err(anyhow!("HTTP/3 request body length overflow"));
            }
        };
        if next > options.max_body_bytes {
            sender.abort();
            recv_stream.stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
            return Err(anyhow!(
                "HTTP/3 request body exceeds configured limit: {} bytes",
                options.max_body_bytes
            ));
        }
        if let Some(content_length) = options.declared_content_length
            && next as u64 > content_length
        {
            sender.abort();
            recv_stream.stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
            return Err(anyhow!("HTTP/3 request body exceeds Content-Length"));
        }
        if let Some(observer) = grpc_observer.as_mut()
            && let Err(err) = observer.feed(bytes.as_ref())
        {
            sender.abort();
            recv_stream.stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
            return Err(anyhow!(err));
        }
        bytes_read = next;
        if sender.send_data(bytes).await.is_err() {
            recv_stream.stop_sending(::h3::error::Code::H3_REQUEST_CANCELLED);
            return Ok((bytes_read as u64, None));
        }
    }

    if let Some(content_length) = options.declared_content_length
        && content_length != bytes_read as u64
    {
        sender.abort();
        recv_stream.stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
        return Err(anyhow!(
            "HTTP/3 request Content-Length mismatch: expected {content_length}, got {bytes_read}"
        ));
    }

    let trailers = tokio::select! {
        _ = sender.closed() => {
            recv_stream.stop_sending(::h3::error::Code::H3_REQUEST_CANCELLED);
            return Ok((bytes_read as u64, None));
        }
        trailers = timeout_or_deadline(
            recv_stream.recv_trailers(),
            options.read_timeout,
            options.grpc_stream_deadline,
            "HTTP/3 request trailers read timed out",
            "HTTP/3 gRPC stream duration exceeded configured limit",
        ) => trailers
    };
    let trailers = match trailers {
        Ok(trailers) => trailers?,
        Err(err) => {
            sender.abort();
            recv_stream.stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
            return Err(err);
        }
    };
    if let Some(trailers) = trailers {
        let trailers = h1_headers_to_http(&trailers)?;
        if let Err(err) = crate::http::semantics::validate_request_trailers(&trailers) {
            sender.abort();
            recv_stream.stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
            return Err(anyhow!("invalid HTTP/3 request trailers: {err}"));
        }
        if sender.send_trailers(trailers).await.is_err() {
            recv_stream.stop_sending(::h3::error::Code::H3_REQUEST_CANCELLED);
            return Ok((bytes_read as u64, None));
        }
    }
    let summary = if let Some(observer) = grpc_observer {
        let protocol = observer.protocol().to_string();
        let summary = match observer.finish().map_err(|err| anyhow!(err)) {
            Ok(summary) => summary,
            Err(err) => {
                sender.abort();
                recv_stream.stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
                return Err(err);
            }
        };
        crate::http::rpc::emit_grpc_body_metrics(
            "request",
            options.listener_name.as_ref(),
            protocol.as_str(),
            &summary,
        );
        Some(summary)
    } else {
        None
    };
    Ok((bytes_read as u64, summary))
}

pub async fn send_h3_response<S>(
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
}

pub async fn send_h3_response_observed<S>(
    response: Response<Body>,
    request_method: &http::Method,
    req_stream: &mut ::h3::server::RequestStream<S, Bytes>,
    options: H3ResponseSendOptions<'_>,
) -> Result<Option<crate::http::rpc::FramedBodySummary>>
where
    S: ::h3::quic::SendStream<Bytes>,
{
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
    timeout_or_deadline(
        req_stream.send_response(prepared.head),
        options.body_read_timeout,
        options.grpc_stream_deadline,
        "HTTP/3 response HEADERS send timed out",
        "HTTP/3 gRPC stream duration exceeded configured limit",
    )
    .await
    .inspect_err(|_| {
        req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
    })??;
    if !prepared.body_allowed {
        if let (Some(listener), Some(protocol)) = (options.listener_name, grpc_protocol.as_deref())
        {
            crate::http::rpc::emit_grpc_status_metric(listener, protocol, &parts.headers, None);
        }
        timeout_or_deadline(
            req_stream.finish(),
            options.body_read_timeout,
            options.grpc_stream_deadline,
            "HTTP/3 response finish timed out",
            "HTTP/3 gRPC stream duration exceeded configured limit",
        )
        .await
        .inspect_err(|_| {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
        })??;
        return Ok(None);
    }

    let mut bytes_sent = 0usize;
    while let Some(chunk) = timeout_or_deadline(
        body.data(),
        options.body_read_timeout,
        options.grpc_stream_deadline,
        "HTTP/3 response body read timed out",
        "HTTP/3 gRPC stream duration exceeded configured limit",
    )
    .await
    .inspect_err(|_| {
        req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
    })? {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                req_stream.stop_stream(::h3::error::Code::H3_MESSAGE_ERROR);
                return Err(err.into());
            }
        };
        let next = match bytes_sent.checked_add(chunk.len()) {
            Some(next) => next,
            None => {
                req_stream.stop_stream(::h3::error::Code::H3_MESSAGE_ERROR);
                return Err(anyhow!("HTTP/3 response body length overflow"));
            }
        };
        if next > options.max_body_bytes {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            return Err(anyhow!(
                "HTTP/3 response body exceeds configured limit: {} bytes",
                options.max_body_bytes
            ));
        }
        if let Some(content_length) = prepared.content_length
            && next as u64 > content_length
        {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            return Err(anyhow!("HTTP/3 response body exceeds Content-Length"));
        }
        if let Some(observer) = grpc_observer.as_mut()
            && let Err(err) = observer.feed(chunk.as_ref())
        {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
            return Err(anyhow!(err));
        }
        bytes_sent = next;
        timeout_or_deadline(
            req_stream.send_data(chunk),
            options.body_read_timeout,
            options.grpc_stream_deadline,
            "HTTP/3 response DATA send timed out",
            "HTTP/3 gRPC stream duration exceeded configured limit",
        )
        .await
        .inspect_err(|_| {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
        })??;
    }

    if let Some(content_length) = prepared.content_length
        && content_length != bytes_sent as u64
    {
        req_stream.stop_stream(::h3::error::Code::H3_MESSAGE_ERROR);
        return Err(anyhow!(
            "HTTP/3 response Content-Length mismatch: expected {content_length}, got {bytes_sent}"
        ));
    }

    let trailers = timeout_or_deadline(
        body.trailers(),
        options.body_read_timeout,
        options.grpc_stream_deadline,
        "HTTP/3 response trailers read timed out",
        "HTTP/3 gRPC stream duration exceeded configured limit",
    )
    .await
    .inspect_err(|_| {
        req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
    })??;
    let mut trailers_for_status = trailers.clone();
    if let Some(mut trailers) = trailers {
        crate::http::semantics::sanitize_response_trailers(&mut trailers);
        let trailers = crate::http3::codec::http_headers_to_h1(&trailers)?;
        timeout_or_deadline(
            req_stream.send_trailers(trailers),
            options.body_read_timeout,
            options.grpc_stream_deadline,
            "HTTP/3 response trailers send timed out",
            "HTTP/3 gRPC stream duration exceeded configured limit",
        )
        .await
        .inspect_err(|_| {
            req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
        })??;
    }
    let summary = if let Some(observer) = grpc_observer {
        let protocol = observer.protocol().to_string();
        let summary = observer.finish().map_err(|err| anyhow!(err))?;
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
    timeout_or_deadline(
        req_stream.finish(),
        options.body_read_timeout,
        options.grpc_stream_deadline,
        "HTTP/3 response finish timed out",
        "HTTP/3 gRPC stream duration exceeded configured limit",
    )
    .await
    .inspect_err(|_| {
        req_stream.stop_stream(::h3::error::Code::H3_INTERNAL_ERROR);
    })??;
    Ok(summary)
}

pub async fn send_h3_static_response<S>(
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
            .status(StatusCode::from_u16(status.as_u16())?)
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
