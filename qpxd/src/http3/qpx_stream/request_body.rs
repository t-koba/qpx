use crate::http3::stream_limits::timeout_or_deadline;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use qpx_http::body::Sender;
use tokio::time::{Duration, Instant};

pub(crate) struct QpxRequestBodyRelayOptions<'a> {
    pub(crate) read_timeout: Duration,
    pub(crate) max_body_bytes: usize,
    pub(crate) declared_content_length: Option<u64>,
    pub(crate) request_headers: &'a HeaderMap,
    pub(crate) listener_name: Option<&'a str>,
    pub(crate) max_grpc_message_bytes: Option<u64>,
    pub(crate) max_grpc_web_trailer_bytes: Option<u64>,
    pub(crate) grpc_stream_deadline: Option<Instant>,
    pub(crate) observe_grpc_messages: bool,
}

pub(crate) async fn relay_qpx_request_body_observed_from_recv(
    req_stream: &mut qpx_h3::RequestRecvStream,
    mut sender: Sender,
    options: QpxRequestBodyRelayOptions<'_>,
) -> Result<(u64, Option<crate::http::rpc::FramedBodySummary>)> {
    relay_qpx_request_body_observed_inner(
        QpxRequestBodyReader::Recv(req_stream),
        &mut sender,
        options,
    )
    .await
}

enum QpxRequestBodyReader<'a> {
    Recv(&'a mut qpx_h3::RequestRecvStream),
}

impl QpxRequestBodyReader<'_> {
    async fn recv_data(&mut self) -> Result<Option<Bytes>> {
        match self {
            Self::Recv(stream) => stream.recv_data().await.map_err(Into::into),
        }
    }

    async fn recv_trailers(&mut self) -> Result<Option<HeaderMap>> {
        match self {
            Self::Recv(stream) => stream.recv_trailers().await.map_err(Into::into),
        }
    }

    fn abort_message_stream(&mut self) {
        match self {
            Self::Recv(stream) => stream.abort_message_stream(),
        }
    }
}

async fn relay_qpx_request_body_observed_inner(
    mut req_stream: QpxRequestBodyReader<'_>,
    sender: &mut Sender,
    options: QpxRequestBodyRelayOptions<'_>,
) -> Result<(u64, Option<crate::http::rpc::FramedBodySummary>)> {
    let mut grpc_observer = options
        .observe_grpc_messages
        .then(|| {
            crate::http::rpc::streaming_rpc_observer(
                options.request_headers,
                None,
                options.max_grpc_message_bytes,
                options.max_grpc_web_trailer_bytes,
            )
        })
        .flatten();
    let mut bytes_read = 0usize;
    let mut receiver_open = true;
    loop {
        let read = timeout_or_deadline(
            req_stream.recv_data(),
            options.read_timeout,
            options.grpc_stream_deadline,
            "qpx-h3 request body read timed out",
            "qpx-h3 gRPC stream duration exceeded configured limit",
        );
        let chunk = if receiver_open {
            tokio::select! {
                _ = sender.closed() => {
                    receiver_open = false;
                    continue;
                }
                chunk = read => chunk,
            }
        } else {
            read.await
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
        if receiver_open && sender.send_data(chunk).await.is_err() {
            receiver_open = false;
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

    let trailers = timeout_or_deadline(
        req_stream.recv_trailers(),
        options.read_timeout,
        options.grpc_stream_deadline,
        "qpx-h3 request trailers read timed out",
        "qpx-h3 gRPC stream duration exceeded configured limit",
    )
    .await;
    receiver_open &= !sender.is_closed();
    let trailers = match trailers {
        Ok(trailers) => trailers?,
        Err(err) => {
            sender.abort();
            req_stream.abort_message_stream();
            return Err(err);
        }
    };
    if let Some(trailers) = trailers {
        if let Err(err) = qpx_http::protocol::semantics::validate_request_trailers(&trailers) {
            sender.abort();
            req_stream.abort_message_stream();
            return Err(anyhow!("invalid qpx-h3 request trailers: {err}"));
        }
        if receiver_open {
            let _ = sender.send_trailers(trailers).await;
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
        if options.observe_grpc_messages
            && let Some(listener) = options.listener_name
        {
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
