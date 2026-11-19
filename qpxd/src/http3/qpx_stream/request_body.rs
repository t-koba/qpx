use crate::http3::stream_limits::timeout_or_deadline;
use anyhow::{Result, anyhow};
use qpx_http::body::{BodyError, Sender};
use std::future::Future;
#[cfg(test)]
use std::task::Poll;
use tokio::time::{Duration, Instant, sleep_until};

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestBodySendEvent {
    DataAccepted,
    DataSendPending,
    TrailerSendPending,
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct RequestBodySendProbe {
    pub(crate) events: tokio::sync::mpsc::UnboundedSender<RequestBodySendEvent>,
}

// Test-only observation of a send's first poll outcome. It reports state
// without awaiting anything extra, changing the send future, or polling it a
// second time; production builds compile none of this.
#[cfg(test)]
async fn observed_send<F>(
    future: F,
    probe: Option<&RequestBodySendProbe>,
    pending_event: RequestBodySendEvent,
    accepted_event: Option<RequestBodySendEvent>,
) -> F::Output
where
    F: Future,
{
    let mut future = std::pin::pin!(future);
    let mut reported = false;
    std::future::poll_fn(|cx| {
        let poll = future.as_mut().poll(cx);
        if !reported {
            let event = match poll {
                Poll::Pending => Some(pending_event),
                Poll::Ready(_) => accepted_event,
            };
            if let Some(event) = event
                && let Some(probe) = probe
            {
                let _ = probe.events.send(event);
            }
            reported = true;
        }
        poll
    })
    .await
}

pub(crate) struct QpxRequestBodyRelayOptions<'a> {
    pub(crate) read_timeout: Duration,
    pub(crate) max_body_bytes: usize,
    pub(crate) declared_content_length: Option<u64>,
    pub(crate) grpc_observer: Option<crate::http::rpc::streaming::StreamingRpcObserver>,
    pub(crate) listener_name: Option<&'a str>,
    pub(crate) grpc_stream_deadline: Option<Instant>,
    pub(crate) request_body_deadline: Option<Instant>,
    pub(crate) observe_grpc_messages: bool,
    #[cfg(test)]
    pub(crate) send_probe: Option<RequestBodySendProbe>,
}

async fn send_before_deadline<F>(
    future: F,
    deadline: Option<Instant>,
) -> Result<std::result::Result<(), BodyError>>
where
    F: Future<Output = std::result::Result<(), BodyError>>,
{
    let mut future = std::pin::pin!(future);
    match deadline {
        Some(deadline) => tokio::select! {
            _ = sleep_until(deadline) => Err(anyhow!(
                "qpx-h3 request body duration exceeded configured limit"
            )),
            result = &mut future => Ok(result),
        },
        None => Ok(future.await),
    }
}

pub(crate) async fn relay_qpx_request_body_observed_from_recv(
    req_stream: &mut qpx_h3::RequestRecvStream,
    mut sender: Sender,
    options: QpxRequestBodyRelayOptions<'_>,
) -> Result<(u64, Option<crate::http::rpc::FramedBodySummary>)> {
    let mut grpc_observer = options.grpc_observer;
    let (stream_deadline, deadline_message) = match options.request_body_deadline {
        Some(deadline) => (
            Some(deadline),
            "qpx-h3 request body duration exceeded configured limit",
        ),
        None => (
            options.grpc_stream_deadline,
            "qpx-h3 gRPC stream duration exceeded configured limit",
        ),
    };
    let mut bytes_read = 0usize;
    let mut receiver_open = true;
    loop {
        let read = timeout_or_deadline(
            req_stream.recv_data(),
            options.read_timeout,
            stream_deadline,
            "qpx-h3 request body read timed out",
            deadline_message,
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
        if receiver_open {
            let send = sender.send_data(chunk);
            #[cfg(test)]
            let send = observed_send(
                send,
                options.send_probe.as_ref(),
                RequestBodySendEvent::DataSendPending,
                Some(RequestBodySendEvent::DataAccepted),
            );
            let send_result = send_before_deadline(send, options.request_body_deadline).await;
            match send_result {
                Ok(Ok(())) => {}
                Ok(Err(_)) => receiver_open = false,
                Err(err) => {
                    sender.abort();
                    req_stream.abort_message_stream();
                    return Err(err);
                }
            }
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
        stream_deadline,
        "qpx-h3 request trailers read timed out",
        deadline_message,
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
            let send = sender.send_trailers(trailers);
            #[cfg(test)]
            let send = observed_send(
                send,
                options.send_probe.as_ref(),
                RequestBodySendEvent::TrailerSendPending,
                None,
            );
            let send_result = send_before_deadline(send, options.request_body_deadline).await;
            if let Err(err) = send_result {
                sender.abort();
                req_stream.abort_message_stream();
                return Err(err);
            }
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
