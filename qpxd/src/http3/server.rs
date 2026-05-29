use crate::http::body::{Body, BodyError};
use crate::http3::codec::h1_headers_to_http;
use crate::http3::stream_limits::timeout_or_deadline;
use anyhow::{Result, anyhow};
use bytes::{Buf, Bytes};
use http::HeaderMap;
use http_body::Frame;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant, Sleep};

mod response;

pub(crate) use self::response::{
    H3ResponseSendOptions, send_h3_response, send_h3_response_observed, send_h3_static_response,
};

pub type H3ServerRequestStream = ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
pub type H3ServerSendStream = ::h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub type H3ServerRecvStream = ::h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

pub(crate) struct H3IncomingBodyOptions {
    pub read_timeout: Duration,
    pub max_body_bytes: usize,
    pub declared_content_length: Option<u64>,
    pub request_headers: HeaderMap,
    pub listener_name: Arc<str>,
    pub max_grpc_message_bytes: Option<u64>,
    pub max_grpc_web_trailer_bytes: Option<u64>,
    pub grpc_stream_deadline: Option<Instant>,
    pub observe_grpc_messages: bool,
}

pub(crate) type H3IncomingBodyResult = Result<(u64, Option<crate::http::rpc::FramedBodySummary>)>;

pub(crate) struct H3IncomingBodyCompletion {
    receiver: oneshot::Receiver<H3IncomingBodyResult>,
}

pub(crate) fn h3_incoming_body(
    recv_stream: H3ServerRecvStream,
    options: H3IncomingBodyOptions,
) -> (Body, H3IncomingBodyCompletion) {
    let (completion_tx, completion_rx) = oneshot::channel();
    let body = H3IncomingBody::new(recv_stream, options, completion_tx);
    (
        Body::wrap(body),
        H3IncomingBodyCompletion {
            receiver: completion_rx,
        },
    )
}

impl H3IncomingBodyCompletion {
    pub(crate) fn try_take_result(&mut self) -> Option<H3IncomingBodyResult> {
        match self.receiver.try_recv() {
            Ok(result) => Some(result),
            Err(oneshot::error::TryRecvError::Empty) => None,
            Err(oneshot::error::TryRecvError::Closed) => {
                Some(Err(anyhow!("HTTP/3 request body completion was dropped")))
            }
        }
    }

    pub(crate) async fn finish(self) -> H3IncomingBodyResult {
        self.receiver
            .await
            .map_err(|_| anyhow!("HTTP/3 request body completion was dropped"))?
    }
}

enum H3IncomingBodyState {
    Data,
    Trailers,
    Done,
}

struct H3IncomingBody {
    recv_stream: Option<H3ServerRecvStream>,
    read_timeout: Duration,
    max_body_bytes: usize,
    declared_content_length: Option<u64>,
    listener_name: Arc<str>,
    observe_grpc_messages: bool,
    grpc_observer: Option<crate::http::rpc::streaming::StreamingRpcObserver>,
    grpc_stream_deadline: Option<Instant>,
    operation_timeout: Pin<Box<Sleep>>,
    operation_timeout_armed: bool,
    deadline_timeout: Option<Pin<Box<Sleep>>>,
    bytes_read: usize,
    state: H3IncomingBodyState,
    completion_tx: Option<oneshot::Sender<H3IncomingBodyResult>>,
}

impl H3IncomingBody {
    fn new(
        recv_stream: H3ServerRecvStream,
        options: H3IncomingBodyOptions,
        completion_tx: oneshot::Sender<H3IncomingBodyResult>,
    ) -> Self {
        let grpc_observer = options
            .observe_grpc_messages
            .then(|| {
                crate::http::rpc::streaming_rpc_observer(
                    &options.request_headers,
                    None,
                    options.max_grpc_message_bytes,
                    options.max_grpc_web_trailer_bytes,
                )
            })
            .flatten();
        Self {
            recv_stream: Some(recv_stream),
            read_timeout: options.read_timeout,
            max_body_bytes: options.max_body_bytes,
            declared_content_length: options.declared_content_length,
            listener_name: options.listener_name,
            observe_grpc_messages: options.observe_grpc_messages,
            grpc_observer,
            grpc_stream_deadline: options.grpc_stream_deadline,
            operation_timeout: Box::pin(tokio::time::sleep(options.read_timeout)),
            operation_timeout_armed: false,
            deadline_timeout: options
                .grpc_stream_deadline
                .map(|deadline| Box::pin(tokio::time::sleep_until(deadline))),
            bytes_read: 0,
            state: H3IncomingBodyState::Data,
            completion_tx: Some(completion_tx),
        }
    }

    fn reset_operation_timeout(&mut self) {
        self.operation_timeout
            .as_mut()
            .reset(crate::runtime::tokio_deadline_after(self.read_timeout));
        self.operation_timeout_armed = true;
    }

    fn poll_timeouts(&mut self, cx: &mut Context<'_>) -> Option<&'static str> {
        if !self.operation_timeout_armed {
            self.reset_operation_timeout();
        }
        if let Some(deadline) = self.deadline_timeout.as_mut()
            && deadline.as_mut().poll(cx).is_ready()
        {
            return Some("HTTP/3 gRPC stream duration exceeded configured limit");
        }
        if self.operation_timeout.as_mut().poll(cx).is_ready() {
            return Some(match self.state {
                H3IncomingBodyState::Data => "HTTP/3 request body read timed out",
                H3IncomingBodyState::Trailers => "HTTP/3 request trailers read timed out",
                H3IncomingBodyState::Done => "HTTP/3 request body read timed out",
            });
        }
        None
    }

    fn fail(
        &mut self,
        message: impl Into<String>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BodyError>>> {
        let message = message.into();
        if let Some(stream) = self.recv_stream.as_mut() {
            stream.stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
        }
        self.recv_stream.take();
        self.state = H3IncomingBodyState::Done;
        self.complete(Err(anyhow!(message.clone())));
        Poll::Ready(Some(Err(BodyError::new(message))))
    }

    fn complete(&mut self, result: H3IncomingBodyResult) {
        if let Some(tx) = self.completion_tx.take() {
            let _ = tx.send(result);
        }
    }

    fn finish_observer(&mut self) -> Result<Option<crate::http::rpc::FramedBodySummary>> {
        let Some(observer) = self.grpc_observer.take() else {
            return Ok(None);
        };
        let protocol = observer.protocol().to_string();
        let summary = observer.finish().map_err(|err| anyhow!(err))?;
        if self.observe_grpc_messages {
            crate::http::rpc::emit_grpc_body_metrics(
                "request",
                self.listener_name.as_ref(),
                protocol.as_str(),
                &summary,
            );
        }
        Ok(Some(summary))
    }

    fn finish_ok(&mut self) -> Poll<Option<std::result::Result<Frame<Bytes>, BodyError>>> {
        let summary = match self.finish_observer() {
            Ok(summary) => summary,
            Err(err) => return self.fail(err.to_string()),
        };
        self.recv_stream.take();
        self.state = H3IncomingBodyState::Done;
        self.complete(Ok((self.bytes_read as u64, summary)));
        Poll::Ready(None)
    }

    fn finish_with_trailers(
        &mut self,
        trailers: HeaderMap,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BodyError>>> {
        let summary = match self.finish_observer() {
            Ok(summary) => summary,
            Err(err) => return self.fail(err.to_string()),
        };
        self.recv_stream.take();
        self.state = H3IncomingBodyState::Done;
        self.complete(Ok((self.bytes_read as u64, summary)));
        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
    }
}

impl http_body::Body for H3IncomingBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        loop {
            if matches!(this.state, H3IncomingBodyState::Done) {
                return Poll::Ready(None);
            }
            if let Some(message) = this.poll_timeouts(cx) {
                return this.fail(message);
            }
            match this.state {
                H3IncomingBodyState::Data => {
                    let poll = {
                        let Some(stream) = this.recv_stream.as_mut() else {
                            return this.fail("HTTP/3 request stream is no longer active");
                        };
                        stream.poll_recv_data(cx)
                    };
                    match poll {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(Some(mut bytes))) => {
                            this.reset_operation_timeout();
                            let len = bytes.remaining();
                            let next = match this.bytes_read.checked_add(len) {
                                Some(next) => next,
                                None => {
                                    return this.fail("HTTP/3 request body length overflow");
                                }
                            };
                            if next > this.max_body_bytes {
                                return this.fail(format!(
                                    "HTTP/3 request body exceeds configured limit: {} bytes",
                                    this.max_body_bytes
                                ));
                            }
                            if let Some(content_length) = this.declared_content_length
                                && next as u64 > content_length
                            {
                                return this.fail("HTTP/3 request body exceeds Content-Length");
                            }
                            let bytes = bytes.copy_to_bytes(len);
                            if let Some(observer) = this.grpc_observer.as_mut()
                                && let Err(err) = observer.feed(bytes.as_ref())
                            {
                                return this.fail(err.to_string());
                            }
                            this.bytes_read = next;
                            return Poll::Ready(Some(Ok(Frame::data(bytes))));
                        }
                        Poll::Ready(Ok(None)) => {
                            this.reset_operation_timeout();
                            if let Some(content_length) = this.declared_content_length
                                && content_length != this.bytes_read as u64
                            {
                                return this.fail(format!(
                                    "HTTP/3 request Content-Length mismatch: expected {content_length}, got {}",
                                    this.bytes_read
                                ));
                            }
                            this.state = H3IncomingBodyState::Trailers;
                        }
                        Poll::Ready(Err(err)) => {
                            return this.fail(format!("HTTP/3 request body failed: {err}"));
                        }
                    }
                }
                H3IncomingBodyState::Trailers => {
                    let poll = {
                        let Some(stream) = this.recv_stream.as_mut() else {
                            return this.fail("HTTP/3 request stream is no longer active");
                        };
                        stream.poll_recv_trailers(cx)
                    };
                    match poll {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(Some(trailers))) => {
                            this.reset_operation_timeout();
                            let trailers = match h1_headers_to_http(&trailers) {
                                Ok(trailers) => trailers,
                                Err(err) => return this.fail(err.to_string()),
                            };
                            if let Err(err) =
                                crate::http::protocol::semantics::validate_request_trailers(
                                    &trailers,
                                )
                            {
                                return this
                                    .fail(format!("invalid HTTP/3 request trailers: {err}"));
                            }
                            return this.finish_with_trailers(trailers);
                        }
                        Poll::Ready(Ok(None)) => return this.finish_ok(),
                        Poll::Ready(Err(err)) => {
                            return this.fail(format!("HTTP/3 request trailers failed: {err}"));
                        }
                    }
                }
                H3IncomingBodyState::Done => return Poll::Ready(None),
            }
        }
    }
}

impl Drop for H3IncomingBody {
    fn drop(&mut self) {
        if matches!(self.state, H3IncomingBodyState::Done) {
            return;
        }
        let Some(recv_stream) = self.recv_stream.take() else {
            return;
        };
        let Some(completion_tx) = self.completion_tx.take() else {
            return;
        };
        let state = std::mem::replace(&mut self.state, H3IncomingBodyState::Done);
        let drain = H3IncomingBodyDrain {
            recv_stream,
            read_timeout: self.read_timeout,
            max_body_bytes: self.max_body_bytes,
            declared_content_length: self.declared_content_length,
            listener_name: self.listener_name.clone(),
            observe_grpc_messages: self.observe_grpc_messages,
            grpc_observer: self.grpc_observer.take(),
            grpc_stream_deadline: self.grpc_stream_deadline,
            bytes_read: self.bytes_read,
            state,
            completion_tx,
        };
        tokio::spawn(async move {
            drain.run().await;
        });
    }
}

struct H3IncomingBodyDrain {
    recv_stream: H3ServerRecvStream,
    read_timeout: Duration,
    max_body_bytes: usize,
    declared_content_length: Option<u64>,
    listener_name: Arc<str>,
    observe_grpc_messages: bool,
    grpc_observer: Option<crate::http::rpc::streaming::StreamingRpcObserver>,
    grpc_stream_deadline: Option<Instant>,
    bytes_read: usize,
    state: H3IncomingBodyState,
    completion_tx: oneshot::Sender<H3IncomingBodyResult>,
}

impl H3IncomingBodyDrain {
    async fn run(mut self) {
        let result = self.drain().await;
        let _ = self.completion_tx.send(result);
    }

    async fn drain(&mut self) -> H3IncomingBodyResult {
        if matches!(self.state, H3IncomingBodyState::Data) {
            self.drain_data().await?;
        }
        self.drain_trailers().await?;
        let summary = self.finish_observer()?;
        Ok((self.bytes_read as u64, summary))
    }

    async fn drain_data(&mut self) -> Result<()> {
        loop {
            let recv = timeout_or_deadline(
                self.recv_stream.recv_data(),
                self.read_timeout,
                self.grpc_stream_deadline,
                "HTTP/3 request body read timed out",
                "HTTP/3 gRPC stream duration exceeded configured limit",
            )
            .await;
            let Some(mut bytes) = self.h3_result(recv)? else {
                break;
            };
            let len = bytes.remaining();
            let next = self
                .bytes_read
                .checked_add(len)
                .ok_or_else(|| self.abort("HTTP/3 request body length overflow"))?;
            if next > self.max_body_bytes {
                return Err(self.abort(format!(
                    "HTTP/3 request body exceeds configured limit: {} bytes",
                    self.max_body_bytes
                )));
            }
            if let Some(content_length) = self.declared_content_length
                && next as u64 > content_length
            {
                return Err(self.abort("HTTP/3 request body exceeds Content-Length"));
            }
            let bytes = bytes.copy_to_bytes(len);
            if let Some(observer) = self.grpc_observer.as_mut()
                && let Err(err) = observer.feed(bytes.as_ref())
            {
                return Err(self.abort(err.to_string()));
            }
            self.bytes_read = next;
        }
        if let Some(content_length) = self.declared_content_length
            && content_length != self.bytes_read as u64
        {
            return Err(self.abort(format!(
                "HTTP/3 request Content-Length mismatch: expected {content_length}, got {}",
                self.bytes_read
            )));
        }
        Ok(())
    }

    async fn drain_trailers(&mut self) -> Result<()> {
        let trailers = timeout_or_deadline(
            self.recv_stream.recv_trailers(),
            self.read_timeout,
            self.grpc_stream_deadline,
            "HTTP/3 request trailers read timed out",
            "HTTP/3 gRPC stream duration exceeded configured limit",
        )
        .await;
        let Some(trailers) = self.h3_result(trailers)? else {
            return Ok(());
        };
        let trailers = h1_headers_to_http(&trailers).map_err(|err| self.abort(err.to_string()))?;
        if let Err(err) = crate::http::protocol::semantics::validate_request_trailers(&trailers) {
            return Err(self.abort(format!("invalid HTTP/3 request trailers: {err}")));
        }
        Ok(())
    }

    fn h3_result<T, E>(
        &mut self,
        result: Result<std::result::Result<Option<T>, E>>,
    ) -> Result<Option<T>>
    where
        E: Into<anyhow::Error>,
    {
        match result {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(err)) => {
                let err: anyhow::Error = err.into();
                Err(self.abort(err.to_string()))
            }
            Err(err) => Err(self.abort(err.to_string())),
        }
    }

    fn finish_observer(&mut self) -> Result<Option<crate::http::rpc::FramedBodySummary>> {
        let Some(observer) = self.grpc_observer.take() else {
            return Ok(None);
        };
        let protocol = observer.protocol().to_string();
        let summary = observer
            .finish()
            .map_err(|err| self.abort(err.to_string()))?;
        if self.observe_grpc_messages {
            crate::http::rpc::emit_grpc_body_metrics(
                "request",
                self.listener_name.as_ref(),
                protocol.as_str(),
                &summary,
            );
        }
        Ok(Some(summary))
    }

    fn abort(&mut self, message: impl Into<String>) -> anyhow::Error {
        self.recv_stream
            .stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
        anyhow!(message.into())
    }
}
