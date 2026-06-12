use crate::http3::codec::h1_headers_to_http;
use crate::http3::h3_buf_to_bytes;
use crate::http3::metrics;
use crate::http3::stream_limits::timeout_or_deadline;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use http_body::Frame;
use qpx_core::config::{H3RequestBodyDrainConfig, H3RequestBodyDrainMode};
use qpx_http::body::{Body, BodyError};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
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
    pub drain_control: H3RequestBodyDrainControl,
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

#[derive(Debug, Clone)]
pub(crate) struct H3RequestBodyDrainControl {
    pub(crate) config: H3RequestBodyDrainConfig,
    pub(crate) semaphore: Arc<Semaphore>,
}

enum H3RequestBodyDrainAdmission {
    Drain(OwnedSemaphorePermit),
    Abort(&'static str),
    Limited,
}

impl H3RequestBodyDrainControl {
    fn admit(&self) -> H3RequestBodyDrainAdmission {
        match self.config.mode {
            H3RequestBodyDrainMode::Abort => H3RequestBodyDrainAdmission::Abort("abort_mode"),
            H3RequestBodyDrainMode::Bounded | H3RequestBodyDrainMode::BestEffort => self
                .semaphore
                .clone()
                .try_acquire_owned()
                .map(H3RequestBodyDrainAdmission::Drain)
                .unwrap_or(H3RequestBodyDrainAdmission::Limited),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.config.timeout_ms.max(1))
    }
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
    drain_control: H3RequestBodyDrainControl,
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
            drain_control: options.drain_control,
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
                        Poll::Ready(Ok(Some(chunk))) => {
                            let bytes = h3_buf_to_bytes(chunk);
                            this.reset_operation_timeout();
                            let len = bytes.len();
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
                                qpx_http::protocol::semantics::validate_request_trailers(&trailers)
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
        let Some(mut recv_stream) = self.recv_stream.take() else {
            return;
        };
        let Some(completion_tx) = self.completion_tx.take() else {
            return;
        };
        let state = std::mem::replace(&mut self.state, H3IncomingBodyState::Done);
        let drain_control = self.drain_control.clone();
        let listener_name = self.listener_name.clone();
        let route = "unknown";
        let permit = match drain_control.admit() {
            H3RequestBodyDrainAdmission::Drain(permit) => {
                metrics::drain(
                    metrics::DRAIN_STARTED,
                    listener_name.as_ref(),
                    route,
                    "body_drop",
                );
                permit
            }
            H3RequestBodyDrainAdmission::Abort(reason) => {
                recv_stream.stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
                metrics::drain(
                    metrics::DRAIN_ABORTED,
                    listener_name.as_ref(),
                    route,
                    reason,
                );
                let _ = completion_tx.send(Err(anyhow!("HTTP/3 request body drain aborted")));
                return;
            }
            H3RequestBodyDrainAdmission::Limited => {
                recv_stream.stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
                metrics::drain(
                    metrics::DRAIN_LIMITED,
                    listener_name.as_ref(),
                    route,
                    "semaphore",
                );
                let _ = completion_tx.send(Err(anyhow!("HTTP/3 request body drain limited")));
                return;
            }
        };
        let drain = H3IncomingBodyDrain {
            recv_stream,
            read_timeout: self.read_timeout,
            drain_timeout: drain_control.timeout(),
            max_body_bytes: self.max_body_bytes,
            declared_content_length: self.declared_content_length,
            listener_name: self.listener_name.clone(),
            route: Arc::from(route),
            observe_grpc_messages: self.observe_grpc_messages,
            grpc_observer: self.grpc_observer.take(),
            grpc_stream_deadline: self.grpc_stream_deadline,
            bytes_read: self.bytes_read,
            state,
            completion_tx,
            _permit: permit,
        };
        tokio::spawn(async move {
            drain.run().await;
        });
    }
}

struct H3IncomingBodyDrain {
    recv_stream: H3ServerRecvStream,
    read_timeout: Duration,
    drain_timeout: Duration,
    max_body_bytes: usize,
    declared_content_length: Option<u64>,
    listener_name: Arc<str>,
    route: Arc<str>,
    observe_grpc_messages: bool,
    grpc_observer: Option<crate::http::rpc::streaming::StreamingRpcObserver>,
    grpc_stream_deadline: Option<Instant>,
    bytes_read: usize,
    state: H3IncomingBodyState,
    completion_tx: oneshot::Sender<H3IncomingBodyResult>,
    _permit: OwnedSemaphorePermit,
}

impl H3IncomingBodyDrain {
    async fn run(mut self) {
        let started = Instant::now();
        let result = match tokio::time::timeout(self.drain_timeout, self.drain()).await {
            Ok(result) => result,
            Err(_) => Err(self.abort("HTTP/3 request body drain timed out")),
        };
        let elapsed = started.elapsed().as_secs_f64();
        match &result {
            Ok(_) => metrics::drain_completed(
                self.listener_name.as_ref(),
                self.route.as_ref(),
                "body_drop",
                elapsed,
            ),
            Err(_) => metrics::drain(
                metrics::DRAIN_ABORTED,
                self.listener_name.as_ref(),
                self.route.as_ref(),
                "error",
            ),
        }
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
            let Some(chunk) = self.h3_result(recv)? else {
                break;
            };
            let bytes = h3_buf_to_bytes(chunk);
            let len = bytes.len();
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
        if let Err(err) = qpx_http::protocol::semantics::validate_request_trailers(&trailers) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn drain_control(
        mode: H3RequestBodyDrainMode,
        max_concurrent: usize,
    ) -> H3RequestBodyDrainControl {
        H3RequestBodyDrainControl {
            config: H3RequestBodyDrainConfig {
                mode,
                max_concurrent,
                timeout_ms: 25,
            },
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    #[test]
    fn h3_request_body_drain_limited_by_semaphore() {
        let control = drain_control(H3RequestBodyDrainMode::Bounded, 1);
        let _permit = match control.admit() {
            H3RequestBodyDrainAdmission::Drain(permit) => permit,
            _ => panic!("first drain must be admitted"),
        };
        assert!(matches!(
            control.admit(),
            H3RequestBodyDrainAdmission::Limited
        ));
    }

    #[test]
    fn h3_request_body_drain_abort_mode() {
        let control = drain_control(H3RequestBodyDrainMode::Abort, 1);
        assert!(matches!(
            control.admit(),
            H3RequestBodyDrainAdmission::Abort("abort_mode")
        ));
    }

    #[test]
    fn h3_request_body_drain_best_effort_mode() {
        let control = drain_control(H3RequestBodyDrainMode::BestEffort, 1);
        assert!(matches!(
            control.admit(),
            H3RequestBodyDrainAdmission::Drain(_)
        ));
    }
}
