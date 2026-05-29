use super::{H3ClientRecvStream, H3PooledConnection, H3RequestRelayJoin};
use crate::http::body::{Body, BodyError};
use crate::http::codec::h2::parse_declared_content_length;
use crate::http3::codec::h1_headers_to_http;
use anyhow::{Result, anyhow};
use bytes::{Buf, Bytes};
use http_body::Frame;
use hyper::{Response, StatusCode};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use tokio::time::{Duration, Sleep, timeout};
use tracing::warn;

pub(super) async fn recv_h3_response_with_interim(
    req_stream: &mut H3ClientRecvStream,
    timeout_dur: Duration,
) -> Result<(Vec<::http::Response<()>>, ::http::Response<()>)> {
    let mut interim = Vec::new();
    loop {
        let response = timeout(timeout_dur, req_stream.recv_response())
            .await
            .map_err(|_| anyhow!("HTTP/3 upstream response timed out"))??;
        if response.status().is_informational() {
            if response.status() == StatusCode::SWITCHING_PROTOCOLS {
                return Err(anyhow!("HTTP/3 upstream must not send 101"));
            }
            interim.push(response);
            continue;
        }
        return Ok((interim, response));
    }
}

pub(super) fn h3_response_to_hyper(
    response: ::http::Response<()>,
    upstream: H3ClientRecvStream,
    inflight_guard: InflightStreamGuard,
    timeout_dur: Duration,
    request_relay: Option<H3RequestRelayJoin>,
) -> Result<Response<Body>> {
    let (parts, _) = response.into_parts();
    let status = crate::http::protocol::semantics::validate_http_status_class(
        parts.status,
        "HTTP/3 response",
    )?;
    let headers = h1_headers_to_http(&parts.headers)?;
    let declared_length = parse_declared_content_length(&headers)?;
    let mut out = Response::builder()
        .status(status)
        .body(body_from_h3_stream(
            upstream,
            inflight_guard,
            timeout_dur,
            request_relay,
            declared_length,
        ))?;
    *out.headers_mut() = headers;
    *out.version_mut() = http::Version::HTTP_3;
    Ok(out)
}

fn body_from_h3_stream(
    upstream: H3ClientRecvStream,
    inflight_guard: InflightStreamGuard,
    timeout_dur: Duration,
    request_relay: Option<H3RequestRelayJoin>,
    declared_content_length: Option<u64>,
) -> Body {
    Body::wrap(H3UpstreamBody::new(
        upstream,
        inflight_guard,
        timeout_dur,
        request_relay,
        declared_content_length,
    ))
}

enum H3UpstreamBodyState {
    Data,
    Trailers,
    Done,
}

struct H3UpstreamBody {
    upstream: H3ClientRecvStream,
    _inflight_guard: InflightStreamGuard,
    timeout_dur: Duration,
    timeout: Pin<Box<Sleep>>,
    request_relay: Option<H3RequestRelayJoin>,
    state: H3UpstreamBodyState,
    declared_content_length: Option<u64>,
    received_body_bytes: u64,
}

impl H3UpstreamBody {
    fn new(
        upstream: H3ClientRecvStream,
        inflight_guard: InflightStreamGuard,
        timeout_dur: Duration,
        request_relay: Option<H3RequestRelayJoin>,
        declared_content_length: Option<u64>,
    ) -> Self {
        Self {
            upstream,
            _inflight_guard: inflight_guard,
            timeout_dur,
            timeout: Box::pin(tokio::time::sleep(timeout_dur)),
            request_relay,
            state: H3UpstreamBodyState::Data,
            declared_content_length,
            received_body_bytes: 0,
        }
    }

    fn reset_timeout(&mut self) {
        self.timeout
            .as_mut()
            .reset(crate::runtime::tokio_deadline_after(self.timeout_dur));
    }

    fn abort_request_relay(&mut self) {
        abort_h3_request_relay(self.request_relay.take());
    }

    fn complete_request_relay(&mut self) {
        if self
            .request_relay
            .as_ref()
            .is_some_and(|relay| !relay.is_finished())
        {
            self.abort_request_relay();
            return;
        }
        self.request_relay.take();
    }

    fn upstream_error(
        &mut self,
        message: impl Into<String>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        self.abort_request_relay();
        self.upstream
            .stop_sending(::h3::error::Code::H3_REQUEST_CANCELLED);
        self.state = H3UpstreamBodyState::Done;
        Poll::Ready(Some(Err(BodyError::new(message))))
    }

    fn record_data_len(&mut self, len: usize) -> Result<()> {
        record_h3_body_content_length(
            self.declared_content_length,
            &mut self.received_body_bytes,
            len,
            "response",
        )
    }

    fn enforce_complete_len(&self) -> Result<()> {
        enforce_h3_body_content_length_complete(
            self.declared_content_length,
            self.received_body_bytes,
            "response",
        )
    }
}

pub(super) fn record_h3_body_content_length(
    declared_content_length: Option<u64>,
    received_body_bytes: &mut u64,
    next_len: usize,
    direction: &'static str,
) -> Result<()> {
    *received_body_bytes = received_body_bytes
        .checked_add(next_len as u64)
        .ok_or_else(|| anyhow!("HTTP/3 upstream {direction} body length overflow"))?;
    if let Some(declared) = declared_content_length
        && *received_body_bytes > declared
    {
        return Err(anyhow!(
            "HTTP/3 upstream {direction} body exceeds Content-Length: Content-Length={declared}, received={}",
            *received_body_bytes
        ));
    }
    Ok(())
}

pub(super) fn enforce_h3_body_content_length_complete(
    declared_content_length: Option<u64>,
    received_body_bytes: u64,
    direction: &'static str,
) -> Result<()> {
    if let Some(declared) = declared_content_length
        && received_body_bytes != declared
    {
        return Err(anyhow!(
            "HTTP/3 upstream {direction} body length mismatch: Content-Length={declared}, received={received_body_bytes}"
        ));
    }
    Ok(())
}

impl http_body::Body for H3UpstreamBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        loop {
            if matches!(this.state, H3UpstreamBodyState::Done) {
                return Poll::Ready(None);
            }
            if this.timeout.as_mut().poll(cx).is_ready() {
                warn!("HTTP/3 upstream response body timed out");
                return this.upstream_error("HTTP/3 upstream response body timed out");
            }
            match this.state {
                H3UpstreamBodyState::Data => match this.upstream.poll_recv_data(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(Some(mut bytes))) => {
                        this.reset_timeout();
                        let remaining = bytes.remaining();
                        if let Err(err) = this.record_data_len(remaining) {
                            warn!(error = ?err, "HTTP/3 upstream response body length mismatch");
                            return this.upstream_error(err.to_string());
                        }
                        let bytes = bytes.copy_to_bytes(remaining);
                        return Poll::Ready(Some(Ok(Frame::data(bytes))));
                    }
                    Poll::Ready(Ok(None)) => {
                        this.reset_timeout();
                        if let Err(err) = this.enforce_complete_len() {
                            warn!(error = ?err, "HTTP/3 upstream response body length mismatch");
                            return this.upstream_error(err.to_string());
                        }
                        this.state = H3UpstreamBodyState::Trailers;
                    }
                    Poll::Ready(Err(err)) => {
                        warn!(error = ?err, "HTTP/3 upstream response body failed");
                        return this.upstream_error(format!(
                            "HTTP/3 upstream response body failed: {err}"
                        ));
                    }
                },
                H3UpstreamBodyState::Trailers => match this.upstream.poll_recv_trailers(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(Some(trailers))) => {
                        this.reset_timeout();
                        this.state = H3UpstreamBodyState::Done;
                        this.complete_request_relay();
                        match h1_headers_to_http(&trailers) {
                            Ok(trailers) => {
                                return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                            }
                            Err(err) => {
                                warn!(error = ?err, "HTTP/3 upstream trailers were invalid");
                                return Poll::Ready(Some(Err(BodyError::new(err.to_string()))));
                            }
                        }
                    }
                    Poll::Ready(Ok(None)) => {
                        this.state = H3UpstreamBodyState::Done;
                        this.complete_request_relay();
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Err(err)) => {
                        warn!(error = ?err, "HTTP/3 upstream trailers failed");
                        return this
                            .upstream_error(format!("HTTP/3 upstream trailers failed: {err}"));
                    }
                },
                H3UpstreamBodyState::Done => return Poll::Ready(None),
            }
        }
    }
}

impl Drop for H3UpstreamBody {
    fn drop(&mut self) {
        if !matches!(self.state, H3UpstreamBodyState::Done) {
            self.upstream
                .stop_sending(::h3::error::Code::H3_REQUEST_CANCELLED);
        }
        self.abort_request_relay();
    }
}

pub(super) async fn join_h3_request_relay(relay: H3RequestRelayJoin) -> Result<()> {
    relay
        .await
        .map_err(|err| anyhow!("HTTP/3 upstream request body relay task failed: {err}"))?
}

pub(super) fn abort_h3_request_relay(relay: Option<H3RequestRelayJoin>) {
    if let Some(relay) = relay {
        relay.abort();
    }
}

pub(super) struct InflightStreamGuard(Option<Arc<H3PooledConnection>>);

impl InflightStreamGuard {
    pub(super) fn new(pooled: Arc<H3PooledConnection>) -> Self {
        Self(Some(pooled))
    }
}

impl Drop for InflightStreamGuard {
    fn drop(&mut self) {
        if let Some(pooled) = self.0.take() {
            pooled.inflight_streams.fetch_sub(1, Ordering::Relaxed);
            pooled.inflight_below_threshold.notify_waiters();
        }
    }
}
