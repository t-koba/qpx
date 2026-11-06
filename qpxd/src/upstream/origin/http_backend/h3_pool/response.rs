use super::{H3ClientRecvStream, H3PooledConnection, H3RequestRelayJoin};
use crate::http::codec::h2::parse_declared_content_length;
use crate::http3::codec::h1_headers_to_http;
use crate::http3::h3_buf_to_bytes;
use crate::upstream::raw_http1::InterimResponseHead;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http_body::Frame;
use hyper::{Method, StatusCode};
use qpx_core::http_message::Response as OwnerResponse;
use qpx_http::body::{Body, BodyError};
use qpx_http::protocol::semantics::response_status_has_no_body;
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
) -> Result<(Vec<InterimResponseHead>, ::http::Response<()>)> {
    let mut interim = Vec::new();
    loop {
        let response = timeout(timeout_dur, req_stream.recv_response())
            .await
            .map_err(|_| anyhow!("HTTP/3 upstream response timed out"))??;
        if response.status().is_informational() {
            if response.status() == StatusCode::SWITCHING_PROTOCOLS {
                return Err(anyhow!("HTTP/3 upstream must not send 101"));
            }
            let (parts, ()) = response.into_parts();
            interim.push(InterimResponseHead::new(parts.status, parts.headers));
            continue;
        }
        return Ok((interim, response));
    }
}

pub(super) fn h3_response_to_owner(
    response: ::http::Response<()>,
    request_method: &Method,
    upstream: H3ClientRecvStream,
    inflight_guard: InflightStreamGuard,
    timeout_dur: Duration,
    request_relay: Option<H3RequestRelayJoin>,
) -> Result<OwnerResponse<Body>> {
    let (response, declared_length) = own_h3_response_head(response, request_method)?;
    Ok(response.map_body(|()| {
        body_from_h3_stream(
            upstream,
            inflight_guard,
            timeout_dur,
            request_relay,
            declared_length,
        )
    }))
}

fn own_h3_response_head(
    mut response: ::http::Response<()>,
    request_method: &Method,
) -> Result<(OwnerResponse<()>, Option<u64>)> {
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        response.status(),
        "HTTP/3 response",
    )?;
    let headers = h1_headers_to_http(response.headers())?;
    let declared_length = declared_h3_response_body_length(request_method, status, &headers)?;
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    *response.version_mut() = http::Version::HTTP_3;
    // The former reconstructed response did not retain library extensions.
    response.extensions_mut().clear();
    Ok((OwnerResponse::from_http(response), declared_length))
}

pub(super) fn declared_h3_response_body_length(
    request_method: &Method,
    status: StatusCode,
    headers: &http::HeaderMap,
) -> Result<Option<u64>> {
    let declared = parse_declared_content_length(headers)?;
    if *request_method == Method::HEAD
        || response_status_has_no_body(status, false)
        || (*request_method == Method::CONNECT && status.is_success())
    {
        Ok(Some(0))
    } else {
        Ok(declared)
    }
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
                    Poll::Ready(Ok(Some(chunk))) => {
                        let bytes = h3_buf_to_bytes(chunk);
                        this.reset_timeout();
                        let len = bytes.len();
                        if let Err(err) = this.record_data_len(len) {
                            warn!(error = ?err, "HTTP/3 upstream response body length mismatch");
                            return this.upstream_error(err.to_string());
                        }
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
            let previous = pooled.inflight_streams.fetch_sub(1, Ordering::Relaxed);
            let current = previous.saturating_sub(1);
            super::metrics::inflight(pooled.origin_label.as_str(), current);
            pooled.inflight_below_threshold.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{CONTENT_LENGTH, COOKIE};
    use http::{HeaderValue, Version};

    #[test]
    fn h3_response_owner_preserves_converted_head() {
        for cookies in [vec![], vec![""], vec!["", "a=1", "", "b=2"]] {
            let mut decoded = http::Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .version(Version::HTTP_2)
                .body(())
                .unwrap();
            decoded.extensions_mut().insert(42_u32);
            let headers = decoded.headers_mut();
            headers.append("x-repeat", HeaderValue::from_static("first"));
            let mut opaque = HeaderValue::from_bytes(b"\x80\xff").unwrap();
            opaque.set_sensitive(true);
            headers.append("x-repeat", opaque);
            headers.append("set-cookie", HeaderValue::from_static("a=1"));
            headers.append("set-cookie", HeaderValue::from_static("b=2"));
            for cookie in cookies {
                let mut value = HeaderValue::from_static(cookie);
                value.set_sensitive(cookie == "b=2");
                headers.append(COOKIE, value);
            }
            headers.append(CONTENT_LENGTH, HeaderValue::from_static("005"));
            let expected = h1_headers_to_http(headers).unwrap();

            let (owner, declared) = own_h3_response_head(decoded, &Method::GET).unwrap();
            assert_eq!(owner.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(owner.version(), Version::HTTP_3);
            assert_eq!(declared, Some(5));
            assert!(owner.extensions().is_empty());
            let actual = owner.into_http_for_library();
            let fields = |headers: &http::HeaderMap| {
                headers
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.clone(),
                            value.as_bytes().to_vec(),
                            value.is_sensitive(),
                        )
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(fields(actual.headers()), fields(&expected));
        }
    }

    #[test]
    fn h3_response_owner_keeps_strict_content_length_and_no_body_rules() {
        for (method, status, no_body) in [
            (Method::GET, StatusCode::OK, false),
            (Method::HEAD, StatusCode::OK, true),
            (Method::GET, StatusCode::NO_CONTENT, true),
            (Method::GET, StatusCode::NOT_MODIFIED, true),
            (Method::GET, StatusCode::RESET_CONTENT, true),
            (Method::CONNECT, StatusCode::OK, true),
            (Method::CONNECT, StatusCode::BAD_GATEWAY, false),
        ] {
            for (values, expected) in [
                (vec![], Ok(None)),
                (vec!["0"], Ok(Some(0))),
                (vec!["005", "5"], Ok(Some(5))),
                (vec!["invalid"], Err(())),
                (vec!["4", "5"], Err(())),
            ] {
                let mut decoded = http::Response::builder().status(status).body(()).unwrap();
                for value in &values {
                    decoded
                        .headers_mut()
                        .append(CONTENT_LENGTH, HeaderValue::from_static(value));
                }
                let result = own_h3_response_head(decoded, &method);
                match expected {
                    Ok(length) => {
                        let (owner, declared) = result.unwrap();
                        assert_eq!(declared, if no_body { Some(0) } else { length });
                        let exported = owner.into_http_for_library();
                        let actual: Vec<_> = exported
                            .headers()
                            .get_all(CONTENT_LENGTH)
                            .iter()
                            .map(|value| value.to_str().unwrap())
                            .collect();
                        assert_eq!(actual, values);
                    }
                    Err(()) => assert!(result.is_err(), "{method} {status}: {values:?}"),
                }
            }
        }
    }

    #[test]
    fn h3_response_owner_rejects_out_of_range_status() {
        let decoded = http::Response::builder().status(600).body(()).unwrap();
        let error = own_h3_response_head(decoded, &Method::GET).unwrap_err();
        assert_eq!(
            error.to_string(),
            "HTTP/3 response status is out of range: 600"
        );
    }
}
