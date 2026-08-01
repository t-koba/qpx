use crate::http::codec::lazy_timeout::timeout_after_pending;
use crate::upstream::raw_http1::{InterimResponseHead, RawHttp1ResponseHead};
use ::http::{Request as Http1Request, Response as Http1Response};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use h2::Reason;
use h2::RecvStream;
use h2::server::SendResponse;
use http_body::Frame;
use hyper::header::{CONTENT_LENGTH, COOKIE};
use hyper::{Request, Response};
use qpx_http::body::{Body, BodyError};
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::time::{Duration, Sleep, timeout};
use tracing::{debug, warn};

const H2_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const H2_ABANDONED_REQUEST_DRAIN_LIMIT: usize = 1024 * 1024;
const H2_INITIAL_STREAM_WINDOW_SIZE: u32 = 1024 * 1024;
const H2_INITIAL_CONNECTION_WINDOW_SIZE: u32 = 4 * 1024 * 1024;
const H2_MAX_FRAME_SIZE: u32 = 64 * 1024;
const H2_MAX_SEND_BUFFER_SIZE: usize = 16 * 1024;
pub(crate) const H2_MAX_CONCURRENT_STREAMS: usize = 256;
const H2_DIRECT_SEND_BODY_MAX_BYTES: u64 = 16 * 1024;
const H2_INITIAL_SCHEDULER_BUFFER_BYTES: usize = H2_MAX_FRAME_SIZE as usize;
const H2_MIN_SCHEDULER_BUFFER_BYTES: usize = H2_MAX_SEND_BUFFER_SIZE;

#[derive(Clone)]
pub(crate) struct H2DownstreamLoad {
    active_streams: Arc<AtomicUsize>,
}

impl H2DownstreamLoad {
    pub(crate) fn new(active_streams: Arc<AtomicUsize>) -> Self {
        Self { active_streams }
    }

    pub(crate) fn upstream_response_frame_size(self) -> usize {
        match self.active_streams.load(Ordering::Relaxed) {
            0..=1 => 1024 * 1024,
            _ => H2_MAX_SEND_BUFFER_SIZE,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct H2TransportTuning {
    pub(crate) initial_stream_window_size: u32,
    pub(crate) initial_connection_window_size: u32,
}

impl Default for H2TransportTuning {
    fn default() -> Self {
        Self {
            initial_stream_window_size: H2_INITIAL_STREAM_WINDOW_SIZE,
            initial_connection_window_size: H2_INITIAL_CONNECTION_WINDOW_SIZE,
        }
    }
}

pub(crate) fn tuned_h2_client_builder() -> h2::client::Builder {
    tuned_h2_client_builder_with(H2TransportTuning::default())
}

pub(crate) fn tuned_h2_client_builder_with(tuning: H2TransportTuning) -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(tuning.initial_stream_window_size);
    builder.initial_connection_window_size(tuning.initial_connection_window_size);
    builder.max_frame_size(H2_MAX_FRAME_SIZE);
    builder.max_send_buffer_size(H2_MAX_SEND_BUFFER_SIZE);
    builder
}

pub(crate) fn tune_h2_server_builder_with(
    builder: &mut h2::server::Builder,
    tuning: H2TransportTuning,
) {
    builder.initial_window_size(tuning.initial_stream_window_size);
    builder.initial_connection_window_size(tuning.initial_connection_window_size);
    builder.max_frame_size(H2_MAX_FRAME_SIZE);
    builder.max_send_buffer_size(H2_MAX_SEND_BUFFER_SIZE);
    builder.max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS as u32);
}

#[cfg(test)]
pub(crate) fn h2_request_to_hyper(req: Http1Request<RecvStream>) -> Result<Request<Body>> {
    h2_request_to_hyper_with_capacity(req, 16)
}

pub(crate) fn h2_request_to_hyper_with_capacity(
    req: Http1Request<RecvStream>,
    body_channel_capacity: usize,
) -> Result<Request<Body>> {
    let (mut parts, body) = req.into_parts();
    parts.headers = h1_headers_into_http(parts.headers)?;
    // The h2 transport already enforces RFC 9113 content-length reconciliation
    // while decoding DATA / END_STREAM on the inbound stream. We still parse the
    // header locally to reject conflicting field-values before handing the
    // request to Hyper, but body-length mismatches surface via the body stream.
    let _declared_length = parse_declared_content_length(&parts.headers)?;
    let body = body_from_h2_stream(body, body_channel_capacity);
    parts.version = http::Version::HTTP_2;
    Ok(Request::from_parts(parts, body))
}

pub(crate) async fn send_h2_response_with_interim(
    mut respond: SendResponse<Bytes>,
    response: Response<Body>,
    interim: &[InterimResponseHead],
    request_method: &http::Method,
    allow_successful_connect_body: bool,
    body_read_timeout: Duration,
    active_streams: usize,
) -> Result<()> {
    for head in interim {
        let status = qpx_http::protocol::semantics::validate_http_status_class(
            head.status,
            "HTTP/2 interim response",
        )?;
        if !status.is_informational() {
            return Err(anyhow!(
                "non-informational interim status for HTTP/2: {}",
                status
            ));
        }
        if status == ::http::StatusCode::SWITCHING_PROTOCOLS {
            return Err(anyhow!("HTTP/2 interim responses must not use 101"));
        }
        let mut headers = head.headers.clone();
        qpx_http::protocol::semantics::sanitize_interim_response_headers(&mut headers);
        let mut informational = Http1Response::new(());
        *informational.status_mut() = status;
        *informational.headers_mut() = http_headers_to_h1(&headers)?;
        respond.send_informational(informational)?;
    }

    let (mut parts, mut body) = response.into_parts();
    let status =
        qpx_http::protocol::semantics::validate_http_status_class(parts.status, "HTTP/2 response")?;
    let no_body = request_method == hyper::Method::HEAD
        || parts.status.is_informational()
        || parts.status == http::StatusCode::NO_CONTENT
        || parts.status == http::StatusCode::RESET_CONTENT
        || parts.status == http::StatusCode::NOT_MODIFIED
        || (request_method == hyper::Method::CONNECT
            && parts.status.is_success()
            && !allow_successful_connect_body);
    let mut headers = if let Some(raw) = parts.extensions.remove::<Arc<RawHttp1ResponseHead>>() {
        raw.materialized_headers()?
    } else {
        parts.headers
    };
    let declared_length = if no_body {
        if request_method == hyper::Method::HEAD {
            qpx_http::protocol::semantics::strip_message_body_framing_headers(&mut headers);
            if parse_declared_content_length(&headers).is_err() {
                headers.remove(http::header::CONTENT_LENGTH);
            }
        } else {
            qpx_http::protocol::semantics::strip_message_body_headers(&mut headers);
        }
        None
    } else {
        parse_declared_content_length(&headers)?
    };
    let flow_control_body =
        declared_length.is_none_or(|length| length > H2_DIRECT_SEND_BODY_MAX_BYTES);
    let mut scheduler_buffer_budget = if flow_control_body {
        h2_scheduler_buffer_budget(active_streams)
    } else {
        0
    };
    let yield_after_initial = active_streams > 1;
    let mut head = Http1Response::new(());
    *head.status_mut() = status;
    *head.headers_mut() = http_headers_into_h1(headers);

    let body_ends_immediately = http_body::Body::is_end_stream(&body);
    let end_stream_on_headers =
        no_body || (body_ends_immediately && declared_length.is_none_or(|length| length == 0));
    let single_frame = (!no_body)
        .then(|| body.take_single_frame_without_trailers())
        .flatten();
    let mut send_stream = match respond.send_response(head, end_stream_on_headers) {
        Ok(stream) => stream,
        Err(error) => {
            return match poll_send_response_reset_now(&mut respond).await {
                Some(Ok(reason)) => {
                    debug!(
                        ?reason,
                        "HTTP/2 request cancelled before response headers were sent"
                    );
                    Ok(())
                }
                Some(Err(reset_error)) => Err(reset_error.into()),
                None => Err(error.into()),
            };
        }
    };

    if end_stream_on_headers {
        return Ok(());
    }

    if let Some(chunk) = single_frame {
        if let Some(expected) = declared_length
            && chunk.len() as u64 != expected
        {
            send_stream.send_reset(Reason::PROTOCOL_ERROR);
            return if chunk.len() as u64 > expected {
                Err(anyhow!(
                    "HTTP/2 response body exceeded declared content-length"
                ))
            } else {
                Err(anyhow!(
                    "HTTP/2 response body ended before declared content-length was satisfied"
                ))
            };
        }
        if !send_h2_data(
            &mut send_stream,
            chunk,
            true,
            flow_control_body,
            &mut scheduler_buffer_budget,
            yield_after_initial,
        )
        .await?
        {
            return Ok(());
        }
        return Ok(());
    }

    let body_read_timeout_enforced = body.read_timeout_is_enforced();
    let mut sent_len = 0u64;
    let mut final_chunk = None;
    while let Some(chunk) = match read_h2_response_body_chunk(
        &mut body,
        &mut send_stream,
        body_read_timeout,
        body_read_timeout_enforced,
    )
    .await
    {
        Ok(H2BodyRead::Value(chunk)) => chunk,
        Ok(H2BodyRead::PeerReset(reason)) => {
            debug!(?reason, "HTTP/2 response body cancelled by peer");
            return Ok(());
        }
        Err(err) => {
            send_stream.send_reset(Reason::CANCEL);
            return Err(err);
        }
    } {
        let chunk = chunk?;
        sent_len = sent_len
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| anyhow!("HTTP/2 response body length overflow"))?;
        if let Some(expected) = declared_length
            && sent_len > expected
        {
            send_stream.send_reset(Reason::PROTOCOL_ERROR);
            return Err(anyhow!(
                "HTTP/2 response body exceeded declared content-length"
            ));
        }
        if !chunk.is_empty() {
            if declared_length == Some(sent_len) {
                final_chunk = Some(chunk);
                break;
            }
            if !send_h2_data(
                &mut send_stream,
                chunk,
                false,
                flow_control_body,
                &mut scheduler_buffer_budget,
                yield_after_initial,
            )
            .await?
            {
                return Ok(());
            }
        }
    }

    if final_chunk.is_some() {
        while let Some(chunk) = match read_h2_response_body_chunk(
            &mut body,
            &mut send_stream,
            body_read_timeout,
            body_read_timeout_enforced,
        )
        .await
        {
            Ok(H2BodyRead::Value(chunk)) => chunk,
            Ok(H2BodyRead::PeerReset(reason)) => {
                debug!(?reason, "HTTP/2 response body cancelled by peer");
                return Ok(());
            }
            Err(err) => {
                send_stream.send_reset(Reason::CANCEL);
                return Err(err);
            }
        } {
            let chunk = chunk?;
            if !chunk.is_empty() {
                send_stream.send_reset(Reason::PROTOCOL_ERROR);
                return Err(anyhow!(
                    "HTTP/2 response body exceeded declared content-length"
                ));
            }
        }
    }

    let trailers = match read_h2_response_trailers(
        &mut body,
        &mut send_stream,
        body_read_timeout,
        body_read_timeout_enforced,
    )
    .await
    {
        Ok(H2BodyRead::Value(trailers)) => trailers,
        Ok(H2BodyRead::PeerReset(reason)) => {
            debug!(?reason, "HTTP/2 response trailers cancelled by peer");
            return Ok(());
        }
        Err(err) => {
            send_stream.send_reset(Reason::CANCEL);
            return Err(err);
        }
    };
    if let Some(expected) = declared_length
        && sent_len != expected
    {
        send_stream.send_reset(Reason::PROTOCOL_ERROR);
        return Err(anyhow!(
            "HTTP/2 response body ended before declared content-length was satisfied"
        ));
    }
    if let Some(mut trailers) = trailers {
        let removed = qpx_http::protocol::semantics::sanitize_response_trailers(&mut trailers);
        if removed > 0 {
            warn!(removed, "dropping forbidden HTTP/2 response trailers");
        }
        if trailers.is_empty() {
            if !send_h2_data(
                &mut send_stream,
                final_chunk.unwrap_or_default(),
                true,
                flow_control_body,
                &mut scheduler_buffer_budget,
                yield_after_initial,
            )
            .await?
            {
                return Ok(());
            }
        } else {
            if let Some(chunk) = final_chunk
                && !send_h2_data(
                    &mut send_stream,
                    chunk,
                    false,
                    flow_control_body,
                    &mut scheduler_buffer_budget,
                    yield_after_initial,
                )
                .await?
            {
                return Ok(());
            }
            let result = send_stream.send_trailers(http_headers_into_h1(trailers));
            if !handle_h2_send_result(&mut send_stream, result).await? {
                return Ok(());
            }
        }
    } else {
        if !send_h2_data(
            &mut send_stream,
            final_chunk.unwrap_or_default(),
            true,
            flow_control_body,
            &mut scheduler_buffer_budget,
            yield_after_initial,
        )
        .await?
        {
            return Ok(());
        }
    }

    Ok(())
}

fn h2_scheduler_buffer_budget(active_streams: usize) -> usize {
    (H2_INITIAL_SCHEDULER_BUFFER_BYTES / active_streams.max(1)).max(H2_MIN_SCHEDULER_BUFFER_BYTES)
}

async fn send_h2_data(
    send_stream: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
    flow_control: bool,
    scheduler_buffer_budget: &mut usize,
    yield_after_initial: bool,
) -> Result<bool> {
    if data.is_empty() || !flow_control {
        let result = send_stream.send_data(data, end_stream);
        if let Err(error) = result {
            return handle_h2_send_result(send_stream, Err(error)).await;
        }
        return Ok(true);
    }
    if *scheduler_buffer_budget > 0 {
        let buffered = data.split_to(data.len().min(*scheduler_buffer_budget));
        *scheduler_buffer_budget -= buffered.len();
        let final_chunk = end_stream && data.is_empty();
        let result = send_stream.send_data(buffered, final_chunk);
        if !handle_h2_send_result(send_stream, result).await? {
            return Ok(false);
        }
        if !final_chunk && yield_after_initial {
            tokio::task::yield_now().await;
        }
    }
    while !data.is_empty() {
        send_stream.reserve_capacity(data.len());
        let capacity = if send_stream.capacity() > 0 {
            send_stream.capacity()
        } else {
            poll_fn(|cx| send_stream.poll_capacity(cx))
                .await
                .ok_or_else(|| anyhow!("HTTP/2 response stream closed while awaiting capacity"))??
        };
        if capacity == 0 {
            continue;
        }
        let chunk = data.split_to(capacity.min(data.len()));
        let final_chunk = end_stream && data.is_empty();
        let result = send_stream.send_data(chunk, final_chunk);
        if !handle_h2_send_result(send_stream, result).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn handle_h2_send_result(
    send_stream: &mut h2::SendStream<Bytes>,
    result: std::result::Result<(), h2::Error>,
) -> Result<bool> {
    let Err(error) = result else {
        return Ok(true);
    };
    match poll_send_stream_reset_now(send_stream).await {
        Some(Ok(reason)) => {
            debug!(?reason, "HTTP/2 response stream cancelled by peer");
            Ok(false)
        }
        Some(Err(reset_error)) => Err(reset_error.into()),
        None => Err(error.into()),
    }
}

async fn poll_send_response_reset_now(
    respond: &mut SendResponse<Bytes>,
) -> Option<std::result::Result<Reason, h2::Error>> {
    poll_fn(|cx| {
        Poll::Ready(match respond.poll_reset(cx) {
            Poll::Ready(reset) => Some(reset),
            Poll::Pending => None,
        })
    })
    .await
}

async fn poll_send_stream_reset_now(
    send_stream: &mut h2::SendStream<Bytes>,
) -> Option<std::result::Result<Reason, h2::Error>> {
    poll_fn(|cx| {
        Poll::Ready(match send_stream.poll_reset(cx) {
            Poll::Ready(reset) => Some(reset),
            Poll::Pending => None,
        })
    })
    .await
}

async fn read_h2_response_body_chunk(
    body: &mut Body,
    send_stream: &mut h2::SendStream<Bytes>,
    body_read_timeout: Duration,
    body_read_timeout_enforced: bool,
) -> Result<H2BodyRead<Option<Result<Bytes, qpx_http::body::BodyError>>>> {
    if body_read_timeout_enforced {
        return Ok(H2BodyRead::Value(body.data().await));
    }
    let read = async {
        timeout_after_pending(body_read_timeout, body.data())
            .await
            .map_err(|_| anyhow!("HTTP/2 response body read timed out"))
    };
    tokio::pin!(read);
    tokio::select! {
        biased;
        value = &mut read => value.map(H2BodyRead::Value),
        reset = poll_fn(|cx| send_stream.poll_reset(cx)) => match reset {
            Ok(reason) => Ok(H2BodyRead::PeerReset(reason)),
            Err(error) => Err(error.into()),
        }
    }
}

async fn read_h2_response_trailers(
    body: &mut Body,
    send_stream: &mut h2::SendStream<Bytes>,
    body_read_timeout: Duration,
    body_read_timeout_enforced: bool,
) -> Result<H2BodyRead<Option<http::HeaderMap>>> {
    if body_read_timeout_enforced {
        return body
            .trailers()
            .await
            .map(H2BodyRead::Value)
            .map_err(Into::into);
    }
    let read = async {
        timeout_after_pending(body_read_timeout, body.trailers())
            .await
            .map_err(|_| anyhow!("HTTP/2 response trailer read timed out"))?
            .map_err(Into::into)
    };
    tokio::pin!(read);
    tokio::select! {
        biased;
        value = &mut read => value.map(H2BodyRead::Value),
        reset = poll_fn(|cx| send_stream.poll_reset(cx)) => match reset {
            Ok(reason) => Ok(H2BodyRead::PeerReset(reason)),
            Err(error) => Err(error.into()),
        }
    }
}

enum H2BodyRead<T> {
    Value(T),
    PeerReset(Reason),
}

pub(crate) fn h1_headers_to_http(src: &::http::HeaderMap) -> Result<http::HeaderMap> {
    if src.get_all(COOKIE).iter().count() <= 1 {
        return Ok(src.clone());
    }
    let mut headers = http::HeaderMap::with_capacity(src.len());
    let mut merged_cookie = Vec::new();
    for (name, value) in src {
        if name == COOKIE {
            if !merged_cookie.is_empty() {
                merged_cookie.extend_from_slice(b"; ");
            }
            merged_cookie.extend_from_slice(value.as_bytes());
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    if !merged_cookie.is_empty() {
        headers.insert(COOKIE, http::HeaderValue::from_bytes(&merged_cookie)?);
    }
    Ok(headers)
}

fn h1_headers_into_http(src: ::http::HeaderMap) -> Result<http::HeaderMap> {
    if src.get_all(COOKIE).iter().count() <= 1 {
        return Ok(src);
    }
    h1_headers_to_http(&src)
}

pub(crate) fn http_headers_to_h1(src: &http::HeaderMap) -> Result<::http::HeaderMap> {
    Ok(src.clone())
}

fn http_headers_into_h1(src: http::HeaderMap) -> ::http::HeaderMap {
    src
}

pub(crate) fn parse_declared_content_length(headers: &http::HeaderMap) -> Result<Option<u64>> {
    let mut parsed = None::<u64>;
    for value in headers.get_all(CONTENT_LENGTH).iter() {
        let raw = value
            .to_str()
            .map_err(|_| anyhow!("invalid content-length header"))?;
        for part in raw.split(',') {
            let len = part
                .trim()
                .parse::<u64>()
                .map_err(|_| anyhow!("invalid content-length value: {}", part.trim()))?;
            match parsed {
                Some(existing) if existing != len => {
                    return Err(anyhow!("conflicting content-length values"));
                }
                Some(_) => {}
                None => parsed = Some(len),
            }
        }
    }
    Ok(parsed)
}

struct InflightRelease(Option<Arc<AtomicUsize>>);

impl Drop for InflightRelease {
    fn drop(&mut self) {
        if let Some(counter) = self.0.take() {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

pub(crate) fn h2_response_body(body: RecvStream) -> Body {
    h2_response_body_with_inflight(body, None)
}

pub(crate) fn h2_response_body_with_inflight(
    body: RecvStream,
    inflight: Option<Arc<AtomicUsize>>,
) -> Body {
    if body.is_end_stream() {
        drop(InflightRelease(inflight));
        return Body::empty();
    }
    Body::wrap(H2RecvBody::response(body, inflight))
}

pub(crate) fn h2_response_to_hyper(
    response: ::http::Response<RecvStream>,
) -> Result<Response<Body>> {
    let (mut parts, body) = response.into_parts();
    parts.status =
        qpx_http::protocol::semantics::validate_http_status_class(parts.status, "HTTP/2 response")?;
    parts.headers = h1_headers_into_http(parts.headers)?;
    parts.version = http::Version::HTTP_2;
    Ok(Response::from_parts(parts, h2_response_body(body)))
}

pub(crate) fn h2_response_to_hyper_with_inflight(
    response: ::http::Response<RecvStream>,
    inflight: Option<Arc<AtomicUsize>>,
) -> Result<Response<Body>> {
    let (mut parts, body) = response.into_parts();
    parts.status =
        qpx_http::protocol::semantics::validate_http_status_class(parts.status, "HTTP/2 response")?;
    parts.headers = h1_headers_into_http(parts.headers)?;
    parts.version = http::Version::HTTP_2;
    Ok(Response::from_parts(
        parts,
        h2_response_body_with_inflight(body, inflight),
    ))
}

fn body_from_h2_stream(body: RecvStream, _body_channel_capacity: usize) -> Body {
    if body.is_end_stream() {
        return Body::empty();
    }
    Body::wrap(H2RecvBody::request(body))
}

enum H2RecvBodyKind {
    Request { seen: u64 },
    Response { _inflight: InflightRelease },
}

enum H2RecvBodyState {
    Data,
    Trailers,
    Done,
}

struct H2RecvBody {
    body: Option<RecvStream>,
    kind: H2RecvBodyKind,
    state: H2RecvBodyState,
    read_timer: Option<Pin<Box<Sleep>>>,
}

impl H2RecvBody {
    fn request(body: RecvStream) -> Self {
        Self {
            body: Some(body),
            kind: H2RecvBodyKind::Request { seen: 0 },
            state: H2RecvBodyState::Data,
            read_timer: None,
        }
    }

    fn response(body: RecvStream, inflight: Option<Arc<AtomicUsize>>) -> Self {
        Self {
            body: Some(body),
            kind: H2RecvBodyKind::Response {
                _inflight: InflightRelease(inflight),
            },
            state: H2RecvBodyState::Data,
            read_timer: None,
        }
    }

    fn error(message: impl Into<String>) -> BodyError {
        BodyError::new(message)
    }

    fn clear_timer(&mut self) {
        self.read_timer = None;
    }

    fn body_mut(&mut self) -> Result<&mut RecvStream, BodyError> {
        self.body
            .as_mut()
            .ok_or_else(|| Self::error("HTTP/2 body stream is unavailable"))
    }
}

impl Drop for H2RecvBody {
    fn drop(&mut self) {
        if !matches!(self.kind, H2RecvBodyKind::Request { .. })
            || matches!(self.state, H2RecvBodyState::Done)
        {
            return;
        }
        let Some(body) = self.body.take() else {
            return;
        };
        if body.is_end_stream() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            warn!("cannot drain abandoned HTTP/2 request body outside a Tokio runtime");
            return;
        };
        runtime.spawn(drain_abandoned_h2_request(body));
    }
}

impl http_body::Body for H2RecvBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        loop {
            match this.state {
                H2RecvBodyState::Data => match poll_h2_data(this, cx) {
                    Poll::Ready(Ok(Some(chunk))) => {
                        if let H2RecvBodyKind::Request { seen } = &mut this.kind {
                            *seen = match seen.checked_add(chunk.len() as u64) {
                                Some(seen) => seen,
                                None => {
                                    this.state = H2RecvBodyState::Done;
                                    return Poll::Ready(Some(Err(Self::error(
                                        "HTTP/2 request body length overflow",
                                    ))));
                                }
                            };
                        }
                        let len = chunk.len();
                        let release = this.body_mut().and_then(|body| {
                            body.flow_control()
                                .release_capacity(len)
                                .map_err(|err| Self::error(err.to_string()))
                        });
                        if let Err(err) = release {
                            this.state = H2RecvBodyState::Done;
                            return Poll::Ready(Some(Err(Self::error(format!(
                                "HTTP/2 body flow control release failed: {err}"
                            )))));
                        }
                        if chunk.is_empty() {
                            continue;
                        }
                        return Poll::Ready(Some(Ok(Frame::data(chunk))));
                    }
                    Poll::Ready(Ok(None)) => {
                        this.state = H2RecvBodyState::Trailers;
                        continue;
                    }
                    Poll::Ready(Err(err)) => {
                        this.state = H2RecvBodyState::Done;
                        return Poll::Ready(Some(Err(err)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                H2RecvBodyState::Trailers => match poll_h2_trailers(this, cx) {
                    Poll::Ready(Ok(Some(trailers))) => {
                        this.state = H2RecvBodyState::Done;
                        let trailers = match h1_headers_to_http(&trailers) {
                            Ok(trailers) => trailers,
                            Err(err) => {
                                return Poll::Ready(Some(Err(Self::error(err.to_string()))));
                            }
                        };
                        if matches!(this.kind, H2RecvBodyKind::Request { .. })
                            && let Err(err) =
                                qpx_http::protocol::semantics::validate_request_trailers(&trailers)
                        {
                            return Poll::Ready(Some(Err(Self::error(format!(
                                "invalid HTTP/2 request trailers: {err:?}"
                            )))));
                        }
                        return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                    }
                    Poll::Ready(Ok(None)) => {
                        this.state = H2RecvBodyState::Done;
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Err(err)) => {
                        this.state = H2RecvBodyState::Done;
                        return Poll::Ready(Some(Err(err)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                H2RecvBodyState::Done => return Poll::Ready(None),
            }
        }
    }
}

fn poll_h2_data(
    body: &mut H2RecvBody,
    cx: &mut Context<'_>,
) -> Poll<Result<Option<Bytes>, BodyError>> {
    ensure_h2_read_timer(body);
    let poll = match body.body_mut() {
        Ok(stream) => stream.poll_data(cx),
        Err(err) => return Poll::Ready(Err(err)),
    };
    match poll {
        Poll::Ready(Some(Ok(chunk))) => {
            body.clear_timer();
            Poll::Ready(Ok(Some(chunk)))
        }
        Poll::Ready(Some(Err(err))) => {
            body.clear_timer();
            Poll::Ready(Err(BodyError::new(err.to_string())))
        }
        Poll::Ready(None) => {
            body.clear_timer();
            Poll::Ready(Ok(None))
        }
        Poll::Pending => poll_h2_idle_timeout(body, cx, "HTTP/2 body stream timed out while idle"),
    }
}

fn poll_h2_trailers(
    body: &mut H2RecvBody,
    cx: &mut Context<'_>,
) -> Poll<Result<Option<::http::HeaderMap>, BodyError>> {
    ensure_h2_read_timer(body);
    let poll = match body.body_mut() {
        Ok(stream) => stream.poll_trailers(cx),
        Err(err) => return Poll::Ready(Err(err)),
    };
    match poll {
        Poll::Ready(Ok(trailers)) => {
            body.clear_timer();
            Poll::Ready(Ok(trailers))
        }
        Poll::Ready(Err(err)) => {
            body.clear_timer();
            Poll::Ready(Err(BodyError::new(err.to_string())))
        }
        Poll::Pending => poll_h2_idle_timeout(body, cx, "HTTP/2 trailers timed out while idle"),
    }
}

async fn drain_abandoned_h2_request(mut body: RecvStream) {
    let drain = async {
        let mut drained = 0usize;
        while let Some(chunk) = body.data().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(err) => {
                    debug!(error = ?err, "abandoned HTTP/2 request body drain failed");
                    return;
                }
            };
            drained = match drained.checked_add(chunk.len()) {
                Some(drained) => drained,
                None => {
                    debug!("abandoned HTTP/2 request body drain size overflow");
                    return;
                }
            };
            if drained > H2_ABANDONED_REQUEST_DRAIN_LIMIT {
                debug!(
                    limit = H2_ABANDONED_REQUEST_DRAIN_LIMIT,
                    "abandoned HTTP/2 request body drain reached its limit"
                );
                return;
            }
            if let Err(err) = body.flow_control().release_capacity(chunk.len()) {
                warn!(error = ?err, "abandoned HTTP/2 request body flow control release failed");
                return;
            }
        }
        if let Err(err) = body.trailers().await {
            debug!(error = ?err, "abandoned HTTP/2 request trailer drain failed");
        }
    };

    if timeout(H2_BODY_IDLE_TIMEOUT, drain).await.is_err() {
        debug!("abandoned HTTP/2 request body drain timed out");
    }
}

fn ensure_h2_read_timer(body: &mut H2RecvBody) {
    if body.read_timer.is_none() {
        body.read_timer = Some(Box::pin(tokio::time::sleep(H2_BODY_IDLE_TIMEOUT)));
    }
}

fn poll_h2_idle_timeout<T>(
    body: &mut H2RecvBody,
    cx: &mut Context<'_>,
    message: &'static str,
) -> Poll<Result<Option<T>, BodyError>> {
    if let Some(timer) = body.read_timer.as_mut()
        && timer.as_mut().poll(cx).is_ready()
    {
        body.clear_timer();
        return Poll::Ready(Err(BodyError::new(message)));
    }
    Poll::Pending
}

#[cfg(test)]
mod tests;
