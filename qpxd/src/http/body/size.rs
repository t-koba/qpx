use crate::http::body::{Body, BodyError};
use crate::http::rpc::{PrecomputedRpcBodySummary, RpcBodySummaryObserver};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use http_body::Frame;
use hyper::{Request, Response};
use metrics::counter;
use std::fmt;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::fs::File as TokioFile;
use tokio::io::AsyncWriteExt;

mod io;
mod storage;

use self::io::{parse_content_length, read_body_data, read_body_trailers};
pub(crate) use self::storage::ObservedBodyReader;
use self::storage::{
    ObservedBodyBytes, ObservedBodyFile, ObservedBodySize, ObservedBodyStorage,
    ObservedBodyTrailers, feed_rpc_summary_observer, finish_rpc_summary_observer,
    should_precompute_rpc_summary,
};

const OBSERVED_BODY_MEMORY_BYTES: usize = 64 * 1024;
const OBSERVED_BODY_FILE_CHUNK_BYTES: usize = 64 * 1024;
#[cfg(test)]
const BUFFER_REASON_REQUEST_BODY: &str = "request.body";
#[cfg(test)]
const BUFFER_REASON_RESPONSE_BODY: &str = "response.body";
#[cfg(test)]
const BUFFER_REASON_REQUEST_SIZE_UNKNOWN: &str = "request.size_exact_unknown";
#[cfg(test)]
const BUFFER_REASON_RESPONSE_SIZE_UNKNOWN: &str = "response.size_exact_unknown";

pub(crate) fn observed_request_size(req: &Request<Body>) -> Option<u64> {
    req.extensions()
        .get::<ObservedBodySize>()
        .map(|size| size.0)
        .or_else(|| parse_content_length(req.headers()))
}

pub(crate) fn has_observed_request_bytes(req: &Request<Body>) -> bool {
    req.extensions().get::<ObservedBodyBytes>().is_some()
}

pub(crate) fn observed_request_body_reader(req: &Request<Body>) -> Option<ObservedBodyReader> {
    req.extensions()
        .get::<ObservedBodyBytes>()
        .cloned()
        .map(|body| ObservedBodyReader { body })
}

#[cfg(test)]
pub(crate) fn observed_request_bytes(req: &Request<Body>) -> Option<Bytes> {
    req.extensions()
        .get::<ObservedBodyBytes>()
        .and_then(|body| body.read_all().ok())
}

pub(crate) fn observed_request_prefix_bytes_async(
    req: &Request<Body>,
    max_bytes: usize,
) -> impl std::future::Future<Output = Option<Bytes>> + Send + 'static {
    let body = req.extensions().get::<ObservedBodyBytes>().cloned();
    async move {
        match body {
            Some(body) => body.read_prefix_async(max_bytes).await.ok(),
            None => None,
        }
    }
}

pub(crate) fn observed_request_trailers(req: &Request<Body>) -> Option<&HeaderMap> {
    req.extensions()
        .get::<ObservedBodyTrailers>()
        .map(|trailers| &trailers.0)
}

pub(crate) fn observed_response_size(response: &Response<Body>) -> Option<u64> {
    response
        .extensions()
        .get::<ObservedBodySize>()
        .map(|size| size.0)
        .or_else(|| parse_content_length(response.headers()))
}

#[cfg(test)]
pub(crate) fn observed_response_bytes(response: &Response<Body>) -> Option<Bytes> {
    response
        .extensions()
        .get::<ObservedBodyBytes>()
        .and_then(|body| body.read_all().ok())
}

pub(crate) fn observed_response_body_reader(
    response: &Response<Body>,
) -> Option<ObservedBodyReader> {
    response
        .extensions()
        .get::<ObservedBodyBytes>()
        .cloned()
        .map(|body| ObservedBodyReader { body })
}

pub(crate) fn observed_response_prefix_bytes_async(
    response: &Response<Body>,
    max_bytes: usize,
) -> impl std::future::Future<Output = Option<Bytes>> + Send + 'static {
    let body = response.extensions().get::<ObservedBodyBytes>().cloned();
    async move {
        match body {
            Some(body) => body.read_prefix_async(max_bytes).await.ok(),
            None => None,
        }
    }
}

pub(crate) fn observed_response_trailers(response: &Response<Body>) -> Option<&HeaderMap> {
    response
        .extensions()
        .get::<ObservedBodyTrailers>()
        .map(|trailers| &trailers.0)
}

pub(crate) fn set_observed_request_size(req: &mut Request<Body>, size: u64) {
    req.extensions_mut().insert(ObservedBodySize(size));
}

pub(crate) fn limit_request_body(
    req: Request<Body>,
    max_body_bytes: usize,
) -> Result<Request<Body>> {
    if let Some(size) = observed_request_size(&req) {
        ensure_observed_size_within_limit(size, max_body_bytes)?;
    }
    if has_observed_request_bytes(&req) {
        return Ok(req);
    }
    let (parts, body) = req.into_parts();
    Ok(Request::from_parts(
        parts,
        Body::wrap(LimitedBody {
            inner: body,
            seen: 0,
            limit: max_body_bytes,
            exceeded: false,
        }),
    ))
}

#[derive(Debug)]
pub(crate) struct ObservedBodyLimitExceeded {
    limit: usize,
}

impl fmt::Display for ObservedBodyLimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "observed body exceeds hard cap of {} bytes", self.limit)
    }
}

impl std::error::Error for ObservedBodyLimitExceeded {}

pub(crate) fn is_observed_body_limit_exceeded(err: &anyhow::Error) -> bool {
    err.downcast_ref::<ObservedBodyLimitExceeded>().is_some()
}

struct LimitedBody {
    inner: Body,
    seen: usize,
    limit: usize,
    exceeded: bool,
}

impl http_body::Body for LimitedBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.exceeded {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let next = self.seen.saturating_add(data.len());
                    if next > self.limit {
                        self.exceeded = true;
                        Poll::Ready(Some(Err(BodyError::new(format!(
                            "request body exceeds hard cap of {} bytes",
                            self.limit
                        )))))
                    } else {
                        self.seen = next;
                        Poll::Ready(Some(Ok(Frame::data(data))))
                    }
                }
                Err(frame) => Poll::Ready(Some(Ok(frame))),
            },
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.exceeded || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let mut hint = self.inner.size_hint();
        if let Some(upper) = hint.upper() {
            hint.set_upper(upper.min(self.limit.saturating_sub(self.seen) as u64));
        } else {
            hint.set_upper(self.limit.saturating_sub(self.seen) as u64);
        }
        hint
    }
}

#[cfg(test)]
pub(crate) async fn buffer_request_body(
    req: Request<Body>,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<Request<Body>> {
    buffer_request_body_with_reason(
        req,
        max_body_bytes,
        read_timeout,
        BUFFER_REASON_REQUEST_BODY,
    )
    .await
}

pub(crate) async fn buffer_request_body_with_reason(
    req: Request<Body>,
    max_body_bytes: usize,
    read_timeout: Duration,
    reason: &'static str,
) -> Result<Request<Body>> {
    observe_request_body(req, true, max_body_bytes, read_timeout, reason).await
}

#[cfg(test)]
pub(crate) async fn observe_request_body_size(
    req: Request<Body>,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<Request<Body>> {
    observe_request_body_size_with_reason(
        req,
        max_body_bytes,
        read_timeout,
        BUFFER_REASON_REQUEST_SIZE_UNKNOWN,
    )
    .await
}

pub(crate) async fn observe_request_body_size_with_reason(
    req: Request<Body>,
    max_body_bytes: usize,
    read_timeout: Duration,
    reason: &'static str,
) -> Result<Request<Body>> {
    observe_request_body(req, false, max_body_bytes, read_timeout, reason).await
}

#[cfg(test)]
pub(crate) async fn buffer_response_body(
    response: Response<Body>,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<Response<Body>> {
    buffer_response_body_with_reason(
        response,
        max_body_bytes,
        read_timeout,
        BUFFER_REASON_RESPONSE_BODY,
    )
    .await
}

pub(crate) async fn buffer_response_body_with_reason(
    response: Response<Body>,
    max_body_bytes: usize,
    read_timeout: Duration,
    reason: &'static str,
) -> Result<Response<Body>> {
    observe_response_body(response, true, max_body_bytes, read_timeout, reason).await
}

#[cfg(test)]
pub(crate) async fn observe_response_body_size(
    response: Response<Body>,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<Response<Body>> {
    observe_response_body_size_with_reason(
        response,
        max_body_bytes,
        read_timeout,
        BUFFER_REASON_RESPONSE_SIZE_UNKNOWN,
    )
    .await
}

pub(crate) async fn observe_response_body_size_with_reason(
    response: Response<Body>,
    max_body_bytes: usize,
    read_timeout: Duration,
    reason: &'static str,
) -> Result<Response<Body>> {
    observe_response_body(response, false, max_body_bytes, read_timeout, reason).await
}

async fn observe_request_body(
    req: Request<Body>,
    keep_bytes: bool,
    max_body_bytes: usize,
    read_timeout: Duration,
    reason: &'static str,
) -> Result<Request<Body>> {
    let (parts, body) = req.into_parts();
    if keep_bytes {
        let rpc_summary_observer = should_precompute_rpc_summary(reason)
            .then(|| crate::http::rpc::request_body_summary_observer(&parts.headers))
            .flatten();
        let (observed, trailers, rpc_summary) = collect_observed_body(
            body,
            max_body_bytes,
            read_timeout,
            "request",
            reason,
            rpc_summary_observer,
        )
        .await?;
        let mut req = Request::from_parts(parts, observed.replay_body(trailers.clone()));
        set_observed_request_size(&mut req, observed.len);
        req.extensions_mut().insert(observed);
        if let Some(summary) = rpc_summary {
            req.extensions_mut().insert(summary);
        }
        if let Some(trailers) = trailers {
            req.extensions_mut().insert(ObservedBodyTrailers(trailers));
        }
        Ok(req)
    } else {
        if let Some(size) = parse_content_length(&parts.headers) {
            ensure_observed_size_within_limit(size, max_body_bytes)?;
            let mut req = Request::from_parts(parts, body);
            set_observed_request_size(&mut req, size);
            return Ok(req);
        }
        let (observed, trailers) =
            collect_observed_body_for_size(body, max_body_bytes, read_timeout, "request", reason)
                .await?;
        let mut req = Request::from_parts(parts, observed.replay_body(trailers));
        set_observed_request_size(&mut req, observed.len);
        Ok(req)
    }
}

async fn observe_response_body(
    response: Response<Body>,
    keep_bytes: bool,
    max_body_bytes: usize,
    read_timeout: Duration,
    reason: &'static str,
) -> Result<Response<Body>> {
    let (parts, body) = response.into_parts();
    if keep_bytes {
        let rpc_summary_observer = should_precompute_rpc_summary(reason)
            .then(|| crate::http::rpc::response_body_summary_observer(&parts.headers))
            .flatten();
        let (observed, trailers, rpc_summary) = collect_observed_body(
            body,
            max_body_bytes,
            read_timeout,
            "response",
            reason,
            rpc_summary_observer,
        )
        .await?;
        let mut response = Response::from_parts(parts, observed.replay_body(trailers.clone()));
        response
            .extensions_mut()
            .insert(ObservedBodySize(observed.len));
        response.extensions_mut().insert(observed);
        if let Some(summary) = rpc_summary {
            response.extensions_mut().insert(summary);
        }
        if let Some(trailers) = trailers {
            response
                .extensions_mut()
                .insert(ObservedBodyTrailers(trailers));
        }
        Ok(response)
    } else {
        if let Some(size) = parse_content_length(&parts.headers) {
            ensure_observed_size_within_limit(size, max_body_bytes)?;
            let mut response = Response::from_parts(parts, body);
            response.extensions_mut().insert(ObservedBodySize(size));
            return Ok(response);
        }
        let (observed, trailers) =
            collect_observed_body_for_size(body, max_body_bytes, read_timeout, "response", reason)
                .await?;
        let mut response = Response::from_parts(parts, observed.replay_body(trailers));
        response
            .extensions_mut()
            .insert(ObservedBodySize(observed.len));
        Ok(response)
    }
}

fn ensure_observed_size_within_limit(size: u64, max_body_bytes: usize) -> Result<()> {
    if size > max_body_bytes as u64 {
        return Err(ObservedBodyLimitExceeded {
            limit: max_body_bytes,
        }
        .into());
    }
    Ok(())
}

async fn collect_observed_body(
    mut body: Body,
    max_body_bytes: usize,
    read_timeout: Duration,
    direction: &'static str,
    reason: &'static str,
    mut rpc_summary_observer: Option<RpcBodySummaryObserver>,
) -> Result<(
    ObservedBodyBytes,
    Option<HeaderMap>,
    Option<PrecomputedRpcBodySummary>,
)> {
    let mut chunks = Vec::new();
    let mut file: Option<(TokioFile, PathBuf)> = None;
    let mut size = 0usize;
    while let Some(chunk) = read_body_data(&mut body, read_timeout).await? {
        let chunk = chunk?;
        let next = size
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("observed body size overflow"))?;
        if next > max_body_bytes {
            return Err(ObservedBodyLimitExceeded {
                limit: max_body_bytes,
            }
            .into());
        }
        size = next;
        feed_rpc_summary_observer(&mut rpc_summary_observer, chunk.as_ref());
        if file.is_none() && size <= OBSERVED_BODY_MEMORY_BYTES {
            chunks.push(chunk);
            continue;
        }
        if file.is_none() {
            let (mut spool, path) = create_observed_body_spool()?;
            for existing in chunks.drain(..) {
                spool.write_all(existing.as_ref()).await?;
            }
            file = Some((spool, path));
        }
        if let Some((spool, _)) = file.as_mut() {
            spool.write_all(chunk.as_ref()).await?;
        }
    }
    let trailers = read_body_trailers(&mut body, read_timeout).await?;
    let mut spooled = 0usize;
    let storage = if let Some((mut spool, path)) = file {
        spool.flush().await?;
        drop(spool);
        spooled = size;
        ObservedBodyStorage::File(Arc::new(ObservedBodyFile { path }))
    } else {
        ObservedBodyStorage::Memory(Arc::from(chunks))
    };
    record_body_buffering(direction, reason, size, spooled);
    let rpc_summary = finish_rpc_summary_observer(rpc_summary_observer);
    Ok((
        ObservedBodyBytes {
            storage,
            len: size as u64,
        },
        trailers,
        rpc_summary,
    ))
}

async fn collect_observed_body_for_size(
    mut body: Body,
    max_body_bytes: usize,
    read_timeout: Duration,
    direction: &'static str,
    reason: &'static str,
) -> Result<(ObservedBodyBytes, Option<HeaderMap>)> {
    let mut chunks = Vec::new();
    let mut file: Option<(TokioFile, PathBuf)> = None;
    let mut size = 0usize;
    while let Some(chunk) = read_body_data(&mut body, read_timeout).await? {
        let chunk = chunk?;
        let next = size
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("observed body size overflow"))?;
        if next > max_body_bytes {
            return Err(ObservedBodyLimitExceeded {
                limit: max_body_bytes,
            }
            .into());
        }
        size = next;
        if file.is_none() && size <= OBSERVED_BODY_MEMORY_BYTES {
            chunks.push(chunk);
            continue;
        }
        if file.is_none() {
            let (mut spool, path) = create_observed_body_spool()?;
            for existing in chunks.drain(..) {
                spool.write_all(existing.as_ref()).await?;
            }
            file = Some((spool, path));
        }
        if let Some((spool, _)) = file.as_mut() {
            spool.write_all(chunk.as_ref()).await?;
        }
    }
    let trailers = read_body_trailers(&mut body, read_timeout).await?;
    let mut spooled = 0usize;
    let storage = if let Some((mut spool, path)) = file {
        spool.flush().await?;
        drop(spool);
        spooled = size;
        ObservedBodyStorage::File(Arc::new(ObservedBodyFile { path }))
    } else {
        ObservedBodyStorage::Memory(Arc::from(chunks))
    };
    record_body_buffering(direction, reason, size, spooled);
    Ok((
        ObservedBodyBytes {
            storage,
            len: size as u64,
        },
        trailers,
    ))
}

fn record_body_buffering(
    direction: &'static str,
    reason: &'static str,
    bytes: usize,
    spooled: usize,
) {
    counter!(
        "qpx_body_buffering_events_total",
        "direction" => direction,
        "reason" => reason
    )
    .increment(1);
    counter!(
        "qpx_body_buffering_bytes_total",
        "direction" => direction,
        "reason" => reason
    )
    .increment(bytes as u64);
    if spooled > 0 {
        counter!(
            "qpx_body_spooled_bytes_total",
            "direction" => direction,
            "reason" => reason
        )
        .increment(spooled as u64);
    }
}
fn create_observed_body_spool() -> Result<(TokioFile, PathBuf)> {
    let (file, path) =
        qpx_core::secure_file::create_secure_temp_file("qpx-observed-body", ".body")?;
    Ok((TokioFile::from_std(file), path))
}

#[cfg(test)]
mod tests;
