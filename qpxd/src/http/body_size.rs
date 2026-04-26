use crate::http::body::Body;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use http::HeaderMap;
use hyper::{Request, Response};
use std::fmt;
use std::time::Duration;
use tokio::time::timeout;

#[derive(Clone, Copy, Debug)]
struct ObservedBodySize(u64);

#[derive(Clone, Debug)]
struct ObservedBodyBytes(Bytes);

#[derive(Clone, Debug)]
struct ObservedBodyTrailers(HeaderMap);

pub(crate) fn observed_request_size(req: &Request<Body>) -> Option<u64> {
    req.extensions()
        .get::<ObservedBodySize>()
        .map(|size| size.0)
        .or_else(|| parse_content_length(req.headers()))
}

pub(crate) fn observed_request_bytes(req: &Request<Body>) -> Option<&Bytes> {
    req.extensions()
        .get::<ObservedBodyBytes>()
        .map(|bytes| &bytes.0)
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

pub(crate) fn observed_response_bytes(response: &Response<Body>) -> Option<&Bytes> {
    response
        .extensions()
        .get::<ObservedBodyBytes>()
        .map(|bytes| &bytes.0)
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

pub(crate) async fn buffer_request_body(
    req: Request<Body>,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<Request<Body>> {
    observe_request_body(req, true, max_body_bytes, read_timeout).await
}

pub(crate) async fn observe_request_body_size(
    req: Request<Body>,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<Request<Body>> {
    observe_request_body(req, false, max_body_bytes, read_timeout).await
}

pub(crate) async fn buffer_response_body(
    response: Response<Body>,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<Response<Body>> {
    observe_response_body(response, true, max_body_bytes, read_timeout).await
}

pub(crate) async fn observe_response_body_size(
    response: Response<Body>,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<Response<Body>> {
    observe_response_body(response, false, max_body_bytes, read_timeout).await
}

async fn observe_request_body(
    req: Request<Body>,
    keep_bytes: bool,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<Request<Body>> {
    let (parts, body) = req.into_parts();
    if keep_bytes {
        let (body, trailers) = collect_body(body, max_body_bytes, read_timeout).await?;
        let mut req = Request::from_parts(parts, Body::replay(body.clone(), trailers.clone()));
        set_observed_request_size(&mut req, body.len() as u64);
        req.extensions_mut().insert(ObservedBodyBytes(body));
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
        let (chunks, trailers, size) =
            collect_body_chunks(body, max_body_bytes, read_timeout).await?;
        let mut req = Request::from_parts(parts, Body::replay_chunks(chunks, trailers));
        set_observed_request_size(&mut req, size);
        Ok(req)
    }
}

async fn observe_response_body(
    response: Response<Body>,
    keep_bytes: bool,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<Response<Body>> {
    let (parts, body) = response.into_parts();
    if keep_bytes {
        let (body, trailers) = collect_body(body, max_body_bytes, read_timeout).await?;
        let mut response =
            Response::from_parts(parts, Body::replay(body.clone(), trailers.clone()));
        response
            .extensions_mut()
            .insert(ObservedBodySize(body.len() as u64));
        response.extensions_mut().insert(ObservedBodyBytes(body));
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
        let (chunks, trailers, size) =
            collect_body_chunks(body, max_body_bytes, read_timeout).await?;
        let mut response = Response::from_parts(parts, Body::replay_chunks(chunks, trailers));
        response.extensions_mut().insert(ObservedBodySize(size));
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

async fn collect_body(
    mut body: Body,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<(Bytes, Option<HeaderMap>)> {
    let mut out = Vec::new();
    while let Some(chunk) = read_body_data(&mut body, read_timeout).await? {
        let chunk = chunk?;
        let next = out
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("observed body size overflow"))?;
        if next > max_body_bytes {
            return Err(ObservedBodyLimitExceeded {
                limit: max_body_bytes,
            }
            .into());
        }
        out.extend_from_slice(&chunk);
    }
    let trailers = read_body_trailers(&mut body, read_timeout).await?;
    Ok((Bytes::from(out), trailers))
}

async fn collect_body_chunks(
    mut body: Body,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> Result<(Vec<Bytes>, Option<HeaderMap>, u64)> {
    let mut chunks = Vec::new();
    let mut size = 0u64;
    while let Some(chunk) = read_body_data(&mut body, read_timeout).await? {
        let chunk = chunk?;
        size = size
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| anyhow!("observed body size overflow"))?;
        if size > max_body_bytes as u64 {
            return Err(ObservedBodyLimitExceeded {
                limit: max_body_bytes,
            }
            .into());
        }
        chunks.push(chunk);
    }
    let trailers = read_body_trailers(&mut body, read_timeout).await?;
    Ok((chunks, trailers, size))
}

async fn read_body_data(
    body: &mut Body,
    read_timeout: Duration,
) -> Result<Option<Result<Bytes, crate::http::body::BodyError>>> {
    timeout(read_timeout, body.data())
        .await
        .map_err(|_| anyhow!("observed body read timed out"))
}

async fn read_body_trailers(body: &mut Body, read_timeout: Duration) -> Result<Option<HeaderMap>> {
    timeout(read_timeout, body.trailers())
        .await
        .map_err(|_| anyhow!("observed body trailers read timed out"))?
        .map_err(Into::into)
}

fn parse_content_length(headers: &http::HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn buffer_request_body_rejects_before_exceeding_hard_cap() {
        let req = Request::builder()
            .body(Body::from(vec![0_u8; 5]))
            .expect("request");
        let err = buffer_request_body(req, 4, Duration::from_secs(1))
            .await
            .expect_err("body over cap must fail");
        assert!(is_observed_body_limit_exceeded(&err));
    }

    #[tokio::test]
    async fn observe_response_body_size_rejects_before_exceeding_hard_cap() {
        let response = Response::builder()
            .body(Body::from(vec![0_u8; 5]))
            .expect("response");
        let err = observe_response_body_size(response, 4, Duration::from_secs(1))
            .await
            .expect_err("body over cap must fail");
        assert!(is_observed_body_limit_exceeded(&err));
    }

    #[tokio::test]
    async fn observe_request_body_size_uses_content_length_without_buffering() {
        let (_sender, body) = Body::channel();
        let req = Request::builder()
            .header(CONTENT_LENGTH, "4")
            .body(body)
            .expect("request");

        let req = timeout(
            Duration::from_millis(25),
            observe_request_body_size(req, 8, Duration::from_secs(1)),
        )
        .await
        .expect("content-length size observation must not wait for body")
        .expect("observe");
        assert_eq!(observed_request_size(&req), Some(4));
    }

    #[tokio::test]
    async fn observe_response_body_size_rejects_content_length_over_cap_without_buffering() {
        let (_sender, body) = Body::channel();
        let response = Response::builder()
            .header(CONTENT_LENGTH, "9")
            .body(body)
            .expect("response");

        let err = timeout(
            Duration::from_millis(25),
            observe_response_body_size(response, 8, Duration::from_secs(1)),
        )
        .await
        .expect("content-length limit check must not wait for body")
        .expect_err("must fail");
        assert!(is_observed_body_limit_exceeded(&err));
    }

    #[tokio::test]
    async fn buffer_request_body_times_out_idle_body() {
        let (_sender, body) = Body::channel();
        let req = Request::builder().body(body).expect("request");

        let err = buffer_request_body(req, 1024, Duration::from_millis(10))
            .await
            .expect_err("idle body must time out");
        assert!(err.to_string().contains("observed body read timed out"));
    }
}
