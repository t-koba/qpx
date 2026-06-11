use crate::upstream::raw_http1::InterimResponseHead;
use ::http::{Request as Http1Request, Response as Http1Response};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use h2::Reason;
use h2::RecvStream;
use h2::server::SendResponse;
use hyper::header::{CONTENT_LENGTH, COOKIE};
use hyper::{Request, Response, Uri};
use qpx_http::body::Body;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::spawn;
use tokio::time::{Duration, sleep, timeout};
use tracing::warn;

const H2_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(test)]
pub(crate) fn h2_request_to_hyper(req: Http1Request<RecvStream>) -> Result<Request<Body>> {
    h2_request_to_hyper_with_capacity(req, 16)
}

pub(crate) fn h2_request_to_hyper_with_capacity(
    req: Http1Request<RecvStream>,
    body_channel_capacity: usize,
) -> Result<Request<Body>> {
    let (parts, body) = req.into_parts();
    let method = parts
        .method
        .as_str()
        .parse::<http::Method>()
        .map_err(|_| anyhow!("invalid HTTP/2 method"))?;
    let uri = parts
        .uri
        .to_string()
        .parse::<Uri>()
        .or_else(|_| {
            let path = parts
                .uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            Uri::builder().path_and_query(path).build()
        })
        .map_err(|e| anyhow!("invalid HTTP/2 URI: {e}"))?;

    let headers = h1_headers_to_http(&parts.headers)?;
    // The h2 transport already enforces RFC 9113 content-length reconciliation
    // while decoding DATA / END_STREAM on the inbound stream. We still parse the
    // header locally to reject conflicting field-values before handing the
    // request to Hyper, but body-length mismatches surface via the body stream.
    let _declared_length = parse_declared_content_length(&headers)?;
    let body = body_from_h2_stream(body, body_channel_capacity);
    let mut out = Request::builder().method(method).uri(uri).body(body)?;
    *out.headers_mut() = headers;
    *out.version_mut() = http::Version::HTTP_2;
    if let Some(protocol) = parts.extensions.get::<h2::ext::Protocol>().cloned() {
        out.extensions_mut().insert(protocol);
    }
    Ok(out)
}

pub(crate) async fn send_h2_response_with_interim(
    mut respond: SendResponse<Bytes>,
    response: Response<Body>,
    interim: &[InterimResponseHead],
    request_method: &http::Method,
    allow_successful_connect_body: bool,
    body_read_timeout: Duration,
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
        let mut informational = Http1Response::builder().status(status).body(())?;
        *informational.headers_mut() = http_headers_to_h1(&headers)?;
        respond.send_informational(informational)?;
    }

    let (parts, mut body) = response.into_parts();
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
    let mut headers = parts.headers;
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
    let mut head = Http1Response::builder().status(status).body(())?;
    *head.headers_mut() = http_headers_to_h1(&headers)?;

    let mut send_stream = respond.send_response(head, no_body)?;

    if no_body {
        return Ok(());
    }

    let mut sent_len = 0u64;
    while let Some(chunk) = match read_h2_response_body_chunk(&mut body, body_read_timeout).await {
        Ok(chunk) => chunk,
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
            send_stream.send_data(chunk, false)?;
        }
    }

    let trailers = match read_h2_response_trailers(&mut body, body_read_timeout).await {
        Ok(trailers) => trailers,
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
            send_stream.send_data(Bytes::new(), true)?;
        } else {
            send_stream.send_trailers(http_headers_to_h1(&trailers)?)?;
        }
    } else {
        send_stream.send_data(Bytes::new(), true)?;
    }

    Ok(())
}

async fn read_h2_response_body_chunk(
    body: &mut Body,
    body_read_timeout: Duration,
) -> Result<Option<Result<Bytes, qpx_http::body::BodyError>>> {
    timeout(body_read_timeout, body.data())
        .await
        .map_err(|_| anyhow!("HTTP/2 response body read timed out"))
}

async fn read_h2_response_trailers(
    body: &mut Body,
    body_read_timeout: Duration,
) -> Result<Option<http::HeaderMap>> {
    timeout(body_read_timeout, body.trailers())
        .await
        .map_err(|_| anyhow!("HTTP/2 response trailer read timed out"))?
        .map_err(Into::into)
}

pub(crate) fn h1_headers_to_http(src: &::http::HeaderMap) -> Result<http::HeaderMap> {
    let mut headers = http::HeaderMap::new();
    for (name, value) in src {
        let name = http::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|e| anyhow!("invalid header name from HTTP/2 message: {e}"))?;
        let value = http::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|e| anyhow!("invalid header value from HTTP/2 message: {e}"))?;
        if name == COOKIE
            && let Some(existing) = headers.get(COOKIE).cloned()
        {
            let mut merged =
                Vec::with_capacity(existing.as_bytes().len() + 2 + value.as_bytes().len());
            merged.extend_from_slice(existing.as_bytes());
            merged.extend_from_slice(b"; ");
            merged.extend_from_slice(value.as_bytes());
            headers.insert(COOKIE, http::HeaderValue::from_bytes(merged.as_slice())?);
            continue;
        }
        headers.append(name, value);
    }
    Ok(headers)
}

pub(crate) fn http_headers_to_h1(src: &http::HeaderMap) -> Result<::http::HeaderMap> {
    let mut headers = ::http::HeaderMap::new();
    for (name, value) in src {
        let name = ::http::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|e| anyhow!("invalid header name for HTTP/2 message: {e}"))?;
        let value = ::http::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|e| anyhow!("invalid header value for HTTP/2 message: {e}"))?;
        headers.append(name, value);
    }
    Ok(headers)
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
    mut body: RecvStream,
    inflight: Option<Arc<AtomicUsize>>,
) -> Body {
    if body.is_end_stream() {
        return Body::empty();
    }

    let (mut sender, out) = Body::channel_with_capacity(16);
    spawn(async move {
        let _release = InflightRelease(inflight);
        let mut flow = body.flow_control().clone();
        loop {
            let chunk = tokio::select! {
                _ = sender.closed() => return,
                _ = sleep(H2_BODY_IDLE_TIMEOUT) => {
                    warn!("HTTP/2 response body stream timed out while idle");
                    sender.abort();
                    return;
                }
                chunk = body.data() => chunk,
            };
            let Some(chunk) = chunk else {
                break;
            };
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(err) => {
                    warn!(error = ?err, "HTTP/2 response body stream failed");
                    sender.abort();
                    return;
                }
            };
            let len = chunk.len();
            if !chunk.is_empty() && sender.send_data(chunk).await.is_err() {
                let _ = flow.release_capacity(len);
                return;
            }
            if let Err(err) = flow.release_capacity(len) {
                warn!(error = ?err, "HTTP/2 response body flow control release failed");
                sender.abort();
                return;
            }
        }

        let trailers = match tokio::select! {
            _ = sender.closed() => return,
            _ = sleep(H2_BODY_IDLE_TIMEOUT) => {
                warn!("HTTP/2 response trailers timed out while idle");
                sender.abort();
                return;
            }
            trailers = body.trailers() => trailers,
        } {
            Ok(trailers) => trailers,
            Err(err) => {
                warn!(error = ?err, "HTTP/2 response trailers failed");
                sender.abort();
                return;
            }
        };
        if let Some(trailers) = trailers {
            let trailers = match h1_headers_to_http(&trailers) {
                Ok(trailers) => trailers,
                Err(err) => {
                    warn!(error = ?err, "invalid HTTP/2 response trailers");
                    sender.abort();
                    return;
                }
            };
            let _ = sender.send_trailers(trailers).await;
        }
    });
    out
}

pub(crate) fn h2_response_to_hyper(
    response: ::http::Response<RecvStream>,
) -> Result<Response<Body>> {
    let (parts, body) = response.into_parts();
    let status =
        qpx_http::protocol::semantics::validate_http_status_class(parts.status, "HTTP/2 response")?;
    let mut out = Response::builder()
        .status(status)
        .body(h2_response_body(body))?;
    *out.headers_mut() = h1_headers_to_http(&parts.headers)?;
    *out.version_mut() = http::Version::HTTP_2;
    Ok(out)
}

pub(crate) fn h2_response_to_hyper_with_inflight(
    response: ::http::Response<RecvStream>,
    inflight: Option<Arc<AtomicUsize>>,
) -> Result<Response<Body>> {
    let (parts, body) = response.into_parts();
    let status =
        qpx_http::protocol::semantics::validate_http_status_class(parts.status, "HTTP/2 response")?;
    let mut out = Response::builder()
        .status(status)
        .body(h2_response_body_with_inflight(body, inflight))?;
    *out.headers_mut() = h1_headers_to_http(&parts.headers)?;
    *out.version_mut() = http::Version::HTTP_2;
    Ok(out)
}

fn body_from_h2_stream(mut body: RecvStream, body_channel_capacity: usize) -> Body {
    if body.is_end_stream() {
        return Body::empty();
    }

    let (mut sender, out) = Body::channel_with_capacity(body_channel_capacity.max(1));
    spawn(async move {
        let mut flow = body.flow_control().clone();
        let mut seen = 0u64;
        loop {
            let chunk = tokio::select! {
                _ = sender.closed() => return,
                _ = sleep(H2_BODY_IDLE_TIMEOUT) => {
                    warn!("HTTP/2 request body stream timed out while idle");
                    sender.abort();
                    return;
                }
                chunk = body.data() => chunk,
            };
            let Some(chunk) = chunk else {
                break;
            };
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(err) => {
                    warn!(error = ?err, "HTTP/2 request body stream failed");
                    sender.abort();
                    return;
                }
            };
            let len = chunk.len();
            seen = match seen.checked_add(len as u64) {
                Some(seen) => seen,
                None => {
                    warn!("HTTP/2 request body length overflow");
                    sender.abort();
                    return;
                }
            };
            if !chunk.is_empty() && sender.send_data(chunk).await.is_err() {
                let _ = flow.release_capacity(len);
                return;
            }
            if let Err(err) = flow.release_capacity(len) {
                warn!(error = ?err, "HTTP/2 request body flow control release failed");
                sender.abort();
                return;
            }
        }

        let trailers = match tokio::select! {
            _ = sender.closed() => return,
            _ = sleep(H2_BODY_IDLE_TIMEOUT) => {
                warn!("HTTP/2 request trailers timed out while idle");
                sender.abort();
                return;
            }
            trailers = body.trailers() => trailers,
        } {
            Ok(trailers) => trailers,
            Err(err) => {
                warn!(error = ?err, "HTTP/2 request trailers failed");
                sender.abort();
                return;
            }
        };
        let Some(trailers) = trailers else {
            return;
        };
        let trailers = match h1_headers_to_http(&trailers) {
            Ok(trailers) => trailers,
            Err(err) => {
                warn!(error = ?err, "invalid HTTP/2 request trailers");
                sender.abort();
                return;
            }
        };
        if let Err(err) = qpx_http::protocol::semantics::validate_request_trailers(&trailers) {
            warn!(error = ?err, "rejecting forbidden HTTP/2 request trailers");
            sender.abort();
            return;
        }
        let _ = sender.send_trailers(trailers).await;
    });
    out
}

#[cfg(test)]
mod tests;
