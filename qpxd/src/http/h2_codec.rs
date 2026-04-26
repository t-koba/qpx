use crate::http::body::Body;
use crate::upstream::raw_http1::InterimResponseHead;
use ::http::{Request as Http1Request, Response as Http1Response};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::server::SendResponse;
use h2::Reason;
use h2::RecvStream;
use hyper::header::{CONTENT_LENGTH, COOKIE};
use hyper::{Request, Response, Uri};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::spawn;
use tokio::time::{sleep, timeout, Duration};
use tracing::warn;

const H2_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub fn h2_request_to_hyper(req: Http1Request<RecvStream>) -> Result<Request<Body>> {
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
    let body = body_from_h2_stream(body);
    let mut out = Request::builder().method(method).uri(uri).body(body)?;
    *out.headers_mut() = headers;
    *out.version_mut() = http::Version::HTTP_2;
    if let Some(protocol) = parts.extensions.get::<h2::ext::Protocol>().cloned() {
        out.extensions_mut().insert(protocol);
    }
    Ok(out)
}

pub async fn send_h2_response_with_interim(
    mut respond: SendResponse<Bytes>,
    response: Response<Body>,
    interim: &[InterimResponseHead],
    request_method: &http::Method,
    allow_successful_connect_body: bool,
    body_read_timeout: Duration,
) -> Result<()> {
    for head in interim {
        let status = ::http::StatusCode::from_u16(head.status.as_u16())
            .map_err(|e| anyhow!("invalid interim status for HTTP/2: {e}"))?;
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
        crate::http::semantics::sanitize_interim_response_headers(&mut headers);
        let mut informational = Http1Response::builder().status(status).body(())?;
        *informational.headers_mut() = http_headers_to_h1(&headers)?;
        respond.send_informational(informational)?;
    }

    let (parts, mut body) = response.into_parts();
    let status = ::http::StatusCode::from_u16(parts.status.as_u16())
        .map_err(|e| anyhow!("invalid response status for HTTP/2: {e}"))?;
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
            crate::http::semantics::strip_message_body_framing_headers(&mut headers);
            if parse_declared_content_length(&headers).is_err() {
                headers.remove(http::header::CONTENT_LENGTH);
            }
        } else {
            crate::http::semantics::strip_message_body_headers(&mut headers);
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
        if let Some(expected) = declared_length {
            if sent_len > expected {
                send_stream.send_reset(Reason::PROTOCOL_ERROR);
                return Err(anyhow!(
                    "HTTP/2 response body exceeded declared content-length"
                ));
            }
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
    if let Some(expected) = declared_length {
        if sent_len != expected {
            send_stream.send_reset(Reason::PROTOCOL_ERROR);
            return Err(anyhow!(
                "HTTP/2 response body ended before declared content-length was satisfied"
            ));
        }
    }
    if let Some(mut trailers) = trailers {
        let removed = crate::http::semantics::sanitize_response_trailers(&mut trailers);
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
) -> Result<Option<Result<Bytes, crate::http::body::BodyError>>> {
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
        if name == COOKIE {
            if let Some(existing) = headers.get(COOKIE).cloned() {
                let mut merged =
                    Vec::with_capacity(existing.as_bytes().len() + 2 + value.as_bytes().len());
                merged.extend_from_slice(existing.as_bytes());
                merged.extend_from_slice(b"; ");
                merged.extend_from_slice(value.as_bytes());
                headers.insert(COOKIE, http::HeaderValue::from_bytes(merged.as_slice())?);
                continue;
            }
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

    let (mut sender, out) = Body::channel();
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
    let status = http::StatusCode::from_u16(parts.status.as_u16())
        .map_err(|e| anyhow!("invalid HTTP/2 response status: {e}"))?;
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
    let status = http::StatusCode::from_u16(parts.status.as_u16())
        .map_err(|e| anyhow!("invalid HTTP/2 response status: {e}"))?;
    let mut out = Response::builder()
        .status(status)
        .body(h2_response_body_with_inflight(body, inflight))?;
    *out.headers_mut() = h1_headers_to_http(&parts.headers)?;
    *out.version_mut() = http::Version::HTTP_2;
    Ok(out)
}

fn body_from_h2_stream(mut body: RecvStream) -> Body {
    if body.is_end_stream() {
        return Body::empty();
    }

    let (mut sender, out) = Body::channel();
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
        if let Err(err) = crate::http::semantics::validate_request_trailers(&trailers) {
            warn!(error = ?err, "dropping forbidden HTTP/2 request trailers");
            sender.abort();
            return;
        }
        let _ = sender.send_trailers(trailers).await;
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::body::to_bytes;
    use hyper::StatusCode;
    use qpx_observability::RequestHandler;
    use std::future::poll_fn;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use tokio::net::{TcpListener, TcpStream};

    #[derive(Clone)]
    struct StaticInterimService;

    impl RequestHandler<Request<Body>> for StaticInterimService {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = Pin<
            Box<
                dyn std::future::Future<Output = Result<Response<Body>, std::convert::Infallible>>
                    + Send,
            >,
        >;

        fn call(&self, _req: Request<Body>) -> Self::Future {
            Box::pin(async move {
                let interim = vec![InterimResponseHead {
                    status: StatusCode::from_u16(103).expect("103"),
                    headers: {
                        let mut headers = http::HeaderMap::new();
                        headers.insert(
                            http::header::LINK,
                            http::HeaderValue::from_static("</app.css>; rel=preload; as=style"),
                        );
                        headers.insert(http::header::CONTENT_LENGTH, "99".parse().unwrap());
                        headers.insert(http::header::TRAILER, "x-trailer".parse().unwrap());
                        headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
                        headers
                    },
                }];
                let mut response = Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("OK"))
                    .expect("response");
                response.extensions_mut().insert(interim);
                Ok(response)
            })
        }
    }

    async fn serve_one_h2(socket: TcpStream) -> Result<()> {
        let mut conn = h2::server::handshake(socket).await?;
        while let Some(result) = conn.accept().await {
            let (request, respond) = result?;
            tokio::spawn(async move {
                let service = StaticInterimService;
                let request = h2_request_to_hyper(request).expect("request");
                let request_method = request.method().clone();
                let mut response = service.call(request).await.expect("response");
                let interim = response
                    .extensions_mut()
                    .remove::<Vec<InterimResponseHead>>()
                    .unwrap_or_default();
                send_h2_response_with_interim(
                    respond,
                    response,
                    &interim,
                    &request_method,
                    false,
                    H2_BODY_IDLE_TIMEOUT,
                )
                .await
                .expect("send response");
            });
        }
        poll_fn(|cx| conn.poll_closed(cx)).await?;
        Ok(())
    }

    #[tokio::test]
    async fn send_h2_response_with_interim_emits_early_hints() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            serve_one_h2(socket).await.expect("serve");
        });

        let socket = TcpStream::connect(addr).await.expect("connect");
        let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
        tokio::spawn(async move {
            connection.await.expect("client connection");
        });

        let mut client = client.ready().await.expect("ready");
        let request = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse.test/asset")
            .body(())
            .expect("request");
        let (mut response_future, _) = client.send_request(request, true).expect("send");

        let interim = poll_fn(|cx| response_future.poll_informational(cx)).await;
        let interim = interim
            .expect("informational state")
            .expect("informational ok");
        assert_eq!(interim.status(), ::http::StatusCode::EARLY_HINTS);
        assert_eq!(
            interim
                .headers()
                .get(::http::header::LINK)
                .and_then(|value: &::http::HeaderValue| value.to_str().ok()),
            Some("</app.css>; rel=preload; as=style")
        );
        assert!(!interim
            .headers()
            .contains_key(::http::header::CONTENT_LENGTH));
        assert!(!interim.headers().contains_key(::http::header::TRAILER));
        assert!(!interim
            .headers()
            .contains_key(::http::header::TRANSFER_ENCODING));

        let response = response_future.await.expect("final response");
        assert_eq!(response.status(), ::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn send_h2_response_strips_body_framing_for_no_body_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut conn = h2::server::handshake(socket).await.expect("handshake");
            while let Some(result) = conn.accept().await {
                let (_request, respond) = result.expect("request");
                tokio::spawn(async move {
                    let response = Response::builder()
                        .status(StatusCode::RESET_CONTENT)
                        .header(http::header::CONTENT_LENGTH, "7")
                        .header(http::header::TRANSFER_ENCODING, "chunked")
                        .header(http::header::TRAILER, "x-trailer")
                        .body(Body::from("payload"))
                        .expect("response");
                    send_h2_response_with_interim(
                        respond,
                        response,
                        &[],
                        &hyper::Method::GET,
                        false,
                        H2_BODY_IDLE_TIMEOUT,
                    )
                    .await
                    .expect("send response");
                });
            }
        });

        let socket = TcpStream::connect(addr).await.expect("connect");
        let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut client = client.ready().await.expect("ready");
        let request = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse.test/reset")
            .body(())
            .expect("request");
        let (response_future, _) = client.send_request(request, true).expect("send");
        let response = response_future.await.expect("response");
        assert_eq!(response.status(), ::http::StatusCode::RESET_CONTENT);
        assert!(!response
            .headers()
            .contains_key(::http::header::CONTENT_LENGTH));
        assert!(!response
            .headers()
            .contains_key(::http::header::TRANSFER_ENCODING));
        assert!(!response.headers().contains_key(::http::header::TRAILER));
        let body = h2_response_to_hyper(response).expect("convert");
        assert!(to_bytes(body.into_body()).await.expect("body").is_empty());
    }

    #[tokio::test]
    async fn send_h2_response_sanitizes_response_trailers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut conn = h2::server::handshake(socket).await.expect("handshake");
            while let Some(result) = conn.accept().await {
                let (_request, respond) = result.expect("request");
                tokio::spawn(async move {
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert(http::header::CONTENT_LENGTH, "2".parse().unwrap());
                    trailers.insert(
                        http::header::AUTHORIZATION,
                        "Bearer secret".parse().unwrap(),
                    );
                    trailers.insert("x-allowed-trailer", "ok".parse().unwrap());
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::replay(Bytes::from_static(b"OK"), Some(trailers)))
                        .expect("response");
                    send_h2_response_with_interim(
                        respond,
                        response,
                        &[],
                        &hyper::Method::GET,
                        false,
                        H2_BODY_IDLE_TIMEOUT,
                    )
                    .await
                    .expect("send response");
                });
            }
        });

        let socket = TcpStream::connect(addr).await.expect("connect");
        let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut client = client.ready().await.expect("ready");
        let request = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse.test/trailers")
            .body(())
            .expect("request");
        let (response_future, _) = client.send_request(request, true).expect("send");
        let response = response_future.await.expect("response");
        let mut body = h2_response_to_hyper(response).expect("convert").into_body();
        assert_eq!(
            body.data().await.expect("data").expect("chunk"),
            Bytes::from_static(b"OK")
        );
        let trailers = body.trailers().await.expect("trailers").expect("present");
        assert!(!trailers.contains_key(http::header::CONTENT_LENGTH));
        assert!(!trailers.contains_key(http::header::AUTHORIZATION));
        assert_eq!(
            trailers
                .get("x-allowed-trailer")
                .and_then(|value| value.to_str().ok()),
            Some("ok")
        );
    }

    #[tokio::test]
    async fn send_h2_response_with_interim_rejects_content_length_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut conn = h2::server::handshake(socket).await.expect("handshake");
            while let Some(result) = conn.accept().await {
                let (_request, respond) = result.expect("request");
                tokio::spawn(async move {
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(http::header::CONTENT_LENGTH, "4")
                        .body(Body::from("OK"))
                        .expect("response");
                    let err = send_h2_response_with_interim(
                        respond,
                        response,
                        &[],
                        &hyper::Method::GET,
                        false,
                        H2_BODY_IDLE_TIMEOUT,
                    )
                    .await
                    .expect_err("mismatch should fail");
                    assert!(err
                        .to_string()
                        .contains("ended before declared content-length"));
                });
            }
        });

        let socket = TcpStream::connect(addr).await.expect("connect");
        let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut client = client.ready().await.expect("ready");
        let request = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse.test/mismatch")
            .body(())
            .expect("request");
        let (response_future, _) = client.send_request(request, true).expect("send");
        let err = response_future.await.expect_err("response should reset");
        assert!(err.is_reset());
        assert_eq!(err.reason(), Some(Reason::PROTOCOL_ERROR));
    }

    #[tokio::test]
    async fn send_h2_response_with_interim_preserves_successful_extended_connect_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut builder = h2::server::Builder::new();
            builder.enable_connect_protocol();
            let mut conn = builder.handshake(socket).await.expect("handshake");
            while let Some(result) = conn.accept().await {
                let (_request, respond) = result.expect("request");
                tokio::spawn(async move {
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from("tunnel-bytes"))
                        .expect("response");
                    send_h2_response_with_interim(
                        respond,
                        response,
                        &[],
                        &hyper::Method::CONNECT,
                        true,
                        H2_BODY_IDLE_TIMEOUT,
                    )
                    .await
                    .expect("send response");
                });
            }
        });

        let socket = TcpStream::connect(addr).await.expect("connect");
        let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut client = client.ready().await.expect("ready");
        let mut request = ::http::Request::builder()
            .method("CONNECT")
            .uri("https://reverse.test/chat")
            .body(())
            .expect("request");
        request
            .extensions_mut()
            .insert(h2::ext::Protocol::from("websocket"));
        let (response_future, _) = client.send_request(request, true).expect("send");
        let response = response_future.await.expect("response");
        let body = h2_response_to_hyper(response).expect("convert");
        assert_eq!(
            to_bytes(body.into_body()).await.expect("body"),
            "tunnel-bytes"
        );
    }

    #[tokio::test]
    async fn h2_request_to_hyper_rejects_content_length_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut conn = h2::server::handshake(socket).await.expect("handshake");
            let Some(result) = conn.accept().await else {
                panic!("request");
            };
            let (request, _respond) = result.expect("request");
            let request = h2_request_to_hyper(request).expect("convert");
            let err = to_bytes(request.into_body())
                .await
                .expect_err("mismatch should fail");
            assert!(
                err.to_string().contains("content-length mismatch")
                    || err.to_string().contains("body aborted"),
                "unexpected error: {err}"
            );
        });

        let socket = TcpStream::connect(addr).await.expect("connect");
        let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut client = client.ready().await.expect("ready");
        let request = ::http::Request::builder()
            .method("POST")
            .uri("https://reverse.test/upload")
            .header(::http::header::CONTENT_LENGTH, "4")
            .body(())
            .expect("request");
        let (_response_future, mut send_stream) =
            client.send_request(request, false).expect("send");
        send_stream
            .send_data(Bytes::from_static(b"OK"), true)
            .expect("data");

        server.await.expect("server");
    }

    #[test]
    fn h2_cookie_fields_are_merged_for_generic_context() {
        let mut headers = ::http::HeaderMap::new();
        headers.append(
            ::http::header::COOKIE,
            ::http::HeaderValue::from_static("a=1"),
        );
        headers.append(
            ::http::header::COOKIE,
            ::http::HeaderValue::from_static("b=2"),
        );

        let converted = h1_headers_to_http(&headers).expect("convert headers");
        let cookie = converted
            .get(http::header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .expect("cookie header");
        assert_eq!(cookie, "a=1; b=2");
        assert_eq!(converted.get_all(http::header::COOKIE).iter().count(), 1);
    }
}
