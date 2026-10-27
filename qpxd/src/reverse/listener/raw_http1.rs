use super::{ReverseInterimService, reverse_body_channel_capacity};
use crate::http::codec::h1::{
    send_http1_response_with_interim_tcp, send_raw_http1_response_relay_with_interim,
    send_static_http1_response, serve_http1_tcp_with_interim_and_capacity,
};
use crate::http::codec::h1_common::MAX_HEADER_BYTES;
use crate::http::codec::lazy_timeout::ReusablePendingTimeout;
use crate::http::dispatcher::InterimList;
use crate::reverse::ReloadableReverse;
use crate::reverse::transport::{
    PreparedRawHttp1Response, RawHttp1ConnectionCache, RawHttp1RequestView, ReverseConnInfo,
    dispatch_prepared_raw_http1_request, prepare_raw_http1_request,
};
use crate::upstream::origin::PreparedPlainHttp1Session;
use anyhow::{Result, anyhow};
use bytes::{Buf, Bytes, BytesMut};
use http::{Response, StatusCode};
use qpx_core::http_message::Response as OwnerResponse;
use qpx_http::body::Body;
use qpx_observability::RequestHandler;
use qpx_observability::access_log::{
    AccessLogContext, AccessLogService, access_log_service_required,
    direct_combined_access_log_enabled,
};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::warn;

const COMMON_HTTP1_REQUEST_HEADERS: usize = 32;
const MAX_HTTP1_REQUEST_HEADERS: usize = 128;

enum FastParse<'a> {
    Prepared {
        consumed: usize,
        request: &'a crate::reverse::transport::PreparedRawHttp1Request,
    },
    Partial,
    Fallback,
}

pub(super) async fn serve_raw_or_fallback(
    mut stream: TcpStream,
    prefix: Bytes,
    reverse: ReloadableReverse,
    conn: ReverseConnInfo,
    header_read_timeout: Duration,
) -> Result<()> {
    let mut read_buf = prefix
        .try_into_mut()
        .unwrap_or_else(|prefix| BytesMut::from(prefix.as_ref()));
    let mut response_head = BytesMut::with_capacity(512);
    let mut request_cache = RawHttp1ConnectionCache::default();
    let mut origin_session = PreparedPlainHttp1Session::default();
    let pending_timer = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(pending_timer);
    let mut pending_timeout = ReusablePendingTimeout::new(pending_timer.as_mut());
    let access_cfg = reverse.runtime.state().resources.access_log.clone();
    let reverse_service = ReverseInterimService::new(reverse.clone(), conn.clone());
    let direct_combined_access = direct_combined_access_log_enabled(&access_cfg);
    let access_service = access_log_service_required(&access_cfg).then(|| {
        AccessLogService::new(
            reverse_service.clone(),
            conn.remote_addr,
            AccessLogContext {
                kind: crate::http::dispatch::ProxyKind::Reverse.as_str(),
                name: Arc::clone(&reverse.name),
            },
            &access_cfg,
        )
    });

    loop {
        if read_buf.is_empty() {
            // Preserve both the validated upstream connection and its active permit when
            // the next keep-alive request is already queued. Release only before actually
            // waiting on an idle downstream connection so admission capacity is never held
            // by an inactive client.
            let read = pending_timeout
                .timeout_after_pending_with(
                    header_read_timeout,
                    stream.read_buf(&mut read_buf),
                    || origin_session.release(),
                )
                .await
                .map_err(|_| anyhow!("HTTP/1 request header read timed out"))??;
            if read == 0 {
                return Ok(());
            }
        }

        match try_prepare_request(read_buf.as_ref(), &reverse, &conn, &mut request_cache) {
            FastParse::Prepared { consumed, request } => {
                read_buf.advance(consumed);
                let request_method = request.method();
                let request_keep_alive = request.keep_alive();
                let direct_log_started = request.raw_access_log_request().map(|_| Instant::now());
                // The cache-hit fast path must be attempted before the
                // generic dispatch: cache routes fall through to a generic
                // request target, and serving their unconditional GET hot
                // hits here skips the generic chain entirely. A miss falls
                // through to the same generic handling as before.
                let fast_served = request.try_serving_cache_hit();
                let fast_served_hit = fast_served.is_some();
                let fast_log_started = direct_combined_access.then(Instant::now);
                let dispatched = if let Some(response) = fast_served {
                    Ok(response)
                } else if let Some(generic) = request.generic_request() {
                    let direct_generic_started = direct_combined_access.then(Instant::now);
                    let direct_generic_log =
                        direct_combined_access.then(|| direct_combined_log_request(&generic));
                    let mut response = if let Some(service) = access_service.as_ref()
                        && !direct_combined_access
                    {
                        match service.call(generic).await {
                            Ok(response) => response,
                            Err(error) => match error {},
                        }
                    } else {
                        match reverse_service.call(generic).await {
                            Ok(response) => response,
                            Err(error) => match error {},
                        }
                    };
                    if let (Some(service), Some(log_request), Some(started)) = (
                        access_service.as_ref(),
                        direct_generic_log.as_ref(),
                        direct_generic_started,
                    ) {
                        let bytes_out = declared_response_bytes(&response);
                        service.record_direct_combined_status(
                            log_request,
                            response.status(),
                            bytes_out,
                            started,
                        );
                    }
                    let interim = response
                        .extensions_mut()
                        .remove::<InterimList>()
                        .unwrap_or_default();
                    Ok(PreparedRawHttp1Response::Generic(interim, response))
                } else {
                    dispatch_prepared_raw_http1_request(
                        request,
                        &reverse,
                        &conn,
                        &mut origin_session,
                        &mut pending_timeout,
                    )
                    .await
                };
                let response = match dispatched {
                    Ok(response) => response,
                    Err(error) => {
                        warn!(error = ?error, "reverse handling failed");
                        let state = reverse.runtime.state();
                        let mut response =
                            Response::new(Body::from(state.messages.reverse_error.clone()));
                        *response.status_mut() = StatusCode::BAD_GATEWAY;
                        let response = crate::http::protocol::l7::finalize_response_for_request(
                            request_method,
                            http::Version::HTTP_11,
                            state.plan.identity.proxy_name.as_ref(),
                            response,
                            false,
                        );
                        PreparedRawHttp1Response::Generic(
                            Vec::new(),
                            OwnerResponse::from_http(response),
                        )
                    }
                };
                if let (Some(service), Some(log_request), Some(started)) = (
                    access_service.as_ref(),
                    request.raw_access_log_request(),
                    direct_log_started,
                ) {
                    let (status, bytes_out) = match &response {
                        PreparedRawHttp1Response::Direct(response) => {
                            // The relay's framing was read through the owner
                            // when the raw head was parsed.
                            (response.status(), response.content_length().unwrap_or(0))
                        }
                        PreparedRawHttp1Response::InMemory { status, body, .. } => {
                            (*status, body.len() as u64)
                        }
                        PreparedRawHttp1Response::Generic(_, response) => {
                            (response.status(), declared_response_bytes(response))
                        }
                    };
                    service.record_direct_combined_status(log_request, status, bytes_out, started);
                }
                if fast_served_hit
                    && let (Some(service), Some(log_request), Some(started)) = (
                        access_service.as_ref(),
                        request.direct_combined_log_request(),
                        fast_log_started,
                    )
                {
                    let PreparedRawHttp1Response::InMemory { status, body, .. } = &response else {
                        unreachable!("fast cache-hit responses are always in-memory");
                    };
                    service.record_direct_combined_status(
                        log_request,
                        *status,
                        body.len() as u64,
                        started,
                    );
                }
                let keep_alive = match response {
                    PreparedRawHttp1Response::Direct(response) => {
                        let (keep_alive, reusable) = send_raw_http1_response_relay_with_interim(
                            &mut stream,
                            http::Version::HTTP_11,
                            request_method,
                            response,
                            request_keep_alive,
                            &mut response_head,
                        )
                        .await?;
                        if let Some(reusable) = reusable {
                            origin_session.recycle_connection(reusable);
                        }
                        keep_alive
                    }
                    PreparedRawHttp1Response::InMemory {
                        status,
                        headers,
                        body,
                    } => {
                        send_static_http1_response(
                            &mut stream,
                            request_method,
                            status,
                            headers,
                            body,
                            request_keep_alive,
                            &mut response_head,
                        )
                        .await?
                    }
                    PreparedRawHttp1Response::Generic(interim, response) => {
                        send_generic_response(
                            &mut stream,
                            request_method,
                            response,
                            &interim,
                            request_keep_alive,
                            header_read_timeout,
                            &mut response_head,
                        )
                        .await?
                    }
                };
                if !keep_alive {
                    let _ = stream.shutdown().await;
                    return Ok(());
                }
            }
            FastParse::Partial if read_buf.len() < MAX_HEADER_BYTES => {
                let read = pending_timeout
                    .timeout_after_pending(header_read_timeout, stream.read_buf(&mut read_buf))
                    .await
                    .map_err(|_| anyhow!("HTTP/1 request header read timed out"))??;
                if read == 0 {
                    return Err(anyhow!("client connection closed mid-header"));
                }
            }
            FastParse::Partial | FastParse::Fallback => {
                let body_channel_capacity = reverse_body_channel_capacity(&reverse);
                return if let Some(service) = access_service {
                    serve_http1_tcp_with_interim_and_capacity(
                        stream,
                        read_buf.freeze(),
                        service,
                        header_read_timeout,
                        body_channel_capacity,
                    )
                    .await
                } else {
                    serve_http1_tcp_with_interim_and_capacity(
                        stream,
                        read_buf.freeze(),
                        ReverseInterimService::new(reverse, conn),
                        header_read_timeout,
                        body_channel_capacity,
                    )
                    .await
                };
            }
        }
    }
}

fn direct_combined_log_request(request: &http::Request<Body>) -> http::Request<()> {
    let mut log_request = http::Request::new(());
    *log_request.method_mut() = request.method().clone();
    *log_request.uri_mut() = request.uri().clone();
    *log_request.version_mut() = request.version();
    for name in [http::header::REFERER, http::header::USER_AGENT] {
        for value in request.headers().get_all(&name) {
            log_request
                .headers_mut()
                .append(name.clone(), value.clone());
        }
    }
    log_request
}

fn try_prepare_request<'a>(
    bytes: &[u8],
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
    cache: &'a mut RawHttp1ConnectionCache,
) -> FastParse<'a> {
    if let Some(consumed) = cache.cached_prefix_len(reverse, bytes) {
        let Some(request) = cache.prepared_request_ref_unchecked() else {
            return FastParse::Fallback;
        };
        return FastParse::Prepared { consumed, request };
    }
    let mut common_headers =
        [const { std::mem::MaybeUninit::uninit() }; COMMON_HTTP1_REQUEST_HEADERS];
    let mut parsed = httparse::Request::new(&mut []);
    match httparse::ParserConfig::default().parse_request_with_uninit_headers(
        &mut parsed,
        bytes,
        &mut common_headers,
    ) {
        Ok(httparse::Status::Complete(consumed)) => {
            return prepare_complete_request(&parsed, consumed, bytes, reverse, conn, cache);
        }
        Ok(httparse::Status::Partial) => return FastParse::Partial,
        Err(httparse::Error::TooManyHeaders) => {}
        Err(_) => return FastParse::Fallback,
    }

    let mut maximum_headers =
        [const { std::mem::MaybeUninit::uninit() }; MAX_HTTP1_REQUEST_HEADERS];
    let mut parsed = httparse::Request::new(&mut []);
    match httparse::ParserConfig::default().parse_request_with_uninit_headers(
        &mut parsed,
        bytes,
        &mut maximum_headers,
    ) {
        Ok(httparse::Status::Complete(consumed)) => {
            prepare_complete_request(&parsed, consumed, bytes, reverse, conn, cache)
        }
        Ok(httparse::Status::Partial) => FastParse::Partial,
        Err(_) => FastParse::Fallback,
    }
}

fn prepare_complete_request<'a>(
    parsed: &httparse::Request<'_, '_>,
    consumed: usize,
    bytes: &[u8],
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
    cache: &'a mut RawHttp1ConnectionCache,
) -> FastParse<'a> {
    let (Some(method), Some(target), Some(version)) = (parsed.method, parsed.path, parsed.version)
    else {
        return FastParse::Fallback;
    };
    let Some(request) = prepare_raw_http1_request(
        reverse,
        conn,
        RawHttp1RequestView {
            raw_head: &bytes[..consumed],
            method,
            target,
            version,
            headers: parsed.headers,
        },
        cache,
    ) else {
        return FastParse::Fallback;
    };
    FastParse::Prepared { consumed, request }
}

// Keep the Generic fallback's static decision before codec export. In particular,
// a nonempty interim list or trailers must continue through the streaming sender.
async fn send_generic_response(
    stream: &mut tokio::net::TcpStream,
    request_method: &http::Method,
    mut response: OwnerResponse<Body>,
    interim: &[crate::upstream::raw_http1::InterimResponseHead],
    request_keep_alive: bool,
    header_read_timeout: tokio::time::Duration,
    response_head: &mut BytesMut,
) -> Result<bool> {
    if interim.is_empty()
        && let Some(body) = response.body_mut().take_single_frame_without_trailers()
    {
        // Actual network serialization boundary, after the unchanged fast-path decision.
        let (parts, _) = response.into_http_for_codec()?.into_parts();
        send_static_http1_response(
            stream,
            request_method,
            parts.status,
            parts.headers,
            body,
            request_keep_alive,
            response_head,
        )
        .await
    } else {
        send_http1_response_with_interim_tcp(
            stream,
            http::Version::HTTP_11,
            request_method,
            response,
            interim,
            request_keep_alive,
            header_read_timeout,
            response_head,
        )
        .await
    }
}

/// The number of bytes the response declares it carries.
///
/// The declaration is read through the owner, so a comma list of equal
/// members is one length and a declaration the owner refuses names no
/// length, which the access log records as no bytes.
fn declared_response_bytes(response: &OwnerResponse<Body>) -> u64 {
    response
        .headers()
        .declared_content_length()
        .ok()
        .flatten()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn socket_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (server, client)
    }

    #[tokio::test]
    async fn generic_single_frame_reaches_static_writer_and_preserves_wire_output() {
        use http::Method;
        // Compare the migrated branch against the original static codec call, including
        // no-body/CONNECT behavior, canonical lengths and duplicate non-framing fields.
        for (method, status) in [
            (Method::GET, StatusCode::OK),
            (Method::HEAD, StatusCode::OK),
            (Method::GET, StatusCode::NO_CONTENT),
            (Method::GET, StatusCode::NOT_MODIFIED),
            (Method::CONNECT, StatusCode::OK),
        ] {
            let make_response = || {
                Response::builder()
                    .status(status)
                    .version(http::Version::HTTP_10)
                    .header("content-length", " 2, 2\t")
                    .header("set-cookie", "a=1")
                    .header("set-cookie", "b=2")
                    .body(Body::from("OK"))
                    .unwrap()
            };
            let mut wires = Vec::new();
            let mut keep_alives = Vec::new();
            for owned in [false, true] {
                let (mut server, mut client) = socket_pair().await;
                let response = make_response();
                let mut head = BytesMut::new();
                let keep_alive = if owned {
                    send_generic_response(
                        &mut server,
                        &method,
                        OwnerResponse::from_http(response),
                        &[],
                        true,
                        tokio::time::Duration::from_secs(1),
                        &mut head,
                    )
                    .await
                    .unwrap()
                } else {
                    let (parts, _) = response.into_parts();
                    send_static_http1_response(
                        &mut server,
                        &method,
                        parts.status,
                        parts.headers,
                        Bytes::from_static(b"OK"),
                        true,
                        &mut head,
                    )
                    .await
                    .unwrap()
                };
                server.shutdown().await.unwrap();
                let mut wire = Vec::new();
                client.read_to_end(&mut wire).await.unwrap();
                wires.push(wire);
                keep_alives.push(keep_alive);
            }
            assert_eq!(wires[0], wires[1], "{method} {status}");
            assert_eq!(keep_alives[0], keep_alives[1]);
        }
        // This diagnostic is unique to the static writer: successful output alone
        // could also pass if this fast branch were accidentally replaced by streaming.
        let (mut server, _client) = socket_pair().await;
        let response = Response::builder()
            .header("content-length", "3")
            .body(Body::from("OK"))
            .unwrap();
        let error = send_generic_response(
            &mut server,
            &Method::GET,
            OwnerResponse::from_http(response),
            &[],
            true,
            tokio::time::Duration::from_secs(1),
            &mut BytesMut::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "static response body length 2 does not match declared content-length 3"
        );
    }

    #[tokio::test]
    async fn generic_interim_and_trailers_still_stream_in_order() {
        let (mut server, mut client) = socket_pair().await;
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-end", http::HeaderValue::from_static("done"));
        let response = Response::builder()
            .header("trailer", "x-end")
            .body(Body::replay(Bytes::from_static(b"OK"), Some(trailers)))
            .unwrap();
        let interim = [103, 102].map(|code| {
            crate::upstream::raw_http1::InterimResponseHead::new(
                StatusCode::from_u16(code).unwrap(),
                http::HeaderMap::new(),
            )
        });
        send_generic_response(
            &mut server,
            &http::Method::GET,
            OwnerResponse::from_http(response),
            &interim,
            false,
            tokio::time::Duration::from_secs(1),
            &mut BytesMut::new(),
        )
        .await
        .unwrap();
        server.shutdown().await.unwrap();
        let mut wire = Vec::new();
        client.read_to_end(&mut wire).await.unwrap();
        let wire = String::from_utf8(wire).unwrap();
        assert!(
            wire.starts_with(
                "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\n"
            ),
            "{wire}"
        );
        assert!(
            wire.ends_with("2\r\nOK\r\n0\r\nx-end: done\r\n\r\n"),
            "{wire}"
        );
    }

    #[test]
    fn the_access_log_counts_the_declared_length_through_the_owner() {
        // A comma list of equal members is one length, so the count is that
        // length instead of no bytes.
        let response = Response::builder()
            .header(http::header::CONTENT_LENGTH, "16, 16")
            .body(Body::empty())
            .expect("response");
        assert_eq!(
            declared_response_bytes(&OwnerResponse::from_http(response)),
            16
        );

        // A declaration the owner refuses names no length, so the count is
        // no bytes.
        let response = Response::builder()
            .header(http::header::CONTENT_LENGTH, "+16")
            .body(Body::empty())
            .expect("response");
        assert_eq!(
            declared_response_bytes(&OwnerResponse::from_http(response)),
            0
        );

        // A response that declares no length counts no bytes either.
        let response = Response::builder().body(Body::empty()).expect("response");
        assert_eq!(
            declared_response_bytes(&OwnerResponse::from_http(response)),
            0
        );
    }
}
