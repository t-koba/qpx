use super::{ReverseInterimService, reverse_body_channel_capacity};
use crate::http::codec::h1::{
    send_http1_response_with_interim, send_raw_http1_response_relay_with_interim,
    send_static_http1_response, serve_http1_tcp_with_interim_and_capacity,
};
use crate::http::codec::h1_common::MAX_HEADER_BYTES;
use crate::http::codec::lazy_timeout::timeout_after_pending;
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
use qpx_http::body::Body;
use qpx_observability::RequestHandler;
use qpx_observability::access_log::{
    AccessLogContext, AccessLogService, access_log_service_required,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::warn;

const COMMON_HTTP1_REQUEST_HEADERS: usize = 32;
const MAX_HTTP1_REQUEST_HEADERS: usize = 128;

enum FastParse {
    Prepared {
        consumed: usize,
        request: std::sync::Arc<crate::reverse::transport::PreparedRawHttp1Request>,
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
    let access_cfg = reverse.runtime.state().resources.access_log.clone();
    let access_service = access_log_service_required(&access_cfg).then(|| {
        AccessLogService::new(
            ReverseInterimService::new(reverse.clone(), conn.clone()),
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
            // Preserve one validated upstream connection across pipelined requests while
            // releasing the active-origin permit during downstream idle time.
            origin_session.release();
            let read = timeout_after_pending(header_read_timeout, stream.read_buf(&mut read_buf))
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
                let dispatched = if let (Some(service), Some(generic)) =
                    (access_service.as_ref(), request.generic_request())
                {
                    let mut response = match service.call(generic).await {
                        Ok(response) => response,
                        Err(error) => match error {},
                    };
                    let interim = response
                        .extensions_mut()
                        .remove::<InterimList>()
                        .unwrap_or_default();
                    Ok(PreparedRawHttp1Response::Generic(interim, response))
                } else {
                    dispatch_prepared_raw_http1_request(
                        request.as_ref(),
                        &reverse,
                        &conn,
                        &mut origin_session,
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
                        PreparedRawHttp1Response::Generic(Vec::new(), response)
                    }
                };
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
                        send_http1_response_with_interim(
                            &mut stream,
                            http::Version::HTTP_11,
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
                let read =
                    timeout_after_pending(header_read_timeout, stream.read_buf(&mut read_buf))
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

fn try_prepare_request(
    bytes: &[u8],
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
    cache: &mut RawHttp1ConnectionCache,
) -> FastParse {
    if let Some((consumed, request)) = cache.prepare_cached_prefix(reverse, bytes) {
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

fn prepare_complete_request(
    parsed: &httparse::Request<'_, '_>,
    consumed: usize,
    bytes: &[u8],
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
    cache: &mut RawHttp1ConnectionCache,
) -> FastParse {
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
