use crate::http::body::Body;
use crate::http::l7::{finalize_response_with_headers, prepare_request_with_headers_in_place};
use crate::http3::codec::{h1_headers_to_http, http_headers_to_h1};
use crate::http3::datagram::{H3DatagramDispatch, H3StreamDatagrams};
use crate::http3::quic::build_h3_client_config;
use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes};
use hyper::{Response, StatusCode};
use qpx_core::rules::CompiledHeaderControl;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::lookup_host;
use tokio::time::{timeout, Duration, Instant};
use tracing::warn;

pub(super) struct UpstreamExtendedConnectStream {
    pub(super) interim: Vec<::http::Response<()>>,
    pub(super) response: ::http::Response<()>,
    pub(super) req_stream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    pub(super) datagrams: Option<H3StreamDatagrams>,
    pub(super) _endpoint: quinn::Endpoint,
    pub(super) driver: tokio::task::JoinHandle<()>,
    pub(super) datagram_task: Option<tokio::task::JoinHandle<()>>,
}

pub(super) struct OpenUpstreamExtendedConnectInput<'a> {
    pub(super) req_head: &'a ::http::Request<()>,
    pub(super) sanitized_headers: &'a http::HeaderMap,
    pub(super) proxy_name: &'a str,
    pub(super) upstream: Option<&'a str>,
    pub(super) verify_upstream: bool,
    pub(super) protocol: ::h3::ext::Protocol,
    pub(super) enable_datagram: bool,
    pub(super) timeout_dur: Duration,
}

fn http1_uri_to_http_uri(uri: &::http::Uri) -> Result<http::Uri> {
    uri.to_string()
        .parse::<http::Uri>()
        .or_else(|_| {
            let mut builder = http::Uri::builder();
            if let Some(scheme) = uri.scheme_str() {
                builder = builder.scheme(scheme);
            }
            if let Some(authority) = uri.authority() {
                builder = builder.authority(authority.as_str());
            }
            builder
                .path_and_query(uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"))
                .build()
        })
        .map_err(|e| anyhow!("invalid upstream CONNECT uri: {e}"))
}

pub(in crate::forward) fn normalize_h3_upstream_connect_headers(
    uri: &::http::Uri,
    headers: &http::HeaderMap,
    proxy_name: &str,
) -> Result<::http::HeaderMap> {
    let mut request = hyper::Request::builder()
        .method(http::Method::CONNECT)
        .uri(http1_uri_to_http_uri(uri)?)
        .body(Body::empty())?;
    *request.version_mut() = http::Version::HTTP_3;
    *request.headers_mut() = headers.clone();
    prepare_request_with_headers_in_place(&mut request, proxy_name, None, false);
    http_headers_to_h1(request.headers())
}

pub(in crate::forward) async fn recv_upstream_h3_response_with_interim(
    req_stream: &mut ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    timeout_dur: Duration,
    context: &str,
) -> Result<(Vec<::http::Response<()>>, ::http::Response<()>)> {
    let mut interim = Vec::new();
    loop {
        let response = match timeout(timeout_dur, req_stream.recv_response()).await {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => return Err(anyhow!("{context} timed out")),
        };
        if response.status().is_informational() {
            interim.push(response);
            continue;
        }
        return Ok((interim, response));
    }
}

pub(super) async fn open_upstream_extended_connect_stream(
    input: OpenUpstreamExtendedConnectInput<'_>,
) -> Result<UpstreamExtendedConnectStream> {
    let (connect_host, connect_port) =
        parse_extended_connect_upstream(input.req_head.uri(), input.upstream).await?;
    let upstream_addr = match timeout(
        input.timeout_dur,
        lookup_host((connect_host.as_str(), connect_port)),
    )
    .await
    {
        Ok(Ok(mut addrs)) => addrs
            .next()
            .ok_or_else(|| anyhow!("failed to resolve extended CONNECT upstream"))?,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => return Err(anyhow!("extended CONNECT upstream resolution timed out")),
    };

    let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(build_h3_client_config(input.verify_upstream)?);

    let connection = match timeout(
        input.timeout_dur,
        endpoint.connect(upstream_addr, &connect_host)?,
    )
    .await
    {
        Ok(Ok(connection)) => connection,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => return Err(anyhow!("extended CONNECT upstream connect timed out")),
    };
    let quic_conn = h3_quinn::Connection::new(connection);
    let mut builder = ::h3::client::builder();
    builder.enable_extended_connect(true);
    builder.enable_datagram(input.enable_datagram);
    let h3_build = builder.build::<_, _, Bytes>(quic_conn);
    let (mut h3_conn, mut sender) = match timeout(input.timeout_dur, h3_build).await {
        Ok(Ok(parts)) => parts,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => return Err(anyhow!("extended CONNECT upstream h3 setup timed out")),
    };
    let normalized_headers = normalize_h3_upstream_connect_headers(
        input.req_head.uri(),
        input.sanitized_headers,
        input.proxy_name,
    )?;

    let mut request = ::http::Request::builder()
        .method(::http::Method::CONNECT)
        .uri(input.req_head.uri().clone())
        .body(())?;
    request.extensions_mut().insert(input.protocol);
    *request.headers_mut() = normalized_headers;

    let mut req_stream = match timeout(input.timeout_dur, sender.send_request(request)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => return Err(anyhow!("extended CONNECT upstream request timed out")),
    };
    let mut datagram_handles = if input.enable_datagram {
        use h3_datagram::datagram_handler::HandleDatagramsExt as _;

        let stream_id = req_stream.id();
        Some((
            h3_conn.get_datagram_reader(),
            h3_conn.get_datagram_sender(stream_id),
        ))
    } else {
        None
    };
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });
    let (interim, response) = recv_upstream_h3_response_with_interim(
        &mut req_stream,
        input.timeout_dur,
        "extended CONNECT upstream response",
    )
    .await?;
    let (datagrams, datagram_task) = if input.enable_datagram && response.status().is_success() {
        let dispatch = Arc::new(H3DatagramDispatch::new(64));
        let (reader, sender) = datagram_handles
            .take()
            .ok_or_else(|| anyhow!("missing HTTP/3 datagram handles"))?;
        let datagram_task = {
            let dispatch = dispatch.clone();
            tokio::spawn(async move {
                dispatch.run(reader).await;
            })
        };
        let datagrams = Some(dispatch.register_stream(req_stream.id(), sender).await);
        (datagrams, Some(datagram_task))
    } else {
        (None, None)
    };
    Ok(UpstreamExtendedConnectStream {
        interim,
        response,
        req_stream,
        datagrams,
        _endpoint: endpoint,
        driver,
        datagram_task,
    })
}

async fn parse_extended_connect_upstream(
    uri: &::http::Uri,
    upstream: Option<&str>,
) -> Result<(String, u16)> {
    if let Some(upstream) = upstream {
        if upstream.contains("://") {
            let parsed = url::Url::parse(upstream)?;
            match parsed.scheme() {
                "https" | "h3" => {}
                _ => return Err(anyhow!("extended CONNECT upstream requires https/h3 URL")),
            }
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow!("extended CONNECT upstream host missing"))?;
            let port = parsed.port().unwrap_or(443);
            return Ok((host.to_string(), port));
        }
        return crate::http::address::parse_authority_host_port(upstream, 443)
            .ok_or_else(|| anyhow!("invalid extended CONNECT upstream authority"));
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow!("extended CONNECT missing authority"))?;
    crate::http::address::parse_authority_host_port(authority.as_str(), 443)
        .ok_or_else(|| anyhow!("invalid extended CONNECT authority"))
}

pub(super) fn finalize_h3_connect_head_response(
    response: ::http::Response<()>,
    proxy_name: &str,
    header_control: Option<&CompiledHeaderControl>,
) -> Result<::http::Response<()>> {
    let (parts, _) = response.into_parts();
    let mut downstream = Response::builder()
        .status(StatusCode::from_u16(parts.status.as_u16())?)
        .body(Body::empty())?;
    *downstream.headers_mut() = h1_headers_to_http(&parts.headers)?;
    let downstream = finalize_response_with_headers(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        downstream,
        header_control,
        false,
    );
    let status = ::http::StatusCode::from_u16(downstream.status().as_u16())?;
    let mut out = ::http::Response::builder().status(status).body(())?;
    *out.headers_mut() = http_headers_to_h1(downstream.headers())?;
    Ok(out)
}

pub(super) fn upstream_extended_connect_error_response(
    response: ::http::Response<()>,
    upstream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    proxy_name: &str,
    header_control: Option<&CompiledHeaderControl>,
    body_read_timeout: Duration,
) -> Result<Response<Body>> {
    let (parts, _) = response.into_parts();
    let mut downstream = Response::builder()
        .status(StatusCode::from_u16(parts.status.as_u16())?)
        .body(body_from_upstream_h3_stream(upstream, body_read_timeout))?;
    *downstream.headers_mut() = h1_headers_to_http(&parts.headers)?;
    Ok(finalize_response_with_headers(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        downstream,
        header_control,
        false,
    ))
}

fn body_from_upstream_h3_stream(
    mut upstream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    body_read_timeout: Duration,
) -> Body {
    let (mut sender, body) = Body::channel();
    tokio::spawn(async move {
        loop {
            let next = tokio::select! {
                _ = sender.closed() => return,
                recv = tokio::time::timeout(body_read_timeout, upstream.recv_data()) => recv,
            };
            match next {
                Err(_) => {
                    warn!("extended CONNECT upstream error body timed out");
                    sender.abort();
                    return;
                }
                Ok(Ok(Some(chunk))) => {
                    let mut chunk = chunk;
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    if sender.send_data(bytes).await.is_err() {
                        return;
                    }
                }
                Ok(Ok(None)) => break,
                Ok(Err(err)) => {
                    warn!(error = ?err, "extended CONNECT upstream error body stream failed");
                    sender.abort();
                    return;
                }
            }
        }
        let trailers = tokio::select! {
            _ = sender.closed() => return,
            recv = tokio::time::timeout(body_read_timeout, upstream.recv_trailers()) => recv,
        };
        match trailers {
            Err(_) => {
                warn!("extended CONNECT upstream error trailers timed out");
                sender.abort();
            }
            Ok(Ok(Some(trailers))) => match h1_headers_to_http(&trailers) {
                Ok(trailers) => {
                    let _ = sender.send_trailers(trailers).await;
                }
                Err(err) => {
                    warn!(error = ?err, "extended CONNECT upstream trailers were invalid");
                }
            },
            Ok(Ok(None)) => {}
            Ok(Err(err)) => {
                warn!(error = ?err, "extended CONNECT upstream error trailers failed");
            }
        }
    });
    body
}

pub(super) async fn relay_h3_extended_connect_stream(
    downstream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut downstream_datagrams: Option<H3StreamDatagrams>,
    upstream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut upstream_datagrams: Option<H3StreamDatagrams>,
    idle_timeout: Duration,
) -> Result<()> {
    let (mut downstream_send, mut downstream_recv) = downstream.split();
    let (mut upstream_send, mut upstream_recv) = upstream.split();

    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);
    let mut downstream_eof = false;
    let mut upstream_eof = false;

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                return Err(anyhow!("forward HTTP/3 extended CONNECT tunnel idle timeout"));
            }
            recv = downstream_recv.recv_data(), if !downstream_eof => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        tokio::time::timeout(idle_timeout, upstream_send.send_data(bytes))
                            .await
                            .map_err(|_| anyhow!("forward HTTP/3 extended CONNECT send timeout"))??;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => {
                        downstream_eof = true;
                        tokio::time::timeout(idle_timeout, upstream_send.finish())
                            .await
                            .map_err(|_| anyhow!("forward HTTP/3 extended CONNECT finish timeout"))??;
                        if upstream_eof {
                            break;
                        }
                    }
                }
            }
            recv = upstream_recv.recv_data(), if !upstream_eof => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        tokio::time::timeout(idle_timeout, downstream_send.send_data(bytes))
                            .await
                            .map_err(|_| anyhow!("forward HTTP/3 extended CONNECT send timeout"))??;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => {
                        upstream_eof = true;
                        tokio::time::timeout(idle_timeout, downstream_send.finish())
                            .await
                            .map_err(|_| anyhow!("forward HTTP/3 extended CONNECT finish timeout"))??;
                        if downstream_eof {
                            break;
                        }
                    }
                }
            }
            down_payload = async {
                if let Some(datagrams) = downstream_datagrams.as_mut() {
                    datagrams.receiver.recv().await
                } else {
                    std::future::pending::<Option<Bytes>>().await
                }
            } => {
                let Some(payload) = down_payload else {
                    break;
                };
                if let Some(datagrams) = upstream_datagrams.as_mut() {
                    if let Err(err) = datagrams.sender.send_datagram(payload) {
                        warn!(error = ?err, "forward HTTP/3 extended CONNECT upstream datagram send failed");
                    }
                }
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
            up_payload = async {
                if let Some(datagrams) = upstream_datagrams.as_mut() {
                    datagrams.receiver.recv().await
                } else {
                    std::future::pending::<Option<Bytes>>().await
                }
            } => {
                let Some(payload) = up_payload else {
                    break;
                };
                if let Some(datagrams) = downstream_datagrams.as_mut() {
                    if let Err(err) = datagrams.sender.send_datagram(payload) {
                        warn!(error = ?err, "forward HTTP/3 extended CONNECT downstream datagram send failed");
                    }
                }
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
        }
    }
    Ok(())
}
