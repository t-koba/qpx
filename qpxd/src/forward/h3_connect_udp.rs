use super::h3::ForwardH3Handler;
use super::h3_connect::{
    build_h3_connect_success_response, prepare_h3_connect_request, H3ConnectPreparation,
};
use crate::http3::capsule::{
    append_capsule_chunk, decode_quic_varint, encode_datagram_capsule, take_next_capsule,
};
use crate::http3::listener::H3ConnInfo;
use crate::http3::quic::build_h3_client_config;
use crate::http3::server::{send_h3_static_response, H3ServerRequestStream};
use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes, BytesMut};
use qpx_core::config::ConnectUdpConfig;
use std::net::SocketAddr;
use tokio::net::{lookup_host, UdpSocket};
use tokio::time::{timeout, Duration, Instant};
use tracing::warn;
use url::Url;

pub(super) async fn handle_h3_connect_udp(
    req_head: http1::Request<()>,
    mut req_stream: H3ServerRequestStream,
    handler: ForwardH3Handler,
    conn: H3ConnInfo,
) -> Result<()> {
    let connect_udp_cfg = handler.connect_udp.clone();
    let prepared = match prepare_h3_connect_request(
        &req_head,
        &mut req_stream,
        &handler,
        &conn,
        Some(&connect_udp_cfg),
    )
    .await?
    {
        H3ConnectPreparation::Continue(prepared) => *prepared,
        H3ConnectPreparation::Responded => return Ok(()),
    };

    let state = handler.runtime.state();
    let upstream_timeout = Duration::from_millis(state.config.runtime.upstream_http_timeout_ms);
    let proxy_name = state.config.identity.proxy_name.clone();
    let super::h3_connect::PreparedH3Connect {
        authority,
        host,
        port,
        action,
    } = prepared;
    let upstream = match crate::forward::request::resolve_upstream(
        &action,
        &state,
        handler.listener_name.as_ref(),
    ) {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(
                error = ?err,
                "forward HTTP/3 CONNECT-UDP upstream resolution failed"
            );
            send_h3_static_response(
                &mut req_stream,
                http1::StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
                &http::Method::CONNECT,
                proxy_name.as_str(),
                state.config.runtime.max_h3_response_body_bytes,
            )
            .await?;
            return Ok(());
        }
    };

    if let Some(upstream) = upstream {
        let upstream_chain =
            match open_upstream_connect_udp_stream(&upstream, &authority, upstream_timeout).await {
                Ok(chain) => chain,
                Err(err) => {
                    let upstream_target = parse_connect_udp_upstream(&upstream)
                        .ok()
                        .map(|(host, port)| format!("{}:{}", host, port))
                        .unwrap_or_else(|| "<invalid>".to_string());
                    warn!(
                        error = ?err,
                        upstream = %upstream_target,
                        "failed to establish CONNECT-UDP upstream chain"
                    );
                    send_h3_static_response(
                        &mut req_stream,
                        http1::StatusCode::BAD_GATEWAY,
                        state.messages.upstream_connect_udp_failed.as_bytes(),
                        &http::Method::CONNECT,
                        proxy_name.as_str(),
                        state.config.runtime.max_h3_response_body_bytes,
                    )
                    .await?;
                    return Ok(());
                }
            };

        let response =
            build_h3_connect_success_response(proxy_name.as_str(), &http::Method::CONNECT, true)?;
        req_stream.send_response(response).await?;

        let relay_result = relay_h3_connect_udp_stream_chained(
            req_stream,
            upstream_chain.req_stream,
            connect_udp_cfg,
        )
        .await;

        upstream_chain.driver.abort();
        let _ = upstream_chain.driver.await;
        return relay_result;
    }

    let target = match timeout(upstream_timeout, lookup_host((host.as_str(), port))).await {
        Ok(Ok(mut addrs)) => match addrs.next() {
            Some(addr) => addr,
            None => {
                send_h3_static_response(
                    &mut req_stream,
                    http1::StatusCode::BAD_GATEWAY,
                    state.messages.proxy_error.as_bytes(),
                    &http::Method::CONNECT,
                    proxy_name.as_str(),
                    state.config.runtime.max_h3_response_body_bytes,
                )
                .await?;
                return Ok(());
            }
        },
        Ok(Err(err)) => {
            warn!(error = ?err, "forward HTTP/3 CONNECT-UDP DNS resolution failed");
            send_h3_static_response(
                &mut req_stream,
                http1::StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
                &http::Method::CONNECT,
                proxy_name.as_str(),
                state.config.runtime.max_h3_response_body_bytes,
            )
            .await?;
            return Ok(());
        }
        Err(_) => {
            warn!("forward HTTP/3 CONNECT-UDP DNS resolution timed out");
            send_h3_static_response(
                &mut req_stream,
                http1::StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
                &http::Method::CONNECT,
                proxy_name.as_str(),
                state.config.runtime.max_h3_response_body_bytes,
            )
            .await?;
            return Ok(());
        }
    };

    let bind_addr: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let udp = match UdpSocket::bind(bind_addr).await {
        Ok(udp) => udp,
        Err(err) => {
            warn!(error = ?err, "forward HTTP/3 CONNECT-UDP bind failed");
            send_h3_static_response(
                &mut req_stream,
                http1::StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
                &http::Method::CONNECT,
                proxy_name.as_str(),
                state.config.runtime.max_h3_response_body_bytes,
            )
            .await?;
            return Ok(());
        }
    };
    match timeout(upstream_timeout, udp.connect(target)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            warn!(error = ?err, "forward HTTP/3 CONNECT-UDP connect failed");
            send_h3_static_response(
                &mut req_stream,
                http1::StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
                &http::Method::CONNECT,
                proxy_name.as_str(),
                state.config.runtime.max_h3_response_body_bytes,
            )
            .await?;
            return Ok(());
        }
        Err(_) => {
            warn!("forward HTTP/3 CONNECT-UDP connect timed out");
            send_h3_static_response(
                &mut req_stream,
                http1::StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
                &http::Method::CONNECT,
                proxy_name.as_str(),
                state.config.runtime.max_h3_response_body_bytes,
            )
            .await?;
            return Ok(());
        }
    }

    let response =
        build_h3_connect_success_response(proxy_name.as_str(), &http::Method::CONNECT, true)?;
    req_stream.send_response(response).await?;

    if let Err(err) = relay_h3_connect_udp_stream(req_stream, udp, connect_udp_cfg).await {
        warn!(error = ?err, "forward HTTP/3 CONNECT-UDP relay failed");
    }
    Ok(())
}

struct UpstreamConnectUdpStream {
    _endpoint: quinn::Endpoint,
    driver: tokio::task::JoinHandle<()>,
    req_stream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
}

async fn open_upstream_connect_udp_stream(
    upstream: &str,
    authority: &str,
    timeout_dur: Duration,
) -> Result<UpstreamConnectUdpStream> {
    let (upstream_host, upstream_port) = parse_connect_udp_upstream(upstream)?;
    let upstream_addr = timeout(
        timeout_dur,
        lookup_host((upstream_host.as_str(), upstream_port)),
    )
    .await??
    .next()
    .ok_or_else(|| anyhow!("failed to resolve CONNECT-UDP upstream proxy"))?;

    let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(build_h3_client_config()?);

    let connection = timeout(
        timeout_dur,
        endpoint.connect(upstream_addr, &upstream_host)?,
    )
    .await??;
    let mut builder = ::h3::client::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let h3_build = builder.build::<_, _, Bytes>(h3_quinn::Connection::new(connection));
    let (mut h3_conn, mut sender) = timeout(timeout_dur, h3_build).await??;
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    let uri = http1::Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query("/")
        .build()?;
    let mut request = http1::Request::builder()
        .method(http1::Method::CONNECT)
        .uri(uri)
        .body(())?;
    request
        .extensions_mut()
        .insert(::h3::ext::Protocol::CONNECT_UDP);
    request.headers_mut().insert(
        http1::header::HeaderName::from_static("capsule-protocol"),
        http1::header::HeaderValue::from_static("?1"),
    );

    let mut req_stream = match timeout(timeout_dur, sender.send_request(request)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            driver.abort();
            let _ = driver.await;
            return Err(err.into());
        }
        Err(_) => {
            driver.abort();
            let _ = driver.await;
            return Err(anyhow!("upstream CONNECT-UDP request timed out"));
        }
    };
    let response = match timeout(timeout_dur, req_stream.recv_response()).await {
        Ok(Ok(response)) => response,
        Ok(Err(err)) => {
            driver.abort();
            let _ = driver.await;
            return Err(err.into());
        }
        Err(_) => {
            driver.abort();
            let _ = driver.await;
            return Err(anyhow!("upstream CONNECT-UDP response timed out"));
        }
    };
    if response.status() != http1::StatusCode::OK {
        driver.abort();
        let _ = driver.await;
        return Err(anyhow!(
            "upstream CONNECT-UDP failed with status {}",
            response.status()
        ));
    }

    Ok(UpstreamConnectUdpStream {
        _endpoint: endpoint,
        driver,
        req_stream,
    })
}

fn parse_connect_udp_upstream(upstream: &str) -> Result<(String, u16)> {
    if upstream.contains("://") {
        let parsed = Url::parse(upstream)?;
        match parsed.scheme() {
            "https" | "h3" => {}
            _ => {
                return Err(anyhow!(
                    "CONNECT-UDP upstream chain requires https/h3 proxy URL"
                ))
            }
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("CONNECT-UDP upstream host missing"))?;
        let port = parsed.port().unwrap_or(443);
        return Ok((host.to_string(), port));
    }

    crate::http::address::parse_authority_host_port(upstream, 443)
        .ok_or_else(|| anyhow!("invalid CONNECT-UDP upstream authority"))
}

async fn relay_h3_connect_udp_stream(
    req_stream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    udp: UdpSocket,
    connect_udp_cfg: ConnectUdpConfig,
) -> Result<()> {
    let (mut req_send, mut req_recv) = req_stream.split();
    let idle_timeout = Duration::from_secs(connect_udp_cfg.idle_timeout_secs.max(1));
    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    let mut capsule_buf = BytesMut::new();
    let mut udp_buf = [0u8; 65535];

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                break;
            }
            recv = req_recv.recv_data() => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        append_capsule_chunk(
                            &mut capsule_buf,
                            &bytes,
                            connect_udp_cfg.max_capsule_buffer_bytes,
                        )?;
                        while let Some((capsule_type, payload)) = take_next_capsule(&mut capsule_buf)? {
                            if capsule_type != 0 {
                                continue;
                            }
                            let (context_id, offset) = match decode_quic_varint(payload.as_ref()) {
                                Some(v) => v,
                                None => continue,
                            };
                            if context_id != 0 || offset > payload.len() {
                                continue;
                            }
                            udp.send(&payload[offset..]).await?;
                        }
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => break,
                }
            }
            recv = udp.recv(&mut udp_buf) => {
                let n = recv?;
                if n == 0 {
                    continue;
                }
                let capsule = encode_datagram_capsule(&udp_buf[..n])?;
                req_send.send_data(capsule).await?;
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
        }
    }

    req_send.finish().await?;
    Ok(())
}

async fn relay_h3_connect_udp_stream_chained(
    downstream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    upstream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    connect_udp_cfg: ConnectUdpConfig,
) -> Result<()> {
    let (mut downstream_send, mut downstream_recv) = downstream.split();
    let (mut upstream_send, mut upstream_recv) = upstream.split();

    let idle_timeout = Duration::from_secs(connect_udp_cfg.idle_timeout_secs.max(1));
    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                break;
            }
            recv = downstream_recv.recv_data() => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        upstream_send.send_data(bytes).await?;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => break,
                }
            }
            recv = upstream_recv.recv_data() => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        downstream_send.send_data(bytes).await?;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => break,
                }
            }
        }
    }

    let _ = upstream_send.finish().await;
    let _ = downstream_send.finish().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect_udp_upstream_accepts_h3_variants() {
        let (host, port) = parse_connect_udp_upstream("https://proxy.example:7443").expect("https");
        assert_eq!(host, "proxy.example");
        assert_eq!(port, 7443);

        let (host, port) = parse_connect_udp_upstream("h3://proxy.example").expect("h3");
        assert_eq!(host, "proxy.example");
        assert_eq!(port, 443);

        let (host, port) = parse_connect_udp_upstream("proxy.example:9443").expect("authority");
        assert_eq!(host, "proxy.example");
        assert_eq!(port, 9443);
    }

    #[test]
    fn parse_connect_udp_upstream_rejects_http_scheme() {
        assert!(parse_connect_udp_upstream("http://proxy.example:8080").is_err());
    }
}
