use super::h3::ForwardH3Handler;
use super::h3_connect::{
    build_h3_connect_success_response, prepare_h3_connect_request, H3ConnectPreparation,
};
use crate::http3::capsule::{
    append_capsule_chunk, decode_quic_varint, encode_datagram_capsule,
    encode_datagram_capsule_value, take_next_capsule,
};
use crate::http3::datagram::{H3DatagramDispatch, H3StreamDatagrams};
use crate::http3::listener::H3ConnInfo;
use crate::http3::quic::build_h3_client_config;
use crate::http3::server::{send_h3_static_response, H3ServerRequestStream};
use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes, BytesMut};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use qpx_core::config::ConnectUdpConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{lookup_host, UdpSocket};
use tokio::time::{timeout, Duration, Instant};
use tracing::warn;
use url::Url;

const TARGET_HOST_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b':')
    .add(b'%')
    .add(b'/')
    .add(b'?')
    .add(b'#')
    .add(b'[')
    .add(b']');

pub(super) async fn handle_h3_connect_udp(
    req_head: http1::Request<()>,
    mut req_stream: H3ServerRequestStream,
    handler: ForwardH3Handler,
    conn: H3ConnInfo,
    datagrams: Option<H3StreamDatagrams>,
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
        authority: _authority,
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
        let upstream_chain = match open_upstream_connect_udp_stream(
            &upstream,
            host.as_str(),
            port,
            upstream_timeout,
        )
        .await
        {
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
            datagrams,
            upstream_chain.req_stream,
            upstream_chain.datagrams,
            connect_udp_cfg,
        )
        .await;

        upstream_chain.driver.abort();
        let _ = upstream_chain.driver.await;
        upstream_chain.datagram_task.abort();
        let _ = upstream_chain.datagram_task.await;
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

    if let Err(err) = relay_h3_connect_udp_stream(req_stream, udp, connect_udp_cfg, datagrams).await
    {
        warn!(error = ?err, "forward HTTP/3 CONNECT-UDP relay failed");
    }
    Ok(())
}

struct UpstreamConnectUdpStream {
    _endpoint: quinn::Endpoint,
    driver: tokio::task::JoinHandle<()>,
    datagram_task: tokio::task::JoinHandle<()>,
    datagrams: Option<H3StreamDatagrams>,
    req_stream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
}

async fn open_upstream_connect_udp_stream(
    upstream: &str,
    target_host: &str,
    target_port: u16,
    timeout_dur: Duration,
) -> Result<UpstreamConnectUdpStream> {
    let (upstream_host, upstream_port, uri) =
        build_upstream_connect_udp_uri(upstream, target_host, target_port)?;
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
    use h3_datagram::datagram_handler::HandleDatagramsExt as _;
    let datagram_dispatch = Arc::new(H3DatagramDispatch::new(64));
    let reader = h3_conn.get_datagram_reader();
    let datagram_task = {
        let dispatch = datagram_dispatch.clone();
        tokio::spawn(async move {
            dispatch.run(reader).await;
        })
    };

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
            datagram_task.abort();
            let _ = datagram_task.await;
            return Err(err.into());
        }
        Err(_) => {
            datagram_task.abort();
            let _ = datagram_task.await;
            return Err(anyhow!("upstream CONNECT-UDP request timed out"));
        }
    };
    let response = match timeout(timeout_dur, req_stream.recv_response()).await {
        Ok(Ok(response)) => response,
        Ok(Err(err)) => {
            datagram_task.abort();
            let _ = datagram_task.await;
            return Err(err.into());
        }
        Err(_) => {
            datagram_task.abort();
            let _ = datagram_task.await;
            return Err(anyhow!("upstream CONNECT-UDP response timed out"));
        }
    };
    if !response.status().is_success() {
        datagram_task.abort();
        let _ = datagram_task.await;
        return Err(anyhow!(
            "upstream CONNECT-UDP failed with status {}",
            response.status()
        ));
    }
    let capsule = response
        .headers()
        .get(http1::header::HeaderName::from_static("capsule-protocol"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    if capsule != Some("?1") {
        datagram_task.abort();
        let _ = datagram_task.await;
        return Err(anyhow!(
            "upstream CONNECT-UDP missing required response header: Capsule-Protocol: ?1"
        ));
    }

    let stream_id = req_stream.id();
    let upstream_datagrams = Some(
        datagram_dispatch
            .register_stream(stream_id, h3_conn.get_datagram_sender(stream_id))
            .await,
    );

    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    Ok(UpstreamConnectUdpStream {
        _endpoint: endpoint,
        driver,
        datagram_task,
        datagrams: upstream_datagrams,
        req_stream,
    })
}

fn build_upstream_connect_udp_uri(
    upstream: &str,
    target_host: &str,
    target_port: u16,
) -> Result<(String, u16, http1::Uri)> {
    let encoded_host = utf8_percent_encode(target_host, TARGET_HOST_ENCODE_SET).to_string();

    // RFC 9298 section 2: upstream configuration is a URI Template containing target_host/target_port.
    // We also support a convenience short form:
    // - authority-form "proxy.example:443" (uses the RFC 9298 default template)
    // - origin URL "https://proxy.example:443" (only if it has no path/query; uses the default template)
    if upstream.contains('{') || upstream.contains('}') {
        let (scheme, authority, path_query_tmpl) = split_uri_template(upstream)?;
        match scheme {
            "https" | "h3" => {}
            _ => {
                return Err(anyhow!(
                    "CONNECT-UDP upstream URI template requires https/h3 scheme"
                ))
            }
        }
        let (connect_host, connect_port) =
            crate::http::address::parse_authority_host_port(authority, 443)
                .ok_or_else(|| anyhow!("invalid CONNECT-UDP upstream authority"))?;
        let request_scheme = if scheme == "h3" { "https" } else { scheme };
        let path_and_query =
            expand_connect_udp_uri_template(path_query_tmpl, &encoded_host, target_port)?;
        let uri = http1::Uri::builder()
            .scheme(request_scheme)
            .authority(authority)
            .path_and_query(path_and_query.as_str())
            .build()?;
        return Ok((connect_host, connect_port, uri));
    }

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
        if parsed.path() != "/" || parsed.query().is_some() {
            return Err(anyhow!(
                "CONNECT-UDP upstream URL must be a URI template when it includes path/query"
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("CONNECT-UDP upstream host missing"))?
            .to_string();
        let port = parsed.port().unwrap_or(443);
        let authority = format_proxy_authority(host.as_str(), port);
        let path_and_query = format!("/.well-known/masque/udp/{encoded_host}/{target_port}/");
        let uri = http1::Uri::builder()
            .scheme("https")
            .authority(authority.as_str())
            .path_and_query(path_and_query.as_str())
            .build()?;
        return Ok((host, port, uri));
    }

    let (host, port) = crate::http::address::parse_authority_host_port(upstream, 443)
        .ok_or_else(|| anyhow!("invalid CONNECT-UDP upstream authority"))?;
    let authority = format_proxy_authority(host.as_str(), port);
    let path_and_query = format!("/.well-known/masque/udp/{encoded_host}/{target_port}/");
    let uri = http1::Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query(path_and_query.as_str())
        .build()?;
    Ok((host, port, uri))
}

fn split_uri_template(template: &str) -> Result<(&str, &str, &str)> {
    let scheme_end = template
        .find("://")
        .ok_or_else(|| anyhow!("CONNECT-UDP upstream URI template must be absolute"))?;
    let scheme = &template[..scheme_end];
    let rest = &template[scheme_end + 3..];
    let slash = rest
        .find('/')
        .ok_or_else(|| anyhow!("CONNECT-UDP upstream URI template must include a path"))?;
    let authority = &rest[..slash];
    if authority.is_empty() {
        return Err(anyhow!(
            "CONNECT-UDP upstream URI template authority is empty"
        ));
    }
    if authority.contains('{') || authority.contains('}') {
        return Err(anyhow!(
            "CONNECT-UDP upstream URI template must not contain variables in authority"
        ));
    }
    let path_query = &rest[slash..];
    if !path_query.starts_with('/') {
        return Err(anyhow!(
            "CONNECT-UDP upstream URI template path must start with '/'"
        ));
    }
    Ok((scheme, authority, path_query))
}

fn expand_connect_udp_uri_template(
    template: &str,
    encoded_target_host: &str,
    target_port: u16,
) -> Result<String> {
    let mut out = String::with_capacity(template.len() + encoded_target_host.len());
    let mut i = 0usize;
    while let Some(rel_start) = template[i..].find('{') {
        let start = i + rel_start;
        out.push_str(&template[i..start]);
        let end = template[start + 1..]
            .find('}')
            .map(|idx| start + 1 + idx)
            .ok_or_else(|| anyhow!("CONNECT-UDP upstream URI template has unterminated '{{'"))?;
        let expr = &template[start + 1..end];
        if expr.starts_with('+')
            || expr.starts_with('#')
            || expr.starts_with('.')
            || expr.starts_with('/')
            || expr.starts_with(';')
        {
            return Err(anyhow!("unsupported URI template operator: {{{}}}", expr));
        }
        let (op, vars) = match expr.chars().next() {
            Some('?') | Some('&') => (expr.chars().next().unwrap(), &expr[1..]),
            _ => ('\0', expr),
        };
        let mut values = Vec::new();
        for var in vars.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            match var {
                "target_host" => values.push((var, encoded_target_host.to_string())),
                "target_port" => values.push((var, target_port.to_string())),
                other => {
                    return Err(anyhow!(
                        "unsupported CONNECT-UDP URI template variable: {}",
                        other
                    ))
                }
            }
        }
        if values.is_empty() {
            return Err(anyhow!("empty URI template expression is not allowed"));
        }
        match op {
            '\0' => {
                // Simple string expansion; RFC 6570 uses comma separators for var lists.
                out.push_str(
                    values
                        .into_iter()
                        .map(|(_, v)| v)
                        .collect::<Vec<_>>()
                        .join(",")
                        .as_str(),
                );
            }
            '?' | '&' => {
                out.push(op);
                for (idx, (k, v)) in values.into_iter().enumerate() {
                    if idx > 0 {
                        out.push('&');
                    }
                    out.push_str(k);
                    out.push('=');
                    out.push_str(v.as_str());
                }
            }
            _ => return Err(anyhow!("unsupported URI template operator")),
        }
        i = end + 1;
    }
    out.push_str(&template[i..]);
    if out.contains('{') || out.contains('}') {
        return Err(anyhow!("CONNECT-UDP URI template expansion failed"));
    }
    if !out.starts_with('/') {
        return Err(anyhow!("expanded CONNECT-UDP path must start with '/'"));
    }
    Ok(out)
}

fn format_proxy_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else if port == 443 {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    }
}

fn parse_connect_udp_upstream(upstream: &str) -> Result<(String, u16)> {
    if upstream.contains('{') || upstream.contains('}') {
        let (scheme, authority, _path) = split_uri_template(upstream)?;
        match scheme {
            "https" | "h3" => {}
            _ => {
                return Err(anyhow!(
                    "CONNECT-UDP upstream chain requires https/h3 proxy URL"
                ))
            }
        }
        return crate::http::address::parse_authority_host_port(authority, 443)
            .ok_or_else(|| anyhow!("invalid CONNECT-UDP upstream authority"));
    }
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
    mut datagrams: Option<H3StreamDatagrams>,
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
            payload = async {
                if let Some(datagrams) = datagrams.as_mut() {
                    datagrams.receiver.recv().await
                } else {
                    std::future::pending::<Option<Bytes>>().await
                }
            } => {
                let Some(payload) = payload else {
                    break;
                };
                let (context_id, offset) = match decode_quic_varint(payload.as_ref()) {
                    Some(v) => v,
                    None => continue,
                };
                if context_id != 0 || offset > payload.len() {
                    continue;
                }
                udp.send(&payload[offset..]).await?;
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
            recv = udp.recv(&mut udp_buf) => {
                let n = recv?;
                if n == 0 {
                    continue;
                }
                let mut sent = false;
                if let Some(datagrams) = datagrams.as_mut() {
                    let mut value = Vec::with_capacity(1 + n);
                    value.push(0); // context id = 0
                    value.extend_from_slice(&udp_buf[..n]);
                    if datagrams.sender.send_datagram(Bytes::from(value)).is_ok() {
                        sent = true;
                    }
                }
                if !sent {
                    let capsule = encode_datagram_capsule(&udp_buf[..n])?;
                    req_send.send_data(capsule).await?;
                }
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
        }
    }

    req_send.finish().await?;
    Ok(())
}

async fn relay_h3_connect_udp_stream_chained(
    downstream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut downstream_datagrams: Option<H3StreamDatagrams>,
    upstream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut upstream_datagrams: Option<H3StreamDatagrams>,
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
                let fallback = payload.clone();
                let mut sent = false;
                if let Some(datagrams) = upstream_datagrams.as_mut() {
                    if datagrams.sender.send_datagram(payload).is_ok() {
                        sent = true;
                    }
                }
                if !sent {
                    let capsule = encode_datagram_capsule_value(fallback.as_ref())?;
                    upstream_send.send_data(capsule).await?;
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
                let fallback = payload.clone();
                let mut sent = false;
                if let Some(datagrams) = downstream_datagrams.as_mut() {
                    if datagrams.sender.send_datagram(payload).is_ok() {
                        sent = true;
                    }
                }
                if !sent {
                    let capsule = encode_datagram_capsule_value(fallback.as_ref())?;
                    downstream_send.send_data(capsule).await?;
                }
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
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
