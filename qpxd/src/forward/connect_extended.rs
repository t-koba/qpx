use super::*;

pub(super) struct H2ExtendedConnectUpstream {
    pub(super) interim: Vec<crate::upstream::raw_http1::InterimResponseHead>,
    pub(super) response: Http1Response<H2RecvStream>,
    pub(super) send_stream: h2::SendStream<Bytes>,
}

pub(super) async fn recv_upstream_h2_response_with_interim(
    response: &mut h2::client::ResponseFuture,
    timeout_dur: Duration,
    context: &str,
) -> Result<(
    Vec<crate::upstream::raw_http1::InterimResponseHead>,
    Http1Response<H2RecvStream>,
)> {
    let mut interim = Vec::new();
    loop {
        enum H2ResponseEvent {
            Informational(Http1Response<()>),
            Final(Http1Response<H2RecvStream>),
        }

        let event = match timeout(
            timeout_dur,
            poll_fn(|cx| match Pin::new(&mut *response).poll(cx) {
                Poll::Ready(Ok(response)) => Poll::Ready(Ok(H2ResponseEvent::Final(response))),
                Poll::Ready(Err(err)) => Poll::Ready(Err(anyhow!(err))),
                Poll::Pending => match response.poll_informational(cx) {
                    Poll::Ready(Some(Ok(response))) => {
                        Poll::Ready(Ok(H2ResponseEvent::Informational(response)))
                    }
                    Poll::Ready(Some(Err(err))) => Poll::Ready(Err(anyhow!(err))),
                    Poll::Ready(None) | Poll::Pending => Poll::Pending,
                },
            }),
        )
        .await
        {
            Ok(Ok(event)) => event,
            Ok(Err(err)) => return Err(err),
            Err(_) => return Err(anyhow!("{context} timed out")),
        };

        match event {
            H2ResponseEvent::Informational(response) => {
                let status = StatusCode::from_u16(response.status().as_u16())?;
                if status == StatusCode::SWITCHING_PROTOCOLS {
                    return Err(anyhow!("HTTP/2 interim responses must not use 101"));
                }
                interim.push(crate::upstream::raw_http1::InterimResponseHead {
                    status,
                    headers: h1_headers_to_http(response.headers())?,
                })
            }
            H2ResponseEvent::Final(response) => return Ok((interim, response)),
        }
    }
}

pub(super) async fn open_upstream_h2_extended_connect_stream(
    uri: &Uri,
    sanitized_headers: &http::HeaderMap,
    protocol: H2Protocol,
    proxy_name: &str,
    upstream: Option<&str>,
    timeout_dur: Duration,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<H2ExtendedConnectUpstream> {
    let (connect_host, connect_port, use_tls) = parse_h2_extended_connect_upstream(uri, upstream)?;
    let upstream_addr = match timeout(
        timeout_dur,
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
    let tcp = match timeout(timeout_dur, TcpStream::connect(upstream_addr)).await {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => return Err(anyhow!("extended CONNECT upstream connect timed out")),
    };
    let _ = tcp.set_nodelay(true);
    let io: BoxTlsStream = if use_tls {
        let (tls, negotiated_h2) = match timeout(
            timeout_dur,
            connect_tls_h2_h1_with_options(connect_host.as_str(), tcp, true, trust),
        )
        .await
        {
            Ok(Ok(tls)) => tls,
            Ok(Err(err)) => return Err(err),
            Err(_) => return Err(anyhow!("extended CONNECT upstream TLS handshake timed out")),
        };
        if !negotiated_h2 {
            return Err(anyhow!(
                "extended CONNECT upstream did not negotiate HTTP/2"
            ));
        }
        tls
    } else {
        Box::new(tcp)
    };
    let (sender, connection) =
        match timeout(timeout_dur, h2_client::Builder::new().handshake(io)).await {
            Ok(Ok(parts)) => parts,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => return Err(anyhow!("extended CONNECT upstream h2 setup timed out")),
        };
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            warn!(error = ?err, "extended CONNECT upstream h2 connection closed");
        }
    });
    let mut sender = match timeout(timeout_dur, sender.ready()).await {
        Ok(Ok(sender)) => sender,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => {
            return Err(anyhow!(
                "extended CONNECT upstream request sender timed out"
            ))
        }
    };
    if !sender.is_extended_connect_protocol_enabled() {
        return Err(anyhow!(
            "extended CONNECT upstream did not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL"
        ));
    }

    let normalized_headers =
        normalize_h2_upstream_connect_headers(uri, sanitized_headers, proxy_name)?;
    let mut request = Http1Request::builder()
        .method(::http::Method::CONNECT)
        .uri(http_uri_to_http1_uri(uri)?)
        .body(())?;
    *request.version_mut() = ::http::Version::HTTP_2;
    *request.headers_mut() = normalized_headers;
    request.extensions_mut().insert(protocol);

    let (mut response, send_stream) = sender.send_request(request, false)?;
    let (interim, response) = recv_upstream_h2_response_with_interim(
        &mut response,
        timeout_dur,
        "extended CONNECT upstream response",
    )
    .await?;
    Ok(H2ExtendedConnectUpstream {
        interim,
        response,
        send_stream,
    })
}

pub(super) fn normalize_h2_upstream_connect_headers(
    uri: &Uri,
    headers: &http::HeaderMap,
    proxy_name: &str,
) -> Result<Http1HeaderMap> {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri.clone())
        .body(Body::empty())?;
    *request.version_mut() = http::Version::HTTP_2;
    *request.headers_mut() = headers.clone();
    prepare_request_with_headers_in_place(&mut request, proxy_name, None, false);
    http_headers_to_h1(request.headers())
}

fn parse_h2_extended_connect_upstream(
    uri: &Uri,
    upstream: Option<&str>,
) -> Result<(String, u16, bool)> {
    if let Some(upstream) = upstream {
        if upstream.contains("://") {
            let parsed = url::Url::parse(upstream)?;
            let use_tls = match parsed.scheme() {
                "https" | "wss" | "h2" => true,
                "http" | "ws" | "h2c" => false,
                _ => return Err(anyhow!("unsupported extended CONNECT upstream scheme")),
            };
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow!("extended CONNECT upstream host missing"))?;
            let port = parsed
                .port()
                .unwrap_or_else(|| default_port_for_scheme(parsed.scheme()));
            return Ok((host.to_string(), port, use_tls));
        }
        let (host, port) = parse_authority_host_port(upstream, 80)
            .ok_or_else(|| anyhow!("invalid extended CONNECT upstream authority"))?;
        return Ok((host, port, false));
    }

    let authority = uri
        .authority()
        .ok_or_else(|| anyhow!("extended CONNECT missing authority"))?;
    let scheme = uri.scheme_str().unwrap_or("https");
    let (host, port) =
        parse_authority_host_port(authority.as_str(), default_port_for_scheme(scheme))
            .ok_or_else(|| anyhow!("invalid extended CONNECT authority"))?;
    let use_tls = matches!(scheme, "https" | "wss" | "h2");
    Ok((host, port, use_tls))
}

pub(super) fn default_port_for_scheme(scheme: &str) -> u16 {
    match scheme {
        "http" | "ws" | "h2c" => 80,
        "https" | "wss" | "h2" => 443,
        _ => 443,
    }
}

fn http_uri_to_http1_uri(uri: &Uri) -> Result<::http::Uri> {
    uri.to_string()
        .parse::<::http::Uri>()
        .or_else(|_| {
            let mut builder = ::http::Uri::builder();
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
        .map_err(|e| anyhow!("invalid HTTP/2 extended CONNECT uri: {e}"))
}

pub(super) fn spawn_h2_extended_connect_relay(
    mut downstream_body: Body,
    declared_request_length: Option<u64>,
    mut upstream_send: h2::SendStream<Bytes>,
    mut upstream_body: H2RecvStream,
    tunnel_idle_timeout: Duration,
) -> Body {
    let (sender, body) = Body::channel();
    tokio::spawn(async move {
        let mut sender = Some(sender);
        let mut upstream_flow = upstream_body.flow_control().clone();
        let mut upload_done = false;
        let mut download_done = false;
        let mut sent_request_len = 0u64;

        loop {
            tokio::select! {
                next = downstream_body.data(), if !upload_done => {
                    match next {
                        Some(Ok(chunk)) => {
                            sent_request_len = match sent_request_len.checked_add(chunk.len() as u64) {
                                Some(len) => len,
                                None => {
                                    upstream_send.send_reset(H2Reason::PROTOCOL_ERROR);
                                    if let Some(mut sender) = sender.take() {
                                        sender.abort();
                                    }
                                    return;
                                }
                            };
                            if let Some(expected) = declared_request_length {
                                if sent_request_len > expected {
                                    upstream_send.send_reset(H2Reason::PROTOCOL_ERROR);
                                    if let Some(mut sender) = sender.take() {
                                        sender.abort();
                                    }
                                    return;
                                }
                            }
                            if !chunk.is_empty() && upstream_send.send_data(chunk, false).is_err() {
                                if let Some(mut sender) = sender.take() {
                                    sender.abort();
                                }
                                return;
                            }
                        }
                        Some(Err(err)) => {
                            warn!(error = ?err, "HTTP/2 extended CONNECT downstream body failed");
                            upstream_send.send_reset(H2Reason::INTERNAL_ERROR);
                            if let Some(mut sender) = sender.take() {
                                sender.abort();
                            }
                            return;
                        }
                        None => {
                            let trailers =
                                match tokio::time::timeout(tunnel_idle_timeout, downstream_body.trailers()).await {
                                Ok(trailers) => trailers,
                                Err(_) => {
                                    upstream_send.send_reset(H2Reason::CANCEL);
                                    if let Some(mut sender) = sender.take() {
                                        sender.abort();
                                    }
                                    return;
                                }
                            };
                            let trailers = match trailers {
                                Ok(trailers) => trailers,
                                Err(err) => {
                                    warn!(error = ?err, "HTTP/2 extended CONNECT downstream trailers failed");
                                    upstream_send.send_reset(H2Reason::INTERNAL_ERROR);
                                    if let Some(mut sender) = sender.take() {
                                        sender.abort();
                                    }
                                    return;
                                }
                            };
                            if let Some(expected) = declared_request_length {
                                if sent_request_len != expected {
                                    upstream_send.send_reset(H2Reason::PROTOCOL_ERROR);
                                    if let Some(mut sender) = sender.take() {
                                        sender.abort();
                                    }
                                    return;
                                }
                            }
                            match trailers {
                                Some(trailers) => {
                                    if let Err(err) = crate::http::semantics::validate_request_trailers(&trailers) {
                                        warn!(error = ?err, "dropping forbidden HTTP/2 extended CONNECT request trailers");
                                        if upstream_send.send_data(Bytes::new(), true).is_err() {
                                            if let Some(mut sender) = sender.take() {
                                                sender.abort();
                                            }
                                            return;
                                        }
                                    } else if upstream_send
                                        .send_trailers(match http_headers_to_h1(&trailers) {
                                            Ok(trailers) => trailers,
                                            Err(err) => {
                                                warn!(error = ?err, "invalid HTTP/2 extended CONNECT request trailers");
                                                if upstream_send.send_data(Bytes::new(), true).is_err() {
                                                    if let Some(mut sender) = sender.take() {
                                                        sender.abort();
                                                    }
                                                }
                                                upload_done = true;
                                                if download_done {
                                                    break;
                                                }
                                                continue;
                                            }
                                        })
                                        .is_err()
                                    {
                                        if let Some(mut sender) = sender.take() {
                                            sender.abort();
                                        }
                                        return;
                                    }
                                }
                                None => {
                                    if upstream_send.send_data(Bytes::new(), true).is_err() {
                                        if let Some(mut sender) = sender.take() {
                                            sender.abort();
                                        }
                                        return;
                                    }
                                }
                            }
                            upload_done = true;
                            if download_done {
                                break;
                            }
                        }
                    }
                }
                next = upstream_body.data(), if !download_done => {
                    match next {
                        Some(Ok(chunk)) => {
                            let len = chunk.len();
                            if !chunk.is_empty()
                                && sender
                                    .as_mut()
                                    .expect("response body sender")
                                    .send_data(chunk)
                                    .await
                                    .is_err()
                            {
                                let _ = upstream_flow.release_capacity(len);
                                return;
                            }
                            if let Err(err) = upstream_flow.release_capacity(len) {
                                warn!(error = ?err, "HTTP/2 extended CONNECT upstream flow control release failed");
                                if let Some(mut sender) = sender.take() {
                                    sender.abort();
                                }
                                return;
                            }
                        }
                        Some(Err(err)) => {
                            warn!(error = ?err, "HTTP/2 extended CONNECT upstream body failed");
                            if let Some(mut sender) = sender.take() {
                                sender.abort();
                            }
                            return;
                        }
                        None => {
                            let trailers =
                                match tokio::time::timeout(tunnel_idle_timeout, upstream_body.trailers()).await {
                                Ok(trailers) => trailers,
                                Err(_) => {
                                    if let Some(mut sender) = sender.take() {
                                        sender.abort();
                                    }
                                    return;
                                }
                            };
                            let trailers = match trailers {
                                Ok(trailers) => trailers,
                                Err(err) => {
                                    warn!(error = ?err, "HTTP/2 extended CONNECT upstream trailers failed");
                                    if let Some(mut sender) = sender.take() {
                                        sender.abort();
                                    }
                                    return;
                                }
                            };
                            if let Some(trailers) = trailers {
                                let mut trailers = match h1_headers_to_http(&trailers) {
                                    Ok(trailers) => trailers,
                                    Err(err) => {
                                        warn!(error = ?err, "invalid HTTP/2 extended CONNECT upstream trailers");
                                        if let Some(mut sender) = sender.take() {
                                            sender.abort();
                                        }
                                        return;
                                    }
                                };
                                let removed = crate::http::semantics::sanitize_response_trailers(&mut trailers);
                                if removed > 0 {
                                    warn!(removed, "dropping forbidden HTTP/2 extended CONNECT response trailers");
                                }
                                let _ = sender
                                    .as_mut()
                                    .expect("response body sender")
                                    .send_trailers(trailers)
                                    .await;
                            }
                            download_done = true;
                            if upload_done {
                                break;
                            }
                        }
                    }
                }
                _ = tokio::time::sleep(tunnel_idle_timeout) => {
                    upstream_send.send_reset(H2Reason::CANCEL);
                    if let Some(mut sender) = sender.take() {
                        sender.abort();
                    }
                    return;
                }
            }
        }
    });
    body
}
