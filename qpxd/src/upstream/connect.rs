use crate::http::address::format_authority_host_port;
use crate::http::semantics::append_via_for_version;
use crate::tls::client::connect_tls_http1_with_options;
use crate::upstream::http1::UpstreamProxyScheme;
use crate::upstream::pool::ResolvedUpstreamProxy;
use anyhow::{anyhow, Result};
use hyper::header::{HeaderMap, HeaderName, HeaderValue, HOST};
use hyper::{StatusCode, Version};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub type TunnelIo = crate::tls::client::BoxTlsStream;

pub struct ConnectedTunnel {
    pub io: TunnelIo,
    pub peer_addr: Option<SocketAddr>,
}

const MAX_CONNECT_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const CONNECT_IO_TIMEOUT: Duration = Duration::from_secs(10);

fn build_upstream_connect_request(
    authority: &str,
    proxy_authorization: Option<&HeaderValue>,
    proxy_name: &str,
) -> Result<String> {
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_str(authority)?);
    if let Some(value) = proxy_authorization {
        headers.insert(
            HeaderName::from_static("proxy-authorization"),
            value.clone(),
        );
    }
    append_via_for_version(&mut headers, Version::HTTP_11, proxy_name);
    qpx_observability::inject_trace_context(&mut headers);

    let mut request = format!("CONNECT {} HTTP/1.1\r\n", authority);
    for (name, value) in &headers {
        request.push_str(name.as_str());
        request.push_str(": ");
        request.push_str(value.to_str()?);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    Ok(request)
}

pub async fn connect_via_upstream(
    upstream: &ResolvedUpstreamProxy,
    host: &str,
    port: u16,
    proxy_name: &str,
) -> Result<ConnectedTunnel> {
    let endpoint = upstream.endpoint().clone();
    let started = std::time::Instant::now();
    let tcp = match timeout(
        CONNECT_IO_TIMEOUT,
        TcpStream::connect(endpoint.authority.as_str()),
    )
    .await
    {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(err)) => {
            upstream.mark_connect_error();
            return Err(err.into());
        }
        Err(_) => {
            upstream.mark_timeout();
            return Err(anyhow!("upstream proxy connect timed out"));
        }
    };
    let _ = tcp.set_nodelay(true);
    let peer_addr = tcp.peer_addr().ok();
    let mut stream: TunnelIo = match endpoint.scheme {
        UpstreamProxyScheme::Http => Box::new(tcp),
        UpstreamProxyScheme::Https => match timeout(
            CONNECT_IO_TIMEOUT,
            connect_tls_http1_with_options(endpoint.host.as_str(), tcp, true, upstream.trust()),
        )
        .await
        {
            Ok(Ok(tls)) => tls,
            Ok(Err(err)) => {
                upstream.mark_connect_error();
                return Err(err);
            }
            Err(_) => {
                upstream.mark_timeout();
                return Err(anyhow!("upstream proxy TLS handshake timed out"));
            }
        },
    };
    let authority = format_authority_host_port(host, port);
    let connect_req = build_upstream_connect_request(
        &authority,
        endpoint.proxy_authorization.as_ref(),
        proxy_name,
    )?;
    match timeout(CONNECT_IO_TIMEOUT, stream.write_all(connect_req.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            upstream.mark_reset();
            return Err(err.into());
        }
        Err(_) => {
            upstream.mark_timeout();
            return Err(anyhow!("upstream proxy CONNECT write timed out"));
        }
    }

    let mut raw = Vec::with_capacity(256);
    let mut one = [0u8; 1];
    loop {
        raw.clear();
        match timeout(CONNECT_IO_TIMEOUT, async {
            loop {
                if raw.len() >= MAX_CONNECT_RESPONSE_HEADER_BYTES {
                    return Err(anyhow!("upstream CONNECT response headers too large"));
                }
                let n = stream.read(&mut one).await?;
                if n == 0 {
                    return Err(anyhow!(
                        "upstream CONNECT response closed before completion"
                    ));
                }
                raw.push(one[0]);
                if raw.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                upstream.mark_reset();
                return Err(err);
            }
            Err(_) => {
                upstream.mark_timeout();
                return Err(anyhow!("upstream CONNECT response timed out"));
            }
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut res = httparse::Response::new(&mut headers);
        let status = match res.parse(&raw)? {
            httparse::Status::Complete(_) => res
                .code
                .ok_or_else(|| anyhow!("upstream CONNECT missing status code"))?,
            httparse::Status::Partial => {
                return Err(anyhow!("upstream CONNECT response incomplete"));
            }
        };
        if (100..200).contains(&status) {
            continue;
        }
        if !(200..300).contains(&status) {
            if let Ok(status) = StatusCode::from_u16(status) {
                upstream.mark_http_response(status, started.elapsed());
            } else {
                upstream.mark_reset();
            }
            return Err(anyhow!("upstream CONNECT failed with status {}", status));
        }
        break;
    }
    upstream.mark_success();
    Ok(ConnectedTunnel {
        io: stream,
        peer_addr,
    })
}

pub async fn connect_tunnel_target(
    host: &str,
    port: u16,
    upstream: Option<&ResolvedUpstreamProxy>,
    proxy_name: &str,
    timeout_dur: Duration,
) -> Result<ConnectedTunnel> {
    if let Some(upstream) = upstream {
        return match timeout(
            timeout_dur,
            connect_via_upstream(upstream, host, port, proxy_name),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                upstream.mark_timeout();
                Err(anyhow!("upstream tunnel connect timed out"))
            }
        };
    }
    let stream = timeout(timeout_dur, TcpStream::connect((host, port))).await??;
    let _ = stream.set_nodelay(true);
    let peer_addr = stream.peer_addr().ok();
    Ok(ConnectedTunnel {
        io: Box::new(stream),
        peer_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_upstream_connect_request_adds_via_and_trace_context() {
        let request =
            build_upstream_connect_request("example.com:443", None, "qpx").expect("request");
        assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(request.contains("host: example.com:443\r\n"));
        assert!(request.contains("via: 1.1 qpx\r\n"));
    }
}
