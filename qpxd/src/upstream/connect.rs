use crate::http::address::format_authority_host_port;
use crate::tls::client::connect_tls_http1;
use crate::upstream::http1::{parse_upstream_proxy_endpoint, UpstreamProxyScheme};
use anyhow::{anyhow, Result};
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

pub async fn connect_via_upstream(
    upstream: &str,
    host: &str,
    port: u16,
) -> Result<ConnectedTunnel> {
    let endpoint = parse_upstream_proxy_endpoint(upstream)?;
    let tcp = timeout(
        CONNECT_IO_TIMEOUT,
        TcpStream::connect(endpoint.authority.as_str()),
    )
    .await??;
    let _ = tcp.set_nodelay(true);
    let peer_addr = tcp.peer_addr().ok();
    let mut stream: TunnelIo = match endpoint.scheme {
        UpstreamProxyScheme::Http => Box::new(tcp),
        UpstreamProxyScheme::Https => {
            timeout(
                CONNECT_IO_TIMEOUT,
                connect_tls_http1(endpoint.host.as_str(), tcp),
            )
            .await??
        }
    };
    let authority = format_authority_host_port(host, port);
    let mut connect_req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", authority, authority);
    if let Some(value) = endpoint.proxy_authorization.as_ref() {
        let value = value
            .to_str()
            .map_err(|_| anyhow!("invalid upstream proxy auth header"))?;
        connect_req.push_str("Proxy-Authorization: ");
        connect_req.push_str(value);
        connect_req.push_str("\r\n");
    }
    connect_req.push_str("\r\n");
    timeout(CONNECT_IO_TIMEOUT, stream.write_all(connect_req.as_bytes())).await??;

    let mut raw = Vec::with_capacity(256);
    let mut one = [0u8; 1];
    loop {
        raw.clear();
        timeout(CONNECT_IO_TIMEOUT, async {
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
        .await??;

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
            return Err(anyhow!("upstream CONNECT failed with status {}", status));
        }
        break;
    }
    Ok(ConnectedTunnel {
        io: stream,
        peer_addr,
    })
}

pub async fn connect_tunnel_target(
    host: &str,
    port: u16,
    upstream: Option<&str>,
    timeout_dur: Duration,
) -> Result<ConnectedTunnel> {
    if let Some(upstream) = upstream {
        return timeout(timeout_dur, connect_via_upstream(upstream, host, port)).await?;
    }
    let stream = timeout(timeout_dur, TcpStream::connect((host, port))).await??;
    let _ = stream.set_nodelay(true);
    let peer_addr = stream.peer_addr().ok();
    Ok(ConnectedTunnel {
        io: Box::new(stream),
        peer_addr,
    })
}
