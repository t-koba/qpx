use super::http1::{
    ensure_origin_form_uri, proxy_websocket_http1, set_absolute_uri, set_host_header,
    WebsocketProxyConfig,
};
use crate::http::address::{format_authority_host_port, parse_authority_host_port};
use crate::http::l7::prepare_request_with_headers_in_place;
use crate::http::websocket::spawn_upgrade_tunnel;
use crate::tls::client::{connect_tls_h2_h1, connect_tls_http1, BoxTlsStream};
use anyhow::{anyhow, Result};
use hyper::client::connect::{Connected, Connection};
use hyper::client::HttpConnector;
use hyper::service::Service;
use hyper::Uri;
use hyper::{Body, Request, Response};
#[cfg(feature = "http3")]
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::{future::Future, pin::Pin, task::Context, task::Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(feature = "http3")]
use tokio::net::lookup_host;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::warn;
use url::Url;

pub(crate) async fn proxy_http(
    req: Request<Body>,
    upstream: &str,
    proxy_name: &str,
) -> Result<Response<Body>> {
    let url = Url::parse(upstream)?;
    match url.scheme() {
        "http" => proxy_http_plain(req, &url, proxy_name).await,
        "https" => proxy_http_tls(req, &url, proxy_name).await,
        "ipc" | "ipc+unix" => crate::ipc_client::proxy_ipc(req, &url, proxy_name).await,
        _ => Err(anyhow!(
            "reverse currently supports only http/https/ipc upstream for HTTP requests"
        )),
    }
}

pub(crate) async fn proxy_websocket(
    req: Request<Body>,
    upstream: &str,
    proxy_name: &str,
    timeout_dur: Duration,
    upgrade_wait_timeout: Duration,
    tunnel_idle_timeout: Duration,
) -> Result<Response<Body>> {
    let upstream_url = Url::parse(upstream)?;
    let scheme = upstream_url.scheme();
    if scheme != "http" && scheme != "https" && scheme != "ws" && scheme != "wss" {
        return Err(anyhow!(
            "reverse websocket supports only http/https/ws/wss upstream"
        ));
    }
    let mut req = req;
    rewrite_direct_upstream_request(
        &mut req,
        &upstream_url,
        if scheme == "https" || scheme == "wss" {
            443
        } else {
            80
        },
    )?;
    prepare_request_with_headers_in_place(&mut req, proxy_name, None, true);

    match scheme {
        "http" | "ws" => {
            let addr = parse_upstream_addr(upstream, 80)?;
            proxy_websocket_http1(
                req,
                WebsocketProxyConfig {
                    upstream_proxy: None,
                    direct_connect_authority: &addr,
                    direct_host_header: &addr,
                    timeout_dur,
                    upgrade_wait_timeout,
                    tunnel_idle_timeout,
                    tunnel_label: "reverse",
                    upstream_context: "reverse websocket upstream proxy",
                    direct_context: "reverse websocket upstream conn",
                },
            )
            .await
        }
        "https" | "wss" => {
            let mut req_tls = req;
            let client_upgrade = hyper::upgrade::on(&mut req_tls);
            let mut sender = open_tls_http1_sender(
                &upstream_url,
                443,
                "reverse websocket upstream TLS conn",
                timeout_dur,
            )
            .await?;
            let mut response = timeout(timeout_dur, sender.send_request(req_tls)).await??;
            spawn_upgrade_tunnel(
                &mut response,
                client_upgrade,
                "reverse",
                upgrade_wait_timeout,
                tunnel_idle_timeout,
            );
            Ok(response)
        }
        _ => Err(anyhow!("unsupported websocket upstream scheme")),
    }
}

#[cfg(feature = "http3")]
pub(crate) async fn resolve_upstream_socket_addr(
    raw: &str,
    default_port: u16,
    timeout_dur: Duration,
) -> Result<SocketAddr> {
    let host_port = parse_upstream_addr(raw, default_port)?;
    timeout(timeout_dur, lookup_host(host_port))
        .await??
        .next()
        .ok_or_else(|| anyhow!("failed to resolve upstream address"))
}

pub(crate) fn parse_upstream_addr(raw: &str, default_port: u16) -> Result<String> {
    if raw.contains("://") {
        let url = Url::parse(raw)?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("missing upstream host"))?;
        let port = url.port().unwrap_or(default_port);
        return Ok(format_authority_host_port(host, port));
    }

    if raw.contains(':') {
        if let Some((host, port)) = parse_authority_host_port(raw, default_port) {
            return Ok(format_authority_host_port(host.as_str(), port));
        }
    }

    Ok(format_authority_host_port(raw, default_port))
}

async fn proxy_http_plain(
    req: Request<Body>,
    upstream_url: &Url,
    proxy_name: &str,
) -> Result<Response<Body>> {
    let mut new_req = req;
    rewrite_client_upstream_request(&mut new_req, upstream_url, 80)?;
    prepare_request_with_headers_in_place(&mut new_req, proxy_name, None, false);
    *new_req.version_mut() = http::Version::HTTP_11;
    *new_req.extensions_mut() = http::Extensions::new();
    Ok(shared_reverse_http_client().request(new_req).await?)
}

async fn proxy_http_tls(
    req: Request<Body>,
    upstream_url: &Url,
    proxy_name: &str,
) -> Result<Response<Body>> {
    let mut new_req = req;
    rewrite_client_upstream_request(&mut new_req, upstream_url, 443)?;
    prepare_request_with_headers_in_place(&mut new_req, proxy_name, None, false);
    *new_req.extensions_mut() = http::Extensions::new();
    *new_req.version_mut() = http::Version::HTTP_11;
    Ok(shared_reverse_https_client().request(new_req).await?)
}

#[derive(Clone)]
struct ReverseTlsConnector {
    timeout_dur: Duration,
}

impl Default for ReverseTlsConnector {
    fn default() -> Self {
        Self {
            timeout_dur: Duration::from_secs(30),
        }
    }
}

struct ReverseTlsStream {
    io: BoxTlsStream,
    negotiated_h2: bool,
}

impl AsyncRead for ReverseTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReverseTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl Connection for ReverseTlsStream {
    fn connected(&self) -> Connected {
        let mut connected = Connected::new();
        if self.negotiated_h2 {
            connected = connected.negotiated_h2();
        }
        connected
    }
}

impl Service<Uri> for ReverseTlsConnector {
    type Response = ReverseTlsStream;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let timeout_dur = self.timeout_dur;
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| anyhow!("reverse https upstream missing host"))?;
            let port = uri.port_u16().unwrap_or(443);
            let addr = format_authority_host_port(host, port);
            let tcp = timeout(timeout_dur, TcpStream::connect(addr)).await??;
            let (tls_stream, negotiated_h2) =
                timeout(timeout_dur, connect_tls_h2_h1(host, tcp)).await??;
            Ok(ReverseTlsStream {
                io: tls_stream,
                negotiated_h2,
            })
        })
    }
}

fn shared_reverse_http_client() -> &'static hyper::Client<HttpConnector, Body> {
    static CLIENT: OnceLock<hyper::Client<HttpConnector, Body>> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        hyper::Client::builder()
            .pool_max_idle_per_host(256)
            .build(connector)
    })
}

fn shared_reverse_https_client() -> &'static hyper::Client<ReverseTlsConnector, Body> {
    static CLIENT: OnceLock<hyper::Client<ReverseTlsConnector, Body>> = OnceLock::new();
    CLIENT.get_or_init(|| {
        hyper::Client::builder()
            .pool_max_idle_per_host(256)
            .build(ReverseTlsConnector::default())
    })
}

fn rewrite_client_upstream_request(
    req: &mut Request<Body>,
    upstream_url: &Url,
    default_port: u16,
) -> Result<()> {
    let authority = parse_upstream_addr(upstream_url.as_str(), default_port)?;
    set_host_header(req, &authority)?;
    set_absolute_uri(req, upstream_url.scheme(), authority.as_str())?;
    Ok(())
}

fn rewrite_direct_upstream_request(
    req: &mut Request<Body>,
    upstream_url: &Url,
    default_port: u16,
) -> Result<()> {
    let authority = parse_upstream_addr(upstream_url.as_str(), default_port)?;
    set_host_header(req, &authority)?;
    ensure_origin_form_uri(req)?;
    Ok(())
}

async fn open_tls_http1_sender(
    upstream_url: &Url,
    default_port: u16,
    context: &str,
    timeout_dur: Duration,
) -> Result<hyper::client::conn::SendRequest<Body>> {
    let host = upstream_url
        .host_str()
        .ok_or_else(|| anyhow!("missing upstream host"))?;
    let addr = parse_upstream_addr(upstream_url.as_str(), default_port)?;
    let tcp = timeout(timeout_dur, TcpStream::connect(addr)).await??;
    let tls_stream = timeout(timeout_dur, connect_tls_http1(host, tcp)).await??;
    let (sender, conn) = timeout(
        timeout_dur,
        hyper::client::conn::Builder::new().handshake(tls_stream),
    )
    .await??;
    let context = context.to_string();
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            warn!(error = ?err, context = %context, "reverse upstream TLS conn closed");
        }
    });
    Ok(sender)
}
