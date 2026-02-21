use crate::http::common::shared_http_client;
use crate::http::websocket::spawn_upgrade_tunnel;
use crate::tls::client::connect_tls_http1;
use crate::upstream::pool::send_via_upstream_proxy;
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hyper::client::conn::Builder as ClientConnBuilder;
use hyper::header::{HeaderValue, HOST, PROXY_AUTHORIZATION};
use hyper::{Body, Request, Response, Uri};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::warn;
use url::Url;

pub struct WebsocketProxyConfig<'a> {
    pub upstream_proxy: Option<&'a str>,
    pub direct_connect_authority: &'a str,
    pub direct_host_header: &'a str,
    pub timeout_dur: Duration,
    pub upgrade_wait_timeout: Duration,
    pub tunnel_idle_timeout: Duration,
    pub tunnel_label: &'static str,
    pub upstream_context: &'a str,
    pub direct_context: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamProxyScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamProxyEndpoint {
    pub scheme: UpstreamProxyScheme,
    pub authority: String,
    pub host: String,
    pub proxy_authorization: Option<HeaderValue>,
}

impl UpstreamProxyEndpoint {
    pub fn cache_key(&self) -> String {
        format!("{}://{}", self.scheme.as_str(), self.authority)
    }
}

impl UpstreamProxyScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

pub fn ensure_absolute_uri(req: &mut Request<Body>, scheme: &str, authority: &str) -> Result<()> {
    if req.uri().scheme().is_none() || req.uri().authority().is_none() {
        set_absolute_uri(req, scheme, authority)?;
    }
    Ok(())
}

pub fn set_absolute_uri(req: &mut Request<Body>, scheme: &str, authority: &str) -> Result<()> {
    let absolute = Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(
            req.uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/"),
        )
        .build()?;
    *req.uri_mut() = absolute;
    Ok(())
}

pub fn ensure_origin_form_uri(req: &mut Request<Body>) -> Result<()> {
    let origin_form = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    *req.uri_mut() = Uri::builder().path_and_query(origin_form).build()?;
    Ok(())
}

pub fn ensure_host_header(req: &mut Request<Body>, authority: &str) -> Result<()> {
    if !req.headers().contains_key(HOST) {
        set_host_header(req, authority)?;
    }
    Ok(())
}

pub fn set_host_header(req: &mut Request<Body>, authority: &str) -> Result<()> {
    req.headers_mut()
        .insert(HOST, HeaderValue::from_str(authority)?);
    Ok(())
}

pub fn parse_upstream_proxy_endpoint(upstream: &str) -> Result<UpstreamProxyEndpoint> {
    let (scheme, authority, host, proxy_authorization) = if upstream.contains("://") {
        let url = Url::parse(upstream)?;
        let scheme = match url.scheme() {
            "http" => UpstreamProxyScheme::Http,
            "https" => UpstreamProxyScheme::Https,
            other => {
                return Err(anyhow!(
                    "unsupported upstream proxy scheme: {} (expected http/https)",
                    other
                ))
            }
        };
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("upstream proxy missing host"))?
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| anyhow!("upstream proxy missing port"))?;
        let authority = crate::http::address::format_authority_host_port(host.as_str(), port);
        let proxy_authorization = if !url.username().is_empty() || url.password().is_some() {
            let creds = format!("{}:{}", url.username(), url.password().unwrap_or(""));
            let encoded = BASE64.encode(creds);
            let value = HeaderValue::from_str(format!("Basic {}", encoded).as_str())
                .map_err(|_| anyhow!("invalid upstream proxy credentials"))?;
            Some(value)
        } else {
            None
        };
        (scheme, authority, host, proxy_authorization)
    } else {
        let (host, port) = crate::http::address::parse_authority_host_port(upstream.trim(), 80)
            .ok_or_else(|| anyhow!("invalid upstream proxy authority: {}", upstream))?;
        let authority = crate::http::address::format_authority_host_port(host.as_str(), port);
        (
            UpstreamProxyScheme::Http,
            authority,
            host,
            None::<HeaderValue>,
        )
    };
    Ok(UpstreamProxyEndpoint {
        scheme,
        authority,
        host,
        proxy_authorization,
    })
}

pub async fn open_upstream_proxy_sender(
    endpoint: &UpstreamProxyEndpoint,
    timeout_dur: Option<Duration>,
    context: &str,
) -> Result<hyper::client::conn::SendRequest<Body>> {
    let tcp = match timeout_dur {
        Some(dur) => timeout(dur, TcpStream::connect(endpoint.authority.as_str())).await??,
        None => TcpStream::connect(endpoint.authority.as_str()).await?,
    };
    match endpoint.scheme {
        UpstreamProxyScheme::Http => {
            let (sender, conn) = match timeout_dur {
                Some(dur) => timeout(dur, ClientConnBuilder::new().handshake(tcp)).await??,
                None => ClientConnBuilder::new().handshake(tcp).await?,
            };
            let authority = endpoint.authority.clone();
            let context = context.to_string();
            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    warn!(
                        error = ?err,
                        upstream = %authority,
                        context = %context,
                        "http/1.1 upstream proxy connection closed"
                    );
                }
            });
            Ok(sender)
        }
        UpstreamProxyScheme::Https => {
            let tls = match timeout_dur {
                Some(dur) => timeout(dur, connect_tls_http1(endpoint.host.as_str(), tcp)).await??,
                None => connect_tls_http1(endpoint.host.as_str(), tcp).await?,
            };
            let (sender, conn) = match timeout_dur {
                Some(dur) => timeout(dur, ClientConnBuilder::new().handshake(tls)).await??,
                None => ClientConnBuilder::new().handshake(tls).await?,
            };
            let authority = endpoint.authority.clone();
            let context = context.to_string();
            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    warn!(
                        error = ?err,
                        upstream = %authority,
                        context = %context,
                        "https upstream proxy connection closed"
                    );
                }
            });
            Ok(sender)
        }
    }
}

pub async fn open_http1_sender(
    authority: &str,
    timeout_dur: Option<Duration>,
    context: &str,
) -> Result<hyper::client::conn::SendRequest<Body>> {
    let stream = match timeout_dur {
        Some(dur) => timeout(dur, TcpStream::connect(authority)).await??,
        None => TcpStream::connect(authority).await?,
    };
    let (sender, conn) = match timeout_dur {
        Some(dur) => timeout(dur, ClientConnBuilder::new().handshake(stream)).await??,
        None => ClientConnBuilder::new().handshake(stream).await?,
    };
    let authority = authority.to_string();
    let context = context.to_string();
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            warn!(
                error = ?err,
                upstream = %authority,
                context = %context,
                "http/1.1 upstream connection closed"
            );
        }
    });
    Ok(sender)
}

pub async fn proxy_websocket_http1(
    mut req: Request<Body>,
    cfg: WebsocketProxyConfig<'_>,
) -> Result<Response<Body>> {
    let WebsocketProxyConfig {
        upstream_proxy,
        direct_connect_authority,
        direct_host_header,
        timeout_dur,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
        tunnel_label,
        upstream_context,
        direct_context,
    } = cfg;
    let client_upgrade = hyper::upgrade::on(&mut req);

    let mut sender = if let Some(upstream_proxy) = upstream_proxy {
        let endpoint = parse_upstream_proxy_endpoint(upstream_proxy)?;
        req.headers_mut().remove(PROXY_AUTHORIZATION);
        if let Some(value) = endpoint.proxy_authorization.as_ref() {
            req.headers_mut().insert(PROXY_AUTHORIZATION, value.clone());
        }
        let sender =
            open_upstream_proxy_sender(&endpoint, Some(timeout_dur), upstream_context).await?;
        if req.uri().scheme().is_none() || req.uri().authority().is_none() {
            set_absolute_uri(&mut req, "http", direct_connect_authority)?;
        }
        sender
    } else {
        let sender =
            open_http1_sender(direct_connect_authority, Some(timeout_dur), direct_context).await?;
        ensure_origin_form_uri(&mut req)?;
        ensure_host_header(&mut req, direct_host_header)?;
        sender
    };

    let mut response = timeout(timeout_dur, sender.send_request(req)).await??;
    spawn_upgrade_tunnel(
        &mut response,
        client_upgrade,
        tunnel_label,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
    );
    Ok(response)
}

pub async fn proxy_http1_request(
    mut req: Request<Body>,
    upstream_proxy: Option<&str>,
    direct_authority: &str,
    timeout_dur: Duration,
) -> Result<Response<Body>> {
    ensure_absolute_uri(&mut req, "http", direct_authority)?;
    *req.version_mut() = http::Version::HTTP_11;
    if let Some(upstream) = upstream_proxy {
        return send_via_upstream_proxy(req, upstream, timeout_dur).await;
    }
    Ok(timeout(timeout_dur, shared_http_client().request(req)).await??)
}
