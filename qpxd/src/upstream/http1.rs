use crate::http::body::Body;
use crate::http::common::request_with_shared_client;
use crate::http::websocket::spawn_upgrade_tunnel;
use crate::tls::client::connect_tls_http1_with_options;
use crate::tls::CompiledUpstreamTlsTrust;
use crate::upstream::origin::OriginEndpoint;
use crate::upstream::pool::send_via_upstream_proxy;
use crate::upstream::raw_http1::{send_http1_request_with_interim, Http1ResponseWithInterim};
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hyper::header::{HeaderValue, CONNECTION, HOST, PROXY_AUTHORIZATION, UPGRADE};
use hyper::{Request, Response, Uri};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};
use tracing::warn;
use url::Url;

pub struct WebsocketProxyConfig<'a> {
    pub upstream_proxy: Option<&'a crate::upstream::pool::ResolvedUpstreamProxy>,
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
    pub logical_authority: Option<String>,
}

impl UpstreamProxyEndpoint {
    pub fn cache_key(&self) -> String {
        format!("{}://{}", self.scheme.as_str(), self.authority)
    }

    pub fn from_origin(origin: &OriginEndpoint) -> Result<Self> {
        let parsed = parse_upstream_proxy_endpoint(origin.upstream.as_str())?;
        let default_port = match parsed.scheme {
            UpstreamProxyScheme::Http => 80,
            UpstreamProxyScheme::Https => 443,
        };
        let authority = origin.connect_authority(default_port)?;
        let logical_authority = origin
            .host_header_authority(default_port)
            .ok()
            .filter(|logical| logical != &authority);
        let host = origin
            .tls_server_name()
            .unwrap_or_else(|_| parsed.host.clone());
        Ok(Self {
            scheme: parsed.scheme,
            authority,
            host,
            proxy_authorization: parsed.proxy_authorization,
            logical_authority,
        })
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
        logical_authority: None,
    })
}

pub async fn open_upstream_proxy_sender(
    endpoint: &UpstreamProxyEndpoint,
    timeout_dur: Option<Duration>,
    context: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<crate::http::common::Http1SendRequest> {
    let tcp = match timeout_dur {
        Some(dur) => timeout(dur, TcpStream::connect(endpoint.authority.as_str())).await??,
        None => TcpStream::connect(endpoint.authority.as_str()).await?,
    };
    match endpoint.scheme {
        UpstreamProxyScheme::Http => {
            let (sender, conn) = match timeout_dur {
                Some(dur) => timeout(dur, crate::http::common::handshake_http1(tcp)).await??,
                None => crate::http::common::handshake_http1(tcp).await?,
            };
            let authority = endpoint.authority.clone();
            let context = context.to_string();
            tokio::spawn(async move {
                if let Err(err) = conn.with_upgrades().await {
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
                Some(dur) => {
                    timeout(
                        dur,
                        connect_tls_http1_with_options(endpoint.host.as_str(), tcp, true, trust),
                    )
                    .await??
                }
                None => {
                    connect_tls_http1_with_options(endpoint.host.as_str(), tcp, true, trust).await?
                }
            };
            let (sender, conn) = match timeout_dur {
                Some(dur) => timeout(dur, crate::http::common::handshake_http1(tls)).await??,
                None => crate::http::common::handshake_http1(tls).await?,
            };
            let authority = endpoint.authority.clone();
            let context = context.to_string();
            tokio::spawn(async move {
                if let Err(err) = conn.with_upgrades().await {
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
) -> Result<crate::http::common::Http1SendRequest> {
    let stream = match timeout_dur {
        Some(dur) => timeout(dur, TcpStream::connect(authority)).await??,
        None => TcpStream::connect(authority).await?,
    };
    let (sender, conn) = match timeout_dur {
        Some(dur) => timeout(dur, crate::http::common::handshake_http1(stream)).await??,
        None => crate::http::common::handshake_http1(stream).await?,
    };
    let authority = authority.to_string();
    let context = context.to_string();
    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
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
    let client_upgrade = crate::http::upgrade::on(&mut req);

    let mut sender = if let Some(upstream_proxy) = upstream_proxy {
        let endpoint = upstream_proxy.endpoint();
        req.headers_mut().remove(PROXY_AUTHORIZATION);
        if let Some(value) = endpoint.proxy_authorization.as_ref() {
            req.headers_mut().insert(PROXY_AUTHORIZATION, value.clone());
        }
        let sender = open_upstream_proxy_sender(
            endpoint,
            Some(timeout_dur),
            upstream_context,
            upstream_proxy.trust(),
        )
        .await?;
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

    let mut response = timeout(timeout_dur, sender.send_request(req))
        .await??
        .map(Body::from);
    normalize_websocket_switching_protocols_response(&mut response);
    spawn_upgrade_tunnel(
        &mut response,
        client_upgrade,
        tunnel_label,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
    );
    Ok(response)
}

pub(crate) fn normalize_websocket_switching_protocols_response(response: &mut Response<Body>) {
    if response.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
        return;
    }
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("upgrade"));
    response
        .headers_mut()
        .entry(UPGRADE)
        .or_insert(HeaderValue::from_static("websocket"));
}

pub async fn proxy_http1_request(
    mut req: Request<Body>,
    upstream_proxy: Option<&crate::upstream::pool::ResolvedUpstreamProxy>,
    direct_authority: &str,
    timeout_dur: Duration,
) -> Result<Response<Body>> {
    ensure_absolute_uri(&mut req, "http", direct_authority)?;
    *req.version_mut() = http::Version::HTTP_11;
    if let Some(upstream) = upstream_proxy {
        return send_via_upstream_proxy(req, upstream, timeout_dur).await;
    }
    Ok(timeout(timeout_dur, request_with_shared_client(req)).await??)
}

pub async fn proxy_http1_request_with_interim(
    mut req: Request<Body>,
    upstream_proxy: Option<&crate::upstream::pool::ResolvedUpstreamProxy>,
    direct_authority: &str,
    timeout_dur: Duration,
) -> Result<Http1ResponseWithInterim> {
    ensure_absolute_uri(&mut req, "http", direct_authority)?;
    *req.version_mut() = http::Version::HTTP_11;
    if let Some(upstream) = upstream_proxy {
        return crate::upstream::pool::send_via_upstream_proxy_with_interim(
            req,
            upstream,
            timeout_dur,
        )
        .await;
    }

    let deadline = Instant::now() + timeout_dur;
    let stream = timeout(timeout_dur, TcpStream::connect(direct_authority)).await??;
    let _ = stream.set_nodelay(true);
    timeout(
        deadline.saturating_duration_since(Instant::now()),
        send_http1_request_with_interim(stream, req),
    )
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn direct_interim_exchange_times_out_after_connect() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind: {err}"),
        };
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0_u8; 256];
            let _ = stream.read(&mut buf).await;
            std::future::pending::<()>().await;
        });

        let req = Request::builder()
            .method(http::Method::GET)
            .uri("/")
            .body(Body::empty())
            .expect("request");
        let authority = addr.to_string();
        let result = proxy_http1_request_with_interim(
            req,
            None,
            authority.as_str(),
            Duration::from_millis(20),
        )
        .await;
        let Err(err) = result else {
            panic!("stalled upstream response head must time out");
        };
        assert!(err.to_string().contains("deadline has elapsed"), "{err}");
        server.abort();
        let _ = server.await;
    }
}
