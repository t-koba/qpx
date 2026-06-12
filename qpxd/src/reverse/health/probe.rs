use crate::upstream::origin::OriginEndpoint;
use anyhow::{Result, anyhow};
use hyper::header::HOST;
use hyper::{Request, StatusCode, Uri};
use qpx_core::tls::CompiledUpstreamTlsTrust;
use qpx_http::body::Body;
use qpx_http::tls::client::connect_tls_http1_with_options;
use tokio::net::TcpStream;
use url::Url;

use super::HttpHealthCheckRuntime;

pub(in crate::reverse) async fn probe_upstream(
    origin: &OriginEndpoint,
    http: Option<&HttpHealthCheckRuntime>,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<()> {
    if let Some(cfg) = http {
        let normalized = if origin.upstream.starts_with("ws://") {
            origin.upstream.replacen("ws://", "http://", 1)
        } else if origin.upstream.starts_with("wss://") {
            origin.upstream.replacen("wss://", "https://", 1)
        } else {
            origin.upstream.clone()
        };
        if normalized.starts_with("http://") || normalized.starts_with("https://") {
            let mut normalized_origin = origin.clone();
            normalized_origin.upstream = normalized;
            return probe_http(&normalized_origin, cfg, trust).await;
        }
    }
    let default_port = if origin.upstream.starts_with("http://") {
        80
    } else {
        443
    };
    let addr = origin.connect_authority(default_port)?;
    let _ = TcpStream::connect(addr).await?;
    Ok(())
}

async fn probe_http(
    origin: &OriginEndpoint,
    cfg: &HttpHealthCheckRuntime,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<()> {
    let url = Url::parse(origin.upstream.as_str())?;
    let scheme = url.scheme();
    match scheme {
        "http" => probe_http_plain(origin, &url, cfg).await,
        "https" => probe_http_tls(origin, &url, cfg, trust).await,
        other => Err(anyhow!("unsupported health check scheme: {}", other)),
    }
}

async fn probe_http_plain(
    origin: &OriginEndpoint,
    _url: &Url,
    cfg: &HttpHealthCheckRuntime,
) -> Result<()> {
    let connect_authority = origin.connect_authority(80)?;
    let host_header = origin.host_header_authority(80)?;
    if !origin.uses_connect_override() {
        let uri = Uri::builder()
            .scheme("http")
            .authority(connect_authority.as_str())
            .path_and_query(cfg.path.as_ref())
            .build()?;
        let req = Request::builder()
            .method(cfg.method.clone())
            .uri(uri)
            .body(Body::empty())?;
        let resp = crate::http::protocol::common::request_with_shared_client(req).await?;
        return validate_probe_status(resp.status(), cfg);
    }
    let mut sender = crate::upstream::http1::open_http1_sender(
        connect_authority.as_str(),
        None,
        "reverse health check conn",
    )
    .await?;
    let req = Request::builder()
        .method(cfg.method.clone())
        .version(http::Version::HTTP_11)
        .uri(Uri::builder().path_and_query(cfg.path.as_ref()).build()?)
        .header(HOST, host_header.as_str())
        .body(Body::empty())?;
    let resp = sender.send_request(req).await?;
    validate_probe_status(resp.status(), cfg)
}

async fn probe_http_tls(
    origin: &OriginEndpoint,
    _url: &Url,
    cfg: &HttpHealthCheckRuntime,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<()> {
    let authority = origin.host_header_authority(443)?;
    let addr = origin.connect_authority(443)?;
    let server_name = origin.tls_server_name()?;
    let tcp = TcpStream::connect(addr).await?;
    let tls = connect_tls_http1_with_options(server_name.as_str(), tcp, true, trust).await?;
    let (mut sender, conn) = qpx_http::protocol::common::handshake_http1(tls).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let uri = Uri::builder().path_and_query(cfg.path.as_ref()).build()?;
    let req = Request::builder()
        .method(cfg.method.clone())
        .version(http::Version::HTTP_11)
        .uri(uri)
        .header(HOST, authority.as_str())
        .body(Body::empty())?;
    let resp = sender.send_request(req).await?;
    validate_probe_status(resp.status(), cfg)
}

fn validate_probe_status(status: StatusCode, cfg: &HttpHealthCheckRuntime) -> Result<()> {
    let code = status.as_u16();
    if let Some(expected) = cfg.expected_status.as_ref() {
        if expected.contains(&code) {
            return Ok(());
        }
        return Err(anyhow!("unexpected health check status: {}", code));
    }
    if status.is_success() || status.is_redirection() {
        return Ok(());
    }
    Err(anyhow!("unhealthy status: {}", code))
}
