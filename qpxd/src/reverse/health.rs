use anyhow::{anyhow, Result};
use hyper::client::conn::Builder as ClientConnBuilder;
use hyper::header::HOST;
use hyper::{Body, Request, StatusCode, Uri};
use qpx_core::config::{HealthCheckConfig, HttpHealthCheckConfig};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub(super) struct HealthCheckRuntime {
    pub(super) interval: Duration,
    pub(super) timeout: Duration,
    pub(super) fail_threshold: u32,
    pub(super) cooldown: Duration,
    pub(super) http: Option<Arc<HttpHealthCheckRuntime>>,
}

#[derive(Debug, Clone)]
pub(super) struct HttpHealthCheckRuntime {
    pub(super) method: http::Method,
    pub(super) path: Arc<str>,
    pub(super) expected_status: Option<Arc<Vec<u16>>>,
}

impl HealthCheckRuntime {
    pub(super) fn from_config(config: Option<&HealthCheckConfig>) -> Self {
        if let Some(cfg) = config {
            return Self {
                interval: Duration::from_millis(cfg.interval_ms),
                timeout: Duration::from_millis(cfg.timeout_ms),
                fail_threshold: cfg.fail_threshold.max(1),
                cooldown: Duration::from_millis(cfg.cooldown_ms),
                http: cfg
                    .http
                    .as_ref()
                    .map(|h| Arc::new(HttpHealthCheckRuntime::from_config(h))),
            };
        }
        Self {
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(1),
            fail_threshold: 3,
            cooldown: Duration::from_secs(30),
            http: None,
        }
    }
}

impl HttpHealthCheckRuntime {
    fn from_config(cfg: &HttpHealthCheckConfig) -> Self {
        let method = cfg
            .method
            .as_deref()
            .unwrap_or("HEAD")
            .trim()
            .to_ascii_uppercase();
        let method = if method == "GET" {
            http::Method::GET
        } else {
            http::Method::HEAD
        };
        let path = cfg.path.as_deref().unwrap_or("/").trim();
        let expected_status = cfg
            .expected_status
            .as_ref()
            .filter(|v| !v.is_empty())
            .map(|v| Arc::new(v.clone()));
        Self {
            method,
            path: Arc::<str>::from(if path.is_empty() { "/" } else { path }),
            expected_status,
        }
    }
}

#[derive(Debug)]
pub(super) struct UpstreamEndpoint {
    pub(super) target: String,
    failures: AtomicU32,
    unhealthy_until_ms: AtomicU64,
    pub(super) inflight: AtomicUsize,
}

impl UpstreamEndpoint {
    pub(super) fn new(target: String) -> Self {
        Self {
            target,
            failures: AtomicU32::new(0),
            unhealthy_until_ms: AtomicU64::new(0),
            inflight: AtomicUsize::new(0),
        }
    }

    pub(super) fn is_healthy(&self, now_ms: u64) -> bool {
        self.unhealthy_until_ms.load(Ordering::Relaxed) <= now_ms
    }

    pub(super) fn mark_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.unhealthy_until_ms.store(0, Ordering::Relaxed);
    }

    pub(super) fn mark_failure(&self, policy: &HealthCheckRuntime) {
        let fails = self
            .failures
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if fails >= policy.fail_threshold {
            let until = now_millis().saturating_add(policy.cooldown.as_millis() as u64);
            self.unhealthy_until_ms.store(until, Ordering::Relaxed);
        }
    }
}

pub(super) async fn probe_upstream(raw: &str, http: Option<&HttpHealthCheckRuntime>) -> Result<()> {
    if let Some(cfg) = http {
        let normalized = if raw.starts_with("ws://") {
            raw.replacen("ws://", "http://", 1)
        } else if raw.starts_with("wss://") {
            raw.replacen("wss://", "https://", 1)
        } else {
            raw.to_string()
        };
        if normalized.starts_with("http://") || normalized.starts_with("https://") {
            return probe_http(&normalized, cfg).await;
        }
    }
    let default_port = if raw.starts_with("http://") { 80 } else { 443 };
    let addr = crate::upstream::origin::parse_upstream_addr(raw, default_port)?;
    let _ = TcpStream::connect(addr).await?;
    Ok(())
}

async fn probe_http(raw: &str, cfg: &HttpHealthCheckRuntime) -> Result<()> {
    let url = Url::parse(raw)?;
    let scheme = url.scheme();
    match scheme {
        "http" => probe_http_plain(&url, cfg).await,
        "https" => probe_http_tls(&url, cfg).await,
        other => Err(anyhow!("unsupported health check scheme: {}", other)),
    }
}

async fn probe_http_plain(url: &Url, cfg: &HttpHealthCheckRuntime) -> Result<()> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("missing upstream host"))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let authority = crate::http::address::format_authority_host_port(host, port);
    let uri = Uri::builder()
        .scheme("http")
        .authority(authority.as_str())
        .path_and_query(cfg.path.as_ref())
        .build()?;
    let req = Request::builder()
        .method(cfg.method.clone())
        .uri(uri)
        .body(Body::empty())?;
    let resp = crate::http::common::shared_http_client()
        .request(req)
        .await?;
    validate_probe_status(resp.status(), cfg)
}

async fn probe_http_tls(url: &Url, cfg: &HttpHealthCheckRuntime) -> Result<()> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("missing upstream host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let authority = crate::http::address::format_authority_host_port(host, port);
    let addr = crate::upstream::origin::parse_upstream_addr(url.as_str(), port)?;
    let tcp = TcpStream::connect(addr).await?;
    let tls = crate::tls::client::connect_tls_http1(host, tcp).await?;
    let (mut sender, conn) = ClientConnBuilder::new().handshake(tls).await?;
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

pub(super) fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis() as u64
}
