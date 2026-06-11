use crate::ObservabilityResult;
use anyhow::{Context, Result};
use cidr::IpCidr;
use metrics::histogram;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use qpx_core::config::MetricsConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::time::{Duration, Instant, timeout};

const MAX_METRICS_REQUEST_BYTES: usize = 16 * 1024;
const METRICS_READ_TIMEOUT: Duration = Duration::from_secs(5);
const METRICS_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const METRICS_RENDER_CACHE_TTL: Duration = Duration::from_millis(250);

pub(crate) fn grpc_stream_duration_seconds(
    listener: &str,
    protocol: String,
    streaming: String,
    seconds: f64,
) {
    histogram!(
        "qpx_grpc_stream_duration_seconds",
        "listener" => listener.to_owned(),
        "protocol" => protocol,
        "streaming" => streaming,
    )
    .record(seconds);
}

enum MetricsResponseBody {
    Static(&'static str),
    Shared(Arc<str>),
}

impl MetricsResponseBody {
    fn as_str(&self) -> &str {
        match self {
            Self::Static(body) => body,
            Self::Shared(body) => body.as_ref(),
        }
    }
}

#[derive(Debug, Default)]
struct MetricsRenderCache {
    body: Option<Arc<str>>,
    generated_at: Option<Instant>,
}

impl MetricsRenderCache {
    fn fresh_body(&self, now: Instant) -> Option<Arc<str>> {
        let generated_at = self.generated_at?;
        if now.duration_since(generated_at) > METRICS_RENDER_CACHE_TTL {
            return None;
        }
        self.body.clone()
    }

    fn store(&mut self, body: Arc<str>, now: Instant) {
        self.body = Some(body);
        self.generated_at = Some(now);
    }
}

/// Starts the Prometheus metrics endpoint.
pub fn start_metrics(
    config: &MetricsConfig,
    inherited_listener: Option<std::net::TcpListener>,
) -> ObservabilityResult<tokio::task::JoinHandle<()>> {
    start_metrics_inner(config, inherited_listener).map_err(Into::into)
}

fn start_metrics_inner(
    config: &MetricsConfig,
    inherited_listener: Option<std::net::TcpListener>,
) -> Result<tokio::task::JoinHandle<()>> {
    let listen: SocketAddr = config.listen.parse()?;
    let path = if config.path.starts_with('/') {
        config.path.clone()
    } else {
        format!("/{}", config.path)
    };
    let allow: Vec<IpCidr> = config
        .allow
        .iter()
        .map(|cidr| cidr.parse())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| anyhow::anyhow!("invalid metrics.allow CIDR"))?;
    let allow = std::sync::Arc::new(allow);
    let max_concurrent = config.max_concurrent_connections.max(1);
    let semaphore = std::sync::Arc::new(Semaphore::new(max_concurrent));

    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder)
        .map_err(|e| anyhow::anyhow!("metrics recorder install failed: {}", e))?;
    let render_cache = Arc::new(AsyncMutex::new(MetricsRenderCache::default()));

    let runtime = tokio::runtime::Handle::try_current()
        .context("metrics endpoint requires running Tokio runtime")?;
    Ok(runtime.spawn(async move {
        let listener = match inherited_listener {
            Some(listener) => {
                if let Err(err) = listener.set_nonblocking(true) {
                    tracing::warn!(error = ?err, "failed to set inherited metrics listener nonblocking");
                    return;
                }
                match TcpListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(err) => {
                        tracing::warn!(error = ?err, "failed to adopt inherited metrics listener");
                        return;
                    }
                }
            }
            None => match TcpListener::bind(listen).await {
                Ok(listener) => listener,
                Err(err) => {
                    tracing::warn!(error = ?err, "failed to bind metrics listener");
                    return;
                }
            },
        };
        loop {
            let (mut stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::warn!(error = ?err, "metrics accept failed");
                    continue;
                }
            };
            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    let _ = write_http_response_with_timeout(
                        &mut stream,
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbusy",
                    )
                    .await;
                    continue;
                }
            };
            let handle = handle.clone();
            let render_cache = render_cache.clone();
            let path = path.clone();
            let allow = allow.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let peer_ip = peer_addr.ip();
                let allowed = if peer_ip.is_loopback() {
                    true
                } else if allow.is_empty() {
                    false
                } else {
                    allow.iter().any(|cidr| cidr.contains(&peer_ip))
                };
                if !allowed {
                    let _ = write_http_response_with_timeout(
                        &mut stream,
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nforbidden",
                    )
                        .await;
                    return;
                }

                let request_path =
                    match timeout(METRICS_READ_TIMEOUT, read_http_request_path(&mut stream)).await {
                        Ok(Ok(Some(path))) => path,
                        Ok(Ok(None)) => return,
                        Ok(Err(_)) | Err(_) => {
                            let _ = write_http_response_with_timeout(
                                &mut stream,
                                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbad request",
                            )
                                .await;
                            return;
                        }
                    };

                let (status, body, content_type) = if request_path == "/health" {
                    ("200 OK", MetricsResponseBody::Static("OK"), "text/plain; charset=utf-8")
                } else if request_path == path {
                    match render_metrics_body(handle.clone(), render_cache.clone()).await {
                        Ok(body) => (
                            "200 OK",
                            MetricsResponseBody::Shared(body),
                            "text/plain; version=0.0.4; charset=utf-8",
                        ),
                        Err(err) => {
                            tracing::warn!(error = ?err, "metrics render task failed");
                            (
                                "500 Internal Server Error",
                                MetricsResponseBody::Static("metrics render failed"),
                                "text/plain; charset=utf-8",
                            )
                        }
                    }
                } else {
                    (
                        "404 Not Found",
                        MetricsResponseBody::Static("not found"),
                        "text/plain; charset=utf-8",
                    )
                };

                let _ =
                    write_http_response_parts_with_timeout(
                        &mut stream,
                        status,
                        content_type,
                        body.as_str(),
                    )
                        .await;
            });
        }
    }))
}

async fn render_metrics_body(
    handle: PrometheusHandle,
    cache: Arc<AsyncMutex<MetricsRenderCache>>,
) -> Result<Arc<str>> {
    let mut cache = cache.lock().await;
    let now = Instant::now();
    if let Some(body) = cache.fresh_body(now) {
        return Ok(body);
    }
    let body = tokio::task::spawn_blocking(move || handle.render())
        .await
        .context("metrics render task failed")?;
    let body = Arc::<str>::from(body);
    cache.store(body.clone(), Instant::now());
    Ok(body)
}

async fn write_http_response_parts_with_timeout(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    timeout(METRICS_WRITE_TIMEOUT, stream.write_all(header.as_bytes())).await??;
    timeout(METRICS_WRITE_TIMEOUT, stream.write_all(body.as_bytes())).await??;
    timeout(METRICS_WRITE_TIMEOUT, stream.shutdown()).await??;
    Ok(())
}

async fn write_http_response_with_timeout(
    stream: &mut tokio::net::TcpStream,
    response: &[u8],
) -> Result<()> {
    timeout(METRICS_WRITE_TIMEOUT, stream.write_all(response)).await??;
    timeout(METRICS_WRITE_TIMEOUT, stream.shutdown()).await??;
    Ok(())
}

async fn read_http_request_path(stream: &mut tokio::net::TcpStream) -> Result<Option<String>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        if buf.len().saturating_add(n) > MAX_METRICS_REQUEST_BYTES {
            return Err(anyhow::anyhow!("metrics request header too large"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_header_terminator(&buf) {
            return parse_request_path(&buf[..end]);
        }
    }
}

fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_request_path(raw_headers: &[u8]) -> Result<Option<String>> {
    let request = std::str::from_utf8(raw_headers)
        .map_err(|_| anyhow::anyhow!("metrics request is not valid utf-8"))?;
    let first = request.lines().next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty() || path.is_empty() || version.is_empty() {
        return Err(anyhow::anyhow!("malformed request line"));
    }
    if method != "GET" {
        return Err(anyhow::anyhow!("unsupported method"));
    }
    if !version.starts_with("HTTP/1.") {
        return Err(anyhow::anyhow!("unsupported http version"));
    }
    Ok(Some(path.to_string()))
}
