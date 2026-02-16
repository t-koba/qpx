use crate::config::{LoggingConfig, MetricsConfig};
use anyhow::{Context, Result};
use cidr::IpCidr;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tracing_subscriber::EnvFilter;

const MAX_METRICS_REQUEST_BYTES: usize = 16 * 1024;
const METRICS_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub fn init_logging(config: &LoggingConfig) -> Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(config.level.clone()));
    if config.format.eq_ignore_ascii_case("json") {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    Ok(())
}

pub fn start_metrics(config: &MetricsConfig) -> Result<()> {
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

    let runtime = tokio::runtime::Handle::try_current()
        .context("metrics endpoint requires running Tokio runtime")?;
    runtime.spawn(async move {
        let listener = match TcpListener::bind(listen).await {
            Ok(listener) => listener,
            Err(err) => {
                tracing::warn!(error = ?err, "failed to bind metrics listener");
                return;
            }
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
                    let _ = timeout(
                        Duration::from_secs(1),
                        stream.write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbusy",
                        ),
                    )
                    .await;
                    let _ = timeout(Duration::from_secs(1), stream.shutdown()).await;
                    continue;
                }
            };
            let handle = handle.clone();
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
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nforbidden",
                        )
                        .await;
                    let _ = stream.shutdown().await;
                    return;
                }

                let request_path = match timeout(METRICS_READ_TIMEOUT, read_http_request_path(&mut stream)).await {
                    Ok(Ok(Some(path))) => path,
                    Ok(Ok(None)) => return,
                    Ok(Err(_)) | Err(_) => {
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbad request",
                            )
                            .await;
                        let _ = stream.shutdown().await;
                        return;
                    }
                };

                let (status, body, content_type) = if request_path == "/health" {
                    ("200 OK", "OK".to_string(), "text/plain; charset=utf-8")
                } else if request_path == path {
                    (
                        "200 OK",
                        handle.render(),
                        "text/plain; version=0.0.4; charset=utf-8",
                    )
                } else {
                    (
                        "404 Not Found",
                        "not found".to_string(),
                        "text/plain; charset=utf-8",
                    )
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
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
