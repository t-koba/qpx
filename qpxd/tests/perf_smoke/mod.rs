#[path = "../common/mod.rs"]
pub mod common;
#[path = "../empty_body_support/mod.rs"]
mod empty_body_support;
#[path = "../http2_client_support/mod.rs"]
mod http2_client_support;
#[path = "../test_client_support/mod.rs"]
mod test_client_support;

use anyhow::{Context, Result, anyhow};
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
use bytes::Buf;
use bytes::Bytes;
use common::QpxdHandle;
use empty_body_support::empty_body;
use http_body_util::{BodyExt as _, Full};
use http2_client_support::handshake_http2;
use hyper::Method;
use hyper::Request;
use hyper::StatusCode;
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
use quinn::crypto::rustls::QuicClientConfig;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use test_client_support::test_client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
const PERF_TLS_SERVER_NAME: &str = "reverse.local";

type PerfOperation =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

#[derive(Clone, Copy)]
struct PerfThresholds {
    min_req_per_sec: f64,
    max_p95: Duration,
}

mod grpc;
mod http;
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
mod http3;

async fn measure_parallel_perf(
    label: &str,
    total_requests: usize,
    concurrency: usize,
    thresholds: PerfThresholds,
    op: PerfOperation,
) -> Result<()> {
    let latencies = Arc::new(Mutex::new(Vec::with_capacity(total_requests)));
    let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let latencies = latencies.clone();
        let next = next.clone();
        let op = op.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let idx = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if idx >= total_requests {
                    break;
                }
                let req_started = Instant::now();
                (op)().await?;
                latencies.lock().await.push(req_started.elapsed());
            }
            Ok::<_, anyhow::Error>(())
        }));
    }

    for task in tasks {
        task.await.expect("join")?;
    }

    let latencies = latencies.lock().await.clone();
    report_perf(
        label,
        total_requests,
        started.elapsed(),
        latencies,
        thresholds,
    )
}

fn report_perf(
    label: &str,
    total_requests: usize,
    elapsed: Duration,
    mut latencies: Vec<Duration>,
    thresholds: PerfThresholds,
) -> Result<()> {
    if latencies.is_empty() {
        return Err(anyhow!("no perf samples recorded for {label}"));
    }
    latencies.sort_unstable();
    let p95_index = ((latencies.len() as f64) * 0.95).ceil() as usize - 1;
    let p95 = latencies[p95_index];
    let req_per_sec = total_requests as f64 / elapsed.as_secs_f64();

    eprintln!(
        "perf_smoke[{label}] total={} elapsed_ms={} req_per_sec={:.1} p95_ms={}",
        total_requests,
        elapsed.as_millis(),
        req_per_sec,
        p95.as_millis()
    );

    assert!(
        req_per_sec >= thresholds.min_req_per_sec,
        "throughput regression on {label}: req_per_sec={req_per_sec:.1} (< {})",
        thresholds.min_req_per_sec
    );
    assert!(
        p95 <= thresholds.max_p95,
        "tail-latency regression on {label}: p95={}ms (> {}ms)",
        p95.as_millis(),
        thresholds.max_p95.as_millis()
    );
    Ok(())
}

fn full_body(
    bytes: Bytes,
) -> http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible> {
    Full::new(bytes).boxed()
}

fn frame_grpc_message(bytes: Bytes) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + bytes.len());
    out.push(0);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&bytes);
    out
}

fn temp_dir(prefix: &str) -> Result<PathBuf> {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}.{suffix}"));
    fs::create_dir_all(&dir).with_context(|| format!("create temp dir {}", dir.display()))?;
    Ok(dir)
}

fn pick_free_tcp_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).context("pick free tcp port")?;
    Ok(listener.local_addr()?.port())
}

fn spawn_qpxd(config_path: &Path, ready_port: u16, log_path: PathBuf) -> Result<QpxdHandle> {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_qpxd"));
    let log = fs::File::create(&log_path).context("create qpxd log")?;
    let log_err = log.try_clone().context("clone qpxd log")?;

    let mut cmd = Command::new(bin);
    cmd.arg("run")
        .arg("--config")
        .arg(config_path)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    let mut child = cmd.spawn().context("spawn qpxd")?;
    wait_for_qpxd(&mut child, ready_port, &log_path)?;
    Ok(QpxdHandle::new(child))
}

fn wait_for_qpxd(child: &mut Child, ready_port: u16, log_path: &Path) -> Result<()> {
    let started = Instant::now();
    let addr: SocketAddr = format!("127.0.0.1:{ready_port}").parse()?;
    while started.elapsed() < Duration::from_secs(15) {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return Ok(());
        }
        if let Some(status) = child.try_wait().context("qpxd wait")? {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!(
                "qpxd exited early: {status} (log: {})",
                log_path.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(anyhow!(
        "timed out waiting for qpxd to listen on {} (log: {})",
        addr,
        log_path.display()
    ))
}

fn is_retryable_bind_error_text(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("address already in use")
        || message.contains("eaddrinuse")
        || message.contains("permission denied")
        || message.contains("operation not permitted")
        || message.contains("os error 1")
}

fn spawn_qpxd_on_random_port(
    config_path: &Path,
    log_path: PathBuf,
    make_config: impl Fn(u16) -> String,
) -> Result<(u16, QpxdHandle)> {
    let mut last_err: Option<anyhow::Error> = None;
    for _ in 0..256 {
        let port = pick_free_tcp_port()?;
        fs::write(config_path, make_config(port)).context("write qpxd config")?;
        match spawn_qpxd(config_path, port, log_path.clone()) {
            Ok(handle) => return Ok((port, handle)),
            Err(err) => {
                let log_retryable = fs::read_to_string(&log_path)
                    .ok()
                    .map(|value| is_retryable_bind_error_text(&value))
                    .unwrap_or(false);
                let err_retryable = is_retryable_bind_error_text(&err.to_string());
                if log_retryable || err_retryable {
                    last_err = Some(err);
                    continue;
                }
                return Err(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("failed to start qpxd after retrying ports")))
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
fn spawn_qpxd_without_ready_check(config_path: &Path, log_path: PathBuf) -> Result<QpxdHandle> {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_qpxd"));
    let log = fs::File::create(&log_path).context("create qpxd log")?;
    let log_err = log.try_clone().context("clone qpxd log")?;

    let mut cmd = Command::new(bin);
    cmd.arg("run")
        .arg("--config")
        .arg(config_path)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    let mut child = cmd.spawn().context("spawn qpxd")?;
    std::thread::sleep(Duration::from_millis(200));
    if child.try_wait()?.is_some() {
        return Err(anyhow!(
            "qpxd exited early while starting UDP/QUIC-only config (log: {})",
            log_path.display()
        ));
    }
    Ok(QpxdHandle::new(child))
}

async fn serve_tcp_echo_loop() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = stream.flush().await;
                }
            });
        }
    });
    Ok(addr)
}

async fn read_http1_status(stream: &mut TcpStream) -> Result<u16> {
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
        if n == 0 {
            return Err(anyhow!("connection closed before HTTP/1 response head"));
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if head.len() > 128 * 1024 {
            return Err(anyhow!("HTTP/1 response head exceeded 128 KiB"));
        }
    }
    let raw = String::from_utf8(head)?;
    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| anyhow!("missing HTTP/1 status line"))?;
    Ok(status.parse::<u16>()?)
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
fn yaml_quote_path(path: &Path) -> String {
    let mut out = String::with_capacity(path.as_os_str().len() + 2);
    out.push('\'');
    for ch in path.to_string_lossy().chars() {
        if ch == '\'' {
            out.push_str("''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
fn write_self_signed_cert(dir: &Path, dns_name: &str) -> Result<(PathBuf, PathBuf)> {
    let mut params = rcgen::CertificateParams::new(vec![dns_name.to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns_name);
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_path = dir.join(format!("{dns_name}.crt.pem"));
    let key_path = dir.join(format!("{dns_name}.key.pem"));
    fs::write(&cert_path, cert.pem()).context("write cert")?;
    fs::write(&key_path, key_pair.serialize_pem()).context("write key")?;
    Ok((cert_path, key_path))
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
fn build_quinn_client_endpoint() -> Result<quinn::Endpoint> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    quinn::Endpoint::client(addr)
        .map_err(|err| anyhow!(err))
        .context("bind quinn client endpoint")
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
fn build_h3_test_client_config(ca_cert_pem: &Path) -> Result<quinn::ClientConfig> {
    let mut roots = quinn::rustls::RootCertStore::empty();
    let certs = qpx_core::tls::load_cert_chain(ca_cert_pem)?;
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!("no certs loaded from {}", ca_cert_pem.display()));
    }

    let provider = quinn::rustls::crypto::ring::default_provider();
    let mut tls = quinn::rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|_| anyhow!("failed to configure h3 client tls versions"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto =
        QuicClientConfig::try_from(tls).map_err(|_| anyhow!("failed to build h3 client crypto"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
}

fn build_test_client_hello() -> Vec<u8> {
    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u24(out: &mut Vec<u8>, value: usize) {
        out.push(((value >> 16) & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push((value & 0xff) as u8);
    }

    fn push_extension(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
        push_u16(out, ty);
        push_u16(out, data.len() as u16);
        out.extend_from_slice(data);
    }

    let mut body = Vec::new();
    push_u16(&mut body, 0x0303);
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);

    let cipher_suites = [0x13u8, 0x01, 0x13, 0x02, 0x13, 0x03];
    push_u16(&mut body, cipher_suites.len() as u16);
    body.extend_from_slice(&cipher_suites);

    body.push(1);
    body.push(0);

    let mut extensions = Vec::new();

    let sni = b"example.com";
    let mut sni_ext = Vec::new();
    push_u16(&mut sni_ext, (sni.len() + 3) as u16);
    sni_ext.push(0);
    push_u16(&mut sni_ext, sni.len() as u16);
    sni_ext.extend_from_slice(sni);
    push_extension(&mut extensions, 0, &sni_ext);

    let groups = [0x00u8, 0x04, 0x00, 0x1d, 0x00, 0x17];
    push_extension(&mut extensions, 10, &groups);

    let ec_point_formats = [1u8, 0];
    push_extension(&mut extensions, 11, &ec_point_formats);

    let alpn = b"h2";
    let mut alpn_ext = Vec::new();
    push_u16(&mut alpn_ext, (alpn.len() + 1) as u16);
    alpn_ext.push(alpn.len() as u8);
    alpn_ext.extend_from_slice(alpn);
    push_extension(&mut extensions, 16, &alpn_ext);

    let supported_versions = [4u8, 0x03, 0x04, 0x03, 0x03];
    push_extension(&mut extensions, 43, &supported_versions);

    push_u16(&mut body, extensions.len() as u16);
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(1);
    push_u24(&mut handshake, body.len());
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(22);
    push_u16(&mut record, 0x0301);
    push_u16(&mut record, handshake.len() as u16);
    record.extend_from_slice(&handshake);
    record
}
