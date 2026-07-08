#[cfg(all(feature = "http3", feature = "tls-rustls"))]
#[path = "../cert_support/mod.rs"]
mod cert_support;
#[path = "../common/mod.rs"]
pub mod common;
#[path = "../empty_body_support/mod.rs"]
mod empty_body_support;
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
#[path = "../h3_client_support/mod.rs"]
mod h3_client_support;
#[path = "../http2_client_support/mod.rs"]
mod http2_client_support;
#[path = "../test_client_support/mod.rs"]
mod test_client_support;
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
#[path = "../yaml_support/mod.rs"]
mod yaml_support;

use anyhow::{Context, Result, anyhow};
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
use bytes::Buf;
use bytes::Bytes;
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
use cert_support::write_self_signed_cert;
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
use common::pick_free_tcp_port;
use common::temp_dir;
use empty_body_support::empty_body;
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
use h3_client_support::{build_h3_test_client_config, build_quinn_client_endpoint};
use http_body_util::{BodyExt as _, Full};
use http2_client_support::handshake_http2;
use hyper::Method;
use hyper::Request;
use hyper::StatusCode;
use std::fs;
use std::future::Future;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};
use test_client_support::test_client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
use yaml_support::yaml_quote_path;

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
const PERF_TLS_SERVER_NAME: &str = "reverse.local";

type PerfOperation =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

struct QpxdHandle {
    inner: common::QpxdHandle,
}

impl QpxdHandle {
    fn new(inner: common::QpxdHandle) -> Self {
        live_qpxd_pids()
            .lock()
            .expect("qpxd pid lock")
            .push(inner.child.id());
        Self { inner }
    }
}

impl Drop for QpxdHandle {
    fn drop(&mut self) {
        live_qpxd_pids()
            .lock()
            .expect("qpxd pid lock")
            .retain(|pid| *pid != self.inner.child.id());
    }
}

fn spawn_qpxd_on_random_port(
    config_path: &Path,
    log_path: PathBuf,
    make_config: impl Fn(u16) -> String,
) -> Result<(u16, QpxdHandle)> {
    let (port, handle) = common::spawn_qpxd_on_random_port(config_path, log_path, make_config)?;
    Ok((port, QpxdHandle::new(handle)))
}

fn live_qpxd_pids() -> &'static StdMutex<Vec<u32>> {
    static PIDS: OnceLock<StdMutex<Vec<u32>>> = OnceLock::new();
    PIDS.get_or_init(|| StdMutex::new(Vec::new()))
}

#[derive(Clone, Copy)]
struct PerfThresholds {
    min_req_per_sec: f64,
    max_p95: Duration,
}

mod dispatch_rules;
mod grpc;
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
mod h3_bulk;
mod http;
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
mod http3;
#[cfg(unix)]
mod ipc_executor;
#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
mod mitm;

async fn measure_parallel_perf(
    label: &str,
    total_requests: usize,
    concurrency: usize,
    thresholds: PerfThresholds,
    op: PerfOperation,
) -> Result<()> {
    let total_requests = profile_total_requests(total_requests);
    let concurrency = profile_concurrency(concurrency, total_requests);
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
    let p50 = latencies[((latencies.len() as f64) * 0.50).ceil() as usize - 1];
    let p99 = latencies[((latencies.len() as f64) * 0.99).ceil() as usize - 1];
    let req_per_sec = total_requests as f64 / elapsed.as_secs_f64();

    eprintln!(
        "perf_smoke[{label}] total={} elapsed_ms={} req_per_sec={:.1} p95_ms={}",
        total_requests,
        elapsed.as_millis(),
        req_per_sec,
        p95.as_millis()
    );
    write_perf_artifact(label, total_requests, elapsed, req_per_sec, p50, p95, p99)?;

    if perf_profile_mode() {
        return Ok(());
    }

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

fn write_perf_artifact(
    label: &str,
    total_requests: usize,
    elapsed: Duration,
    req_per_sec: f64,
    p50: Duration,
    p95: Duration,
    p99: Duration,
) -> Result<()> {
    let Some(path) = std::env::var_os("QPX_PERF_SMOKE_JSON") else {
        return Ok(());
    };
    let _guard = perf_artifact_lock().lock().expect("perf artifact lock");
    let path = PathBuf::from(path);
    let (rss_peak_mb, cpu_ms) = resource_snapshot();
    let record = serde_json::json!({
        "bench": canonical_perf_bench_label(label),
        "legacy_bench": label,
        "first_byte_ms": serde_json::Value::Null,
        "p95_chunk_gap_ms": serde_json::Value::Null,
        "total_ms": elapsed.as_secs_f64() * 1000.0,
        "rss_peak_mb": rss_peak_mb,
        "cpu_ms": cpu_ms,
        "bytes": serde_json::Value::Null,
        "commit": perf_commit(),
        "total_requests": total_requests,
        "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        "req_per_sec": req_per_sec,
        "p50_ms": p50.as_secs_f64() * 1000.0,
        "p95_ms": p95.as_secs_f64() * 1000.0,
        "p99_ms": p99.as_secs_f64() * 1000.0,
        "profile_mode": perf_profile_mode(),
    });
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create perf artifact dir {}", parent.display()))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open perf artifact {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(&record)?).context("write perf artifact")?;
    Ok(())
}

#[cfg(unix)]
fn resource_snapshot() -> (serde_json::Value, serde_json::Value) {
    // SAFETY: getrusage initializes the provided rusage structs and does not retain the pointers.
    unsafe {
        let mut self_usage: libc::rusage = std::mem::zeroed();
        let mut child_usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut self_usage) != 0
            || libc::getrusage(libc::RUSAGE_CHILDREN, &mut child_usage) != 0
        {
            return (serde_json::Value::Null, serde_json::Value::Null);
        }
        let (live_qpxd_rss_peak_mb, live_qpxd_cpu_ms) = live_qpxd_resource_snapshot();
        let cpu_ms = timeval_ms(self_usage.ru_utime)
            + timeval_ms(self_usage.ru_stime)
            + timeval_ms(child_usage.ru_utime)
            + timeval_ms(child_usage.ru_stime)
            + live_qpxd_cpu_ms;
        let rss_peak_mb = maxrss_to_mb(self_usage.ru_maxrss.max(child_usage.ru_maxrss))
            .max(live_qpxd_rss_peak_mb);
        (serde_json::json!(rss_peak_mb), serde_json::json!(cpu_ms))
    }
}

#[cfg(not(unix))]
fn resource_snapshot() -> (serde_json::Value, serde_json::Value) {
    (serde_json::Value::Null, serde_json::Value::Null)
}

#[cfg(unix)]
fn timeval_ms(value: libc::timeval) -> f64 {
    value.tv_sec as f64 * 1000.0 + value.tv_usec as f64 / 1000.0
}

#[cfg(all(unix, target_os = "linux"))]
fn maxrss_to_mb(value: libc::c_long) -> f64 {
    value as f64 / 1024.0
}

#[cfg(all(unix, not(target_os = "linux")))]
fn maxrss_to_mb(value: libc::c_long) -> f64 {
    value as f64 / 1024.0 / 1024.0
}

#[cfg(all(unix, target_os = "linux"))]
fn live_qpxd_resource_snapshot() -> (f64, f64) {
    // SAFETY: sysconf reads a process-global constant and does not dereference pointers.
    let clock_ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if clock_ticks <= 0 {
        return (0.0, 0.0);
    }
    let mut rss_peak_kb = 0.0_f64;
    let mut cpu_ms = 0.0_f64;
    let pids = live_qpxd_pids().lock().expect("qpxd pid lock").clone();
    for pid in pids {
        rss_peak_kb += linux_status_kb(pid, "VmHWM");
        cpu_ms += linux_cpu_ticks(pid) * 1000.0 / clock_ticks as f64;
    }
    (rss_peak_kb / 1024.0, cpu_ms)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn live_qpxd_resource_snapshot() -> (f64, f64) {
    (0.0, 0.0)
}

#[cfg(all(unix, target_os = "linux"))]
fn linux_status_kb(pid: u32, key: &str) -> f64 {
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return 0.0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}:")) {
            return rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<f64>().ok())
                .unwrap_or(0.0);
        }
    }
    0.0
}

#[cfg(all(unix, target_os = "linux"))]
fn linux_cpu_ticks(pid: u32) -> f64 {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0.0;
    };
    let Some((_, rest)) = stat.split_once(") ") else {
        return 0.0;
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let utime = fields
        .get(11)
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(0.0);
    let stime = fields
        .get(12)
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(0.0);
    utime + stime
}

fn perf_profile_mode() -> bool {
    std::env::var("QPX_PERF_PROFILE").is_ok_and(|value| value == "1" || value == "true")
}

fn profile_total_requests(total_requests: usize) -> usize {
    if !perf_profile_mode() {
        return total_requests;
    }
    let limit = std::env::var("QPX_PERF_PROFILE_REQUESTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(32);
    total_requests.min(limit).max(1)
}

fn profile_concurrency(concurrency: usize, total_requests: usize) -> usize {
    if !perf_profile_mode() {
        return concurrency;
    }
    let limit = std::env::var("QPX_PERF_PROFILE_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(4);
    concurrency.min(limit).min(total_requests).max(1)
}

fn profile_timeout(duration: Duration) -> Duration {
    if !perf_profile_mode() {
        return duration;
    }
    let multiplier = std::env::var("QPX_PERF_PROFILE_TIMEOUT_MULTIPLIER")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(50);
    duration.saturating_mul(multiplier)
}

fn perf_artifact_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

fn canonical_perf_bench_label(label: &str) -> &str {
    match label {
        "reverse_upstream_http1" | "reverse_local_response" => "reverse_http1_plain_small",
        "grpc_unary" => "reverse_http2_plain_small",
        "reverse_http3_terminate" => {
            #[cfg(feature = "http3-backend-qpx")]
            {
                "h3_qpx_backend_unary_1kb"
            }
            #[cfg(all(not(feature = "http3-backend-qpx"), feature = "http3-backend-h3"))]
            {
                "h3_h3_backend_unary_1kb"
            }
            #[cfg(not(any(feature = "http3-backend-qpx", feature = "http3-backend-h3")))]
            {
                "h3_h3_backend_unary_1kb"
            }
        }
        "reverse_h3_bulk" => {
            #[cfg(feature = "http3-backend-qpx")]
            {
                "h3_qpx_backend_stream_100mb"
            }
            #[cfg(all(not(feature = "http3-backend-qpx"), feature = "http3-backend-h3"))]
            {
                "h3_h3_backend_stream_100mb"
            }
            #[cfg(not(any(feature = "http3-backend-qpx", feature = "http3-backend-h3")))]
            {
                "h3_h3_backend_stream_100mb"
            }
        }
        "grpc_streaming" => "grpc_server_stream_10000_messages",
        "forward_connect" => "connect_streaming_messages",
        other => other,
    }
}

fn perf_commit() -> String {
    if let Ok(value) = std::env::var("GITHUB_SHA")
        && !value.trim().is_empty()
    {
        return value;
    }
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
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

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
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
    Ok(QpxdHandle::new(common::QpxdHandle::new(child)))
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
        let n = timeout(
            profile_timeout(Duration::from_secs(3)),
            stream.read(&mut buf),
        )
        .await??;
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
