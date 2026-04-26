use anyhow::{anyhow, Context, Result};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

pub struct QpxdHandle {
    child: Child,
}

impl Drop for QpxdHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn temp_dir(prefix: &str) -> Result<PathBuf> {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}.{suffix}"));
    fs::create_dir_all(&dir).with_context(|| format!("create temp dir {}", dir.display()))?;
    Ok(dir)
}

const PORT_PICK_ATTEMPTS: usize = 256;

pub fn pick_free_tcp_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).context("pick free tcp port")?;
    Ok(listener.local_addr()?.port())
}

fn is_retryable_bind_error_text(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("address already in use")
        || message.contains("eaddrinuse")
        || message.contains("permission denied")
        || message.contains("operation not permitted")
        || message.contains("os error 1")
}

pub fn spawn_qpxd(config_path: &Path, ready_port: u16, log_path: PathBuf) -> Result<QpxdHandle> {
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
    Ok(QpxdHandle { child })
}

fn wait_for_qpxd(child: &mut Child, ready_port: u16, log_path: &Path) -> Result<()> {
    let started = Instant::now();
    let addr: SocketAddr = format!("127.0.0.1:{ready_port}").parse()?;
    while started.elapsed() < Duration::from_secs(5) {
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
        "timed out waiting for qpxd to listen on {addr} (log: {})",
        log_path.display()
    ))
}

pub fn spawn_qpxd_on_random_port(
    config_path: &Path,
    log_path: PathBuf,
    make_config: impl Fn(u16) -> String,
) -> Result<(u16, QpxdHandle)> {
    let mut last_err: Option<anyhow::Error> = None;
    for _ in 0..PORT_PICK_ATTEMPTS {
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
    Err(last_err.unwrap_or_else(|| {
        anyhow!(
            "failed to start qpxd after {} port attempts",
            PORT_PICK_ATTEMPTS
        )
    }))
}

pub type Http1Head = (u16, Vec<(String, String)>, Vec<u8>);

pub async fn send_http1_and_read_head(addr: SocketAddr, request_bytes: &[u8]) -> Result<Http1Head> {
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .context("connect timed out")??;
    stream.write_all(request_bytes).await?;
    stream.flush().await?;
    read_http1_head(&mut stream).await
}

pub async fn read_http1_head(stream: &mut TcpStream) -> Result<Http1Head> {
    let buf = read_until(stream, b"\r\n\r\n", 128 * 1024, Duration::from_secs(3)).await?;
    parse_http1_head(&buf)
}

async fn read_until(
    stream: &mut TcpStream,
    delim: &[u8],
    max_bytes: usize,
    timeout_dur: Duration,
) -> Result<Vec<u8>> {
    let started = Instant::now();
    let mut out = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        if out.windows(delim.len()).any(|window| window == delim) {
            break;
        }
        if out.len() > max_bytes {
            return Err(anyhow!("read_until exceeded max_bytes={max_bytes}"));
        }
        if started.elapsed() > timeout_dur {
            return Err(anyhow!("read_until timed out"));
        }
        let n = match timeout(Duration::from_millis(200), stream.read(&mut tmp)).await {
            Ok(read) => read?,
            Err(_) => continue,
        };
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    Ok(out)
}

fn parse_http1_head(buf: &[u8]) -> Result<Http1Head> {
    let text = String::from_utf8_lossy(buf);
    let Some(index) = text.find("\r\n\r\n") else {
        return Err(anyhow!("missing header delimiter"));
    };
    let (head, rest) = buf.split_at(index + 4);
    let head_text = String::from_utf8_lossy(head);
    let mut lines = head_text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("invalid status line: {status_line:?}"))?
        .parse::<u16>()
        .context("parse status code")?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Ok((code, headers, rest.to_vec()))
}

pub async fn serve_http1_capture_once(
    response_bytes: Vec<u8>,
) -> Result<(SocketAddr, oneshot::Receiver<Vec<u8>>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("bind tcp")?;
    let addr = listener.local_addr()?;
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = run_http1_capture_once(listener, response_bytes, tx).await;
    });
    Ok((addr, rx))
}

async fn run_http1_capture_once(
    listener: TcpListener,
    response_bytes: Vec<u8>,
    tx: oneshot::Sender<Vec<u8>>,
) -> Result<()> {
    let (mut stream, _) = listener.accept().await?;
    let req = read_until(&mut stream, b"\r\n\r\n", 128 * 1024, Duration::from_secs(3)).await?;
    let _ = tx.send(req);
    stream.write_all(&response_bytes).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

pub fn build_proxy_v2_header(src: SocketAddr, dst: SocketAddr) -> Result<Vec<u8>> {
    const SIGNATURE: [u8; 12] = [
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
    ];
    match (src, dst) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            let mut out = Vec::with_capacity(28);
            out.extend_from_slice(&SIGNATURE);
            out.push(0x21);
            out.push(0x11);
            out.extend_from_slice(&(12u16).to_be_bytes());
            out.extend_from_slice(&src.ip().octets());
            out.extend_from_slice(&dst.ip().octets());
            out.extend_from_slice(&src.port().to_be_bytes());
            out.extend_from_slice(&dst.port().to_be_bytes());
            Ok(out)
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            let mut out = Vec::with_capacity(52);
            out.extend_from_slice(&SIGNATURE);
            out.push(0x21);
            out.push(0x21);
            out.extend_from_slice(&(36u16).to_be_bytes());
            out.extend_from_slice(&src.ip().octets());
            out.extend_from_slice(&dst.ip().octets());
            out.extend_from_slice(&src.port().to_be_bytes());
            out.extend_from_slice(&dst.port().to_be_bytes());
            Ok(out)
        }
        _ => Err(anyhow!(
            "proxy-v2 source/destination address families must match"
        )),
    }
}
