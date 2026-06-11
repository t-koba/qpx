use anyhow::{Context, Result, anyhow};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct QpxdHandle {
    child: Child,
}

impl QpxdHandle {
    pub fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for QpxdHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const PORT_PICK_ATTEMPTS: usize = 256;

pub fn temp_dir(prefix: &str) -> Result<PathBuf> {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time before unix epoch")?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}.{suffix}"));
    fs::create_dir_all(&dir).with_context(|| format!("create temp dir {}", dir.display()))?;
    Ok(dir)
}

pub fn pick_free_tcp_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).context("pick free tcp port")?;
    Ok(listener.local_addr()?.port())
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
    Ok(QpxdHandle::new(child))
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

fn wait_for_qpxd(child: &mut Child, ready_port: u16, log_path: &Path) -> Result<()> {
    let started = Instant::now();
    let addr = SocketAddr::from(([127, 0, 0, 1], ready_port));
    while started.elapsed() < Duration::from_secs(15) {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return Ok(());
        }
        if let Some(status) = child.try_wait().context("qpxd wait")? {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!(
                "qpxd exited early: {status} (log: {}){}",
                log_path.display(),
                log_excerpt(log_path)
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(anyhow!(
        "timed out waiting for qpxd to listen on {addr} (log: {}){}",
        log_path.display(),
        log_excerpt(log_path)
    ))
}

fn log_excerpt(log_path: &Path) -> String {
    let Ok(bytes) = fs::read(log_path) else {
        return String::new();
    };
    if bytes.is_empty() {
        return String::new();
    }
    const MAX_LOG_BYTES: usize = 4096;
    let start = bytes.len().saturating_sub(MAX_LOG_BYTES);
    let text = String::from_utf8_lossy(&bytes[start..]);
    format!("\nqpxd log tail:\n{text}")
}

fn is_retryable_bind_error_text(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("address already in use")
        || message.contains("eaddrinuse")
        || message.contains("permission denied")
        || message.contains("operation not permitted")
        || message.contains("os error 1")
}
