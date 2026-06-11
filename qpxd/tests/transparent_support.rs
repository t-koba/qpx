use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

#[path = "common/mod.rs"]
pub mod common;

pub use common::{spawn_qpxd_on_random_port, temp_dir};

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
