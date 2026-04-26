mod transparent_support;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use transparent_support::{
    build_proxy_v2_header, send_http1_and_read_head, serve_http1_capture_once,
    spawn_qpxd_on_random_port, temp_dir,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_http_uses_host_fallback_when_original_dst_is_unavailable() -> Result<()> {
    let dir = temp_dir("qpxd-transparent-host-e2e")?;
    let cfg = dir.join("transparent-host.yaml");
    let (backend_addr, backend_capture) = serve_http1_capture_once(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nHOST".to_vec(),
    )
    .await?;

    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("transparent-host.log"), |port| {
            format!(
                r#"listeners:
- name: transparent
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  rules: []
  mode: transparent
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#
            )
        })?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let request =
        format!("GET /host HTTP/1.1\r\nHost: {backend_addr}\r\nConnection: close\r\n\r\n");
    let (status, _, _) = send_http1_and_read_head(proxy_addr, request.as_bytes()).await?;
    assert_eq!(status, 200);
    let captured = timeout(Duration::from_secs(5), backend_capture)
        .await
        .context("timed out waiting for host-fallback upstream request")??;
    let captured = String::from_utf8_lossy(&captured);
    assert!(
        captured.contains("GET /host HTTP/1.1"),
        "unexpected forwarded request:\n{captured}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_http_accepts_proxy_v2_original_destination_metadata() -> Result<()> {
    let dir = temp_dir("qpxd-transparent-proxyv2-e2e")?;
    let cfg = dir.join("transparent-proxyv2.yaml");
    let (backend_addr, backend_capture) = serve_http1_capture_once(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nMETA".to_vec(),
    )
    .await?;

    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("transparent-proxyv2.log"), |port| {
            format!(
                r#"listeners:
- name: transparent
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  rules: []
  xdp:
    enabled: true
    metadata_mode: proxy-v2
    require_metadata: true
    trusted_peers:
    - 127.0.0.1/32
  mode: transparent
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#
            )
        })?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(proxy_addr)).await??;
    let metadata = build_proxy_v2_header("192.0.2.10:41000".parse()?, backend_addr)?;
    stream.write_all(&metadata).await?;
    stream
        .write_all(b"GET /proxyv2 HTTP/1.0\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
    let mut raw = Vec::new();
    timeout(Duration::from_secs(3), stream.read_to_end(&mut raw)).await??;
    let raw = String::from_utf8_lossy(&raw);
    assert!(raw.contains("200 OK"), "unexpected response:\n{raw}");

    let captured = timeout(Duration::from_secs(5), backend_capture)
        .await
        .context("timed out waiting for proxy-v2 upstream request")??;
    let captured = String::from_utf8_lossy(&captured);
    assert!(
        captured.contains("GET /proxyv2 HTTP/1.1"),
        "unexpected forwarded request:\n{captured}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_http_rejects_connect() -> Result<()> {
    let dir = temp_dir("qpxd-transparent-connect-reject")?;
    let cfg = dir.join("transparent-connect.yaml");

    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("transparent-connect.log"), |port| {
            format!(
                r#"listeners:
- name: transparent
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  rules: []
  mode: transparent
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#
            )
        })?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    let (status, headers, _) = send_http1_and_read_head(proxy_addr, request).await?;
    assert_eq!(status, 405);
    assert!(
        !headers.is_empty(),
        "expected a valid HTTP response head for rejected CONNECT"
    );
    Ok(())
}
