#![cfg(all(feature = "http3", feature = "tls-rustls"))]

use anyhow::{Context, Result, anyhow};
use bytes::{Buf, Bytes};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::timeout;

mod cert_support;
pub mod common;
mod h3_client_support;
mod yaml_support;

use cert_support::write_self_signed_cert;
use common::{QpxdHandle, pick_free_tcp_port, spawn_qpxd_on_random_port, temp_dir};
use h3_client_support::{build_h3_test_client_config, build_quinn_client_endpoint};
use yaml_support::yaml_quote_path;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_http3_passthrough_smoke() -> Result<()> {
    let backend_dir = temp_dir("qpxd-reverse-h3-backend")?;
    let front_dir = temp_dir("qpxd-reverse-h3-passthrough")?;
    let backend_cfg = backend_dir.join("backend.yaml");
    let front_cfg = front_dir.join("front.yaml");
    let (cert_path, key_path) = write_self_signed_cert(&backend_dir, "reverse.local")?;

    let (backend_port, _backend) =
        spawn_qpxd_on_random_port(&backend_cfg, backend_dir.join("backend.log"), |port| {
            let cert_yaml = yaml_quote_path(&cert_path);
            let key_yaml = yaml_quote_path(&key_path);
            format!(
                r#"edges:
- kind: reverse
  name: backend
  listen: 127.0.0.1:{port}
  tls:
    certificates:
    - sni: reverse.local
      cert: {cert_yaml}
      key: {key_yaml}
  http3:
    enabled: true
  routes:
  - name: h3
    match:
      host:
      - reverse.local
      path:
      - /h3
    target:
      type: local_response
      response:
        status: 200
        body: H3PASS
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
                cert_yaml = cert_yaml,
                key_yaml = key_yaml,
            )
        })?;

    let front_port = pick_free_tcp_port()?;
    let front_log = front_dir.join("front.log");
    let front_state_dir = front_dir.join("state");
    fs::create_dir_all(&front_state_dir)?;
    let front_state_yaml = yaml_quote_path(&front_state_dir);
    fs::write(
        &front_cfg,
        format!(
            r#"state_dir: {front_state_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: passthrough
  listen: 127.0.0.1:{front_port}
  http3:
    enabled: true
    listen: 127.0.0.1:{front_port}
    passthrough_upstreams:
    - 127.0.0.1:{backend_port}
  routes: []"#,
            front_state_yaml = front_state_yaml
        ),
    )?;
    let _front = spawn_qpxd_without_ready_check(&front_cfg, front_log.clone())?;

    let mut last_err: Option<anyhow::Error> = None;
    for _ in 0..50 {
        match request_h3_body(front_port, &cert_path).await {
            Ok(body) => {
                if body == b"H3PASS" {
                    return Ok(());
                }
                return Err(anyhow!("unexpected passthrough body: {:?}", body));
            }
            Err(err) => {
                last_err = Some(err);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("reverse HTTP/3 passthrough never became ready")))
}

async fn request_h3_body(port: u16, ca_cert: &Path) -> Result<Vec<u8>> {
    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(ca_cert)?);
    let conn = timeout(
        Duration::from_secs(3),
        endpoint.connect(SocketAddr::from(([127, 0, 0, 1], port)), "reverse.local")?,
    )
    .await??;

    let mut builder = ::h3::client::builder();
    let (mut h3_conn, mut sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
        .await?;
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    let uri = http::Uri::builder()
        .scheme("https")
        .authority(format!("reverse.local:{port}"))
        .path_and_query("/h3")
        .build()?;
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .body(())?;
    let mut stream = sender.send_request(request).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    if response.status() != http::StatusCode::OK {
        driver.abort();
        let _ = driver.await;
        return Err(anyhow!(
            "expected reverse h3 passthrough status 200, got {}",
            response.status()
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        let mut chunk = chunk;
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    driver.abort();
    let _ = driver.await;
    Ok(body)
}

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
