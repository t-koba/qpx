#![cfg(all(feature = "http3", feature = "tls-rustls"))]

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, Bytes};
use quinn::crypto::rustls::QuicClientConfig;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;

struct QpxdHandle {
    child: Child,
}

impl Drop for QpxdHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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
                r#"reverse:
- name: backend
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
    local_response:
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
            r#"state_dir:
  {front_state_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
- name: passthrough
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

fn temp_dir(prefix: &str) -> Result<PathBuf> {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}.{suffix}"));
    fs::create_dir_all(&dir).with_context(|| format!("create temp dir {}", dir.display()))?;
    Ok(dir)
}

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
    Ok(QpxdHandle { child })
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

fn write_self_signed_cert(dir: &Path, dns_name: &str) -> Result<(PathBuf, PathBuf)> {
    let mut params = rcgen::CertificateParams::new(vec![dns_name.to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns_name);
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let cert_path = dir.join(format!("{dns_name}.crt.pem"));
    let key_path = dir.join(format!("{dns_name}.key.pem"));
    fs::write(&cert_path, cert_pem).context("write cert")?;
    fs::write(&key_path, key_pem).context("write key")?;
    Ok((cert_path, key_path))
}

fn build_quinn_client_endpoint() -> Result<quinn::Endpoint> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    quinn::Endpoint::client(addr)
        .map_err(|err| anyhow!(err))
        .context("bind quinn client endpoint")
}

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
