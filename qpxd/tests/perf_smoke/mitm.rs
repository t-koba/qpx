use super::*;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::io::ErrorKind;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const MITM_SERVER_NAME: &str = "mitm.local";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_mitm_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    qpx_core::tls::init_rustls_crypto_provider();
    let dir = temp_dir("qpxd-forward-mitm-perf")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let backend = spawn_tls_backend().await?;
    let cfg = dir.join("forward-mitm-perf.yaml");
    let backend_authority = backend.addr.to_string();
    let state_dir_yaml = serde_json::to_string(state_dir.to_string_lossy().as_ref())?;
    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("forward-mitm-perf.log"), |port| {
            format!(
                r#"state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: forward
  name: forward-mitm
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  tls_inspection:
    enabled: true
    verify_upstream: false
  rules:
  - name: inspect-mitm-local
    match:
      sni:
      - {MITM_SERVER_NAME}
      method:
      - CONNECT
    action:
      type: inspect"#
            )
        })?;
    let ca_cert = state_dir.join("ca.crt");
    wait_for_file(&ca_cert).await?;

    let op: PerfOperation = Arc::new(move || {
        let ca_cert = ca_cert.clone();
        let backend_authority = backend_authority.clone();
        Box::pin(async move { mitm_round_trip(port, &backend_authority, &ca_cert).await })
    });
    let result = measure_parallel_perf(
        "forward_mitm",
        32,
        4,
        PerfThresholds {
            min_req_per_sec: 8.0,
            max_p95: Duration::from_millis(800),
        },
        op,
    )
    .await;
    backend.task.abort();
    result
}

struct TlsBackend {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

async fn spawn_tls_backend() -> Result<TlsBackend> {
    let certified = generate_simple_self_signed(vec![MITM_SERVER_NAME.to_string()])?;
    let cert_der = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let Ok(n) = timeout(Duration::from_secs(3), tls.read(&mut buf)).await else {
                        return;
                    };
                    let Ok(n) = n else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    head.extend_from_slice(&buf[..n]);
                    if head.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                    if head.len() > 8192 {
                        return;
                    }
                }
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nMITM")
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Ok(TlsBackend { addr, task })
}

async fn mitm_round_trip(port: u16, backend_authority: &str, ca_cert: &Path) -> Result<()> {
    let mut stream = timeout(
        Duration::from_secs(3),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    let connect = format!(
        "CONNECT {backend_authority} HTTP/1.1\r\nHost: {backend_authority}\r\nConnection: keep-alive\r\n\r\n"
    );
    stream.write_all(connect.as_bytes()).await?;
    stream.flush().await?;
    let status = read_http1_status(&mut stream).await?;
    if status != 200 {
        return Err(anyhow!("expected CONNECT 200, got {status}"));
    }
    let mut roots = rustls::RootCertStore::empty();
    let certs = qpx_core::tls::load_cert_chain(ca_cert)?;
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!("no qpxd MITM CA loaded"));
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(MITM_SERVER_NAME.to_string()).map_err(|_| anyhow!("bad sni"))?;
    let mut tls = timeout(
        Duration::from_secs(3),
        connector.connect(server_name, stream),
    )
    .await??;
    tls.write_all(
        format!("GET /mitm HTTP/1.1\r\nHost: {MITM_SERVER_NAME}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await?;
    tls.flush().await?;
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match timeout(Duration::from_secs(3), tls.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => response.extend_from_slice(&buf[..n]),
            Ok(Err(err)) if err.kind() == ErrorKind::UnexpectedEof => break,
            Ok(Err(err)) => return Err(err.into()),
            Err(err) => return Err(err.into()),
        }
    }
    if !response.ends_with(b"\r\n\r\nMITM") && !response.ends_with(b"MITM") {
        return Err(anyhow!("unexpected MITM response"));
    }
    Ok(())
}

async fn wait_for_file(path: &Path) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if path.is_file() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(anyhow!("timed out waiting for {}", path.display()))
}

async fn read_http1_status(stream: &mut TcpStream) -> Result<u16> {
    let mut head = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
        if n == 0 {
            return Err(anyhow!("connection closed before CONNECT response"));
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if head.len() > 8192 {
            return Err(anyhow!("CONNECT response head too large"));
        }
    }
    let text = std::str::from_utf8(&head)?;
    let status = text
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("missing CONNECT status"))?
        .parse::<u16>()?;
    Ok(status)
}
