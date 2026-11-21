use super::*;

#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
use rcgen::generate_simple_self_signed;
#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
use std::fs;
#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
use std::io::ErrorKind;
#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
use std::path::Path;
#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
use std::sync::Arc;
#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
use tokio::net::TcpListener;
#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
const MITM_SERVER_NAME: &str = "mitm.local";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
pub(super) async fn forward_connect_tunnels_bytes() -> Result<()> {
    let dir = temp_dir("qpxd-forward-connect-e2e")?;
    let cfg = dir.join("forward-connect.yaml");
    let (echo_addr, captured) = serve_tcp_echo_once().await?;

    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("forward-connect.log"), |port| {
        format!(
            r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  rules: []
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#
        )
    })?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(proxy_addr)).await??;
    let authority = echo_addr.to_string();
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let (status, _, _) = read_http1_head(&mut stream).await?;
    assert_eq!(status, 200);

    stream.write_all(b"ping").await?;
    stream.flush().await?;
    let mut pong = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut pong)).await??;
    assert_eq!(&pong, b"pong");

    let echoed = timeout(Duration::from_secs(5), captured)
        .await
        .context("timed out waiting for echo capture")??;
    assert_eq!(echoed, b"ping");
    Ok(())
}

#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_connect_mitm_negotiates_http1() -> Result<()> {
    qpx_core::tls::init_rustls_crypto_provider().expect("crypto provider");
    let dir = temp_dir("qpxd-forward-connect-mitm-alpn")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let origin = spawn_mitm_origin().await?;
    let cfg = dir.join("forward-connect-mitm.yaml");
    let origin_authority = origin.addr.to_string();
    let state_dir_yaml = serde_json::to_string(state_dir.to_string_lossy().as_ref())?;
    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("forward-connect-mitm.log"), |port| {
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
    wait_for_ca(&ca_cert).await?;
    let mut stream = timeout(
        Duration::from_secs(3),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    let connect = format!(
        "CONNECT {origin_authority} HTTP/1.1\r\nHost: {origin_authority}\r\nConnection: keep-alive\r\n\r\n"
    );
    stream.write_all(connect.as_bytes()).await?;
    stream.flush().await?;
    let (status, _, _) = read_http1_head(&mut stream).await?;
    assert_eq!(status, 200, "CONNECT was not established");

    let mut roots = rustls::RootCertStore::empty();
    let certs = qpx_core::tls::load_cert_chain(&ca_cert)?;
    let (added, _) = roots.add_parsable_certificates(certs);
    assert!(added > 0, "no qpxd MITM CA loaded");
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Offer h2 first: the MITM listener selects it, but the inspected inner
    // connection is served as HTTP/1.1.
    client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(MITM_SERVER_NAME.to_string())
        .map_err(|_| anyhow::anyhow!("bad sni"))?;
    let mut tls = timeout(
        Duration::from_secs(5),
        connector.connect(server_name, stream),
    )
    .await??;
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );

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
        if let Ok((_, _, body)) = common::parse_http1_head(&response)
            && !body.is_empty()
        {
            break;
        }
    }
    let (status, _, body) = common::parse_http1_head(&response)?;
    assert_eq!(
        status,
        200,
        "unexpected MITM response: {}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(body, b"MITM");
    origin.task.abort();
    Ok(())
}

#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
struct MitmOrigin {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
async fn spawn_mitm_origin() -> Result<MitmOrigin> {
    let certified = generate_simple_self_signed(vec![MITM_SERVER_NAME.to_string()])?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)?;
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
                    let Ok(Ok(n)) = timeout(Duration::from_secs(3), tls.read(&mut buf)).await
                    else {
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
    Ok(MitmOrigin { addr, task })
}

#[cfg(all(feature = "tls-rustls", feature = "mitm"))]
async fn wait_for_ca(ca_cert: &Path) -> Result<()> {
    let started = tokio::time::Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        if ca_cert.is_file() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(anyhow::anyhow!(
        "timed out waiting for {}",
        ca_cert.display()
    ))
}
