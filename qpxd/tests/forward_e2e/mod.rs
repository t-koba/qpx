#[path = "../forward_common/mod.rs"]
mod common;
#[path = "../common/mod.rs"]
pub mod handle_common;

#[cfg(any(
    feature = "auth-basic",
    feature = "auth-digest",
    all(feature = "http3", feature = "tls-rustls", feature = "mitm")
))]
use anyhow::anyhow;
use anyhow::{Context, Result};
#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
use async_trait::async_trait;
#[cfg(feature = "auth-basic")]
use base64::Engine;
#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
use bytes::Bytes;
#[cfg(any(
    feature = "auth-basic",
    all(feature = "http3", feature = "tls-rustls", feature = "mitm")
))]
use common::yaml_quote_path;
#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
use common::{build_h3_test_client_config, build_quinn_client_endpoint};
#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
use common::{pick_free_tcp_port, spawn_qpxd};
use common::{read_http1_head, serve_tcp_echo_once, spawn_qpxd_on_random_port, temp_dir};
#[cfg(feature = "auth-basic")]
use common::{send_http1_and_read_head, serve_http1_capture_once};
#[cfg(feature = "auth-digest")]
use sha2::{Digest, Sha256};
#[cfg(any(
    feature = "auth-basic",
    all(feature = "http3", feature = "tls-rustls", feature = "mitm")
))]
use std::fs;
use std::net::SocketAddr;
#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
use std::path::Path;
#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
use tokio::task::JoinHandle;
use tokio::time::timeout;

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
use rcgen::generate_simple_self_signed;

#[cfg(feature = "auth-basic")]
mod auth;
mod connect;
#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
mod h3;
#[cfg(feature = "auth-basic")]
fn header_values(headers: &[(String, String)], name: &str) -> Vec<String> {
    let name = name.to_ascii_lowercase();
    headers
        .iter()
        .filter(|(key, _)| key == &name)
        .map(|(_, value)| value.clone())
        .collect()
}

#[cfg(feature = "auth-digest")]
fn build_digest_proxy_authorization(
    challenge: &str,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
) -> Result<String> {
    let params = parse_digest_challenge(challenge);
    let realm = params
        .get("realm")
        .ok_or_else(|| anyhow!("digest challenge missing realm"))?;
    let nonce = params
        .get("nonce")
        .ok_or_else(|| anyhow!("digest challenge missing nonce"))?;
    let opaque = params
        .get("opaque")
        .ok_or_else(|| anyhow!("digest challenge missing opaque"))?;
    let algorithm = params
        .get("algorithm")
        .map(String::as_str)
        .unwrap_or("SHA-256");
    let cnonce = "abcdef0123456789";
    let nc = "00000001";
    let qop = "auth";
    let ha1 = sha256_hex(format!("{username}:{realm}:{password}").as_bytes());
    let ha2 = sha256_hex(format!("{method}:{uri}").as_bytes());
    let response = sha256_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}").as_bytes());
    Ok(format!(
        "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\", algorithm={algorithm}, qop={qop}, nc={nc}, cnonce=\"{cnonce}\", opaque=\"{opaque}\""
    ))
}

#[cfg(feature = "auth-digest")]
fn parse_digest_challenge(input: &str) -> std::collections::HashMap<String, String> {
    let payload = input
        .strip_prefix("Digest ")
        .or_else(|| input.strip_prefix("Digest"))
        .unwrap_or(input)
        .trim();
    let mut out = std::collections::HashMap::new();
    for part in payload.split(',') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        out.insert(
            name.trim().to_ascii_lowercase(),
            value.trim().trim_matches('"').to_string(),
        );
    }
    out
}

#[cfg(feature = "auth-digest")]
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
async fn wait_for_file(path: &Path) -> Result<()> {
    let started = tokio::time::Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if path.is_file() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(anyhow!("timed out waiting for {}", path.display()))
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
#[derive(Clone, Default)]
struct QpxH3ExtendedEchoHandler;

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
#[async_trait]
impl qpx_h3::RequestHandler for QpxH3ExtendedEchoHandler {
    fn settings(&self) -> qpx_h3::Settings {
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            read_timeout: Duration::from_secs(5),
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        _request: qpx_h3::Request,
        _conn: qpx_h3::ConnectionInfo,
        _stream: qpx_h3::RequestStream,
    ) -> std::result::Result<(), qpx_h3::H3Error> {
        Err(anyhow!("unexpected buffered request").into())
    }

    async fn handle_connect_stream(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: qpx_h3::RequestStream,
        _conn: qpx_h3::ConnectionInfo,
        protocol: qpx_h3::Protocol,
        mut datagrams: Option<qpx_h3::StreamDatagrams>,
    ) -> std::result::Result<(), qpx_h3::H3Error> {
        match protocol {
            qpx_h3::Protocol::Other(name) if name == "websocket" => {}
            other => return Err(anyhow!("unexpected protocol: {other:?}").into()),
        }
        req_stream
            .send_response_head(&ok_qpx_response_head(false))
            .await?;
        let chunk = timeout(Duration::from_secs(5), req_stream.recv_data())
            .await
            .map_err(|_| anyhow!("timed out waiting for extended CONNECT request data"))??
            .ok_or_else(|| anyhow!("missing extended CONNECT request data"))?;
        req_stream.send_data(chunk).await?;
        let payload = timeout(Duration::from_secs(5), async {
            datagrams
                .as_mut()
                .ok_or_else(|| anyhow!("missing downstream datagrams"))?
                .receiver
                .recv()
                .await
                .ok_or_else(|| anyhow!("missing downstream extended CONNECT datagram"))
        })
        .await
        .map_err(|_| anyhow!("timed out waiting for extended CONNECT datagram"))??;
        let mut scratch = bytes::BytesMut::new();
        datagrams
            .as_mut()
            .expect("checked above")
            .sender
            .send_unprefixed_datagram_with_scratch(payload, &mut scratch)?;
        req_stream.finish().await
    }
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
#[derive(Clone, Default)]
struct QpxH3WebTransportEchoHandler;

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
#[async_trait]
impl qpx_h3::RequestHandler for QpxH3WebTransportEchoHandler {
    fn settings(&self) -> qpx_h3::Settings {
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: 8,
            read_timeout: Duration::from_secs(5),
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        _request: qpx_h3::Request,
        _conn: qpx_h3::ConnectionInfo,
        _stream: qpx_h3::RequestStream,
    ) -> std::result::Result<(), qpx_h3::H3Error> {
        Err(anyhow!("unexpected buffered request").into())
    }

    async fn handle_webtransport_connect(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: qpx_h3::RequestStream,
        _conn: qpx_h3::ConnectionInfo,
        session: qpx_h3::WebTransportSession,
    ) -> std::result::Result<(), qpx_h3::H3Error> {
        let qpx_h3::WebTransportSession {
            session_id,
            mut opener,
            mut datagrams,
            mut bidi_streams,
            mut uni_streams,
        } = session;

        req_stream
            .send_response_head(&ok_qpx_response_head(false))
            .await?;

        let server_bidi = opener.open_webtransport_bidi(session_id).await?;
        let (mut server_bidi_send, _) = server_bidi.split();
        server_bidi_send
            .send_chunk(Bytes::from_static(b"server-bidi"))
            .await?;
        server_bidi_send.finish().await?;

        let mut server_uni = opener.open_webtransport_uni(session_id).await?;
        server_uni
            .send_chunk(Bytes::from_static(b"server-uni"))
            .await?;
        server_uni.finish().await?;

        let chunk = timeout(Duration::from_secs(5), req_stream.recv_data())
            .await
            .map_err(|_| anyhow!("timed out waiting for WebTransport request data"))??
            .ok_or_else(|| anyhow!("missing WebTransport request data"))?;
        req_stream.send_data(chunk).await?;

        let payload = timeout(Duration::from_secs(5), async {
            datagrams
                .as_mut()
                .ok_or_else(|| anyhow!("missing WebTransport datagrams"))?
                .receiver
                .recv()
                .await
                .ok_or_else(|| anyhow!("missing WebTransport datagram"))
        })
        .await
        .map_err(|_| anyhow!("timed out waiting for WebTransport datagram"))??;
        let mut scratch = bytes::BytesMut::new();
        datagrams
            .as_mut()
            .expect("checked above")
            .sender
            .send_unprefixed_datagram_with_scratch(payload, &mut scratch)?;

        let bidi = timeout(Duration::from_secs(5), bidi_streams.recv())
            .await
            .map_err(|_| anyhow!("timed out waiting for client bidi stream"))?
            .ok_or_else(|| anyhow!("missing client bidi stream"))?;
        let (mut bidi_send, mut bidi_recv) = bidi.split();
        while let Some(chunk) = bidi_recv.recv_chunk().await? {
            bidi_send.send_chunk(chunk).await?;
        }
        bidi_send.finish().await?;

        let uni = timeout(Duration::from_secs(5), uni_streams.recv())
            .await
            .map_err(|_| anyhow!("timed out waiting for client uni stream"))?
            .ok_or_else(|| anyhow!("missing client uni stream"))?;
        let echoed = read_qpx_uni_stream(uni).await?;
        let mut reply_uni = opener.open_webtransport_uni(session_id).await?;
        reply_uni.send_chunk(Bytes::from(echoed)).await?;
        reply_uni.finish().await?;

        req_stream.finish().await
    }
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn start_qpx_h3_server<H: qpx_h3::RequestHandler>(
    handler: H,
) -> Result<(
    SocketAddr,
    quinn::ClientConfig,
    JoinHandle<std::result::Result<(), qpx_h3::H3Error>>,
)> {
    let (server_config, client_config) = build_qpx_h3_tls_configs()?;
    let endpoint = quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = endpoint.local_addr()?;
    let task = tokio::spawn(async move {
        let connecting = timeout(Duration::from_secs(5), endpoint.accept())
            .await
            .map_err(|_| anyhow!("timed out waiting for inbound QUIC connection"))?
            .ok_or_else(|| anyhow!("server endpoint closed before accept"))?;
        qpx_h3::serve_connection(connecting, addr.port(), handler).await
    });
    Ok((addr, client_config, task))
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
fn build_qpx_h3_tls_configs() -> Result<(quinn::ServerConfig, quinn::ClientConfig)> {
    let certified =
        generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let cert_der = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));

    let provider = quinn::rustls::crypto::ring::default_provider();
    let mut tls = quinn::rustls::ServerConfig::builder_with_provider(provider.clone().into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|_| anyhow!("failed to configure test server tls versions"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;

    let quic_crypto = QuicServerConfig::try_from(tls)
        .map_err(|_| anyhow!("failed to build test QUIC server config"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow!("failed to configure test QUIC transport"))?;
    transport.max_concurrent_bidi_streams(64_u32.into());
    transport.max_concurrent_uni_streams(64_u32.into());
    server_config.migration(false);

    let mut roots = quinn::rustls::RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates([cert_der]);
    if added == 0 {
        return Err(anyhow!("failed to add self-signed root certificate"));
    }
    let mut client_tls = quinn::rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|_| anyhow!("failed to configure test client tls versions"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let client_quic = QuicClientConfig::try_from(client_tls)
        .map_err(|_| anyhow!("failed to build test QUIC client config"))?;
    let client_config = quinn::ClientConfig::new(Arc::new(client_quic));

    Ok((server_config, client_config))
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
fn ok_qpx_response_head(capsule_protocol: bool) -> http::Response<()> {
    let mut response = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .expect("static response");
    if capsule_protocol {
        response.headers_mut().insert(
            http::header::HeaderName::from_static("capsule-protocol"),
            http::HeaderValue::from_static("?1"),
        );
    }
    response
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn read_qpx_bidi_stream(stream: qpx_h3::BidiStream) -> Result<Vec<u8>> {
    let (_, mut recv) = stream.split();
    let mut out = Vec::new();
    while let Some(chunk) = recv.recv_chunk().await? {
        out.extend_from_slice(chunk.as_ref());
    }
    Ok(out)
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn read_qpx_uni_stream(mut stream: qpx_h3::UniRecvStream) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = stream.recv_chunk().await? {
        out.extend_from_slice(chunk.as_ref());
    }
    Ok(out)
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn shutdown_qpx_extended_stream(mut stream: qpx_h3::ExtendedConnectStream) -> Result<()> {
    let _ = stream.request_stream.finish().await;
    if let Some(task) = stream.datagram_task.take() {
        task.abort();
        let _ = task.await;
    }
    stream.driver.abort();
    let _ = stream.driver.await;
    Ok(())
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn wait_for_forward_qpx_webtransport_session(
    udp_port: u16,
    upstream_port: u16,
    ca_cert: &Path,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let started = tokio::time::Instant::now();
    let mut last_error = None;
    let mut delay = Duration::from_millis(50);
    while started.elapsed() < Duration::from_secs(20) {
        match open_forward_qpx_webtransport_session(udp_port, upstream_port, ca_cert).await {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                last_error = Some(err);
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(500));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("timed out waiting for WebTransport readiness")))
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn wait_for_forward_qpx_webtransport_ready_session(
    udp_port: u16,
    upstream_port: u16,
    ca_cert: &Path,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let stream =
        wait_for_forward_qpx_webtransport_session(udp_port, upstream_port, ca_cert).await?;
    if stream.response.status() != http::StatusCode::OK {
        let status = stream.response.status();
        shutdown_qpx_extended_stream(stream).await?;
        anyhow::bail!("WebTransport readiness probe returned {status}");
    }
    if stream.datagrams.is_none() || stream.opener.is_none() {
        shutdown_qpx_extended_stream(stream).await?;
        anyhow::bail!("WebTransport readiness probe missed negotiated capabilities");
    }
    Ok(stream)
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn open_forward_qpx_webtransport_session(
    udp_port: u16,
    upstream_port: u16,
    ca_cert: &Path,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(ca_cert)?);
    let connection = timeout(
        Duration::from_secs(5),
        endpoint.connect(SocketAddr::from(([127, 0, 0, 1], udp_port)), "localhost")?,
    )
    .await??;
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://127.0.0.1:{upstream_port}/webtransport"))
        .body(())?;
    Ok(qpx_h3::open_extended_connect_stream(
        endpoint,
        connection,
        request,
        Some(qpx_h3::Protocol::WebTransport),
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: 4,
            read_timeout: Duration::from_secs(5),
            ..Default::default()
        },
        Duration::from_secs(5),
    )
    .await?)
}
