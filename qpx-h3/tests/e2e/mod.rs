use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use qpx_h3::{
    BidiStream, ConnectionInfo, Protocol, Request, RequestHandler, RequestStream, Settings,
    StreamDatagrams, UniRecvStream, WebTransportSession,
};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rcgen::generate_simple_self_signed;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const FRAME_DATA: u64 = 0x0;
const FRAME_HEADERS: u64 = 0x1;
const FRAME_SETTINGS: u64 = 0x4;
const STREAM_QPACK_ENCODER: u64 = 0x2;
const H3_FRAME_UNEXPECTED: u64 = 0x105;
const H3_SETTINGS_ERROR: u64 = 0x109;
const H3_MESSAGE_ERROR: u64 = 0x10e;
const SETTING_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;
const SETTING_H3_DATAGRAM: u64 = 0x33;
const SETTING_ENABLE_WEBTRANSPORT: u64 = 0x2b603742;
const SETTING_WEBTRANSPORT_MAX_SESSIONS: u64 = 0x2b603743;
const DEFAULT_QPACK_TABLE_CAPACITY: usize = 4096;

#[derive(Clone, Default)]
struct ExtendedEchoHandler;

#[async_trait]
impl RequestHandler for ExtendedEchoHandler {
    fn settings(&self) -> Settings {
        Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        _request: Request,
        _conn: ConnectionInfo,
        _stream: RequestStream,
    ) -> Result<()> {
        anyhow::bail!("unexpected request")
    }

    async fn handle_connect_stream(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: RequestStream,
        _conn: ConnectionInfo,
        protocol: Protocol,
        mut datagrams: Option<StreamDatagrams>,
    ) -> Result<()> {
        match protocol {
            Protocol::Other(name) if name == "websocket" => {}
            other => return Err(anyhow!("unexpected protocol: {other:?}")),
        }
        req_stream.send_response_head(&ok_head(false)).await?;
        let chunk = timeout(TEST_TIMEOUT, req_stream.recv_data())
            .await
            .map_err(|_| anyhow!("timed out waiting for extended CONNECT request data"))??
            .ok_or_else(|| anyhow!("missing extended CONNECT request data"))?;
        req_stream.send_data(chunk).await?;
        let payload = timeout(TEST_TIMEOUT, async {
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
        datagrams
            .as_mut()
            .expect("checked above")
            .sender
            .send_datagram(payload)?;
        req_stream.finish().await
    }
}

#[derive(Clone, Default)]
struct ConnectUdpEchoHandler;

#[async_trait]
impl RequestHandler for ConnectUdpEchoHandler {
    fn settings(&self) -> Settings {
        Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        _request: Request,
        _conn: ConnectionInfo,
        _stream: RequestStream,
    ) -> Result<()> {
        anyhow::bail!("unexpected request")
    }

    async fn handle_connect_stream(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: RequestStream,
        _conn: ConnectionInfo,
        protocol: Protocol,
        mut datagrams: Option<StreamDatagrams>,
    ) -> Result<()> {
        if protocol != Protocol::ConnectUdp {
            return Err(anyhow!("unexpected protocol: {protocol:?}"));
        }
        req_stream.send_response_head(&ok_head(true)).await?;
        let capsule = timeout(TEST_TIMEOUT, req_stream.recv_data())
            .await
            .map_err(|_| anyhow!("timed out waiting for CONNECT-UDP capsule"))??
            .ok_or_else(|| anyhow!("missing CONNECT-UDP capsule"))?;
        req_stream.send_data(capsule).await?;
        let payload = timeout(TEST_TIMEOUT, async {
            datagrams
                .as_mut()
                .ok_or_else(|| anyhow!("missing CONNECT-UDP datagrams"))?
                .receiver
                .recv()
                .await
                .ok_or_else(|| anyhow!("missing CONNECT-UDP datagram payload"))
        })
        .await
        .map_err(|_| anyhow!("timed out waiting for CONNECT-UDP datagram"))??;
        datagrams
            .as_mut()
            .expect("checked above")
            .sender
            .send_datagram(payload)?;
        req_stream.finish().await
    }
}

#[derive(Clone, Default)]
struct WebTransportEchoHandler;

#[async_trait]
impl RequestHandler for WebTransportEchoHandler {
    fn settings(&self) -> Settings {
        Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: 8,
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        _request: Request,
        _conn: ConnectionInfo,
        _stream: RequestStream,
    ) -> Result<()> {
        anyhow::bail!("unexpected request")
    }

    async fn handle_webtransport_connect(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: RequestStream,
        _conn: ConnectionInfo,
        session: WebTransportSession,
    ) -> Result<()> {
        let WebTransportSession {
            session_id,
            mut opener,
            mut datagrams,
            mut bidi_streams,
            mut uni_streams,
        } = session;

        req_stream.send_response_head(&ok_head(false)).await?;

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

        let chunk = timeout(TEST_TIMEOUT, req_stream.recv_data())
            .await
            .map_err(|_| anyhow!("timed out waiting for WebTransport request data"))??
            .ok_or_else(|| anyhow!("missing WebTransport request data"))?;
        req_stream.send_data(chunk).await?;

        let payload = timeout(TEST_TIMEOUT, async {
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
        datagrams
            .as_mut()
            .expect("checked above")
            .sender
            .send_datagram(payload)?;

        let bidi = timeout(TEST_TIMEOUT, bidi_streams.recv())
            .await
            .map_err(|_| anyhow!("timed out waiting for client bidi stream"))?
            .ok_or_else(|| anyhow!("missing client bidi stream"))?;
        let (mut bidi_send, mut bidi_recv) = bidi.split();
        while let Some(chunk) = bidi_recv.recv_chunk().await? {
            bidi_send.send_chunk(chunk).await?;
        }
        bidi_send.finish().await?;

        let uni = timeout(TEST_TIMEOUT, uni_streams.recv())
            .await
            .map_err(|_| anyhow!("timed out waiting for client uni stream"))?
            .ok_or_else(|| anyhow!("missing client uni stream"))?;
        let echoed = read_uni_stream(uni).await?;
        let mut reply_uni = opener.open_webtransport_uni(session_id).await?;
        reply_uni.send_chunk(Bytes::from(echoed)).await?;
        reply_uni.finish().await?;

        req_stream.finish().await
    }
}

#[derive(Clone, Default)]
struct WebTransportZeroSessionHandler;

#[derive(Clone, Default)]
struct WebTransportRejectHandler;

#[async_trait]
impl RequestHandler for WebTransportZeroSessionHandler {
    fn settings(&self) -> Settings {
        Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: 0,
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        }
    }

    fn via_received_by(&self) -> String {
        "qpx-test".to_string()
    }

    async fn handle_request(
        &self,
        _request: Request,
        _conn: ConnectionInfo,
        _stream: RequestStream,
    ) -> Result<()> {
        anyhow::bail!("unexpected request")
    }

    async fn handle_webtransport_connect(
        &self,
        _req_head: http::Request<()>,
        _req_stream: RequestStream,
        _conn: ConnectionInfo,
        _session: WebTransportSession,
    ) -> Result<()> {
        anyhow::bail!("WebTransport handler must not run when max sessions is zero")
    }
}

#[async_trait]
impl RequestHandler for WebTransportRejectHandler {
    fn settings(&self) -> Settings {
        Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: 8,
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        _request: Request,
        _conn: ConnectionInfo,
        _stream: RequestStream,
    ) -> Result<()> {
        anyhow::bail!("unexpected request")
    }

    async fn handle_webtransport_connect(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: RequestStream,
        _conn: ConnectionInfo,
        _session: WebTransportSession,
    ) -> Result<()> {
        let response = http::Response::builder()
            .status(http::StatusCode::FORBIDDEN)
            .body(())?;
        req_stream.send_response_head(&response).await?;
        req_stream.send_data(Bytes::from_static(b"denied")).await?;
        req_stream.finish().await
    }
}

#[derive(Clone)]
struct DynamicHeaderHandler {
    seen: Arc<Mutex<Option<oneshot::Sender<String>>>>,
}

#[async_trait]
impl RequestHandler for DynamicHeaderHandler {
    fn settings(&self) -> Settings {
        Settings {
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        request: Request,
        _conn: ConnectionInfo,
        mut stream: RequestStream,
    ) -> Result<()> {
        let value = request
            .head
            .headers()
            .get("x-dynamic")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| anyhow!("missing x-dynamic header"))?
            .to_string();
        if let Some(tx) = self.seen.lock().await.take() {
            let _ = tx.send(value);
        }
        let response = http::Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .body(())?;
        stream.send_response_head(&response).await?;
        stream.finish().await
    }
}

#[derive(Clone, Default)]
struct HeadBodyAttemptHandler;

#[async_trait]
impl RequestHandler for HeadBodyAttemptHandler {
    fn settings(&self) -> Settings {
        Settings {
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        request: Request,
        _conn: ConnectionInfo,
        mut stream: RequestStream,
    ) -> Result<()> {
        if request.head.method() != http::Method::HEAD {
            return Err(anyhow!("expected HEAD request"));
        }
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_LENGTH, "5")
            .body(())?;
        stream.send_response_head(&response).await?;
        let err = stream
            .send_data(Bytes::from_static(b"hello"))
            .await
            .expect_err("HEAD response DATA must be rejected");
        assert!(
            err.to_string().contains("DATA is not allowed"),
            "unexpected DATA rejection: {err}"
        );
        stream.finish().await
    }
}

#[derive(Clone, Default)]
struct ExtendedConnectDisabledHandler;

#[async_trait]
impl RequestHandler for ExtendedConnectDisabledHandler {
    fn settings(&self) -> Settings {
        Settings {
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        _request: Request,
        _conn: ConnectionInfo,
        _stream: RequestStream,
    ) -> Result<()> {
        anyhow::bail!("unexpected request")
    }

    async fn handle_connect_stream(
        &self,
        _req_head: http::Request<()>,
        _req_stream: RequestStream,
        _conn: ConnectionInfo,
        _protocol: Protocol,
        _datagrams: Option<StreamDatagrams>,
    ) -> Result<()> {
        anyhow::bail!("extended CONNECT handler must not run when disabled")
    }
}

mod connect;
mod protocol;
mod webtransport;

async fn start_server<H: RequestHandler>(
    handler: H,
) -> Result<(SocketAddr, quinn::ClientConfig, JoinHandle<Result<()>>)> {
    let (server_config, client_config) = build_tls_configs()?;
    let endpoint = quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = endpoint.local_addr()?;
    let task = tokio::spawn(async move {
        let connecting = timeout(TEST_TIMEOUT, endpoint.accept())
            .await
            .map_err(|_| anyhow!("timed out waiting for inbound QUIC connection"))?
            .ok_or_else(|| anyhow!("server endpoint closed before accept"))?;
        qpx_h3::serve_connection(connecting, addr.port(), handler).await
    });
    Ok((addr, client_config, task))
}

async fn connect_client(
    addr: SocketAddr,
    client_config: quinn::ClientConfig,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    endpoint.set_default_client_config(client_config);
    let connection = timeout(TEST_TIMEOUT, endpoint.connect(addr, "localhost")?)
        .await
        .map_err(|_| anyhow!("timed out establishing QUIC client connection"))??;
    Ok((endpoint, connection))
}

fn build_tls_configs() -> Result<(quinn::ServerConfig, quinn::ClientConfig)> {
    let certified = generate_simple_self_signed(vec!["localhost".to_string()])?;
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

fn ok_head(capsule_protocol: bool) -> http::Response<()> {
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

async fn read_bidi_stream(stream: BidiStream) -> Result<Vec<u8>> {
    let (_, mut recv) = stream.split();
    let mut out = Vec::new();
    while let Some(chunk) = recv.recv_chunk().await? {
        out.extend_from_slice(chunk.as_ref());
    }
    Ok(out)
}

async fn read_uni_stream(mut stream: UniRecvStream) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = stream.recv_chunk().await? {
        out.extend_from_slice(chunk.as_ref());
    }
    Ok(out)
}

async fn shutdown_extended_stream(mut stream: qpx_h3::ExtendedConnectStream) -> Result<()> {
    let _ = stream.request_stream.finish().await;
    if let Some(task) = stream.datagram_task.take() {
        task.abort();
        let _ = task.await;
    }
    stream.driver.abort();
    let _ = stream.driver.await;
    Ok(())
}

fn connect_udp_payload(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0];
    out.extend_from_slice(payload);
    out
}

fn decode_connect_udp_payload(payload: &[u8]) -> Result<&[u8]> {
    if payload.first().copied() != Some(0) {
        return Err(anyhow!("CONNECT-UDP payload must start with context id 0"));
    }
    Ok(&payload[1..])
}

fn encode_datagram_capsule(payload: &[u8]) -> Bytes {
    let value = connect_udp_payload(payload);
    let mut out = Vec::with_capacity(value.len() + 4);
    push_varint(&mut out, 0);
    push_varint(&mut out, value.len() as u64);
    out.extend_from_slice(&value);
    Bytes::from(out)
}

fn decode_datagram_capsule(payload: &[u8]) -> Result<&[u8]> {
    let (capsule_type, used_type) = read_varint(payload)?;
    if capsule_type != 0 {
        return Err(anyhow!("unexpected capsule type {capsule_type}"));
    }
    let (len, used_len) = read_varint(&payload[used_type..])?;
    let len = len as usize;
    let start = used_type + used_len;
    let end = start + len;
    if payload.len() < end {
        return Err(anyhow!("truncated datagram capsule"));
    }
    decode_connect_udp_payload(&payload[start..end])
}

fn push_varint(out: &mut Vec<u8>, value: u64) {
    if value <= 63 {
        out.push(value as u8);
    } else if value <= 16_383 {
        out.push(((value >> 8) as u8) | 0x40);
        out.push((value & 0xff) as u8);
    } else if value <= 1_073_741_823 {
        out.push(((value >> 24) as u8 & 0x3f) | 0x80);
        out.push(((value >> 16) & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push((value & 0xff) as u8);
    } else {
        panic!("test helper only supports up to 30-bit varints");
    }
}

fn encode_prefixed_int(out: &mut Vec<u8>, prefix_bits: u8, flags: u8, value: u64) {
    let mask = if prefix_bits == 8 {
        u8::MAX
    } else {
        ((1u16 << prefix_bits) - 1) as u8
    };
    if value < mask as u64 {
        let prefix = if prefix_bits == 8 {
            0
        } else {
            flags << prefix_bits
        };
        out.push(prefix | value as u8);
        return;
    }
    let prefix = if prefix_bits == 8 {
        0
    } else {
        flags << prefix_bits
    };
    out.push(prefix | mask);
    let mut remaining = value - mask as u64;
    while remaining >= 128 {
        out.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
}

fn encode_string(out: &mut Vec<u8>, total_bits: u8, flags: u8, value: &[u8]) {
    encode_prefixed_int(out, total_bits - 1, flags << 1, value.len() as u64);
    out.extend_from_slice(value);
}

fn encode_header_prefix(out: &mut Vec<u8>, required_insert_count: usize, base: usize) {
    let max_entries = DEFAULT_QPACK_TABLE_CAPACITY / 32;
    let encoded_insert_count = required_insert_count % (2 * max_entries) + 1;
    let (sign_bit, delta_base) = if required_insert_count > base {
        (1, required_insert_count - base - 1)
    } else {
        (0, base - required_insert_count)
    };
    encode_prefixed_int(out, 8, 0, encoded_insert_count as u64);
    encode_prefixed_int(out, 7, sign_bit, delta_base as u64);
}

async fn write_frame_raw(
    send: &mut quinn::SendStream,
    frame_type: u64,
    payload: &[u8],
) -> Result<()> {
    let mut encoded = Vec::new();
    push_varint(&mut encoded, frame_type);
    push_varint(&mut encoded, payload.len() as u64);
    encoded.extend_from_slice(payload);
    send.write_all(&encoded).await?;
    Ok(())
}

async fn send_dynamic_qpack_request(connection: &quinn::Connection, authority: &str) -> Result<()> {
    open_client_control_stream(connection).await?;

    let mut encoder = connection.open_uni().await?;
    let mut encoder_stream = Vec::new();
    push_varint(&mut encoder_stream, STREAM_QPACK_ENCODER);
    encoder_stream.extend_from_slice(&build_dynamic_encoder_instructions("dynamic-value"));
    encoder.write_all(&encoder_stream).await?;
    tokio::spawn(async move {
        let _encoder = encoder;
        std::future::pending::<()>().await;
    });

    let (mut send, _) = connection.open_bi().await?;
    let headers = build_dynamic_request_headers(authority);
    write_frame_raw(&mut send, FRAME_HEADERS, &headers).await?;
    send.finish()?;
    Ok(())
}

async fn open_client_control_stream(connection: &quinn::Connection) -> Result<()> {
    let mut control = connection.open_uni().await?;
    let mut control_stream = Vec::new();
    push_varint(&mut control_stream, 0);
    push_varint(&mut control_stream, FRAME_SETTINGS);
    push_varint(&mut control_stream, 0);
    control.write_all(&control_stream).await?;
    tokio::spawn(async move {
        let _control = control;
        std::future::pending::<()>().await;
    });
    Ok(())
}

async fn open_client_control_stream_with_webtransport(
    connection: &quinn::Connection,
) -> Result<()> {
    let mut payload = Vec::new();
    push_varint(&mut payload, SETTING_ENABLE_CONNECT_PROTOCOL);
    push_varint(&mut payload, 1);
    push_varint(&mut payload, SETTING_H3_DATAGRAM);
    push_varint(&mut payload, 1);
    push_varint(&mut payload, SETTING_ENABLE_WEBTRANSPORT);
    push_varint(&mut payload, 1);
    push_varint(&mut payload, SETTING_WEBTRANSPORT_MAX_SESSIONS);
    push_varint(&mut payload, 4);

    let mut control = connection.open_uni().await?;
    let mut control_stream = Vec::new();
    push_varint(&mut control_stream, 0);
    push_varint(&mut control_stream, FRAME_SETTINGS);
    push_varint(&mut control_stream, payload.len() as u64);
    control_stream.extend_from_slice(&payload);
    control.write_all(&control_stream).await?;
    tokio::spawn(async move {
        let _control = control;
        std::future::pending::<()>().await;
    });
    Ok(())
}

fn build_dynamic_encoder_instructions(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_prefixed_int(&mut out, 5, 0b001, DEFAULT_QPACK_TABLE_CAPACITY as u64);
    encode_string(&mut out, 6, 0b01, b"x-dynamic");
    encode_string(&mut out, 8, 0, value.as_bytes());
    out
}

fn build_extended_connect_headers(authority: &str) -> Vec<u8> {
    build_extended_connect_headers_with_protocol(authority, "websocket")
}

fn build_extended_connect_headers_with_protocol(authority: &str, protocol: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_prefixed_int(&mut out, 8, 0, 0);
    encode_prefixed_int(&mut out, 7, 0, 0);
    encode_prefixed_int(&mut out, 6, 0b11, 15);
    encode_prefixed_int(&mut out, 6, 0b11, 23);
    encode_prefixed_int(&mut out, 4, 0b0101, 0);
    encode_string(&mut out, 8, 0, authority.as_bytes());
    encode_prefixed_int(&mut out, 6, 0b11, 1);
    encode_string(&mut out, 4, 0b0010, b":protocol");
    encode_string(&mut out, 8, 0, protocol.as_bytes());
    out
}

fn build_extended_connect_headers_with_content_lengths(authority: &str) -> Vec<u8> {
    let mut out = build_extended_connect_headers(authority);
    encode_prefixed_int(&mut out, 6, 0b11, 1);
    encode_string(&mut out, 4, 0b0010, b"content-length");
    encode_string(&mut out, 8, 0, b"1");
    encode_prefixed_int(&mut out, 6, 0b11, 1);
    encode_string(&mut out, 4, 0b0010, b"content-length");
    encode_string(&mut out, 8, 0, b"2");
    out
}

fn build_dynamic_request_headers(authority: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_header_prefix(&mut out, 1, 1);
    encode_prefixed_int(&mut out, 6, 0b11, 17);
    encode_prefixed_int(&mut out, 6, 0b11, 23);
    encode_prefixed_int(&mut out, 4, 0b0101, 0);
    encode_string(&mut out, 8, 0, authority.as_bytes());
    encode_prefixed_int(&mut out, 6, 0b11, 1);
    encode_prefixed_int(&mut out, 6, 0b10, 0);
    out
}

fn build_head_request_headers(authority: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_prefixed_int(&mut out, 8, 0, 0);
    encode_prefixed_int(&mut out, 7, 0, 0);
    encode_prefixed_int(&mut out, 6, 0b11, 18);
    encode_prefixed_int(&mut out, 6, 0b11, 23);
    encode_prefixed_int(&mut out, 4, 0b0101, 0);
    encode_string(&mut out, 8, 0, authority.as_bytes());
    encode_prefixed_int(&mut out, 6, 0b11, 1);
    out
}

fn read_varint(buf: &[u8]) -> Result<(u64, usize)> {
    let first = *buf.first().ok_or_else(|| anyhow!("missing varint"))?;
    match first >> 6 {
        0 => Ok((u64::from(first & 0x3f), 1)),
        1 => {
            if buf.len() < 2 {
                return Err(anyhow!("truncated two-byte varint"));
            }
            Ok((((u64::from(first & 0x3f)) << 8) | u64::from(buf[1]), 2))
        }
        _ => Err(anyhow!("test helper does not support long varints")),
    }
}

async fn read_non_empty_chunk(recv: &mut quinn::RecvStream, label: &str) -> Result<Bytes> {
    loop {
        let chunk = timeout(TEST_TIMEOUT, recv.read_chunk(4096, true))
            .await
            .map_err(|_| anyhow!("timed out waiting for {label}"))??
            .ok_or_else(|| anyhow!("missing {label}"))?;
        if !chunk.bytes.is_empty() {
            return Ok(chunk.bytes);
        }
    }
}
