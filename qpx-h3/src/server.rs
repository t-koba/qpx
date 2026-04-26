use crate::protocol::{
    decode_settings_frame, read_frame, read_frame_with_limit, read_varint, write_frame,
    write_varint, ConnectionClose, Frame, PeerControlState, FRAME_DATA, FRAME_HEADERS,
    FRAME_SETTINGS, H3_CLOSED_CRITICAL_STREAM, H3_FRAME_ERROR, H3_FRAME_UNEXPECTED, H3_ID_ERROR,
    H3_MESSAGE_ERROR, H3_MISSING_SETTINGS, H3_SETTINGS_ERROR, SETTING_ENABLE_CONNECT_PROTOCOL,
    SETTING_ENABLE_WEBTRANSPORT, SETTING_H3_DATAGRAM, SETTING_MAX_FIELD_SECTION_SIZE,
    SETTING_QPACK_MAX_BLOCKED_STREAMS, SETTING_QPACK_MAX_TABLE_CAPACITY,
    SETTING_WEBTRANSPORT_MAX_SESSIONS, STREAM_CONTROL, STREAM_PUSH, STREAM_QPACK_DECODER,
    STREAM_QPACK_ENCODER, STREAM_WEBTRANSPORT_BIDI, STREAM_WEBTRANSPORT_UNI,
};
use crate::qpack::{
    encode_response_head, encode_trailers, QpackConnection, DEFAULT_DYNAMIC_TABLE_CAPACITY,
    DEFAULT_ENCODER_STREAM_BUFFER_BYTES, DEFAULT_MAX_BLOCKED_STREAMS,
};
use crate::response::{
    parse_content_length, sanitize_interim_response_for_h3, sanitize_response_for_h3,
    sanitize_trailers_for_h3,
};
use crate::transport::{
    BidiStream, DatagramDispatch, OpenStreams, RequestStream, StreamDatagrams, UniRecvStream,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::timeout;
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportLevel {
    BufferedServer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    ConnectUdp,
    WebTransport,
    Other(String),
}

impl Protocol {
    pub fn as_str(&self) -> &str {
        match self {
            Self::ConnectUdp => "connect-udp",
            Self::WebTransport => "webtransport",
            Self::Other(other) => other.as_str(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub remote_addr: SocketAddr,
    pub dst_port: u16,
    pub tls_sni: Option<Arc<str>>,
    pub peer_certificates: Option<Arc<Vec<Vec<u8>>>>,
}

pub struct WebTransportSession {
    pub session_id: u64,
    pub opener: OpenStreams,
    pub datagrams: Option<StreamDatagrams>,
    pub bidi_streams: mpsc::UnboundedReceiver<BidiStream>,
    pub uni_streams: mpsc::UnboundedReceiver<UniRecvStream>,
}

struct WebTransportSessionIngress {
    bidi_tx: mpsc::UnboundedSender<BidiStream>,
    uni_tx: mpsc::UnboundedSender<UniRecvStream>,
}

type WebTransportSessionRegistry = Arc<Mutex<HashMap<u64, WebTransportSessionIngress>>>;

#[derive(Debug, Clone)]
pub struct Settings {
    pub enable_extended_connect: bool,
    pub enable_datagram: bool,
    pub enable_webtransport: bool,
    pub qpack_max_table_capacity: usize,
    pub qpack_max_blocked_streams: u64,
    pub max_webtransport_sessions: u64,
    pub max_request_body_bytes: usize,
    pub max_concurrent_streams_per_connection: usize,
    pub read_timeout: Duration,
    pub max_field_section_size: u64,
    pub max_frame_payload_bytes: usize,
    pub max_control_frame_payload_bytes: usize,
    pub max_encoder_stream_buffer_bytes: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enable_extended_connect: false,
            enable_datagram: false,
            enable_webtransport: false,
            qpack_max_table_capacity: DEFAULT_DYNAMIC_TABLE_CAPACITY,
            qpack_max_blocked_streams: DEFAULT_MAX_BLOCKED_STREAMS,
            max_webtransport_sessions: 0,
            max_request_body_bytes: 16 * 1024 * 1024,
            max_concurrent_streams_per_connection: 64,
            read_timeout: Duration::from_secs(30),
            max_field_section_size: 16 * 1024 * 1024,
            max_frame_payload_bytes: 16 * 1024 * 1024,
            max_control_frame_payload_bytes: 1024 * 1024,
            max_encoder_stream_buffer_bytes: DEFAULT_ENCODER_STREAM_BUFFER_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub head: http::Request<()>,
    pub body: Bytes,
    pub trailers: Option<HeaderMap>,
    pub protocol: Option<Protocol>,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub interim: Vec<http::Response<()>>,
    pub response: http::Response<Bytes>,
    pub trailers: Option<HeaderMap>,
}

impl Response {
    pub fn final_only(response: http::Response<Bytes>) -> Self {
        Self {
            interim: Vec::new(),
            response,
            trailers: None,
        }
    }
}

#[async_trait]
pub trait RequestHandler: Clone + Send + Sync + 'static {
    fn settings(&self) -> Settings;

    async fn handle_request(&self, request: Request, conn: ConnectionInfo) -> Result<Response>;

    async fn handle_connect_stream(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: RequestStream,
        _conn: ConnectionInfo,
        _protocol: Protocol,
        _datagrams: Option<StreamDatagrams>,
    ) -> Result<()> {
        send_simple_response(
            req_stream.send_mut(),
            http::StatusCode::NOT_IMPLEMENTED,
            b"extended CONNECT is not supported",
        )
        .await?;
        req_stream.finish().await
    }

    async fn handle_webtransport_connect(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: RequestStream,
        _conn: ConnectionInfo,
        _session: WebTransportSession,
    ) -> Result<()> {
        send_simple_response(
            req_stream.send_mut(),
            http::StatusCode::NOT_IMPLEMENTED,
            b"WEBTRANSPORT over extended CONNECT is not supported",
        )
        .await?;
        req_stream.finish().await
    }
}

pub async fn serve_connection<H: RequestHandler>(
    connecting: quinn::Incoming,
    dst_port: u16,
    handler: H,
) -> Result<()> {
    let settings = handler.settings();
    let connection = connecting.await?;
    let conn_info = ConnectionInfo {
        remote_addr: connection.remote_address(),
        dst_port,
        tls_sni: extract_tls_sni(&connection),
        peer_certificates: extract_peer_certificates(&connection),
    };

    let (control, encoder, decoder) = open_critical_streams(&connection, &settings).await?;
    let qpack = QpackConnection::new(
        decoder,
        settings.qpack_max_table_capacity,
        settings.qpack_max_blocked_streams,
        settings.max_field_section_size,
        settings.max_encoder_stream_buffer_bytes,
        settings.read_timeout,
    );
    let _critical_streams = (control, encoder);
    let control_state = PeerControlState::default();

    let session_registry: WebTransportSessionRegistry = Arc::new(Mutex::new(HashMap::new()));
    let datagram_dispatch = settings
        .enable_datagram
        .then(|| DatagramDispatch::new(connection.clone(), 64));
    if let Some(dispatch) = datagram_dispatch.as_ref() {
        let dispatch = dispatch.clone();
        tokio::spawn(async move {
            dispatch.run().await;
        });
    }

    let uni_conn = connection.clone();
    let uni_registry = session_registry.clone();
    let uni_qpack = qpack.clone();
    let uni_control_state = control_state.clone();
    let max_control_frame_payload_bytes = settings.max_control_frame_payload_bytes;
    tokio::spawn(async move {
        loop {
            let recv = match uni_conn.accept_uni().await {
                Ok(recv) => recv,
                Err(_) => break,
            };
            let registry = uni_registry.clone();
            let qpack = uni_qpack.clone();
            let conn = uni_conn.clone();
            let control_state = uni_control_state.clone();
            tokio::spawn(async move {
                if let Err(err) = consume_uni_stream(
                    recv,
                    registry,
                    qpack,
                    control_state,
                    max_control_frame_payload_bytes,
                )
                .await
                {
                    close_connection(&conn, err);
                }
            });
        }
    });

    let request_semaphore = Arc::new(Semaphore::new(
        settings.max_concurrent_streams_per_connection.max(1),
    ));
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::TimedOut)
            | Err(quinn::ConnectionError::ConnectionClosed(_))
            | Err(quinn::ConnectionError::Reset) => break,
            Err(err) => return Err(err.into()),
        };

        let permit = match request_semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => break,
        };
        let handler = handler.clone();
        let conn_info = conn_info.clone();
        let settings = settings.clone();
        let request_conn = connection.clone();
        let session_registry = session_registry.clone();
        let datagram_dispatch = datagram_dispatch.clone();
        let qpack = qpack.clone();
        let control = control_state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let ctx = RequestStreamContext {
                conn_info,
                settings,
                connection: request_conn,
                session_registry,
                datagram_dispatch,
                qpack,
                control,
            };
            if let Err(err) = handle_request_stream(send, recv, handler, ctx).await {
                warn!(error = ?err, "qpx-h3 request stream failed");
            }
        });
    }

    Ok(())
}

async fn open_critical_streams(
    connection: &quinn::Connection,
    settings: &Settings,
) -> Result<(quinn::SendStream, quinn::SendStream, quinn::SendStream)> {
    let mut control = connection.open_uni().await?;
    write_varint(&mut control, STREAM_CONTROL).await?;
    let payload = encode_settings(settings);
    write_frame(&mut control, FRAME_SETTINGS, &payload).await?;
    control.flush().await?;

    let mut encoder = connection.open_uni().await?;
    write_varint(&mut encoder, STREAM_QPACK_ENCODER).await?;
    encoder.flush().await?;

    let mut decoder = connection.open_uni().await?;
    write_varint(&mut decoder, STREAM_QPACK_DECODER).await?;
    decoder.flush().await?;

    Ok((control, encoder, decoder))
}

pub(crate) fn encode_settings(settings: &Settings) -> Vec<u8> {
    let mut payload = Vec::new();
    crate::protocol::push_varint(&mut payload, SETTING_QPACK_MAX_TABLE_CAPACITY);
    crate::protocol::push_varint(&mut payload, settings.qpack_max_table_capacity as u64);
    crate::protocol::push_varint(&mut payload, SETTING_QPACK_MAX_BLOCKED_STREAMS);
    crate::protocol::push_varint(&mut payload, settings.qpack_max_blocked_streams);
    crate::protocol::push_varint(&mut payload, SETTING_MAX_FIELD_SECTION_SIZE);
    crate::protocol::push_varint(&mut payload, settings.max_field_section_size);
    crate::protocol::push_varint(&mut payload, SETTING_ENABLE_CONNECT_PROTOCOL);
    crate::protocol::push_varint(&mut payload, settings.enable_extended_connect as u64);
    crate::protocol::push_varint(&mut payload, SETTING_ENABLE_WEBTRANSPORT);
    crate::protocol::push_varint(&mut payload, settings.enable_webtransport as u64);
    crate::protocol::push_varint(&mut payload, SETTING_H3_DATAGRAM);
    crate::protocol::push_varint(&mut payload, settings.enable_datagram as u64);
    crate::protocol::push_varint(&mut payload, SETTING_WEBTRANSPORT_MAX_SESSIONS);
    crate::protocol::push_varint(&mut payload, settings.max_webtransport_sessions);
    payload
}

async fn consume_uni_stream(
    mut recv: quinn::RecvStream,
    registry: WebTransportSessionRegistry,
    qpack: QpackConnection,
    control_state: PeerControlState,
    max_control_frame_payload_bytes: usize,
) -> std::result::Result<(), ConnectionClose> {
    let Some(stream_type) = read_varint(&mut recv)
        .await
        .map_err(|err| ConnectionClose::new(H3_MESSAGE_ERROR, err.to_string()))?
    else {
        return Ok(());
    };
    match stream_type {
        STREAM_CONTROL => {
            control_state.register_control_stream().await?;
            let mut saw_settings = false;
            loop {
                let Some(frame) = read_frame(&mut recv, max_control_frame_payload_bytes)
                    .await
                    .map_err(|err| ConnectionClose::new(H3_MESSAGE_ERROR, err.to_string()))?
                else {
                    return Err(ConnectionClose::new(
                        if saw_settings {
                            H3_CLOSED_CRITICAL_STREAM
                        } else {
                            H3_MISSING_SETTINGS
                        },
                        "HTTP/3 control stream closed before graceful shutdown",
                    ));
                };
                if !saw_settings {
                    if frame.ty != FRAME_SETTINGS {
                        return Err(ConnectionClose::new(
                            H3_MISSING_SETTINGS,
                            "HTTP/3 control stream did not begin with SETTINGS",
                        ));
                    }
                    let peer_settings = decode_settings_frame(frame.payload.as_ref())
                        .map_err(|err| ConnectionClose::new(H3_SETTINGS_ERROR, err.to_string()))?;
                    control_state.register_settings(peer_settings).await?;
                    saw_settings = true;
                    continue;
                }
                control_state
                    .handle_control_frame(frame.ty, frame.payload.as_ref(), false)
                    .await?;
            }
        }
        STREAM_WEBTRANSPORT_UNI => {
            let session_id = read_varint(&mut recv)
                .await
                .map_err(|err| ConnectionClose::new(H3_MESSAGE_ERROR, err.to_string()))?
                .ok_or_else(|| {
                    ConnectionClose::new(H3_MESSAGE_ERROR, "missing WebTransport session id")
                })?;
            if !is_client_initiated_bidi_stream_id(session_id) {
                return Err(ConnectionClose::new(
                    H3_ID_ERROR,
                    "WebTransport associated stream used invalid session id",
                ));
            }
            let tx = {
                registry
                    .lock()
                    .await
                    .get(&session_id)
                    .map(|entry| entry.uni_tx.clone())
            };
            if let Some(tx) = tx {
                let _ = tx.send(UniRecvStream::new(recv));
            } else {
                return Err(ConnectionClose::new(
                    H3_ID_ERROR,
                    "WebTransport associated stream referenced unknown session",
                ));
            }
        }
        STREAM_QPACK_ENCODER => {
            control_state.register_encoder_stream().await?;
            qpack
                .process_encoder_stream(recv)
                .await
                .map_err(|err| match err {
                    crate::qpack::EncoderStreamError::Closed(message) => {
                        ConnectionClose::new(H3_CLOSED_CRITICAL_STREAM, message)
                    }
                    crate::qpack::EncoderStreamError::Invalid(message) => {
                        ConnectionClose::new(crate::protocol::QPACK_ENCODER_STREAM_ERROR, message)
                    }
                })?;
        }
        STREAM_QPACK_DECODER => {
            control_state.register_decoder_stream().await?;
            let mut sink = tokio::io::sink();
            tokio::io::copy(&mut recv, &mut sink)
                .await
                .map_err(|err| ConnectionClose::new(H3_CLOSED_CRITICAL_STREAM, err.to_string()))?;
            return Err(ConnectionClose::new(
                H3_CLOSED_CRITICAL_STREAM,
                "peer closed QPACK decoder stream",
            ));
        }
        STREAM_PUSH => {
            return Err(ConnectionClose::new(
                crate::protocol::H3_STREAM_CREATION_ERROR,
                "HTTP/3 push streams are not permitted from clients",
            ));
        }
        _ => {
            let mut sink = tokio::io::sink();
            tokio::io::copy(&mut recv, &mut sink)
                .await
                .map_err(|err| ConnectionClose::new(H3_MESSAGE_ERROR, err.to_string()))?;
        }
    }
    Ok(())
}

struct RequestStreamContext {
    conn_info: ConnectionInfo,
    settings: Settings,
    connection: quinn::Connection,
    session_registry: WebTransportSessionRegistry,
    datagram_dispatch: Option<Arc<DatagramDispatch>>,
    qpack: QpackConnection,
    control: PeerControlState,
}

async fn handle_request_stream<H: RequestHandler>(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    handler: H,
    ctx: RequestStreamContext,
) -> Result<()> {
    let first_type = match timeout(ctx.settings.read_timeout, read_varint(&mut recv)).await {
        Ok(result) => result?,
        Err(_) => {
            send_simple_response(&mut send, http::StatusCode::REQUEST_TIMEOUT, b"").await?;
            send.finish()?;
            return Ok(());
        }
    };
    let Some(first_type) = first_type else {
        send.finish()?;
        return Ok(());
    };
    if first_type == STREAM_WEBTRANSPORT_BIDI && ctx.settings.enable_webtransport {
        let peer_settings =
            match timeout(ctx.settings.read_timeout, ctx.control.wait_for_settings()).await {
                Ok(settings) => settings,
                Err(_) => {
                    abort_stream_with_code(&mut send, &mut recv, H3_MISSING_SETTINGS).await?;
                    return Ok(());
                }
            };
        if !peer_settings.enable_webtransport {
            abort_stream_with_code(&mut send, &mut recv, H3_SETTINGS_ERROR).await?;
            return Ok(());
        }
        let session_id = timeout(ctx.settings.read_timeout, read_varint(&mut recv))
            .await
            .map_err(|_| anyhow!("timed out reading WebTransport session id"))??
            .ok_or_else(|| anyhow!("missing WebTransport session id"))?;
        if !is_client_initiated_bidi_stream_id(session_id) {
            abort_stream_with_code(&mut send, &mut recv, H3_ID_ERROR).await?;
            return Ok(());
        }
        let tx = {
            ctx.session_registry
                .lock()
                .await
                .get(&session_id)
                .map(|entry| entry.bidi_tx.clone())
        };
        if let Some(tx) = tx {
            let _ = tx.send(BidiStream::new(send, recv));
        } else {
            abort_stream_with_code(&mut send, &mut recv, H3_ID_ERROR).await?;
        }
        return Ok(());
    }

    if first_type != FRAME_HEADERS {
        abort_stream_with_code(&mut send, &mut recv, H3_FRAME_UNEXPECTED).await?;
        return Ok(());
    }
    let peer_settings =
        match timeout(ctx.settings.read_timeout, ctx.control.wait_for_settings()).await {
            Ok(settings) => settings,
            Err(_) => {
                abort_stream_with_code(&mut send, &mut recv, H3_MISSING_SETTINGS).await?;
                return Ok(());
            }
        };
    let first = match read_frame_with_known_type(
        &mut recv,
        first_type,
        ctx.settings.read_timeout,
        field_section_limit(&ctx.settings),
    )
    .await
    {
        Ok(frame) => frame,
        Err(err) => {
            warn!(error = ?err, "qpx-h3 rejected malformed first request frame");
            abort_stream_with_code(&mut send, &mut recv, H3_FRAME_ERROR).await?;
            return Ok(());
        }
    };
    let stream_id: u64 = send.id().into();

    let decoded = match ctx
        .qpack
        .decode_request_head(stream_id, first.payload.as_ref(), ctx.settings.read_timeout)
        .await
    {
        Ok(decoded) => decoded,
        Err(err) => {
            warn!(error = ?err, "qpx-h3 failed to decode request head");
            abort_stream_with_code(&mut send, &mut recv, err.code()).await?;
            return Ok(());
        }
    };

    let protocol = decoded.protocol.as_deref().map(parse_protocol);
    if decoded.request.method() == http::Method::CONNECT {
        if let Some(protocol) = protocol.as_ref() {
            if !ctx.settings.enable_extended_connect {
                abort_stream_with_code(&mut send, &mut recv, H3_SETTINGS_ERROR).await?;
                return Ok(());
            }
            if *protocol == Protocol::WebTransport && !ctx.settings.enable_webtransport {
                abort_stream_with_code(&mut send, &mut recv, H3_SETTINGS_ERROR).await?;
                return Ok(());
            }
            if *protocol == Protocol::ConnectUdp && !ctx.settings.enable_datagram {
                abort_stream_with_code(&mut send, &mut recv, H3_SETTINGS_ERROR).await?;
                return Ok(());
            }
        }
    }
    if decoded.request.method() == http::Method::CONNECT
        && protocol == Some(Protocol::WebTransport)
        && ctx.settings.enable_webtransport
    {
        if !peer_settings.enable_webtransport {
            abort_stream_with_code(&mut send, &mut recv, H3_SETTINGS_ERROR).await?;
            return Ok(());
        }
        let (bidi_tx, bidi_rx) = mpsc::unbounded_channel();
        let (uni_tx, uni_rx) = mpsc::unbounded_channel();
        {
            let mut sessions = ctx.session_registry.lock().await;
            if ctx.settings.max_webtransport_sessions == 0
                || sessions.len() as u64 >= ctx.settings.max_webtransport_sessions
            {
                send_simple_response(
                    &mut send,
                    http::StatusCode::TOO_MANY_REQUESTS,
                    b"too many WebTransport sessions",
                )
                .await?;
                send.finish()?;
                return Ok(());
            }
            sessions.insert(stream_id, WebTransportSessionIngress { bidi_tx, uni_tx });
        }
        let datagrams = if ctx.settings.enable_datagram && peer_settings.enable_datagram {
            let dispatch = ctx
                .datagram_dispatch
                .as_ref()
                .ok_or_else(|| anyhow!("missing datagram dispatch"))?;
            Some(dispatch.register_stream(stream_id).await)
        } else {
            None
        };
        let result = handler
            .handle_webtransport_connect(
                decoded.request,
                RequestStream::new_server_response(
                    send,
                    recv,
                    stream_id,
                    ctx.qpack.clone(),
                    ctx.settings.read_timeout,
                    ctx.settings.max_frame_payload_bytes,
                ),
                ctx.conn_info.clone(),
                WebTransportSession {
                    session_id: stream_id,
                    opener: OpenStreams::new(ctx.connection),
                    datagrams,
                    bidi_streams: bidi_rx,
                    uni_streams: uni_rx,
                },
            )
            .await;
        ctx.session_registry.lock().await.remove(&stream_id);
        return result;
    }
    if decoded.request.method() == http::Method::CONNECT {
        if let Some(protocol) = protocol.clone() {
            if protocol == Protocol::ConnectUdp && !peer_settings.enable_datagram {
                abort_stream_with_code(&mut send, &mut recv, H3_SETTINGS_ERROR).await?;
                return Ok(());
            }
            let datagrams = if ctx.settings.enable_datagram && peer_settings.enable_datagram {
                let dispatch = ctx
                    .datagram_dispatch
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing datagram dispatch"))?;
                Some(dispatch.register_stream(stream_id).await)
            } else {
                None
            };
            let _datagram_registration = if datagrams.is_none() {
                if let Some(dispatch) = ctx.datagram_dispatch.as_ref() {
                    Some(dispatch.register_stream_without_datagrams(stream_id).await)
                } else {
                    None
                }
            } else {
                None
            };
            return handler
                .handle_connect_stream(
                    decoded.request,
                    RequestStream::new_server_response(
                        send,
                        recv,
                        stream_id,
                        ctx.qpack.clone(),
                        ctx.settings.read_timeout,
                        ctx.settings.max_frame_payload_bytes,
                    ),
                    ctx.conn_info,
                    protocol,
                    datagrams,
                )
                .await;
        }
    }

    let _datagram_registration = if let Some(dispatch) = ctx.datagram_dispatch.as_ref() {
        Some(dispatch.register_stream_without_datagrams(stream_id).await)
    } else {
        None
    };

    let request_content_length = match parse_content_length(decoded.request.headers()) {
        Ok(value) => value,
        Err(err) => {
            warn!(error = ?err, "qpx-h3 rejected malformed Content-Length");
            abort_stream_with_code(&mut send, &mut recv, H3_MESSAGE_ERROR).await?;
            return Ok(());
        }
    };
    let mut body = BytesMut::new();
    let mut trailers = None;
    let mut saw_trailers = false;
    loop {
        let next = match timeout(
            ctx.settings.read_timeout,
            read_frame_with_limit(&mut recv, |ty| match ty {
                FRAME_DATA => ctx
                    .settings
                    .max_request_body_bytes
                    .saturating_sub(body.len())
                    .min(ctx.settings.max_frame_payload_bytes),
                FRAME_HEADERS => {
                    field_section_limit(&ctx.settings).min(ctx.settings.max_frame_payload_bytes)
                }
                _ => ctx.settings.max_frame_payload_bytes,
            }),
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => {
                warn!(error = ?err, "qpx-h3 rejected oversized or malformed request frame");
                abort_stream_with_code(&mut send, &mut recv, H3_FRAME_ERROR).await?;
                return Ok(());
            }
            Err(_) => {
                send_simple_response(&mut send, http::StatusCode::REQUEST_TIMEOUT, b"").await?;
                send.finish()?;
                return Ok(());
            }
        };
        let Some(frame) = next else {
            break;
        };
        match frame.ty {
            FRAME_DATA => {
                if saw_trailers {
                    abort_stream_with_code(&mut send, &mut recv, H3_FRAME_UNEXPECTED).await?;
                    return Ok(());
                }
                let next_len = body
                    .len()
                    .checked_add(frame.payload.len())
                    .ok_or_else(|| anyhow!("request body length overflow"))?;
                if next_len > ctx.settings.max_request_body_bytes {
                    send_simple_response(&mut send, http::StatusCode::PAYLOAD_TOO_LARGE, b"")
                        .await?;
                    send.finish()?;
                    return Ok(());
                }
                body.extend_from_slice(frame.payload.as_ref());
            }
            FRAME_HEADERS => {
                if saw_trailers {
                    abort_stream_with_code(&mut send, &mut recv, H3_FRAME_UNEXPECTED).await?;
                    return Ok(());
                }
                let decoded_trailers = match ctx
                    .qpack
                    .decode_trailers(stream_id, frame.payload.as_ref(), ctx.settings.read_timeout)
                    .await
                {
                    Ok(decoded) => decoded,
                    Err(err) => {
                        abort_stream_with_code(&mut send, &mut recv, err.code()).await?;
                        return Ok(());
                    }
                };
                trailers = Some(decoded_trailers);
                saw_trailers = true;
            }
            _ => {
                if let Err(close) = crate::protocol::validate_message_stream_frame(frame.ty) {
                    abort_stream_with_code(&mut send, &mut recv, close.code).await?;
                    return Ok(());
                }
            }
        }
    }
    if let Some(content_length) = request_content_length {
        if content_length != body.len() as u64 {
            warn!(
                expected = content_length,
                actual = body.len(),
                "qpx-h3 rejected Content-Length mismatch"
            );
            abort_stream_with_code(&mut send, &mut recv, H3_MESSAGE_ERROR).await?;
            return Ok(());
        }
    }

    let request_method = decoded.request.method().clone();
    let response = handler
        .handle_request(
            Request {
                head: decoded.request,
                body: body.freeze(),
                trailers,
                protocol,
            },
            ctx.conn_info,
        )
        .await?;

    for interim in &response.interim {
        let mut interim = interim.clone();
        sanitize_interim_response_for_h3(&mut interim)?;
        let payload = encode_response_head(&interim);
        write_frame(&mut send, FRAME_HEADERS, &payload).await?;
    }

    let (response_parts, response_body) = response.response.into_parts();
    let mut response_body = response_body;
    let mut response_head = http::Response::from_parts(response_parts, ());
    let body_allowed =
        sanitize_response_for_h3(&mut response_head, &mut response_body, &request_method)?;
    let head_payload = encode_response_head(&response_head);
    write_frame(&mut send, FRAME_HEADERS, &head_payload).await?;
    if !response_body.is_empty() {
        write_frame(&mut send, FRAME_DATA, response_body.as_ref()).await?;
    }
    if body_allowed {
        if let Some(trailers) = response.trailers.as_ref() {
            let mut trailers = trailers.clone();
            sanitize_trailers_for_h3(&mut trailers)?;
            let payload = encode_trailers(&trailers);
            write_frame(&mut send, FRAME_HEADERS, &payload).await?;
        }
    }
    send.finish()?;
    Ok(())
}

fn is_client_initiated_bidi_stream_id(stream_id: u64) -> bool {
    stream_id & 0b11 == 0
}

fn close_connection(conn: &quinn::Connection, close: ConnectionClose) {
    warn!(code = close.code, message = %close.message, "qpx-h3 closing connection");
    if let Ok(code) = quinn::VarInt::from_u64(close.code) {
        conn.close(code, close.message.as_bytes());
    } else {
        conn.close(
            quinn::VarInt::from_u32(H3_MESSAGE_ERROR as u32),
            b"invalid close code",
        );
    }
}

async fn read_frame_with_known_type(
    recv: &mut quinn::RecvStream,
    frame_type: u64,
    read_timeout: Duration,
    max_payload_bytes: usize,
) -> Result<Frame> {
    let len = timeout(read_timeout, read_varint(recv))
        .await
        .map_err(|_| anyhow!("timed out reading frame length"))??
        .ok_or_else(|| anyhow!("truncated frame length"))?;
    if len > max_payload_bytes as u64 {
        return Err(anyhow!(
            "HTTP/3 frame 0x{frame_type:x} payload length {len} exceeds limit {max_payload_bytes}"
        ));
    }
    let len = len as usize;
    let mut payload = vec![0u8; len];
    timeout(read_timeout, recv.read_exact(&mut payload))
        .await
        .map_err(|_| anyhow!("timed out reading frame payload"))??;
    Ok(Frame {
        ty: frame_type,
        payload: Bytes::from(payload),
    })
}

fn field_section_limit(settings: &Settings) -> usize {
    settings.max_field_section_size.min(usize::MAX as u64) as usize
}

async fn send_simple_response(
    send: &mut quinn::SendStream,
    status: http::StatusCode,
    body: &[u8],
) -> Result<()> {
    let response = http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())
        .expect("static response");
    let head = encode_response_head(&response);
    write_frame(send, FRAME_HEADERS, &head).await?;
    if !body.is_empty() {
        write_frame(send, FRAME_DATA, body).await?;
    }
    Ok(())
}

fn parse_protocol(protocol: &str) -> Protocol {
    match protocol {
        "connect-udp" => Protocol::ConnectUdp,
        "webtransport" => Protocol::WebTransport,
        other => Protocol::Other(other.to_string()),
    }
}

async fn abort_stream_with_code(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    code: u64,
) -> Result<()> {
    let code =
        quinn::VarInt::from_u64(code).map_err(|_| anyhow!("invalid HTTP/3 application error"))?;
    recv.stop(code)?;
    send.reset(code)?;
    Ok(())
}

fn extract_tls_sni(conn: &quinn::Connection) -> Option<Arc<str>> {
    conn.handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|hs| hs.server_name.clone())
        .map(Arc::<str>::from)
}

fn extract_peer_certificates(conn: &quinn::Connection) -> Option<Arc<Vec<Vec<u8>>>> {
    let identity = conn.peer_identity()?;
    let certs = identity
        .downcast::<Vec<quinn::rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    Some(Arc::new(
        certs
            .iter()
            .map(|cert: &quinn::rustls::pki_types::CertificateDer<'static>| cert.as_ref().to_vec())
            .collect::<Vec<_>>(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::sanitize_streaming_response_head_for_h3;

    #[test]
    fn sanitize_response_strips_forbidden_fields_and_reconciles_length() {
        let mut response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONNECTION, "close")
            .header(http::header::TE, "trailers")
            .header(http::header::TRANSFER_ENCODING, "chunked")
            .header(http::header::CONTENT_LENGTH, "999")
            .body(())
            .expect("response");
        let mut body = Bytes::from_static(b"hello");

        sanitize_response_for_h3(&mut response, &mut body, &http::Method::GET).expect("sanitize");

        assert!(!response.headers().contains_key(http::header::CONNECTION));
        assert!(!response.headers().contains_key(http::header::TE));
        assert!(!response
            .headers()
            .contains_key(http::header::TRANSFER_ENCODING));
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("5")
        );
        assert_eq!(body, Bytes::from_static(b"hello"));
    }

    #[test]
    fn sanitize_response_preserves_head_content_length_without_body() {
        let mut response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_LENGTH, "42")
            .body(())
            .expect("response");
        let mut body = Bytes::from_static(b"not serialized");

        sanitize_response_for_h3(&mut response, &mut body, &http::Method::HEAD).expect("sanitize");

        assert!(body.is_empty());
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("42")
        );
    }

    #[test]
    fn sanitize_response_removes_body_framing_for_forbidden_statuses() {
        for status in [
            http::StatusCode::NO_CONTENT,
            http::StatusCode::RESET_CONTENT,
        ] {
            let mut response = http::Response::builder()
                .status(status)
                .header(http::header::CONTENT_LENGTH, "7")
                .body(())
                .expect("response");
            let mut body = Bytes::from_static(b"payload");

            sanitize_response_for_h3(&mut response, &mut body, &http::Method::GET)
                .expect("sanitize");

            assert!(body.is_empty(), "status {status} must not carry DATA");
            assert!(
                !response
                    .headers()
                    .contains_key(http::header::CONTENT_LENGTH),
                "status {status} must not carry Content-Length"
            );
        }
    }

    #[test]
    fn sanitize_response_rejects_informational_final_status() {
        let mut response = http::Response::builder()
            .status(http::StatusCode::EARLY_HINTS)
            .body(())
            .expect("response");
        let mut body = Bytes::new();

        let err = sanitize_response_for_h3(&mut response, &mut body, &http::Method::GET)
            .expect_err("1xx final response must fail");
        assert!(err.to_string().contains("must not be informational"));
    }

    #[test]
    fn sanitize_interim_and_trailers_strip_forbidden_fields() {
        let mut interim = http::Response::builder()
            .status(http::StatusCode::CONTINUE)
            .header(http::header::CONNECTION, "close")
            .header(http::header::TE, "trailers")
            .header(http::header::TRAILER, "x-end")
            .header(http::header::CONTENT_LENGTH, "0")
            .body(())
            .expect("interim");
        sanitize_interim_response_for_h3(&mut interim).expect("sanitize interim");
        assert!(!interim.headers().contains_key(http::header::CONNECTION));
        assert!(!interim.headers().contains_key(http::header::TE));
        assert!(!interim.headers().contains_key(http::header::TRAILER));
        assert!(!interim.headers().contains_key(http::header::CONTENT_LENGTH));

        let mut trailers = http::HeaderMap::new();
        trailers.insert(http::header::TE, "trailers".parse().unwrap());
        trailers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        trailers.insert(http::header::CONTENT_LENGTH, "0".parse().unwrap());
        trailers.insert(
            http::header::AUTHORIZATION,
            "Bearer secret".parse().unwrap(),
        );
        trailers.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        trailers.insert("x-safe-trailer", "ok".parse().unwrap());
        sanitize_trailers_for_h3(&mut trailers).expect("sanitize trailers");
        assert!(!trailers.contains_key(http::header::TE));
        assert!(!trailers.contains_key(http::header::TRANSFER_ENCODING));
        assert!(!trailers.contains_key(http::header::CONTENT_LENGTH));
        assert!(!trailers.contains_key(http::header::AUTHORIZATION));
        assert!(!trailers.contains_key(http::header::CONTENT_TYPE));
        assert_eq!(
            trailers
                .get("x-safe-trailer")
                .and_then(|value| value.to_str().ok()),
            Some("ok")
        );
    }

    #[test]
    fn sanitize_interim_rejects_final_status_in_interim_slot() {
        let mut interim = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .expect("interim");
        let err = sanitize_interim_response_for_h3(&mut interim).expect_err("invalid interim");
        assert!(err.to_string().contains("informational"));
    }

    #[test]
    fn sanitize_response_reports_trailers_forbidden_for_no_body_status() {
        let mut response = http::Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .body(())
            .expect("response");
        let mut body = Bytes::from_static(b"ignored");
        let body_allowed = sanitize_response_for_h3(&mut response, &mut body, &http::Method::GET)
            .expect("sanitize");
        assert!(!body_allowed);
        assert!(body.is_empty());
    }

    #[test]
    fn sanitize_streaming_response_strips_framing_metadata() {
        let mut response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_LENGTH, "99")
            .header(http::header::TRAILER, "x-end")
            .header(http::header::TE, "trailers")
            .body(())
            .expect("response");

        let body_allowed =
            sanitize_streaming_response_head_for_h3(&mut response).expect("sanitize");

        assert_eq!(body_allowed, Some(true));
        assert!(!response
            .headers()
            .contains_key(http::header::CONTENT_LENGTH));
        assert!(!response.headers().contains_key(http::header::TRAILER));
        assert!(!response.headers().contains_key(http::header::TE));
    }
}
