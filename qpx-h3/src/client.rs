use crate::protocol::{
    decode_settings_frame, read_frame, read_varint, write_frame, write_varint, ConnectionClose,
    PeerControlState, FRAME_DATA, FRAME_HEADERS, FRAME_SETTINGS, H3_CLOSED_CRITICAL_STREAM,
    H3_FRAME_UNEXPECTED, H3_ID_ERROR, H3_MESSAGE_ERROR, H3_MISSING_SETTINGS, H3_SETTINGS_ERROR,
    H3_STREAM_CREATION_ERROR, STREAM_CONTROL, STREAM_PUSH, STREAM_QPACK_DECODER,
    STREAM_QPACK_ENCODER, STREAM_WEBTRANSPORT_BIDI, STREAM_WEBTRANSPORT_UNI,
};
use crate::qpack::{encode_request_head, QpackConnection};
use crate::server::{Protocol, Settings};
use crate::transport::{
    BidiStream, DatagramDispatch, OpenStreams, RequestStream, StreamDatagrams, UniRecvStream,
};
use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::{timeout, Duration};

pub struct ExtendedConnectStream {
    pub interim: Vec<http::Response<()>>,
    pub response: http::Response<()>,
    pub request_stream: RequestStream,
    pub datagrams: Option<StreamDatagrams>,
    pub opener: Option<OpenStreams>,
    pub associated_bidi: Option<mpsc::UnboundedReceiver<BidiStream>>,
    pub associated_uni: Option<mpsc::UnboundedReceiver<UniRecvStream>>,
    pub _critical_streams: Option<(quinn::SendStream, quinn::SendStream)>,
    pub _endpoint: quinn::Endpoint,
    pub driver: JoinHandle<()>,
    pub datagram_task: Option<JoinHandle<()>>,
    #[doc(hidden)]
    pub _connection_use: ClientConnectionUse,
}

struct SessionIngress {
    bidi_tx: mpsc::UnboundedSender<BidiStream>,
    uni_tx: mpsc::UnboundedSender<UniRecvStream>,
}

type SessionRegistry = Arc<Mutex<HashMap<u64, SessionIngress>>>;

static ACTIVE_CLIENT_CONNECTIONS: OnceLock<StdMutex<HashSet<usize>>> = OnceLock::new();

#[doc(hidden)]
pub struct ClientConnectionUse {
    stable_id: usize,
    abort_handles: Vec<AbortHandle>,
    connection: quinn::Connection,
}

impl ClientConnectionUse {
    fn acquire(connection: &quinn::Connection) -> Result<Self> {
        let stable_id = connection.stable_id();
        let active = ACTIVE_CLIENT_CONNECTIONS.get_or_init(|| StdMutex::new(HashSet::new()));
        let mut guard = active
            .lock()
            .map_err(|_| anyhow!("qpx-h3 client connection registry poisoned"))?;
        if !guard.insert(stable_id) {
            return Err(anyhow!(
                "qpx-h3 client connection is already owned by an active HTTP/3 driver"
            ));
        }
        Ok(Self {
            stable_id,
            abort_handles: Vec::new(),
            connection: connection.clone(),
        })
    }

    fn set_abort_handles(
        &mut self,
        driver: &JoinHandle<()>,
        datagram_task: Option<&JoinHandle<()>>,
    ) {
        self.abort_handles.clear();
        self.abort_handles.push(driver.abort_handle());
        if let Some(datagram_task) = datagram_task {
            self.abort_handles.push(datagram_task.abort_handle());
        }
    }
}

impl Drop for ClientConnectionUse {
    fn drop(&mut self) {
        for handle in self.abort_handles.drain(..) {
            handle.abort();
        }
        self.connection.close(
            quinn::VarInt::from_u32(0x100),
            b"qpx-h3 client connection owner dropped",
        );
        if let Some(active) = ACTIVE_CLIENT_CONNECTIONS.get() {
            if let Ok(mut guard) = active.lock() {
                guard.remove(&self.stable_id);
            }
        }
    }
}

pub async fn open_extended_connect_stream(
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    request: http::Request<()>,
    protocol: Option<Protocol>,
    settings: Settings,
    timeout_dur: Duration,
) -> Result<ExtendedConnectStream> {
    let mut connection_use = ClientConnectionUse::acquire(&connection)?;
    let (control, encoder, decoder) = match open_critical_streams(&connection, &settings).await {
        Ok(streams) => streams,
        Err(err) => return fail_client_setup(&connection, err),
    };
    let qpack = QpackConnection::new(
        decoder,
        settings.qpack_max_table_capacity,
        settings.qpack_max_blocked_streams,
        settings.max_field_section_size,
        settings.max_encoder_stream_buffer_bytes,
        settings.read_timeout,
    );
    let control_state = PeerControlState::default();

    let registry: SessionRegistry = Arc::new(Mutex::new(HashMap::new()));
    let datagram_dispatch = settings
        .enable_datagram
        .then(|| DatagramDispatch::new(connection.clone(), 64));
    let datagram_task = datagram_dispatch.as_ref().map(|dispatch| {
        let dispatch = dispatch.clone();
        tokio::spawn(async move { dispatch.run().await })
    });

    let driver = {
        let connection = connection.clone();
        let registry = registry.clone();
        let qpack = qpack.clone();
        let control_state = control_state.clone();
        let max_control_frame_payload_bytes = settings.max_control_frame_payload_bytes;
        tokio::spawn(async move {
            if let Err(err) = drive_connection(
                connection.clone(),
                registry,
                qpack,
                control_state,
                max_control_frame_payload_bytes,
            )
            .await
            {
                tracing::warn!(error = ?err, "qpx-h3 client driver stopped");
            }
        })
    };
    connection_use.set_abort_handles(&driver, datagram_task.as_ref());

    let peer_settings = match timeout(timeout_dur, control_state.wait_for_settings()).await {
        Ok(settings) => settings,
        Err(_) => {
            return fail_client_setup(
                &connection,
                anyhow!("timed out waiting for peer HTTP/3 SETTINGS"),
            );
        }
    };
    if protocol.is_some() && !peer_settings.enable_extended_connect {
        return fail_client_setup(
            &connection,
            anyhow!("peer did not negotiate HTTP/3 extended CONNECT"),
        );
    }
    if protocol == Some(Protocol::ConnectUdp) && !peer_settings.enable_datagram {
        return fail_client_setup(
            &connection,
            anyhow!("peer did not negotiate HTTP/3 datagrams"),
        );
    }
    if protocol == Some(Protocol::WebTransport)
        && (!peer_settings.enable_webtransport || !peer_settings.enable_extended_connect)
    {
        return fail_client_setup(
            &connection,
            anyhow!("peer did not negotiate WebTransport over HTTP/3"),
        );
    }
    if protocol == Some(Protocol::WebTransport) && peer_settings.max_webtransport_sessions == 0 {
        return fail_client_setup(
            &connection,
            anyhow!("peer advertised zero WebTransport sessions for this HTTP/3 connection"),
        );
    }

    let opener = OpenStreams::new(connection.clone());
    let (bidi_send, bidi_recv) = match timeout(timeout_dur, connection.open_bi()).await {
        Ok(Ok(streams)) => streams,
        Ok(Err(err)) => return fail_client_setup(&connection, err.into()),
        Err(_) => {
            return fail_client_setup(&connection, anyhow!("extended CONNECT open_bi timed out"))
        }
    };
    let stream_id: u64 = bidi_send.id().into();
    if let Some(goaway_id) = control_state.goaway_id().await {
        if stream_id >= goaway_id {
            return fail_client_setup(
                &connection,
                anyhow!(
                    "peer GOAWAY disallows opening request stream {stream_id} (limit {goaway_id})"
                ),
            );
        }
    }
    let protocol_name = protocol.as_ref().map(Protocol::as_str);
    let payload = match encode_request_head(&request, protocol_name) {
        Ok(payload) => payload,
        Err(err) => return fail_client_setup(&connection, err),
    };
    let mut request_stream = RequestStream::new_client_request(
        bidi_send,
        bidi_recv,
        stream_id,
        qpack.clone(),
        timeout_dur,
        settings.max_frame_payload_bytes,
    );
    if let Err(err) = request_stream.send_headers(&payload).await {
        return fail_client_setup(&connection, err);
    }

    let webtransport_session_id = match protocol {
        Some(Protocol::WebTransport) => Some(stream_id),
        _ => None,
    };
    let (mut associated_bidi, mut associated_uni) = if webtransport_session_id.is_some() {
        let (bidi_tx, bidi_rx) = mpsc::unbounded_channel();
        let (uni_tx, uni_rx) = mpsc::unbounded_channel();
        registry
            .lock()
            .await
            .insert(stream_id, SessionIngress { bidi_tx, uni_tx });
        (Some(bidi_rx), Some(uni_rx))
    } else {
        (None, None)
    };

    let (interim, response) =
        match recv_response_with_interim(&mut request_stream, timeout_dur).await {
            Ok(response) => response,
            Err(err) => return fail_client_setup(&connection, err),
        };
    let webtransport_established =
        webtransport_session_id.is_some() && response.status().is_success();
    if !webtransport_established {
        if let Some(session_id) = webtransport_session_id {
            registry.lock().await.remove(&session_id);
        }
        associated_bidi = None;
        associated_uni = None;
    }

    let datagrams = if settings.enable_datagram
        && peer_settings.enable_datagram
        && response.status().is_success()
    {
        let Some(dispatch) = datagram_dispatch else {
            return fail_client_setup(&connection, anyhow!("missing datagram dispatch"));
        };
        Some(dispatch.register_stream(stream_id).await)
    } else {
        None
    };

    Ok(ExtendedConnectStream {
        interim,
        response,
        request_stream,
        datagrams,
        opener: webtransport_established.then_some(opener),
        associated_bidi,
        associated_uni,
        _critical_streams: Some((control, encoder)),
        _endpoint: endpoint,
        driver,
        datagram_task,
        _connection_use: connection_use,
    })
}

fn fail_client_setup<T>(connection: &quinn::Connection, err: anyhow::Error) -> Result<T> {
    connection.close(
        quinn::VarInt::from_u32(H3_MESSAGE_ERROR as u32),
        b"qpx-h3 client setup failed",
    );
    Err(err)
}

async fn open_critical_streams(
    connection: &quinn::Connection,
    settings: &Settings,
) -> Result<(quinn::SendStream, quinn::SendStream, quinn::SendStream)> {
    let mut control = connection.open_uni().await?;
    write_varint(&mut control, STREAM_CONTROL).await?;
    let payload = crate::server::encode_settings(settings);
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

async fn recv_response_with_interim(
    request_stream: &mut RequestStream,
    timeout_dur: Duration,
) -> Result<(Vec<http::Response<()>>, http::Response<()>)> {
    let mut interim = Vec::new();
    loop {
        let response = timeout(timeout_dur, recv_response_head(request_stream))
            .await
            .map_err(|_| anyhow!("extended CONNECT response timed out"))??;
        if response.status().is_informational() {
            if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
                request_stream.abort_with_code(H3_FRAME_UNEXPECTED);
                return Err(anyhow!("HTTP/3 interim response must not use 101"));
            }
            interim.push(response);
            continue;
        }
        return Ok((interim, response));
    }
}

async fn recv_response_head(request_stream: &mut RequestStream) -> Result<http::Response<()>> {
    loop {
        let Some(frame) = request_stream.recv_frame().await? else {
            return Err(anyhow!("response stream closed before headers"));
        };
        if frame.ty == FRAME_DATA {
            request_stream.abort_with_code(H3_FRAME_UNEXPECTED);
            return Err(anyhow!(
                "received DATA before response HEADERS on HTTP/3 stream"
            ));
        }
        if let Err(close) = crate::protocol::validate_message_stream_frame(frame.ty) {
            request_stream.abort_with_code(close.code);
            return Err(anyhow!(close.message));
        }
        if frame.ty != FRAME_HEADERS {
            continue;
        }
        return request_stream
            .decode_response_head(frame.payload.as_ref())
            .await
            .map_err(|err| {
                request_stream.abort_with_code(err.code());
                anyhow!(err.to_string())
            });
    }
}

async fn drive_connection(
    connection: quinn::Connection,
    registry: SessionRegistry,
    qpack: QpackConnection,
    control_state: PeerControlState,
    max_control_frame_payload_bytes: usize,
) -> Result<()> {
    loop {
        tokio::select! {
            accepted = connection.accept_uni() => {
                let recv = match accepted {
                    Ok(recv) => recv,
                    Err(quinn::ConnectionError::ApplicationClosed(_))
                    | Err(quinn::ConnectionError::LocallyClosed)
                    | Err(quinn::ConnectionError::TimedOut)
                    | Err(quinn::ConnectionError::ConnectionClosed(_))
                    | Err(quinn::ConnectionError::Reset) => break,
                    Err(err) => return Err(err.into()),
                };
                let registry = registry.clone();
                let qpack = qpack.clone();
                let control_state = control_state.clone();
                let conn = connection.clone();
                tokio::spawn(async move {
                    if let Err(err) = route_uni_stream(
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
            accepted = connection.accept_bi() => {
                let (send, recv) = match accepted {
                    Ok(stream) => stream,
                    Err(quinn::ConnectionError::ApplicationClosed(_))
                    | Err(quinn::ConnectionError::LocallyClosed)
                    | Err(quinn::ConnectionError::TimedOut)
                    | Err(quinn::ConnectionError::ConnectionClosed(_))
                    | Err(quinn::ConnectionError::Reset) => break,
                    Err(err) => return Err(err.into()),
                };
                let registry = registry.clone();
                let conn = connection.clone();
                tokio::spawn(async move {
                    if let Err(err) = route_bidi_stream(send, recv, registry).await {
                        close_connection(&conn, err);
                    }
                });
            }
        }
    }
    Ok(())
}

async fn route_uni_stream(
    mut recv: quinn::RecvStream,
    registry: SessionRegistry,
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
                            crate::protocol::H3_CLOSED_CRITICAL_STREAM
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
                    .handle_control_frame(frame.ty, frame.payload.as_ref(), true)
                    .await?;
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
                H3_STREAM_CREATION_ERROR,
                "HTTP/3 push streams were not negotiated",
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

async fn route_bidi_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    registry: SessionRegistry,
) -> std::result::Result<(), ConnectionClose> {
    let Some(first) = read_varint(&mut recv)
        .await
        .map_err(|err| ConnectionClose::new(H3_MESSAGE_ERROR, err.to_string()))?
    else {
        return Err(ConnectionClose::new(
            H3_STREAM_CREATION_ERROR,
            "server-initiated bidirectional stream without a stream type",
        ));
    };
    if first != STREAM_WEBTRANSPORT_BIDI {
        return Err(ConnectionClose::new(
            H3_STREAM_CREATION_ERROR,
            format!("server-initiated bidirectional stream type {first:#x} is not supported"),
        ));
    }
    let session_id = read_varint(&mut recv)
        .await
        .map_err(|err| ConnectionClose::new(H3_MESSAGE_ERROR, err.to_string()))?
        .ok_or_else(|| ConnectionClose::new(H3_MESSAGE_ERROR, "missing WebTransport session id"))?;
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
            .map(|entry| entry.bidi_tx.clone())
    };
    if let Some(tx) = tx {
        let _ = tx.send(BidiStream::new(send, recv));
    } else {
        return Err(ConnectionClose::new(
            H3_ID_ERROR,
            "WebTransport associated stream referenced unknown session",
        ));
    }
    Ok(())
}

fn is_client_initiated_bidi_stream_id(stream_id: u64) -> bool {
    stream_id & 0b11 == 0
}

fn close_connection(conn: &quinn::Connection, close: ConnectionClose) {
    tracing::warn!(code = close.code, message = %close.message, "qpx-h3 client closing connection");
    if let Ok(code) = quinn::VarInt::from_u64(close.code) {
        conn.close(code, close.message.as_bytes());
    } else {
        conn.close(
            quinn::VarInt::from_u32(H3_MESSAGE_ERROR as u32),
            b"invalid close code",
        );
    }
}
