use super::registry::SessionRegistry;
use crate::protocol::{
    ConnectionClose, FRAME_SETTINGS, H3_CLOSED_CRITICAL_STREAM, H3_FRAME_UNEXPECTED, H3_ID_ERROR,
    H3_MESSAGE_ERROR, H3_MISSING_SETTINGS, H3_SETTINGS_ERROR, H3_STREAM_CREATION_ERROR,
    PeerControlState, PeerSettings, STREAM_CONTROL, STREAM_PUSH, STREAM_QPACK_DECODER,
    STREAM_QPACK_ENCODER, STREAM_WEBTRANSPORT_BIDI, STREAM_WEBTRANSPORT_UNI,
    decode_settings_frame_from_reader, discard_frame_payload, read_frame_header, read_varint,
    write_frame, write_varint,
};
use crate::qpack::QpackConnection;
use crate::server::{Protocol, Settings};
use crate::transport::{BidiStream, RequestStream, UniRecvStream};
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

#[derive(Clone, Copy)]
struct ClientDriverLimits {
    read_timeout: Duration,
    max_control_frame_payload_bytes: usize,
    max_concurrent_streams_per_connection: usize,
}

pub(super) fn spawn_client_driver(
    connection: quinn::Connection,
    registry: SessionRegistry,
    qpack: QpackConnection,
    control_state: PeerControlState,
    settings: &Settings,
) -> JoinHandle<()> {
    let limits = ClientDriverLimits {
        read_timeout: settings.read_timeout,
        max_control_frame_payload_bytes: settings.max_control_frame_payload_bytes,
        max_concurrent_streams_per_connection: settings
            .max_concurrent_streams_per_connection
            .max(1),
    };
    tokio::spawn(async move {
        if let Err(err) =
            drive_connection(connection.clone(), registry, qpack, control_state, limits).await
        {
            tracing::warn!(error = ?err, "qpx-h3 client driver stopped");
        }
    })
}

pub(super) fn validate_peer_settings_for_protocol(
    connection: &quinn::Connection,
    peer_settings: &PeerSettings,
    protocol: Option<&Protocol>,
    close_on_error: bool,
) -> Result<()> {
    let err = if protocol.is_some() && !peer_settings.enable_extended_connect {
        Some(anyhow!("peer did not negotiate HTTP/3 extended CONNECT"))
    } else if protocol == Some(&Protocol::ConnectUdp) && !peer_settings.enable_datagram {
        Some(anyhow!("peer did not negotiate HTTP/3 datagrams"))
    } else if protocol == Some(&Protocol::WebTransport)
        && (!peer_settings.enable_webtransport || !peer_settings.enable_extended_connect)
    {
        Some(anyhow!("peer did not negotiate WebTransport over HTTP/3"))
    } else if protocol == Some(&Protocol::WebTransport)
        && peer_settings.max_webtransport_sessions == 0
    {
        Some(anyhow!(
            "peer advertised zero WebTransport sessions for this HTTP/3 connection"
        ))
    } else {
        None
    };
    if let Some(err) = err {
        if close_on_error {
            return fail_client_setup(connection, err);
        }
        return Err(err);
    }
    Ok(())
}

pub(super) fn fail_client_setup<T>(
    connection: &quinn::Connection,
    err: anyhow::Error,
) -> Result<T> {
    connection.close(
        quinn::VarInt::from_u32(H3_MESSAGE_ERROR as u32),
        b"qpx-h3 client setup failed",
    );
    Err(err)
}

pub(super) async fn open_critical_streams(
    connection: &quinn::Connection,
    settings: &Settings,
) -> Result<(quinn::SendStream, quinn::SendStream, quinn::SendStream)> {
    let timeout_dur = settings.read_timeout;
    let mut control = timeout(timeout_dur, connection.open_uni())
        .await
        .map_err(|_| anyhow!("HTTP/3 control stream open timed out"))?
        .map_err(anyhow::Error::from)?;
    timeout(timeout_dur, write_varint(&mut control, STREAM_CONTROL))
        .await
        .map_err(|_| anyhow!("HTTP/3 control stream type write timed out"))??;
    let payload = crate::server::encode_settings(settings);
    timeout(
        timeout_dur,
        write_frame(&mut control, FRAME_SETTINGS, &payload),
    )
    .await
    .map_err(|_| anyhow!("HTTP/3 SETTINGS frame write timed out"))??;
    timeout(timeout_dur, control.flush())
        .await
        .map_err(|_| anyhow!("HTTP/3 control stream flush timed out"))?
        .map_err(anyhow::Error::from)?;

    let mut encoder = timeout(timeout_dur, connection.open_uni())
        .await
        .map_err(|_| anyhow!("QPACK encoder stream open timed out"))?
        .map_err(anyhow::Error::from)?;
    timeout(
        timeout_dur,
        write_varint(&mut encoder, STREAM_QPACK_ENCODER),
    )
    .await
    .map_err(|_| anyhow!("QPACK encoder stream type write timed out"))??;
    timeout(timeout_dur, encoder.flush())
        .await
        .map_err(|_| anyhow!("QPACK encoder stream flush timed out"))?
        .map_err(anyhow::Error::from)?;

    let mut decoder = timeout(timeout_dur, connection.open_uni())
        .await
        .map_err(|_| anyhow!("QPACK decoder stream open timed out"))?
        .map_err(anyhow::Error::from)?;
    timeout(
        timeout_dur,
        write_varint(&mut decoder, STREAM_QPACK_DECODER),
    )
    .await
    .map_err(|_| anyhow!("QPACK decoder stream type write timed out"))??;
    timeout(timeout_dur, decoder.flush())
        .await
        .map_err(|_| anyhow!("QPACK decoder stream flush timed out"))?
        .map_err(anyhow::Error::from)?;

    Ok((control, encoder, decoder))
}

pub(super) async fn recv_response_with_interim(
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
    request_stream
        .recv_response_head()
        .await?
        .ok_or_else(|| anyhow!("response stream closed before headers"))
}

async fn drive_connection(
    connection: quinn::Connection,
    registry: SessionRegistry,
    qpack: QpackConnection,
    control_state: PeerControlState,
    limits: ClientDriverLimits,
) -> Result<()> {
    let stream_semaphore = Arc::new(Semaphore::new(limits.max_concurrent_streams_per_connection));
    loop {
        tokio::select! {
            accepted = connection.accept_uni() => {
                let mut recv = match accepted {
                    Ok(recv) => recv,
                    Err(quinn::ConnectionError::ApplicationClosed(_))
                    | Err(quinn::ConnectionError::LocallyClosed)
                    | Err(quinn::ConnectionError::TimedOut)
                    | Err(quinn::ConnectionError::ConnectionClosed(_))
                    | Err(quinn::ConnectionError::Reset) => break,
                    Err(err) => return Err(err.into()),
                };
                let permit = match stream_semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(tokio::sync::TryAcquireError::NoPermits) => {
                        stop_recv_with_code(&mut recv, H3_STREAM_CREATION_ERROR);
                        continue;
                    }
                    Err(tokio::sync::TryAcquireError::Closed) => break,
                };
                let registry = registry.clone();
                let qpack = qpack.clone();
                let control_state = control_state.clone();
                let conn = connection.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = route_uni_stream(
                        recv,
                        registry,
                        qpack,
                        control_state,
                        limits,
                    )
                    .await
                    {
                        close_connection(&conn, err);
                    }
                });
            }
            accepted = connection.accept_bi() => {
                let (mut send, mut recv) = match accepted {
                    Ok(stream) => stream,
                    Err(quinn::ConnectionError::ApplicationClosed(_))
                    | Err(quinn::ConnectionError::LocallyClosed)
                    | Err(quinn::ConnectionError::TimedOut)
                    | Err(quinn::ConnectionError::ConnectionClosed(_))
                    | Err(quinn::ConnectionError::Reset) => break,
                    Err(err) => return Err(err.into()),
                };
                let permit = match stream_semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(tokio::sync::TryAcquireError::NoPermits) => {
                        abort_bidi_with_code(&mut send, &mut recv, H3_STREAM_CREATION_ERROR);
                        continue;
                    }
                    Err(tokio::sync::TryAcquireError::Closed) => break,
                };
                let registry = registry.clone();
                let conn = connection.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = route_bidi_stream(send, recv, registry, limits.read_timeout).await {
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
    limits: ClientDriverLimits,
) -> std::result::Result<(), ConnectionClose> {
    let Some(stream_type) =
        read_varint_with_timeout(&mut recv, limits.read_timeout, "unidirectional stream type")
            .await?
    else {
        return Ok(());
    };
    match stream_type {
        STREAM_WEBTRANSPORT_UNI => {
            let session_id =
                read_varint_with_timeout(&mut recv, limits.read_timeout, "WebTransport session id")
                    .await?
                    .ok_or_else(|| {
                        ConnectionClose::new(H3_MESSAGE_ERROR, "missing WebTransport session id")
                    })?;
            if !is_client_initiated_bidi_stream_id(session_id) {
                return Err(ConnectionClose::new(
                    H3_ID_ERROR,
                    "WebTransport associated stream used invalid session id",
                ));
            }
            let tx = registry.uni_sender(session_id).await;
            if let Some(tx) = tx {
                match tx.try_send(UniRecvStream::new(recv)) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(stream))
                    | Err(mpsc::error::TrySendError::Closed(stream)) => {
                        stream.stop_with_code(H3_STREAM_CREATION_ERROR);
                    }
                }
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
                let Some((frame_ty, frame_len)) =
                    timeout(limits.read_timeout, read_frame_header(&mut recv))
                        .await
                        .map_err(|_| {
                            ConnectionClose::new(
                                H3_CLOSED_CRITICAL_STREAM,
                                "control stream timed out",
                            )
                        })?
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
                    if frame_ty != FRAME_SETTINGS {
                        return Err(ConnectionClose::new(
                            H3_MISSING_SETTINGS,
                            "HTTP/3 control stream did not begin with SETTINGS",
                        ));
                    }
                    let peer_settings = timeout(
                        limits.read_timeout,
                        decode_settings_frame_from_reader(
                            &mut recv,
                            frame_len,
                            limits.max_control_frame_payload_bytes,
                        ),
                    )
                    .await
                    .map_err(|_| {
                        ConnectionClose::new(H3_CLOSED_CRITICAL_STREAM, "control stream timed out")
                    })?
                    .map_err(|err| ConnectionClose::new(H3_SETTINGS_ERROR, err.to_string()))?;
                    control_state.register_settings(peer_settings).await?;
                    saw_settings = true;
                    continue;
                }
                if crate::protocol::control_frame_payload_is_known(frame_ty) {
                    timeout(
                        limits.read_timeout,
                        control_state.handle_control_frame_from_reader(
                            &mut recv,
                            frame_ty,
                            frame_len,
                            limits.max_control_frame_payload_bytes,
                            true,
                        ),
                    )
                    .await
                    .map_err(|_| {
                        ConnectionClose::new(H3_CLOSED_CRITICAL_STREAM, "control stream timed out")
                    })??;
                } else {
                    control_state
                        .handle_control_frame(frame_ty, &[], true)
                        .await?;
                    timeout(
                        limits.read_timeout,
                        discard_frame_payload(
                            &mut recv,
                            frame_len,
                            limits.max_control_frame_payload_bytes,
                        ),
                    )
                    .await
                    .map_err(|_| {
                        ConnectionClose::new(H3_CLOSED_CRITICAL_STREAM, "control stream timed out")
                    })?
                    .map_err(|err| ConnectionClose::new(H3_MESSAGE_ERROR, err.to_string()))?;
                }
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
            discard_uni_stream(
                &mut recv,
                limits.max_control_frame_payload_bytes,
                limits.read_timeout,
                H3_CLOSED_CRITICAL_STREAM,
                "QPACK decoder stream",
            )
            .await?;
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
            ignore_unknown_uni_stream(
                &mut recv,
                limits.max_control_frame_payload_bytes,
                limits.read_timeout,
                "unknown server-initiated unidirectional stream",
            )
            .await;
        }
    }
    Ok(())
}

async fn route_bidi_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    registry: SessionRegistry,
    read_timeout: Duration,
) -> std::result::Result<(), ConnectionClose> {
    let Some(first) = read_varint_with_timeout(
        &mut recv,
        read_timeout,
        "server-initiated bidirectional stream type",
    )
    .await?
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
    let session_id = read_varint_with_timeout(&mut recv, read_timeout, "WebTransport session id")
        .await?
        .ok_or_else(|| ConnectionClose::new(H3_MESSAGE_ERROR, "missing WebTransport session id"))?;
    if !is_client_initiated_bidi_stream_id(session_id) {
        return Err(ConnectionClose::new(
            H3_ID_ERROR,
            "WebTransport associated stream used invalid session id",
        ));
    }
    let tx = registry.bidi_sender(session_id).await;
    if let Some(tx) = tx {
        match tx.try_send(BidiStream::new(send, recv)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(stream))
            | Err(mpsc::error::TrySendError::Closed(stream)) => {
                stream.abort_with_code(H3_STREAM_CREATION_ERROR);
            }
        }
    } else {
        return Err(ConnectionClose::new(
            H3_ID_ERROR,
            "WebTransport associated stream referenced unknown session",
        ));
    }
    Ok(())
}

async fn read_varint_with_timeout(
    recv: &mut quinn::RecvStream,
    read_timeout: Duration,
    label: &'static str,
) -> std::result::Result<Option<u64>, ConnectionClose> {
    timeout(read_timeout, read_varint(recv))
        .await
        .map_err(|_| ConnectionClose::new(H3_MESSAGE_ERROR, format!("{label} timed out")))?
        .map_err(|err| ConnectionClose::new(H3_MESSAGE_ERROR, err.to_string()))
}

async fn discard_uni_stream(
    recv: &mut quinn::RecvStream,
    max_bytes: usize,
    read_timeout: Duration,
    error_code: u64,
    label: &'static str,
) -> std::result::Result<(), ConnectionClose> {
    let mut discarded = 0usize;
    let mut buf = [0u8; 4096];
    loop {
        let n = timeout(read_timeout, recv.read(&mut buf))
            .await
            .map_err(|_| ConnectionClose::new(error_code, format!("{label} timed out")))?
            .map_err(|err| ConnectionClose::new(error_code, err.to_string()))?;
        let Some(n) = n else {
            return Ok(());
        };
        discarded = discarded.saturating_add(n);
        if discarded > max_bytes {
            return Err(ConnectionClose::new(
                error_code,
                format!("{label} exceeded discard limit"),
            ));
        }
    }
}

async fn ignore_unknown_uni_stream(
    recv: &mut quinn::RecvStream,
    max_bytes: usize,
    read_timeout: Duration,
    label: &'static str,
) {
    if let Err(err) = discard_uni_stream(
        recv,
        max_bytes,
        read_timeout,
        H3_STREAM_CREATION_ERROR,
        label,
    )
    .await
    {
        tracing::debug!(
            error = %err.message,
            code = err.code,
            "{label} ignored after bounded discard stopped"
        );
    }
}

fn stop_recv_with_code(recv: &mut quinn::RecvStream, code: u64) {
    if let Ok(code) = quinn::VarInt::from_u64(code) {
        let _ = recv.stop(code);
    }
}

fn abort_bidi_with_code(send: &mut quinn::SendStream, recv: &mut quinn::RecvStream, code: u64) {
    stop_recv_with_code(recv, code);
    if let Ok(code) = quinn::VarInt::from_u64(code) {
        let _ = send.reset(code);
    }
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
