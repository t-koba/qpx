use super::helpers::{
    abort_stream_with_code, field_section_limit, is_client_initiated_bidi_stream_id,
    parse_protocol, read_known_frame_len, request_stream_config, send_simple_response,
};
use super::registry::{WebTransportSessionIngress, WebTransportSessionRegistry};
use super::{ConnectionInfo, Protocol, Request, RequestHandler, Settings, WebTransportSession};
use crate::H3Result as Result;
use crate::protocol::{
    ConnectionClose, FRAME_HEADERS, FRAME_SETTINGS, H3_CLOSED_CRITICAL_STREAM, H3_FRAME_ERROR,
    H3_FRAME_UNEXPECTED, H3_ID_ERROR, H3_MESSAGE_ERROR, H3_MISSING_SETTINGS, H3_SETTINGS_ERROR,
    H3_STREAM_CREATION_ERROR, PeerControlState, PriorityUpdates, SETTING_ENABLE_CONNECT_PROTOCOL,
    SETTING_ENABLE_WEBTRANSPORT, SETTING_H3_DATAGRAM, SETTING_MAX_FIELD_SECTION_SIZE,
    SETTING_QPACK_MAX_BLOCKED_STREAMS, SETTING_QPACK_MAX_TABLE_CAPACITY,
    SETTING_WEBTRANSPORT_MAX_SESSIONS, STREAM_CONTROL, STREAM_PUSH, STREAM_QPACK_DECODER,
    STREAM_QPACK_ENCODER, STREAM_WEBTRANSPORT_BIDI, STREAM_WEBTRANSPORT_UNI,
    decode_settings_frame_from_reader, discard_frame_payload, read_frame_header, read_varint,
    write_frame, write_varint,
};
use crate::qpack::QpackConnection;
use crate::response::parse_content_length;
use crate::transport::{BidiStream, DatagramDispatch, OpenStreams, RequestStream, UniRecvStream};
use anyhow::anyhow;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::warn;

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
    let payload = encode_settings(settings);
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

pub(super) async fn consume_uni_stream(
    mut recv: quinn::RecvStream,
    registry: WebTransportSessionRegistry,
    qpack: QpackConnection,
    control_state: PeerControlState,
    max_control_frame_payload_bytes: usize,
    read_timeout: Duration,
) -> std::result::Result<(), ConnectionClose> {
    let Some(stream_type) = timeout(read_timeout, read_varint(&mut recv))
        .await
        .map_err(|_| {
            ConnectionClose::new(H3_MESSAGE_ERROR, "unidirectional stream type timed out")
        })?
        .map_err(|err| ConnectionClose::new(H3_MESSAGE_ERROR, err.to_string()))?
    else {
        return Ok(());
    };
    match stream_type {
        STREAM_CONTROL => {
            control_state.register_control_stream().await?;
            let mut saw_settings = false;
            loop {
                let Some((frame_ty, frame_len)) =
                    timeout(read_timeout, read_frame_header(&mut recv))
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
                            H3_CLOSED_CRITICAL_STREAM
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
                        read_timeout,
                        decode_settings_frame_from_reader(
                            &mut recv,
                            frame_len,
                            max_control_frame_payload_bytes,
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
                        read_timeout,
                        control_state.handle_control_frame_from_reader(
                            &mut recv,
                            frame_ty,
                            frame_len,
                            max_control_frame_payload_bytes,
                            false,
                        ),
                    )
                    .await
                    .map_err(|_| {
                        ConnectionClose::new(H3_CLOSED_CRITICAL_STREAM, "control stream timed out")
                    })??;
                } else {
                    control_state
                        .handle_control_frame(frame_ty, &[], false)
                        .await?;
                    timeout(
                        read_timeout,
                        discard_frame_payload(
                            &mut recv,
                            frame_len,
                            max_control_frame_payload_bytes,
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
        STREAM_WEBTRANSPORT_UNI => {
            let session_id = timeout(read_timeout, read_varint(&mut recv))
                .await
                .map_err(|_| {
                    ConnectionClose::new(H3_MESSAGE_ERROR, "WebTransport session id timed out")
                })?
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
            let tx = registry.uni_sender(session_id).await;
            if let Some(tx) = tx {
                match tx.try_send(UniRecvStream::new(recv)) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(stream))
                    | Err(mpsc::error::TrySendError::Closed(stream)) => {
                        stream.stop_with_code(crate::protocol::H3_STREAM_CREATION_ERROR);
                    }
                }
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
            discard_uni_stream(
                &mut recv,
                max_control_frame_payload_bytes,
                read_timeout,
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
                crate::protocol::H3_STREAM_CREATION_ERROR,
                "HTTP/3 push streams are not permitted from clients",
            ));
        }
        _ => {
            ignore_unknown_uni_stream(
                &mut recv,
                max_control_frame_payload_bytes,
                read_timeout,
                "unknown client-initiated unidirectional stream",
            )
            .await;
        }
    }
    Ok(())
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
        crate::protocol::H3_STREAM_CREATION_ERROR,
        label,
    )
    .await
    {
        tracing::debug!(error = %err.message, code = err.code, "{label} discarded with local stop");
        stop_recv_with_code(recv, crate::protocol::H3_STREAM_CREATION_ERROR);
    }
}

fn stop_recv_with_code(recv: &mut quinn::RecvStream, code: u64) {
    if let Ok(code) = quinn::VarInt::from_u64(code) {
        let _ = recv.stop(code);
    }
}

pub(super) struct RequestStreamContext {
    pub(super) conn_info: ConnectionInfo,
    pub(super) settings: Settings,
    pub(super) connection: quinn::Connection,
    pub(super) session_registry: WebTransportSessionRegistry,
    pub(super) datagram_dispatch: Option<Arc<DatagramDispatch>>,
    pub(super) qpack: QpackConnection,
    pub(super) control: PeerControlState,
}

pub(super) async fn handle_request_stream<H: RequestHandler>(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    handler: H,
    ctx: RequestStreamContext,
) -> Result<()> {
    let via_received_by = handler.via_received_by();
    let first_type = match timeout(ctx.settings.read_timeout, read_varint(&mut recv)).await {
        Ok(result) => result?,
        Err(_) => {
            send_simple_response(
                &mut send,
                http::StatusCode::REQUEST_TIMEOUT,
                b"",
                via_received_by.as_str(),
            )
            .await?;
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
        let tx = ctx.session_registry.bidi_sender(session_id).await;
        if let Some(tx) = tx {
            match tx.try_send(BidiStream::new(send, recv)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(stream))
                | Err(mpsc::error::TrySendError::Closed(stream)) => {
                    stream.abort_with_code(H3_STREAM_CREATION_ERROR);
                }
            }
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
    let first_len = match read_known_frame_len(
        &mut recv,
        first_type,
        ctx.settings.read_timeout,
        field_section_limit(&ctx.settings),
    )
    .await
    {
        Ok(len) => len,
        Err(err) => {
            warn!(error = ?err, "qpx-h3 rejected malformed first request frame");
            abort_stream_with_code(&mut send, &mut recv, H3_FRAME_ERROR).await?;
            return Ok(());
        }
    };
    let stream_id: u64 = send.id().into();

    let mut decoded = match ctx
        .qpack
        .decode_request_head_from_reader(stream_id, &mut recv, first_len, ctx.settings.read_timeout)
        .await
    {
        Ok(decoded) => decoded,
        Err(err) => {
            warn!(error = ?err, "qpx-h3 failed to decode request head");
            abort_stream_with_code(&mut send, &mut recv, err.code()).await?;
            return Ok(());
        }
    };
    let priority = ctx
        .control
        .priority_for_request(
            stream_id,
            decoded
                .request
                .headers()
                .get("priority")
                .and_then(|value| value.to_str().ok()),
        )
        .await;
    decoded.request.extensions_mut().insert(priority);

    let protocol = decoded.protocol.as_deref().map(parse_protocol);
    if decoded.request.method() == http::Method::CONNECT
        && let Some(protocol) = protocol.as_ref()
    {
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
    let declared_content_length = match parse_content_length(decoded.request.headers()) {
        Ok(value) => value,
        Err(err) => {
            warn!(error = ?err, "qpx-h3 rejected malformed Content-Length");
            abort_stream_with_code(&mut send, &mut recv, H3_MESSAGE_ERROR).await?;
            return Ok(());
        }
    };
    if decoded.request.method() == http::Method::CONNECT
        && protocol == Some(Protocol::WebTransport)
        && ctx.settings.enable_webtransport
    {
        if !peer_settings.enable_webtransport {
            abort_stream_with_code(&mut send, &mut recv, H3_SETTINGS_ERROR).await?;
            return Ok(());
        }
        let stream_channel_capacity = ctx.settings.webtransport_stream_channel_capacity.max(1);
        let (bidi_tx, bidi_rx) = mpsc::channel(stream_channel_capacity);
        let (uni_tx, uni_rx) = mpsc::channel(stream_channel_capacity);
        if !ctx
            .session_registry
            .reserve(ctx.settings.max_webtransport_sessions)
        {
            send_simple_response(
                &mut send,
                http::StatusCode::TOO_MANY_REQUESTS,
                b"too many WebTransport sessions",
                via_received_by.as_str(),
            )
            .await?;
            send.finish()?;
            return Ok(());
        }
        ctx.session_registry
            .insert(stream_id, WebTransportSessionIngress { bidi_tx, uni_tx })
            .await;
        let datagrams = if ctx.settings.enable_datagram && peer_settings.enable_datagram {
            let dispatch = ctx
                .datagram_dispatch
                .as_ref()
                .ok_or_else(|| anyhow!("missing datagram dispatch"))?;
            Some(
                dispatch
                    .register_stream_with_capacity(
                        stream_id,
                        ctx.settings.webtransport_datagram_channel_capacity,
                    )
                    .await?,
            )
        } else {
            None
        };
        let request_method = decoded.request.method().clone();
        let stream_config = request_stream_config(&ctx.settings);
        let result = handler
            .handle_webtransport_connect(
                decoded.request,
                RequestStream::new_server_response(
                    send,
                    recv,
                    stream_id,
                    ctx.qpack.clone(),
                    stream_config,
                    request_method,
                    declared_content_length,
                ),
                ctx.conn_info.clone(),
                WebTransportSession {
                    session_id: stream_id,
                    opener: OpenStreams::new(ctx.connection, ctx.settings.read_timeout),
                    datagrams,
                    bidi_streams: bidi_rx,
                    uni_streams: uni_rx,
                },
            )
            .await;
        ctx.session_registry.remove(stream_id).await;
        return result;
    }
    if decoded.request.method() == http::Method::CONNECT
        && let Some(protocol) = protocol.clone()
    {
        if protocol == Protocol::ConnectUdp && !peer_settings.enable_datagram {
            abort_stream_with_code(&mut send, &mut recv, H3_SETTINGS_ERROR).await?;
            return Ok(());
        }
        let datagrams = if ctx.settings.enable_datagram && peer_settings.enable_datagram {
            let dispatch = ctx
                .datagram_dispatch
                .as_ref()
                .ok_or_else(|| anyhow!("missing datagram dispatch"))?;
            Some(dispatch.register_stream(stream_id).await?)
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
        let request_method = decoded.request.method().clone();
        let stream_config = request_stream_config(&ctx.settings);
        return handler
            .handle_connect_stream(
                decoded.request,
                RequestStream::new_server_response(
                    send,
                    recv,
                    stream_id,
                    ctx.qpack.clone(),
                    stream_config,
                    request_method,
                    declared_content_length,
                ),
                ctx.conn_info,
                protocol,
                datagrams,
            )
            .await;
    }

    let _datagram_registration = if let Some(dispatch) = ctx.datagram_dispatch.as_ref() {
        Some(dispatch.register_stream_without_datagrams(stream_id).await)
    } else {
        None
    };

    let request = Request {
        head: decoded.request,
        protocol,
        priority_updates: PriorityUpdates::new(ctx.control.clone(), stream_id),
    };
    let request_method = request.head.method().clone();
    let stream_config = request_stream_config(&ctx.settings);
    let stream = RequestStream::new_server_response(
        send,
        recv,
        stream_id,
        ctx.qpack.clone(),
        stream_config,
        request_method,
        declared_content_length,
    );
    handler
        .handle_request(request, ctx.conn_info, stream)
        .await?;
    Ok(())
}
