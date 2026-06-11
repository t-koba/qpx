use super::{Protocol, Settings};
use crate::H3Result as Result;
use crate::protocol::{
    ConnectionClose, FRAME_DATA, FRAME_HEADERS, H3_MESSAGE_ERROR, read_varint, write_frame,
};
use crate::qpack::encode_response_head;
use crate::transport::RequestStreamConfig;
use anyhow::anyhow;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::warn;

pub(super) fn is_client_initiated_bidi_stream_id(stream_id: u64) -> bool {
    stream_id & 0b11 == 0
}

pub(super) fn close_connection(conn: &quinn::Connection, close: ConnectionClose) {
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

pub(super) async fn read_known_frame_len(
    recv: &mut quinn::RecvStream,
    frame_type: u64,
    read_timeout: Duration,
    max_payload_bytes: usize,
) -> Result<usize> {
    let len = timeout(read_timeout, read_varint(recv))
        .await
        .map_err(|_| anyhow!("timed out reading frame length"))??
        .ok_or_else(|| anyhow!("truncated frame length"))?;
    if len > max_payload_bytes as u64 {
        return Err(anyhow!(
            "HTTP/3 frame 0x{frame_type:x} payload length {len} exceeds limit {max_payload_bytes}"
        )
        .into());
    }
    Ok(len as usize)
}

pub(super) fn field_section_limit(settings: &Settings) -> usize {
    settings.max_field_section_size.min(usize::MAX as u64) as usize
}

pub(super) fn request_stream_config(settings: &Settings) -> RequestStreamConfig {
    RequestStreamConfig {
        read_timeout: settings.read_timeout,
        max_frame_payload_bytes: settings.max_frame_payload_bytes,
        max_non_data_frame_payload_bytes: settings.max_control_frame_payload_bytes,
        max_field_section_bytes: field_section_limit(settings),
        max_request_body_bytes: Some(settings.max_request_body_bytes),
    }
}

pub(super) async fn send_simple_response(
    send: &mut quinn::SendStream,
    status: http::StatusCode,
    body: &[u8],
    via_received_by: &str,
) -> Result<()> {
    let via = format!("3 {via_received_by}");
    let response = http::Response::builder()
        .status(status)
        .header(
            http::header::DATE,
            httpdate::fmt_http_date(std::time::SystemTime::now()),
        )
        .header(http::header::VIA, via)
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())
        .unwrap_or_else(|_| http::Response::new(()));
    let head = encode_response_head(&response);
    write_frame(send, FRAME_HEADERS, &head).await?;
    if !body.is_empty() {
        write_frame(send, FRAME_DATA, body).await?;
    }
    Ok(())
}

pub(super) fn parse_protocol(protocol: &str) -> Protocol {
    match protocol {
        "connect-udp" => Protocol::ConnectUdp,
        "webtransport" => Protocol::WebTransport,
        other => Protocol::Other(other.to_string()),
    }
}

pub(super) async fn abort_stream_with_code(
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

pub(super) fn extract_tls_sni(conn: &quinn::Connection) -> Option<Arc<str>> {
    conn.handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|hs| hs.server_name.clone())
        .map(Arc::<str>::from)
}

pub(super) fn extract_peer_certificates(conn: &quinn::Connection) -> Option<Arc<Vec<Vec<u8>>>> {
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
