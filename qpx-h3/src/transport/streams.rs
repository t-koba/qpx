use crate::H3Result as Result;
use crate::protocol::encode_varint;
use anyhow::anyhow;
use bytes::Bytes;
use std::time::Duration;
use tokio::time::timeout;

use super::{WEBTRANSPORT_STREAM_CHUNK_BYTES, abort_bidi_stream, stop_recv_stream};

/// WebTransport bidirectional stream.
pub struct BidiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl BidiStream {
    pub(crate) fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }

    pub(crate) fn abort_with_code(mut self, code: u64) {
        abort_bidi_stream(&mut self.send, &mut self.recv, code);
    }

    /// Splits the stream into send and receive halves.
    pub fn split(self) -> (StreamSend, StreamRecv) {
        (
            StreamSend { send: self.send },
            StreamRecv { recv: self.recv },
        )
    }
}

/// Send half of a WebTransport stream.
pub struct StreamSend {
    send: quinn::SendStream,
}

impl StreamSend {
    /// Sends one stream chunk.
    pub async fn send_chunk(&mut self, payload: Bytes) -> Result<()> {
        self.send.write_all(payload.as_ref()).await?;
        Ok(())
    }

    /// Finishes the send stream.
    pub async fn finish(&mut self) -> Result<()> {
        self.send.finish()?;
        Ok(())
    }
}

/// Receive half of a WebTransport stream.
#[derive(Debug)]
pub struct StreamRecv {
    recv: quinn::RecvStream,
}

impl StreamRecv {
    /// Receives one stream chunk.
    pub async fn recv_chunk(&mut self) -> Result<Option<Bytes>> {
        Ok(self
            .recv
            .read_chunk(WEBTRANSPORT_STREAM_CHUNK_BYTES, true)
            .await?
            .map(|chunk| chunk.bytes))
    }
}

/// Incoming WebTransport unidirectional stream.
#[derive(Debug)]
pub struct UniRecvStream {
    recv: quinn::RecvStream,
}

impl UniRecvStream {
    pub(crate) fn new(recv: quinn::RecvStream) -> Self {
        Self { recv }
    }

    pub(crate) fn stop_with_code(mut self, code: u64) {
        stop_recv_stream(&mut self.recv, code);
    }

    /// Receives one stream chunk.
    pub async fn recv_chunk(&mut self) -> Result<Option<Bytes>> {
        Ok(self
            .recv
            .read_chunk(WEBTRANSPORT_STREAM_CHUNK_BYTES, true)
            .await?
            .map(|chunk| chunk.bytes))
    }
}

/// Outgoing WebTransport unidirectional stream.
#[derive(Debug)]
pub struct UniSendStream {
    send: quinn::SendStream,
}

impl UniSendStream {
    pub(crate) fn new(send: quinn::SendStream) -> Self {
        Self { send }
    }

    /// Sends one stream chunk.
    pub async fn send_chunk(&mut self, payload: Bytes) -> Result<()> {
        self.send.write_all(payload.as_ref()).await?;
        Ok(())
    }

    /// Finishes the send stream.
    pub async fn finish(&mut self) -> Result<()> {
        self.send.finish()?;
        Ok(())
    }
}

/// Opener for WebTransport associated streams.
#[derive(Debug, Clone)]
pub struct OpenStreams {
    conn: quinn::Connection,
    write_timeout: Duration,
}

impl OpenStreams {
    pub(crate) fn new(conn: quinn::Connection, write_timeout: Duration) -> Self {
        Self {
            conn,
            write_timeout,
        }
    }

    /// Opens an associated WebTransport bidirectional stream.
    pub async fn open_webtransport_bidi(&mut self, session_id: u64) -> Result<BidiStream> {
        let opened = timeout(self.write_timeout, self.conn.open_bi())
            .await
            .map_err(|_| anyhow!("WebTransport bidi stream open timed out"))?;
        let (mut send, recv) = opened?;
        write_webtransport_varint(
            &mut send,
            crate::protocol::STREAM_WEBTRANSPORT_BIDI,
            self.write_timeout,
            "bidi stream type",
        )
        .await?;
        write_webtransport_varint(&mut send, session_id, self.write_timeout, "bidi session id")
            .await?;
        Ok(BidiStream::new(send, recv))
    }

    /// Opens an associated WebTransport unidirectional stream.
    pub async fn open_webtransport_uni(&mut self, session_id: u64) -> Result<UniSendStream> {
        let opened = timeout(self.write_timeout, self.conn.open_uni())
            .await
            .map_err(|_| anyhow!("WebTransport uni stream open timed out"))?;
        let mut send = opened?;
        write_webtransport_varint(
            &mut send,
            crate::protocol::STREAM_WEBTRANSPORT_UNI,
            self.write_timeout,
            "uni stream type",
        )
        .await?;
        write_webtransport_varint(&mut send, session_id, self.write_timeout, "uni session id")
            .await?;
        Ok(UniSendStream::new(send))
    }
}

async fn write_webtransport_varint(
    send: &mut quinn::SendStream,
    value: u64,
    write_timeout: Duration,
    label: &'static str,
) -> Result<()> {
    let encoded = encode_varint(value)?;
    let result = timeout(write_timeout, send.write_all(&encoded))
        .await
        .map_err(|_| anyhow!("WebTransport {label} write timed out"))?;
    result?;
    Ok(())
}
