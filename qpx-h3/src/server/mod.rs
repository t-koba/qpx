mod connection;
mod helpers;
mod registry;

#[cfg(test)]
mod tests;

pub(crate) use connection::encode_settings;
use connection::{
    RequestStreamContext, consume_uni_stream, handle_request_stream, open_critical_streams,
};
use registry::{ShardedWebTransportSessionRegistry, WebTransportSessionRegistry};

use crate::protocol::{PeerControlState, PriorityUpdates};
use crate::qpack::{
    DEFAULT_DYNAMIC_TABLE_CAPACITY, DEFAULT_ENCODER_STREAM_BUFFER_BYTES,
    DEFAULT_MAX_BLOCKED_STREAMS, QpackConnection,
};
use crate::transport::{
    BidiStream, DatagramDispatch, OpenStreams, RequestStream, StreamDatagrams, UniRecvStream,
};
use anyhow::Result;
use async_trait::async_trait;
use helpers::{close_connection, extract_peer_certificates, extract_tls_sni, send_simple_response};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use tracing::warn;

const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportLevel {
    StreamingServer,
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
    pub bidi_streams: mpsc::Receiver<BidiStream>,
    pub uni_streams: mpsc::Receiver<UniRecvStream>,
}

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
    pub datagram_channel_capacity: usize,
    pub webtransport_datagram_channel_capacity: usize,
    pub webtransport_stream_channel_capacity: usize,
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
            max_field_section_size: DEFAULT_MAX_FIELD_SECTION_SIZE,
            max_frame_payload_bytes: 16 * 1024 * 1024,
            max_control_frame_payload_bytes: 1024 * 1024,
            max_encoder_stream_buffer_bytes: DEFAULT_ENCODER_STREAM_BUFFER_BYTES,
            datagram_channel_capacity: 64,
            webtransport_datagram_channel_capacity: 64,
            webtransport_stream_channel_capacity: 64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub head: http::Request<()>,
    pub protocol: Option<Protocol>,
    pub priority_updates: PriorityUpdates,
}

#[async_trait]
pub trait RequestHandler: Clone + Send + Sync + 'static {
    fn settings(&self) -> Settings;

    fn via_received_by(&self) -> String {
        "qpx-h3".to_string()
    }

    async fn handle_request(
        &self,
        request: Request,
        conn: ConnectionInfo,
        stream: RequestStream,
    ) -> Result<()>;

    async fn handle_connect_stream(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: RequestStream,
        _conn: ConnectionInfo,
        _protocol: Protocol,
        _datagrams: Option<StreamDatagrams>,
    ) -> Result<()> {
        let via_received_by = self.via_received_by();
        send_simple_response(
            req_stream.send_mut(),
            http::StatusCode::NOT_IMPLEMENTED,
            b"extended CONNECT is not supported",
            via_received_by.as_str(),
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
        let via_received_by = self.via_received_by();
        send_simple_response(
            req_stream.send_mut(),
            http::StatusCode::NOT_IMPLEMENTED,
            b"WEBTRANSPORT over extended CONNECT is not supported",
            via_received_by.as_str(),
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

    let session_registry: WebTransportSessionRegistry =
        Arc::new(ShardedWebTransportSessionRegistry::new());
    let datagram_dispatch = settings
        .enable_datagram
        .then(|| DatagramDispatch::new(connection.clone(), settings.datagram_channel_capacity));
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
    let uni_read_timeout = settings.read_timeout;
    let uni_stream_semaphore = Arc::new(Semaphore::new(
        settings.max_concurrent_streams_per_connection.max(1),
    ));
    tokio::spawn(async move {
        loop {
            let recv = match uni_conn.accept_uni().await {
                Ok(recv) => recv,
                Err(_) => break,
            };
            let permit = match uni_stream_semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => break,
            };
            let registry = uni_registry.clone();
            let qpack = uni_qpack.clone();
            let conn = uni_conn.clone();
            let control_state = uni_control_state.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(err) = consume_uni_stream(
                    recv,
                    registry,
                    qpack,
                    control_state,
                    max_control_frame_payload_bytes,
                    uni_read_timeout,
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
