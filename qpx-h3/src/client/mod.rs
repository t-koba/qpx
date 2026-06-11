mod driver;
mod registry;

use self::driver::{
    fail_client_setup, open_critical_streams, recv_response_with_interim, spawn_client_driver,
    validate_peer_settings_for_protocol,
};
use self::registry::{SessionIngress, SessionRegistry, ShardedSessionRegistry};
use crate::H3Result as Result;
use crate::protocol::{PeerControlState, PeerSettings};
use crate::qpack::{QpackConnection, encode_request_head};
use crate::server::{Protocol, Settings};
use crate::transport::{
    BidiStream, DatagramDispatch, OpenStreams, RequestStream, RequestStreamConfig, StreamDatagrams,
    UniRecvStream,
};
use anyhow::anyhow;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use tokio::sync::{Notify, mpsc};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::{Duration, timeout};

/// Opened extended CONNECT stream and associated resources.
pub struct ExtendedConnectStream {
    /// Interim responses received before the final response.
    pub interim: Vec<http::Response<()>>,
    /// Final response head.
    pub response: http::Response<()>,
    /// Request stream.
    pub request_stream: RequestStream,
    /// Stream datagrams, if enabled.
    pub datagrams: Option<StreamDatagrams>,
    /// Stream opener for associated streams.
    pub opener: Option<OpenStreams>,
    /// Incoming associated bidirectional streams.
    pub associated_bidi: Option<mpsc::Receiver<BidiStream>>,
    /// Incoming associated unidirectional streams.
    pub associated_uni: Option<mpsc::Receiver<UniRecvStream>>,
    /// Critical stream handles kept alive by this stream.
    pub _critical_streams: Option<(quinn::SendStream, quinn::SendStream)>,
    /// Endpoint kept alive by this stream.
    pub _endpoint: quinn::Endpoint,
    /// Background connection driver task.
    pub driver: JoinHandle<()>,
    /// Background datagram dispatcher task.
    pub datagram_task: Option<JoinHandle<()>>,
    #[doc(hidden)]
    pub _connection_use: Option<ClientConnectionUse>,
    #[doc(hidden)]
    pub _session: Option<ClientSession>,
    #[doc(hidden)]
    _session_stream_use: Option<ClientSessionStreamUse>,
}

static ACTIVE_CLIENT_CONNECTIONS: OnceLock<StdMutex<HashSet<usize>>> = OnceLock::new();

/// Reusable HTTP/3 client session.
#[derive(Clone)]
pub struct ClientSession {
    inner: Arc<ClientSessionInner>,
}

struct ClientSessionInner {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    settings: Settings,
    qpack: QpackConnection,
    control_state: PeerControlState,
    peer_settings: PeerSettings,
    registry: SessionRegistry,
    datagram_dispatch: Option<Arc<DatagramDispatch>>,
    inflight_streams: Arc<AtomicUsize>,
    stream_available: Arc<Notify>,
    _critical_streams: (quinn::SendStream, quinn::SendStream),
    _connection_use: ClientConnectionUse,
    driver: JoinHandle<()>,
    datagram_task: Option<JoinHandle<()>>,
}

struct ClientSessionStreamUse {
    inflight_streams: Arc<AtomicUsize>,
    stream_available: Arc<Notify>,
}

impl Drop for ClientSessionStreamUse {
    fn drop(&mut self) {
        self.inflight_streams.fetch_sub(1, Ordering::Relaxed);
        self.stream_available.notify_waiters();
    }
}

fn client_request_stream_config(
    settings: &Settings,
    read_timeout: Duration,
) -> RequestStreamConfig {
    RequestStreamConfig {
        read_timeout,
        max_frame_payload_bytes: settings.max_frame_payload_bytes,
        max_non_data_frame_payload_bytes: settings.max_control_frame_payload_bytes,
        max_field_section_bytes: settings.max_field_section_size.min(usize::MAX as u64) as usize,
        max_request_body_bytes: None,
    }
}

impl Drop for ClientSessionInner {
    fn drop(&mut self) {
        self.driver.abort();
        if let Some(task) = self.datagram_task.as_ref() {
            task.abort();
        }
    }
}

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
            )
            .into());
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
        if let Some(active) = ACTIVE_CLIENT_CONNECTIONS.get()
            && let Ok(mut guard) = active.lock()
        {
            guard.remove(&self.stable_id);
        }
    }
}

impl ClientSession {
    /// Creates a reusable HTTP/3 client session on an existing QUIC connection.
    pub async fn new(
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        settings: Settings,
        timeout_dur: Duration,
    ) -> Result<Self> {
        let mut connection_use = ClientConnectionUse::acquire(&connection)?;
        let (control, encoder, decoder) = match open_critical_streams(&connection, &settings).await
        {
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
        let registry: SessionRegistry = Arc::new(ShardedSessionRegistry::new());
        let datagram_dispatch = settings
            .enable_datagram
            .then(|| DatagramDispatch::new(connection.clone(), settings.datagram_channel_capacity));
        let datagram_task = datagram_dispatch.as_ref().map(|dispatch| {
            let dispatch = dispatch.clone();
            tokio::spawn(async move { dispatch.run().await })
        });
        let driver = spawn_client_driver(
            connection.clone(),
            registry.clone(),
            qpack.clone(),
            control_state.clone(),
            &settings,
        );
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
        Ok(Self {
            inner: Arc::new(ClientSessionInner {
                endpoint,
                connection,
                settings,
                qpack,
                control_state,
                peer_settings,
                registry,
                datagram_dispatch,
                inflight_streams: Arc::new(AtomicUsize::new(0)),
                stream_available: Arc::new(Notify::new()),
                _critical_streams: (control, encoder),
                _connection_use: connection_use,
                driver,
                datagram_task,
            }),
        })
    }

    /// Returns whether the underlying session is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.driver.is_finished() || self.inner.connection.close_reason().is_some()
    }

    /// Returns the current number of in-flight request streams.
    pub fn inflight_streams(&self) -> usize {
        self.inner.inflight_streams.load(Ordering::Relaxed)
    }

    /// Waits until in-flight streams drop below a limit.
    pub async fn wait_for_inflight_below(&self, limit: usize, timeout_dur: Duration) -> bool {
        if self.inflight_streams() < limit || self.is_closed() {
            return true;
        }
        timeout(timeout_dur, async {
            loop {
                let notified = self.inner.stream_available.notified();
                if self.inflight_streams() < limit || self.is_closed() {
                    return;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }

    /// Opens an extended CONNECT stream on this session.
    pub async fn open_extended_connect_stream(
        &self,
        request: http::Request<()>,
        protocol: Option<Protocol>,
        timeout_dur: Duration,
    ) -> Result<ExtendedConnectStream> {
        open_extended_connect_on_session(self.clone(), request, protocol, timeout_dur).await
    }
}

/// Opens an extended CONNECT stream using a fresh HTTP/3 client driver.
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

    let registry: SessionRegistry = Arc::new(ShardedSessionRegistry::new());
    let datagram_dispatch = settings
        .enable_datagram
        .then(|| DatagramDispatch::new(connection.clone(), settings.datagram_channel_capacity));
    let datagram_task = datagram_dispatch.as_ref().map(|dispatch| {
        let dispatch = dispatch.clone();
        tokio::spawn(async move { dispatch.run().await })
    });

    let driver = spawn_client_driver(
        connection.clone(),
        registry.clone(),
        qpack.clone(),
        control_state.clone(),
        &settings,
    );
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

    let opener = OpenStreams::new(connection.clone(), settings.read_timeout);
    let (bidi_send, bidi_recv) = match timeout(timeout_dur, connection.open_bi()).await {
        Ok(Ok(streams)) => streams,
        Ok(Err(err)) => return fail_client_setup(&connection, err),
        Err(_) => {
            return fail_client_setup(&connection, anyhow!("extended CONNECT open_bi timed out"));
        }
    };
    let stream_id: u64 = bidi_send.id().into();
    if let Some(goaway_id) = control_state.goaway_id().await
        && stream_id >= goaway_id
    {
        return fail_client_setup(
            &connection,
            anyhow!("peer GOAWAY disallows opening request stream {stream_id} (limit {goaway_id})"),
        );
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
        client_request_stream_config(&settings, timeout_dur),
        request.method().clone(),
    );
    if let Err(err) = request_stream.send_headers(&payload).await {
        return fail_client_setup(&connection, err);
    }

    let webtransport_session_id = match protocol {
        Some(Protocol::WebTransport) => Some(stream_id),
        _ => None,
    };
    let (mut associated_bidi, mut associated_uni) = if webtransport_session_id.is_some() {
        let stream_channel_capacity = settings.webtransport_stream_channel_capacity.max(1);
        let (bidi_tx, bidi_rx) = mpsc::channel(stream_channel_capacity);
        let (uni_tx, uni_rx) = mpsc::channel(stream_channel_capacity);
        registry
            .insert(stream_id, SessionIngress { bidi_tx, uni_tx })
            .await;
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
            registry.remove(session_id).await;
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
        Some(dispatch.register_stream(stream_id).await?)
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
        _connection_use: Some(connection_use),
        _session: None,
        _session_stream_use: None,
    })
}

async fn open_extended_connect_on_session(
    session: ClientSession,
    request: http::Request<()>,
    protocol: Option<Protocol>,
    timeout_dur: Duration,
) -> Result<ExtendedConnectStream> {
    let inner = session.inner.clone();
    validate_peer_settings_for_protocol(
        &inner.connection,
        &inner.peer_settings,
        protocol.as_ref(),
        false,
    )?;
    let opener = OpenStreams::new(inner.connection.clone(), inner.settings.read_timeout);
    inner.inflight_streams.fetch_add(1, Ordering::Relaxed);
    let session_stream_use = ClientSessionStreamUse {
        inflight_streams: inner.inflight_streams.clone(),
        stream_available: inner.stream_available.clone(),
    };
    let (bidi_send, bidi_recv) = match timeout(timeout_dur, inner.connection.open_bi()).await {
        Ok(Ok(streams)) => streams,
        Ok(Err(err)) => {
            drop(session_stream_use);
            return Err(err.into());
        }
        Err(_) => {
            drop(session_stream_use);
            return Err(anyhow!("extended CONNECT open_bi timed out").into());
        }
    };
    let stream_id: u64 = bidi_send.id().into();
    if let Some(goaway_id) = inner.control_state.goaway_id().await
        && stream_id >= goaway_id
    {
        drop(session_stream_use);
        return Err(anyhow!(
            "peer GOAWAY disallows opening request stream {stream_id} (limit {goaway_id})"
        )
        .into());
    }
    let protocol_name = protocol.as_ref().map(Protocol::as_str);
    let payload = match encode_request_head(&request, protocol_name) {
        Ok(payload) => payload,
        Err(err) => {
            drop(session_stream_use);
            return Err(err);
        }
    };
    let mut request_stream = RequestStream::new_client_request(
        bidi_send,
        bidi_recv,
        stream_id,
        inner.qpack.clone(),
        client_request_stream_config(&inner.settings, timeout_dur),
        request.method().clone(),
    );
    if let Err(err) = request_stream.send_headers(&payload).await {
        drop(session_stream_use);
        return Err(err);
    }

    let webtransport_session_id = match protocol {
        Some(Protocol::WebTransport) => Some(stream_id),
        _ => None,
    };
    let (mut associated_bidi, mut associated_uni) = if webtransport_session_id.is_some() {
        let stream_channel_capacity = inner.settings.webtransport_stream_channel_capacity.max(1);
        let (bidi_tx, bidi_rx) = mpsc::channel(stream_channel_capacity);
        let (uni_tx, uni_rx) = mpsc::channel(stream_channel_capacity);
        inner
            .registry
            .insert(stream_id, SessionIngress { bidi_tx, uni_tx })
            .await;
        (Some(bidi_rx), Some(uni_rx))
    } else {
        (None, None)
    };

    let (interim, response) =
        match recv_response_with_interim(&mut request_stream, timeout_dur).await {
            Ok(response) => response,
            Err(err) => return Err(err),
        };
    let webtransport_established =
        webtransport_session_id.is_some() && response.status().is_success();
    if !webtransport_established {
        if let Some(session_id) = webtransport_session_id {
            inner.registry.remove(session_id).await;
        }
        associated_bidi = None;
        associated_uni = None;
    }

    let datagrams = if inner.settings.enable_datagram
        && inner.peer_settings.enable_datagram
        && response.status().is_success()
    {
        let Some(dispatch) = inner.datagram_dispatch.as_ref() else {
            return Err(anyhow!("missing datagram dispatch").into());
        };
        Some(dispatch.register_stream(stream_id).await?)
    } else {
        None
    };

    let driver = tokio::spawn(std::future::pending());
    Ok(ExtendedConnectStream {
        interim,
        response,
        request_stream,
        datagrams,
        opener: webtransport_established.then_some(opener),
        associated_bidi,
        associated_uni,
        _critical_streams: None,
        _endpoint: inner.endpoint.clone(),
        driver,
        datagram_task: None,
        _connection_use: None,
        _session: Some(session),
        _session_stream_use: Some(session_stream_use),
    })
}
