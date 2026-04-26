use anyhow::{anyhow, Context, Result};
use quinn::{AsyncUdpSocket, UdpPoller};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{ErrorKind, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(windows)]
use std::net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream as StdUnixStream;
#[cfg(windows)]
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use tokio::io::Interest;
#[cfg(any(unix, windows))]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(windows)]
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::sync::mpsc;

const ENV_INHERITED_QUIC_BROKERS: &str = "QPX_INHERITED_QUIC_BROKERS";

#[cfg(unix)]
pub(crate) type QuinnBrokerStream = StdUnixStream;

#[cfg(windows)]
pub(crate) type QuinnBrokerStream = StdTcpStream;

#[cfg(not(any(unix, windows)))]
#[derive(Debug)]
pub(crate) struct QuinnBrokerStream;

enum TokioQuinnBrokerStream {
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(windows)]
    Tcp(TokioTcpStream),
}

impl AsyncRead for TokioQuinnBrokerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(windows)]
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TokioQuinnBrokerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(windows)]
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(windows)]
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(windows)]
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct QuicConnectionId {
    len: u8,
    bytes: [u8; 20],
}

impl QuicConnectionId {
    fn from_slice(value: &[u8]) -> Option<Self> {
        if value.len() > 20 {
            return None;
        }
        let mut bytes = [0u8; 20];
        bytes[..value.len()].copy_from_slice(value);
        Some(Self {
            len: value.len() as u8,
            bytes,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct ParsedQuicLongHeader {
    dcid_len: u8,
    scid_len: u8,
    dcid: Option<QuicConnectionId>,
    scid: Option<QuicConnectionId>,
}

fn parse_quic_long_header(packet: &[u8]) -> Option<ParsedQuicLongHeader> {
    let first = *packet.first()?;
    if (first & 0x80) == 0 || packet.len() < 6 {
        return None;
    }
    let mut idx = 5usize;
    let dcid_len = *packet.get(idx)? as usize;
    idx += 1;
    if dcid_len > 20 || idx + dcid_len > packet.len() {
        return None;
    }
    let dcid = if dcid_len == 0 {
        None
    } else {
        QuicConnectionId::from_slice(&packet[idx..idx + dcid_len])
    };
    idx += dcid_len;
    let scid_len = *packet.get(idx)? as usize;
    idx += 1;
    if scid_len > 20 || idx + scid_len > packet.len() {
        return None;
    }
    let scid = if scid_len == 0 {
        None
    } else {
        QuicConnectionId::from_slice(&packet[idx..idx + scid_len])
    };
    Some(ParsedQuicLongHeader {
        dcid_len: dcid_len as u8,
        scid_len: scid_len as u8,
        dcid,
        scid,
    })
}

fn parse_quic_short_dcid(packet: &[u8], dcid_len: u8) -> Option<QuicConnectionId> {
    let first = *packet.first()?;
    if (first & 0x80) != 0 {
        return None;
    }
    let dcid_len = dcid_len as usize;
    if dcid_len == 0 || packet.len() < 1 + dcid_len {
        return None;
    }
    QuicConnectionId::from_slice(&packet[1..1 + dcid_len])
}

#[derive(Default)]
struct RouteState {
    addrs: HashSet<SocketAddr>,
    cids: HashSet<QuicConnectionId>,
    known_server_cid_lens: HashSet<u8>,
}

impl RouteState {
    fn observe_inbound(&mut self, addr: SocketAddr, packet: &[u8]) {
        self.addrs.insert(addr);
        if let Some(long) = parse_quic_long_header(packet) {
            if let Some(cid) = long.dcid {
                self.cids.insert(cid);
            }
            if long.dcid_len > 0 {
                self.known_server_cid_lens.insert(long.dcid_len);
            }
            return;
        }
        for len in self.known_server_cid_lens.clone() {
            if let Some(cid) = parse_quic_short_dcid(packet, len) {
                self.cids.insert(cid);
            }
        }
    }

    fn observe_outbound(&mut self, addr: SocketAddr, packet: &[u8]) {
        self.addrs.insert(addr);
        if let Some(long) = parse_quic_long_header(packet) {
            if let Some(cid) = long.scid {
                self.cids.insert(cid);
            }
            if long.scid_len > 0 {
                self.known_server_cid_lens.insert(long.scid_len);
            }
        }
    }

    fn matches_cid(&self, packet: &[u8]) -> bool {
        if let Some(long) = parse_quic_long_header(packet) {
            return long
                .dcid
                .into_iter()
                .chain(long.scid)
                .any(|cid| self.cids.contains(&cid));
        }
        for len in &self.known_server_cid_lens {
            if let Some(cid) = parse_quic_short_dcid(packet, *len) {
                if self.cids.contains(&cid) {
                    return true;
                }
            }
        }
        false
    }
}

#[derive(Debug, Clone)]
struct InjectedPacket {
    addr: SocketAddr,
    ecn: Option<quinn::udp::EcnCodepoint>,
    dst_ip: Option<IpAddr>,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct OwnedTransmit {
    destination: SocketAddr,
    ecn: Option<quinn::udp::EcnCodepoint>,
    contents: Vec<u8>,
    segment_size: Option<usize>,
    src_ip: Option<IpAddr>,
}

impl OwnedTransmit {
    fn borrowed(&self) -> quinn::udp::Transmit<'_> {
        quinn::udp::Transmit {
            destination: self.destination,
            ecn: self.ecn,
            contents: self.contents.as_slice(),
            segment_size: self.segment_size,
            src_ip: self.src_ip,
        }
    }

    fn datagrams(&self) -> impl Iterator<Item = &[u8]> {
        let segment = self.segment_size.unwrap_or(self.contents.len()).max(1);
        self.contents.chunks(segment)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InheritedQuicBrokers {
    forward: Vec<InheritedQuicBroker>,
    reverse: Vec<InheritedQuicBroker>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InheritedQuicBroker {
    name: String,
    #[cfg(unix)]
    fd: i32,
    #[cfg(windows)]
    addr: String,
    #[cfg(windows)]
    token: String,
}

pub(crate) struct QuinnBrokerPreparedHandoff {
    pub(crate) env_value: String,
    #[cfg(unix)]
    pub(crate) kept_fds: Vec<OwnedFd>,
    #[cfg(windows)]
    cleanup_path: PathBuf,
    #[cfg(windows)]
    accept_tasks: Vec<tokio::task::JoinHandle<()>>,
}

#[derive(Default)]
pub(crate) struct QuinnBrokerRestoreSet {
    #[cfg(any(unix, windows))]
    forward: HashMap<String, QuinnBrokerStream>,
    #[cfg(any(unix, windows))]
    reverse: HashMap<String, QuinnBrokerStream>,
}

impl QuinnBrokerRestoreSet {
    pub(crate) fn take_from_env() -> Result<Option<Self>> {
        let Some(raw) = std::env::var_os(ENV_INHERITED_QUIC_BROKERS) else {
            return Ok(None);
        };
        unsafe {
            std::env::remove_var(ENV_INHERITED_QUIC_BROKERS);
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = raw;
            Err(anyhow!(
                "QUIC broker handoff is only supported on unix and windows"
            ))
        }

        #[cfg(unix)]
        {
            let inherited: InheritedQuicBrokers =
                serde_json::from_str(raw.to_string_lossy().as_ref())
                    .context("invalid inherited QUIC broker manifest")?;
            let mut restore = Self::default();
            for entry in inherited.forward {
                restore
                    .forward
                    .insert(entry.name, adopt_unix_stream(entry.fd)?);
            }
            for entry in inherited.reverse {
                restore
                    .reverse
                    .insert(entry.name, adopt_unix_stream(entry.fd)?);
            }
            Ok(Some(restore))
        }

        #[cfg(windows)]
        {
            let path = PathBuf::from(raw);
            let inherited: InheritedQuicBrokers =
                crate::windows_handoff::read_json_wait(path.as_path())
                    .context("invalid inherited QUIC broker manifest")?;
            let _ = std::fs::remove_file(&path);
            let mut restore = Self::default();
            for entry in inherited.forward {
                restore.forward.insert(
                    entry.name,
                    connect_windows_broker(entry.addr.as_str(), entry.token.as_str())?,
                );
            }
            for entry in inherited.reverse {
                restore.reverse.insert(
                    entry.name,
                    connect_windows_broker(entry.addr.as_str(), entry.token.as_str())?,
                );
            }
            Ok(Some(restore))
        }
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn take_forward(&mut self, name: &str) -> Option<QuinnBrokerStream> {
        self.forward.remove(name)
    }

    #[cfg(not(any(unix, windows)))]
    pub(crate) fn take_forward(&mut self, _name: &str) -> Option<QuinnBrokerStream> {
        None
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn take_reverse(&mut self, name: &str) -> Option<QuinnBrokerStream> {
        self.reverse.remove(name)
    }

    #[cfg(not(any(unix, windows)))]
    pub(crate) fn take_reverse(&mut self, _name: &str) -> Option<QuinnBrokerStream> {
        None
    }

    pub(crate) fn ensure_consumed(&self) -> Result<()> {
        #[cfg(not(any(unix, windows)))]
        {
            Ok(())
        }

        #[cfg(any(unix, windows))]
        {
            if self.forward.is_empty() && self.reverse.is_empty() {
                return Ok(());
            }
            Err(anyhow!(
                "unused inherited QUIC brokers remain: forward={:?}, reverse={:?}",
                self.forward.keys().collect::<Vec<_>>(),
                self.reverse.keys().collect::<Vec<_>>(),
            ))
        }
    }

    pub(crate) fn handoff_env_key() -> &'static str {
        ENV_INHERITED_QUIC_BROKERS
    }
}

#[cfg(windows)]
impl QuinnBrokerPreparedHandoff {
    pub(crate) fn cleanup_pending(&self) {
        for task in &self.accept_tasks {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.cleanup_path);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuinnBrokerKind {
    Forward,
    ReverseTerminate,
}

#[derive(Clone)]
pub(crate) struct QuinnEndpointSocket {
    socket: Arc<dyn AsyncUdpSocket>,
}

impl QuinnEndpointSocket {
    pub(crate) fn as_async_socket(&self) -> Arc<dyn AsyncUdpSocket> {
        self.socket.clone()
    }
}

pub(crate) struct PreparedServerEndpointSocket {
    pub(crate) endpoint_socket: QuinnEndpointSocket,
    pub(crate) local_broker_handle: Option<LocalQuinnBrokerHandle>,
}

pub(crate) trait QuinnUdpIngressFilter: Send + Sync + 'static {
    fn allow(&self, remote_addr: SocketAddr, packet: &[u8]) -> bool;
}

#[derive(Default)]
pub(crate) struct NoopQuinnUdpIngressFilter;

impl QuinnUdpIngressFilter for NoopQuinnUdpIngressFilter {
    fn allow(&self, _remote_addr: SocketAddr, _packet: &[u8]) -> bool {
        true
    }
}

pub(crate) struct LocalQuinnBrokerHandle {
    kind: QuinnBrokerKind,
    name: String,
    socket: Arc<LocalBrokerSocket>,
}

impl Clone for LocalQuinnBrokerHandle {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind,
            name: self.name.clone(),
            socket: self.socket.clone(),
        }
    }
}

impl LocalQuinnBrokerHandle {
    #[cfg(unix)]
    fn prepare_remote_handoff(
        &self,
        inherited: &mut InheritedQuicBrokers,
        kept_fds: &mut Vec<OwnedFd>,
    ) -> Result<()> {
        let (parent, child) =
            StdUnixStream::pair().context("failed to create QUIC broker socketpair")?;
        parent
            .set_nonblocking(true)
            .context("failed to set QUIC broker parent socket nonblocking")?;
        child
            .set_nonblocking(true)
            .context("failed to set QUIC broker child socket nonblocking")?;
        self.socket.attach_remote(parent)?;
        let owned = unix_stream_into_owned_fd(child);
        let raw = owned.as_raw_fd();
        kept_fds.push(owned);
        let entry = InheritedQuicBroker {
            name: self.name.clone(),
            fd: raw,
        };
        match self.kind {
            QuinnBrokerKind::Forward => inherited.forward.push(entry),
            QuinnBrokerKind::ReverseTerminate => inherited.reverse.push(entry),
        }
        Ok(())
    }

    #[cfg(windows)]
    fn prepare_remote_handoff(
        &self,
        inherited: &mut InheritedQuicBrokers,
        accept_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    ) -> Result<()> {
        let listener = StdTcpListener::bind("127.0.0.1:0")
            .context("failed to bind QUIC broker rendezvous listener")?;
        listener
            .set_nonblocking(true)
            .context("failed to set QUIC broker rendezvous listener nonblocking")?;
        let addr = listener
            .local_addr()
            .context("failed to resolve QUIC broker rendezvous listener addr")?;
        let token = uuid::Uuid::new_v4().to_string();
        let socket = self.socket.clone();
        let expected = token.clone();
        let task = tokio::spawn(async move {
            let listener = match TokioTcpListener::from_std(listener) {
                Ok(listener) => listener,
                Err(_) => return,
            };
            let deadline = std::time::Instant::now() + crate::windows_handoff::HANDOFF_WAIT_TIMEOUT;
            loop {
                let Ok(remaining) = remaining_handoff_wait(deadline) else {
                    return;
                };
                let accepted = tokio::time::timeout(remaining, listener.accept()).await;
                let Ok(Ok((mut stream, _))) = accepted else {
                    return;
                };
                let Ok(remaining) = remaining_handoff_wait(deadline) else {
                    return;
                };
                match tokio::time::timeout(
                    remaining,
                    read_broker_token(&mut stream, expected.as_str()),
                )
                .await
                {
                    Ok(Ok(())) => {
                        let _ = socket.attach_remote_tokio(TokioQuinnBrokerStream::Tcp(stream));
                        return;
                    }
                    Ok(Err(_)) => continue,
                    Err(_) => return,
                }
            }
        });
        let entry = InheritedQuicBroker {
            name: self.name.clone(),
            addr: addr.to_string(),
            token,
        };
        accept_tasks.push(task);
        match self.kind {
            QuinnBrokerKind::Forward => inherited.forward.push(entry),
            QuinnBrokerKind::ReverseTerminate => inherited.reverse.push(entry),
        }
        Ok(())
    }

    pub(crate) fn detach_remote(&self) {
        self.socket.detach_remote();
    }
}

pub(crate) fn prepare_quic_broker_handoff(
    handles: &[LocalQuinnBrokerHandle],
    _config: &qpx_core::config::Config,
) -> Result<Option<QuinnBrokerPreparedHandoff>> {
    #[cfg(not(any(unix, windows)))]
    {
        let _ = handles;
        let _ = _config;
        Err(anyhow!(
            "QUIC broker handoff is only supported on unix and windows"
        ))
    }

    #[cfg(unix)]
    {
        if handles.is_empty() {
            return Ok(None);
        }
        let mut inherited = InheritedQuicBrokers {
            forward: Vec::new(),
            reverse: Vec::new(),
        };
        let mut kept_fds = Vec::new();
        let mut attached: Vec<LocalQuinnBrokerHandle> = Vec::new();
        for handle in handles {
            if let Err(err) = handle.prepare_remote_handoff(&mut inherited, &mut kept_fds) {
                for attached_handle in &attached {
                    attached_handle.detach_remote();
                }
                return Err(err);
            }
            attached.push(handle.clone());
        }
        let env_value = match serde_json::to_string(&inherited) {
            Ok(value) => value,
            Err(err) => {
                for handle in handles {
                    handle.detach_remote();
                }
                return Err(err).context("failed to serialize inherited QUIC brokers");
            }
        };
        Ok(Some(QuinnBrokerPreparedHandoff {
            env_value,
            kept_fds,
        }))
    }

    #[cfg(windows)]
    {
        if handles.is_empty() {
            return Ok(None);
        }
        let mut inherited = InheritedQuicBrokers {
            forward: Vec::new(),
            reverse: Vec::new(),
        };
        let mut accept_tasks = Vec::new();
        for handle in handles {
            if let Err(err) = handle.prepare_remote_handoff(&mut inherited, &mut accept_tasks) {
                for task in &accept_tasks {
                    task.abort();
                }
                return Err(err);
            }
        }
        let path = crate::windows_handoff::create_handoff_path(_config, "quic-brokers")?;
        if let Err(err) = crate::windows_handoff::write_json_file(path.as_path(), &inherited) {
            for task in &accept_tasks {
                task.abort();
            }
            return Err(err).context("failed to serialize inherited QUIC brokers");
        }
        Ok(Some(QuinnBrokerPreparedHandoff {
            env_value: path.display().to_string(),
            cleanup_path: path,
            accept_tasks,
        }))
    }
}

pub(crate) fn detach_quic_broker_handoff(handles: &[LocalQuinnBrokerHandle]) {
    for handle in handles {
        handle.detach_remote();
    }
}

pub(crate) fn prepare_server_endpoint_socket(
    name: &str,
    kind: QuinnBrokerKind,
    std_socket: std::net::UdpSocket,
    inherited_stream: Option<QuinnBrokerStream>,
    filter: Arc<dyn QuinnUdpIngressFilter>,
) -> Result<PreparedServerEndpointSocket> {
    if let Some(stream) = inherited_stream {
        return Ok(PreparedServerEndpointSocket {
            endpoint_socket: new_remote_broker_socket(std_socket, stream, filter)?,
            local_broker_handle: None,
        });
    }

    let (endpoint_socket, local_broker_handle) =
        new_local_broker_socket(name, kind, std_socket, filter)?;
    Ok(PreparedServerEndpointSocket {
        endpoint_socket,
        local_broker_handle: Some(local_broker_handle),
    })
}

#[cfg(feature = "http3")]
pub(crate) fn build_server_endpoint(
    socket: QuinnEndpointSocket,
    server_config: quinn::ServerConfig,
) -> Result<quinn::Endpoint> {
    Ok(quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket.as_async_socket(),
        Arc::new(quinn::TokioRuntime),
    )?)
}

fn new_local_broker_socket(
    name: &str,
    kind: QuinnBrokerKind,
    std_socket: std::net::UdpSocket,
    filter: Arc<dyn QuinnUdpIngressFilter>,
) -> Result<(QuinnEndpointSocket, LocalQuinnBrokerHandle)> {
    std_socket.set_nonblocking(true)?;
    let socket = Arc::new(LocalBrokerSocket::new(std_socket, filter)?);
    socket.start_recv_loop();
    Ok((
        QuinnEndpointSocket {
            socket: socket.clone(),
        },
        LocalQuinnBrokerHandle {
            kind,
            name: name.to_string(),
            socket,
        },
    ))
}

fn new_remote_broker_socket(
    std_socket: std::net::UdpSocket,
    inherited_stream: QuinnBrokerStream,
    filter: Arc<dyn QuinnUdpIngressFilter>,
) -> Result<QuinnEndpointSocket> {
    std_socket.set_nonblocking(true)?;
    let local_addr = std_socket.local_addr()?;
    let socket = Arc::new(RemoteBrokerSocket::new(
        std_socket,
        inherited_stream,
        filter,
    )?);
    socket.start_remote_tasks();
    let _ = local_addr;
    Ok(QuinnEndpointSocket { socket })
}

struct LocalBrokerSocket {
    io: Arc<UdpSocket>,
    inner: quinn::udp::UdpSocketState,
    recv_tx: mpsc::UnboundedSender<InjectedPacket>,
    recv_rx: Mutex<mpsc::UnboundedReceiver<InjectedPacket>>,
    filter: Arc<dyn QuinnUdpIngressFilter>,
    local_route: Mutex<RouteState>,
    remote_route: Arc<Mutex<RouteState>>,
    remote_writer: Arc<Mutex<Option<mpsc::UnboundedSender<BrokerFrame>>>>,
}

impl fmt::Debug for LocalBrokerSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalBrokerSocket").finish_non_exhaustive()
    }
}

impl LocalBrokerSocket {
    fn new(
        std_socket: std::net::UdpSocket,
        filter: Arc<dyn QuinnUdpIngressFilter>,
    ) -> Result<Self> {
        let io = Arc::new(UdpSocket::from_std(std_socket)?);
        let inner = quinn::udp::UdpSocketState::new((&*io).into())?;
        let (recv_tx, recv_rx) = mpsc::unbounded_channel();
        Ok(Self {
            io,
            inner,
            recv_tx,
            recv_rx: Mutex::new(recv_rx),
            filter,
            local_route: Mutex::new(RouteState::default()),
            remote_route: Arc::new(Mutex::new(RouteState::default())),
            remote_writer: Arc::new(Mutex::new(None)),
        })
    }

    fn start_recv_loop(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let recv = this.io.recv_from(buf.as_mut_slice()).await;
                let (n, addr) = match recv {
                    Ok(value) => value,
                    Err(_) => break,
                };
                let payload = &buf[..n];
                if !this.filter.allow(addr, payload) {
                    continue;
                }
                match this.route_inbound(addr, payload) {
                    RouteDecision::Local => {
                        this.local_route
                            .lock()
                            .expect("local route lock")
                            .observe_inbound(addr, payload);
                        let _ = this.recv_tx.send(InjectedPacket {
                            addr,
                            ecn: None,
                            dst_ip: None,
                            payload: payload.to_vec(),
                        });
                    }
                    RouteDecision::Remote => {
                        this.remote_route
                            .lock()
                            .expect("remote route lock")
                            .observe_inbound(addr, payload);
                        if let Some(writer) = this
                            .remote_writer
                            .lock()
                            .expect("remote writer lock")
                            .clone()
                        {
                            if writer
                                .send(BrokerFrame::InboundDatagram(InjectedPacket {
                                    addr,
                                    ecn: None,
                                    dst_ip: None,
                                    payload: payload.to_vec(),
                                }))
                                .is_err()
                            {
                                this.detach_remote();
                                this.local_route
                                    .lock()
                                    .expect("local route lock")
                                    .observe_inbound(addr, payload);
                                let _ = this.recv_tx.send(InjectedPacket {
                                    addr,
                                    ecn: None,
                                    dst_ip: None,
                                    payload: payload.to_vec(),
                                });
                            }
                        } else {
                            this.local_route
                                .lock()
                                .expect("local route lock")
                                .observe_inbound(addr, payload);
                            let _ = this.recv_tx.send(InjectedPacket {
                                addr,
                                ecn: None,
                                dst_ip: None,
                                payload: payload.to_vec(),
                            });
                        }
                    }
                    RouteDecision::Drop => {}
                }
            }
        });
    }

    fn route_inbound(&self, addr: SocketAddr, packet: &[u8]) -> RouteDecision {
        let remote_active = self
            .remote_writer
            .lock()
            .expect("remote writer lock")
            .is_some();
        if !remote_active {
            return RouteDecision::Local;
        }

        if self
            .local_route
            .lock()
            .expect("local route lock")
            .matches_cid(packet)
        {
            return RouteDecision::Local;
        }
        if self
            .remote_route
            .lock()
            .expect("remote route lock")
            .matches_cid(packet)
        {
            return RouteDecision::Remote;
        }
        if crate::transparent::quic::looks_like_quic_initial(packet) || is_quic_long_header(packet)
        {
            return RouteDecision::Remote;
        }
        if self
            .local_route
            .lock()
            .expect("local route lock")
            .addrs
            .contains(&addr)
        {
            return RouteDecision::Local;
        }
        if self
            .remote_route
            .lock()
            .expect("remote route lock")
            .addrs
            .contains(&addr)
        {
            return RouteDecision::Remote;
        }
        RouteDecision::Drop
    }

    #[cfg(unix)]
    fn attach_remote(&self, stream: QuinnBrokerStream) -> Result<()> {
        let tokio_stream = tokio_broker_stream_from_std(stream)?;
        self.attach_remote_tokio(tokio_stream)
    }

    fn attach_remote_tokio(&self, tokio_stream: TokioQuinnBrokerStream) -> Result<()> {
        let (read_half, write_half) = tokio::io::split(tokio_stream);
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        {
            let mut writer = self.remote_writer.lock().expect("remote writer lock");
            if writer.is_some() {
                return Err(anyhow!("QUIC broker remote is already attached"));
            }
            *writer = Some(write_tx);
        }
        *self.remote_route.lock().expect("remote route lock") = RouteState::default();
        let send_owner = Arc::new(SendActual {
            io: self.io.clone(),
            inner: quinn::udp::UdpSocketState::new((&*self.io).into())
                .context("failed to create QUIC broker send socket state")?,
        });
        let view = LocalBrokerView {
            remote_writer: self.remote_writer.clone(),
            remote_route: self.remote_route.clone(),
        };
        tokio::spawn(async move {
            broker_writer_loop(write_half, write_rx).await;
        });
        tokio::spawn(async move {
            local_remote_reader_loop(view, send_owner, read_half).await;
        });
        Ok(())
    }

    fn detach_remote(&self) {
        *self.remote_writer.lock().expect("remote writer lock") = None;
        *self.remote_route.lock().expect("remote route lock") = RouteState::default();
    }
}

struct RemoteBrokerSocket {
    io: Arc<UdpSocket>,
    inner: quinn::udp::UdpSocketState,
    recv_tx: mpsc::UnboundedSender<InjectedPacket>,
    recv_rx: Mutex<mpsc::UnboundedReceiver<InjectedPacket>>,
    filter: Arc<dyn QuinnUdpIngressFilter>,
    mode: AtomicU8,
    outbound_writer: Mutex<Option<mpsc::UnboundedSender<BrokerFrame>>>,
    inbound_stream: Mutex<Option<QuinnBrokerStream>>,
}

impl fmt::Debug for RemoteBrokerSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteBrokerSocket").finish_non_exhaustive()
    }
}

impl RemoteBrokerSocket {
    fn new(
        std_socket: std::net::UdpSocket,
        inherited_stream: QuinnBrokerStream,
        filter: Arc<dyn QuinnUdpIngressFilter>,
    ) -> Result<Self> {
        let io = Arc::new(UdpSocket::from_std(std_socket)?);
        let inner = quinn::udp::UdpSocketState::new((&*io).into())?;
        let (recv_tx, recv_rx) = mpsc::unbounded_channel();
        Ok(Self {
            io,
            inner,
            recv_tx,
            recv_rx: Mutex::new(recv_rx),
            filter,
            mode: AtomicU8::new(RemoteMode::Brokered as u8),
            outbound_writer: Mutex::new(None),
            inbound_stream: Mutex::new(Some(inherited_stream)),
        })
    }

    fn start_remote_tasks(self: &Arc<Self>) {
        let Some(stream) = self
            .inbound_stream
            .lock()
            .expect("inbound stream lock")
            .take()
        else {
            return;
        };
        let tokio_stream = match tokio_broker_stream_from_std(stream) {
            Ok(stream) => stream,
            Err(_) => {
                self.enter_direct_mode();
                return;
            }
        };
        let (read_half, write_half) = tokio::io::split(tokio_stream);
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        *self.outbound_writer.lock().expect("outbound writer lock") = Some(write_tx);
        tokio::spawn(async move {
            broker_writer_loop(write_half, write_rx).await;
        });
        let this = self.clone();
        tokio::spawn(async move {
            remote_broker_reader_loop(this, read_half).await;
        });
    }

    fn enter_direct_mode(self: &Arc<Self>) {
        if self
            .mode
            .compare_exchange(
                RemoteMode::Brokered as u8,
                RemoteMode::Direct as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_err()
        {
            return;
        }
        *self.outbound_writer.lock().expect("outbound writer lock") = None;
        let this = self.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let recv = this.io.recv_from(buf.as_mut_slice()).await;
                let (n, addr) = match recv {
                    Ok(value) => value,
                    Err(_) => break,
                };
                let payload = &buf[..n];
                if !this.filter.allow(addr, payload) {
                    continue;
                }
                let _ = this.recv_tx.send(InjectedPacket {
                    addr,
                    ecn: None,
                    dst_ip: None,
                    payload: payload.to_vec(),
                });
            }
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RouteDecision {
    Local,
    Remote,
    Drop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemoteMode {
    Brokered = 0,
    Direct = 1,
}

impl AsyncUdpSocket for LocalBrokerSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SocketPoller::new(self.io.clone(), false))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        for packet in datagrams_for_transmit(transmit) {
            self.local_route
                .lock()
                .expect("local route lock")
                .observe_outbound(transmit.destination, packet);
        }
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&*self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        poll_injected_packets(&self.recv_rx, cx, bufs, meta)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

impl AsyncUdpSocket for RemoteBrokerSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let immediate = self.mode.load(Ordering::SeqCst) == RemoteMode::Brokered as u8;
        Box::pin(SocketPoller::new(self.io.clone(), immediate))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        if self.mode.load(Ordering::SeqCst) == RemoteMode::Brokered as u8 {
            if let Some(writer) = self
                .outbound_writer
                .lock()
                .expect("outbound writer lock")
                .clone()
            {
                writer
                    .send(BrokerFrame::OutboundTransmit(OwnedTransmit {
                        destination: transmit.destination,
                        ecn: transmit.ecn,
                        contents: transmit.contents.to_vec(),
                        segment_size: transmit.segment_size,
                        src_ip: transmit.src_ip,
                    }))
                    .map_err(|_| std::io::Error::new(ErrorKind::BrokenPipe, "broker closed"))?;
                return Ok(());
            }
        }
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&*self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        poll_injected_packets(&self.recv_rx, cx, bufs, meta)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

struct SocketPoller {
    io: Arc<UdpSocket>,
    immediate: bool,
}

impl fmt::Debug for SocketPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketPoller")
            .field("immediate", &self.immediate)
            .finish()
    }
}

impl SocketPoller {
    fn new(io: Arc<UdpSocket>, immediate: bool) -> Self {
        Self { io, immediate }
    }
}

impl UdpPoller for SocketPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        if self.immediate {
            return Poll::Ready(Ok(()));
        }
        self.io.poll_send_ready(cx)
    }
}

fn poll_injected_packets(
    receiver: &Mutex<mpsc::UnboundedReceiver<InjectedPacket>>,
    cx: &mut TaskContext<'_>,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [quinn::udp::RecvMeta],
) -> Poll<std::io::Result<usize>> {
    let mut rx = receiver.lock().expect("recv queue lock");
    let mut count = 0usize;
    loop {
        let packet = if count == 0 {
            match Pin::new(&mut *rx).poll_recv(cx) {
                Poll::Ready(Some(packet)) => Some(packet),
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Pending => return Poll::Pending,
            }
        } else {
            rx.try_recv().ok()
        };
        let Some(packet) = packet else {
            break;
        };
        if count >= bufs.len() || count >= meta.len() {
            break;
        }
        let dst = &mut bufs[count];
        let len = packet.payload.len().min(dst.len());
        dst[..len].copy_from_slice(&packet.payload[..len]);
        meta[count] = quinn::udp::RecvMeta {
            addr: packet.addr,
            len,
            stride: len,
            ecn: packet.ecn,
            dst_ip: packet.dst_ip,
        };
        count += 1;
    }
    Poll::Ready(Ok(count))
}

struct SendActual {
    io: Arc<UdpSocket>,
    inner: quinn::udp::UdpSocketState,
}

async fn send_actual(sender: &SendActual, transmit: &OwnedTransmit) -> std::io::Result<()> {
    loop {
        let borrowed = transmit.borrowed();
        match sender.io.try_io(Interest::WRITABLE, || {
            sender.inner.send((&*sender.io).into(), &borrowed)
        }) {
            Ok(result) => return Ok(result),
            Err(err) if err.kind() == ErrorKind::WouldBlock => sender.io.writable().await?,
            Err(err) => return Err(err),
        }
    }
}

#[derive(Debug)]
enum BrokerFrame {
    InboundDatagram(InjectedPacket),
    OutboundTransmit(OwnedTransmit),
}

struct LocalBrokerView {
    remote_writer: Arc<Mutex<Option<mpsc::UnboundedSender<BrokerFrame>>>>,
    remote_route: Arc<Mutex<RouteState>>,
}

async fn broker_writer_loop<S>(
    mut write_half: WriteHalf<S>,
    mut frames: mpsc::UnboundedReceiver<BrokerFrame>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(frame) = frames.recv().await {
        if write_frame(&mut write_half, &frame).await.is_err() {
            break;
        }
    }
}

async fn local_remote_reader_loop<S>(
    broker: LocalBrokerView,
    sender: Arc<SendActual>,
    mut read_half: ReadHalf<S>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let frame = match read_frame(&mut read_half).await {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => break,
        };
        match frame {
            BrokerFrame::OutboundTransmit(transmit) => {
                for packet in transmit.datagrams() {
                    broker
                        .remote_route
                        .lock()
                        .expect("remote route lock")
                        .observe_outbound(transmit.destination, packet);
                }
                let _ = send_actual(sender.as_ref(), &transmit).await;
            }
            BrokerFrame::InboundDatagram(_) => {}
        }
    }
    *broker.remote_writer.lock().expect("remote writer lock") = None;
    *broker.remote_route.lock().expect("remote route lock") = RouteState::default();
}

async fn remote_broker_reader_loop<S>(socket: Arc<RemoteBrokerSocket>, mut read_half: ReadHalf<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match read_frame(&mut read_half).await {
            Ok(Some(BrokerFrame::InboundDatagram(packet))) => {
                let _ = socket.recv_tx.send(packet);
            }
            Ok(Some(BrokerFrame::OutboundTransmit(_))) => {}
            Ok(None) | Err(_) => {
                socket.enter_direct_mode();
                break;
            }
        }
    }
}

async fn write_frame<W>(write_half: &mut W, frame: &BrokerFrame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = encode_frame(frame)?;
    write_half
        .write_u32(encoded.len() as u32)
        .await
        .context("failed to write broker frame length")?;
    write_half
        .write_all(encoded.as_slice())
        .await
        .context("failed to write broker frame payload")?;
    write_half.flush().await.ok();
    Ok(())
}

async fn read_frame<R>(read_half: &mut R) -> Result<Option<BrokerFrame>>
where
    R: AsyncRead + Unpin,
{
    let len = match read_half.read_u32().await {
        Ok(len) => len as usize,
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).context("failed to read broker frame length"),
    };
    let mut buf = vec![0u8; len];
    read_half
        .read_exact(buf.as_mut_slice())
        .await
        .context("failed to read broker frame payload")?;
    decode_frame(buf.as_slice()).map(Some)
}

fn encode_frame(frame: &BrokerFrame) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match frame {
        BrokerFrame::InboundDatagram(packet) => {
            out.push(1);
            encode_socket_addr(packet.addr, &mut out);
            encode_optional_ecn(packet.ecn, &mut out);
            encode_optional_ip(packet.dst_ip, &mut out);
            out.extend_from_slice(&(packet.payload.len() as u32).to_be_bytes());
            out.extend_from_slice(packet.payload.as_slice());
        }
        BrokerFrame::OutboundTransmit(transmit) => {
            out.push(2);
            encode_socket_addr(transmit.destination, &mut out);
            encode_optional_ecn(transmit.ecn, &mut out);
            encode_optional_ip(transmit.src_ip, &mut out);
            out.extend_from_slice(
                &(transmit.segment_size.unwrap_or(0).min(u32::MAX as usize) as u32).to_be_bytes(),
            );
            out.extend_from_slice(&(transmit.contents.len() as u32).to_be_bytes());
            out.extend_from_slice(transmit.contents.as_slice());
        }
    }
    Ok(out)
}

fn decode_frame(mut buf: &[u8]) -> Result<BrokerFrame> {
    let Some(kind) = take_u8(&mut buf) else {
        return Err(anyhow!("broker frame missing kind"));
    };
    match kind {
        1 => {
            let addr = decode_socket_addr(&mut buf)?;
            let ecn = decode_optional_ecn(&mut buf)?;
            let dst_ip = decode_optional_ip(&mut buf)?;
            let len = take_u32(&mut buf).ok_or_else(|| anyhow!("broker frame missing len"))?;
            if buf.len() != len as usize {
                return Err(anyhow!("invalid broker inbound datagram length"));
            }
            Ok(BrokerFrame::InboundDatagram(InjectedPacket {
                addr,
                ecn,
                dst_ip,
                payload: buf.to_vec(),
            }))
        }
        2 => {
            let destination = decode_socket_addr(&mut buf)?;
            let ecn = decode_optional_ecn(&mut buf)?;
            let src_ip = decode_optional_ip(&mut buf)?;
            let segment_size =
                take_u32(&mut buf).ok_or_else(|| anyhow!("broker frame missing segment size"))?;
            let len = take_u32(&mut buf).ok_or_else(|| anyhow!("broker frame missing len"))?;
            if buf.len() != len as usize {
                return Err(anyhow!("invalid broker outbound transmit length"));
            }
            Ok(BrokerFrame::OutboundTransmit(OwnedTransmit {
                destination,
                ecn,
                contents: buf.to_vec(),
                segment_size: (segment_size != 0).then_some(segment_size as usize),
                src_ip,
            }))
        }
        _ => Err(anyhow!("unknown broker frame kind {}", kind)),
    }
}

fn encode_socket_addr(addr: SocketAddr, out: &mut Vec<u8>) {
    match addr {
        SocketAddr::V4(addr) => {
            out.push(4);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            out.push(6);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
}

fn decode_socket_addr(buf: &mut &[u8]) -> Result<SocketAddr> {
    let family = take_u8(buf).ok_or_else(|| anyhow!("missing socket addr family"))?;
    match family {
        4 => {
            let ip = take_array::<4>(buf).ok_or_else(|| anyhow!("missing ipv4 addr"))?;
            let port = take_u16(buf).ok_or_else(|| anyhow!("missing ipv4 port"))?;
            Ok(SocketAddr::new(Ipv4Addr::from(ip).into(), port))
        }
        6 => {
            let ip = take_array::<16>(buf).ok_or_else(|| anyhow!("missing ipv6 addr"))?;
            let port = take_u16(buf).ok_or_else(|| anyhow!("missing ipv6 port"))?;
            Ok(SocketAddr::new(Ipv6Addr::from(ip).into(), port))
        }
        _ => Err(anyhow!("unknown socket addr family {}", family)),
    }
}

fn encode_optional_ip(ip: Option<IpAddr>, out: &mut Vec<u8>) {
    match ip {
        Some(IpAddr::V4(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
        None => out.push(0),
    }
}

fn decode_optional_ip(buf: &mut &[u8]) -> Result<Option<IpAddr>> {
    let family = take_u8(buf).ok_or_else(|| anyhow!("missing optional ip family"))?;
    Ok(match family {
        0 => None,
        4 => Some(IpAddr::V4(Ipv4Addr::from(
            take_array::<4>(buf).ok_or_else(|| anyhow!("missing optional ipv4"))?,
        ))),
        6 => Some(IpAddr::V6(Ipv6Addr::from(
            take_array::<16>(buf).ok_or_else(|| anyhow!("missing optional ipv6"))?,
        ))),
        _ => return Err(anyhow!("unknown optional ip family {}", family)),
    })
}

fn encode_optional_ecn(ecn: Option<quinn::udp::EcnCodepoint>, out: &mut Vec<u8>) {
    out.push(ecn.map(|value| value as u8).unwrap_or(0xff));
}

fn decode_optional_ecn(buf: &mut &[u8]) -> Result<Option<quinn::udp::EcnCodepoint>> {
    let value = take_u8(buf).ok_or_else(|| anyhow!("missing ecn"))?;
    if value == 0xff {
        return Ok(None);
    }
    quinn::udp::EcnCodepoint::from_bits(value)
        .map(Some)
        .ok_or_else(|| anyhow!("invalid ecn bits {}", value))
}

fn take_u8(buf: &mut &[u8]) -> Option<u8> {
    let value = *buf.first()?;
    *buf = &buf[1..];
    Some(value)
}

fn take_u16(buf: &mut &[u8]) -> Option<u16> {
    let bytes = take_array::<2>(buf)?;
    Some(u16::from_be_bytes(bytes))
}

fn take_u32(buf: &mut &[u8]) -> Option<u32> {
    let bytes = take_array::<4>(buf)?;
    Some(u32::from_be_bytes(bytes))
}

fn take_array<const N: usize>(buf: &mut &[u8]) -> Option<[u8; N]> {
    let bytes = buf.get(..N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    *buf = &buf[N..];
    Some(out)
}

fn datagrams_for_transmit<'a>(
    transmit: &'a quinn::udp::Transmit<'a>,
) -> impl Iterator<Item = &'a [u8]> {
    let segment = transmit
        .segment_size
        .unwrap_or(transmit.contents.len())
        .max(1);
    transmit.contents.chunks(segment)
}

fn is_quic_long_header(packet: &[u8]) -> bool {
    packet.first().is_some_and(|first| (first & 0x80) != 0)
}

#[cfg(unix)]
fn unix_stream_into_owned_fd(stream: QuinnBrokerStream) -> OwnedFd {
    let raw = stream.into_raw_fd();
    unsafe { OwnedFd::from_raw_fd(raw) }
}

#[cfg(unix)]
fn adopt_unix_stream(fd: i32) -> Result<QuinnBrokerStream> {
    let stream = unsafe { QuinnBrokerStream::from_raw_fd(fd) };
    stream
        .set_nonblocking(true)
        .context("failed to set inherited QUIC broker stream nonblocking")?;
    Ok(stream)
}

#[cfg(windows)]
fn connect_windows_broker(addr: &str, token: &str) -> Result<QuinnBrokerStream> {
    let addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid QUIC broker rendezvous addr {addr}"))?;
    let deadline = std::time::Instant::now() + crate::windows_handoff::HANDOFF_WAIT_TIMEOUT;
    loop {
        match StdTcpStream::connect(addr) {
            Ok(mut stream) => {
                write_broker_token(&mut stream, token)?;
                stream
                    .set_nonblocking(true)
                    .context("failed to set inherited QUIC broker tcp stream nonblocking")?;
                return Ok(stream);
            }
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                if std::time::Instant::now() >= deadline {
                    return Err(err)
                        .with_context(|| format!("timed out connecting QUIC broker {addr}"));
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(err) => {
                return Err(err).with_context(|| format!("failed to connect QUIC broker {addr}"));
            }
        }
    }
}

fn tokio_broker_stream_from_std(stream: QuinnBrokerStream) -> Result<TokioQuinnBrokerStream> {
    #[cfg(unix)]
    {
        Ok(TokioQuinnBrokerStream::Unix(UnixStream::from_std(stream)?))
    }

    #[cfg(windows)]
    {
        Ok(TokioQuinnBrokerStream::Tcp(TokioTcpStream::from_std(
            stream,
        )?))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = stream;
        Err(anyhow!(
            "QUIC broker handoff is unsupported on this platform"
        ))
    }
}

#[cfg(windows)]
fn write_broker_token(stream: &mut StdTcpStream, token: &str) -> Result<()> {
    let bytes = token.as_bytes();
    let len = u16::try_from(bytes.len()).context("broker token too long")?;
    std::io::Write::write_all(stream, &len.to_be_bytes())
        .context("failed to write broker token length")?;
    std::io::Write::write_all(stream, bytes).context("failed to write broker token")?;
    std::io::Write::flush(stream).ok();
    Ok(())
}

#[cfg(windows)]
async fn read_broker_token(stream: &mut TokioTcpStream, expected: &str) -> Result<()> {
    const MAX_BROKER_TOKEN_LEN: usize = 512;
    let len = stream
        .read_u16()
        .await
        .context("failed to read broker token length")? as usize;
    if len == 0 || len > MAX_BROKER_TOKEN_LEN {
        return Err(anyhow!("invalid broker token length {len}"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .context("failed to read broker token")?;
    if buf != expected.as_bytes() {
        return Err(anyhow!("broker token mismatch"));
    }
    Ok(())
}

#[cfg(windows)]
fn remaining_handoff_wait(deadline: std::time::Instant) -> Result<std::time::Duration> {
    deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| anyhow!("timed out waiting for broker handoff"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn long_packet(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut packet = vec![0xc0, 0, 0, 0, 1, dcid.len() as u8];
        packet.extend_from_slice(dcid);
        packet.push(scid.len() as u8);
        packet.extend_from_slice(scid);
        packet.extend_from_slice(&[0u8; 8]);
        packet
    }

    fn short_packet(dcid: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x40];
        packet.extend_from_slice(dcid);
        packet.extend_from_slice(&[0u8; 4]);
        packet
    }

    #[test]
    fn route_state_matches_observed_long_and_short_headers() {
        let mut state = RouteState::default();
        let addr: SocketAddr = "127.0.0.1:4433".parse().expect("addr");
        let server_cid = [0x11, 0x22, 0x33, 0x44];
        let client_cid = [0xaa, 0xbb, 0xcc, 0xdd];

        state.observe_outbound(addr, &long_packet(&client_cid, &server_cid));
        assert!(
            state.matches_cid(&short_packet(&server_cid)),
            "short header should match observed server CID"
        );

        state.observe_inbound(addr, &long_packet(&server_cid, &client_cid));
        assert!(
            state.matches_cid(&long_packet(&server_cid, &client_cid)),
            "long header should match observed client/server CIDs"
        );
    }

    #[cfg(any(unix, windows))]
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn test_config() -> qpx_core::config::Config {
        qpx_core::config::Config {
            state_dir: None,
            identity: Default::default(),
            messages: Default::default(),
            runtime: Default::default(),
            system_log: Default::default(),
            access_log: Default::default(),
            audit_log: Default::default(),
            metrics: None,
            otel: None,
            acme: None,
            exporter: None,
            auth: Default::default(),
            identity_sources: Vec::new(),
            ext_authz: Vec::new(),
            destination_resolution: Default::default(),
            listeners: Vec::new(),
            named_sets: Vec::new(),
            http_guard_profiles: Vec::new(),
            rate_limit_profiles: Vec::new(),
            upstream_trust_profiles: Vec::new(),
            reverse: Vec::new(),
            upstreams: Vec::new(),
            cache: Default::default(),
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn broker_frame_round_trip_preserves_transmit() {
        let transmit = BrokerFrame::OutboundTransmit(OwnedTransmit {
            destination: "127.0.0.1:9443".parse().expect("destination"),
            ecn: quinn::udp::EcnCodepoint::from_bits(0b10),
            contents: vec![1, 2, 3, 4, 5, 6],
            segment_size: Some(3),
            src_ip: Some("127.0.0.1".parse().expect("src ip")),
        });
        let encoded = encode_frame(&transmit).expect("encode");
        let decoded = decode_frame(encoded.as_slice()).expect("decode");
        match decoded {
            BrokerFrame::OutboundTransmit(decoded) => {
                assert_eq!(decoded.destination, "127.0.0.1:9443".parse().unwrap());
                assert_eq!(decoded.contents, vec![1, 2, 3, 4, 5, 6]);
                assert_eq!(decoded.segment_size, Some(3));
                assert_eq!(decoded.src_ip, Some("127.0.0.1".parse().unwrap()));
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn quic_broker_handoff_round_trip_restores_roles() {
        let _guard = env_lock().lock().expect("env lock");

        let forward_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("forward bind");
        let reverse_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("reverse bind");
        let (_, forward_handle) = new_local_broker_socket(
            "forward-h3",
            QuinnBrokerKind::Forward,
            forward_socket,
            Arc::new(NoopQuinnUdpIngressFilter),
        )
        .expect("forward broker");
        let (_, reverse_handle) = new_local_broker_socket(
            "reverse-h3",
            QuinnBrokerKind::ReverseTerminate,
            reverse_socket,
            Arc::new(NoopQuinnUdpIngressFilter),
        )
        .expect("reverse broker");

        let handoff =
            prepare_quic_broker_handoff(&[forward_handle, reverse_handle], &test_config())
                .expect("prepare handoff")
                .expect("handoff");
        unsafe {
            std::env::set_var(ENV_INHERITED_QUIC_BROKERS, &handoff.env_value);
        }
        #[cfg(unix)]
        std::mem::forget(handoff.kept_fds);

        let mut restored = QuinnBrokerRestoreSet::take_from_env()
            .expect("take handoff")
            .expect("restore");
        assert!(
            restored.take_forward("forward-h3").is_some(),
            "forward broker should restore by role"
        );
        assert!(
            restored.take_reverse("reverse-h3").is_some(),
            "reverse broker should restore by role"
        );
        restored.ensure_consumed().expect("restore consumed");
    }
}
