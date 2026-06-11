mod metrics;
mod packet_pool;
mod poller;
mod queue;
mod rate_limiter;

use super::endpoint::{QuinnEndpointSocket, QuinnUdpIngressFilter};
use super::frame::{BrokerFrame, InjectedPacket, OwnedTransmit, datagrams_for_transmit};
use super::routing::{SharedRouteState, is_quic_long_header};
use super::stream::{QuinnBrokerStream, TokioQuinnBrokerStream, tokio_broker_stream_from_std};
use super::tasks::{
    LocalBrokerView, SendActual, broker_writer_loop, local_remote_reader_loop,
    remote_broker_reader_loop,
};
use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use packet_pool::{PacketBufferPool, pooled_bytes_from_slice, pooled_bytes_from_vec};
use poller::{SocketPoller, poll_injected_packets};
use queue::{
    EnqueueFailure, allow_source_datagram, enqueue_broker_frame, enqueue_injected_packet,
    packet_from_bytes, record_broker_drop,
};
use quinn::{AsyncUdpSocket, UdpPoller};
use rate_limiter::ShardedDatagramRateLimiter;
use std::fmt;
use std::io::{ErrorKind, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const BROKER_RECV_QUEUE_CAPACITY: usize = 4096;
const BROKER_FRAME_QUEUE_CAPACITY: usize = 4096;
const BROKER_SOURCE_RATE_SHARDS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuinnBrokerKind {
    Forward,
    ReverseTerminate,
}

pub(crate) struct LocalQuinnBrokerHandle {
    pub(super) kind: QuinnBrokerKind,
    pub(super) name: String,
    pub(super) socket: Arc<LocalBrokerSocket>,
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
    pub(crate) fn detach_remote(&self) {
        self.socket.detach_remote();
    }
}

pub(super) fn new_local_broker_socket(
    name: &str,
    kind: QuinnBrokerKind,
    std_socket: std::net::UdpSocket,
    filter: Arc<dyn QuinnUdpIngressFilter>,
) -> Result<(QuinnEndpointSocket, LocalQuinnBrokerHandle)> {
    std_socket.set_nonblocking(true)?;
    let socket = Arc::new(LocalBrokerSocket::new(std_socket, filter)?);
    socket.start_recv_loop();
    Ok((
        QuinnEndpointSocket::new(socket.clone()),
        LocalQuinnBrokerHandle {
            kind,
            name: name.to_string(),
            socket,
        },
    ))
}

pub(super) fn new_remote_broker_socket(
    std_socket: std::net::UdpSocket,
    inherited_stream: QuinnBrokerStream,
    filter: Arc<dyn QuinnUdpIngressFilter>,
) -> Result<QuinnEndpointSocket> {
    std_socket.set_nonblocking(true)?;
    let _ = std_socket.local_addr()?;
    let socket = Arc::new(RemoteBrokerSocket::new(
        std_socket,
        inherited_stream,
        filter,
    )?);
    socket.start_remote_tasks();
    Ok(QuinnEndpointSocket::new(socket))
}

pub(super) struct LocalBrokerSocket {
    io: Arc<UdpSocket>,
    inner: quinn::udp::UdpSocketState,
    recv_tx: mpsc::Sender<InjectedPacket>,
    recv_rx: Mutex<mpsc::Receiver<InjectedPacket>>,
    source_limiter: ShardedDatagramRateLimiter,
    packet_pool: Arc<PacketBufferPool>,
    filter: Arc<dyn QuinnUdpIngressFilter>,
    local_route: SharedRouteState,
    remote_route: Arc<SharedRouteState>,
    remote_writer: Arc<ArcSwapOption<mpsc::Sender<BrokerFrame>>>,
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
        let (recv_tx, recv_rx) = mpsc::channel(BROKER_RECV_QUEUE_CAPACITY);
        Ok(Self {
            io,
            inner,
            recv_tx,
            recv_rx: Mutex::new(recv_rx),
            source_limiter: ShardedDatagramRateLimiter::new(BROKER_SOURCE_RATE_SHARDS),
            packet_pool: Arc::new(PacketBufferPool::new(512)),
            filter,
            local_route: SharedRouteState::default(),
            remote_route: Arc::new(SharedRouteState::default()),
            remote_writer: Arc::new(ArcSwapOption::from(None)),
        })
    }

    fn start_recv_loop(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let mut buf = this.packet_pool.take(65_535);
                buf.resize(65_535, 0);
                let recv = this.io.recv_from(buf.as_mut()).await;
                let (n, addr) = match recv {
                    Ok(value) => value,
                    Err(_) => break,
                };
                let payload = pooled_bytes_from_vec(this.packet_pool.clone(), buf, n);
                if !this.filter.allow(addr, payload.as_ref()) {
                    continue;
                }
                if !this.allow_source_datagram(addr, "local") {
                    continue;
                }
                match this.route_inbound(addr, payload.as_ref()) {
                    RouteDecision::Local => {
                        this.observe_local_inbound(addr, payload.as_ref());
                        this.enqueue_packet(packet_from_bytes(addr, payload), "local_endpoint");
                    }
                    RouteDecision::Remote => {
                        this.observe_remote_inbound(addr, payload.as_ref());
                        if let Some(writer) = this.remote_writer.load_full() {
                            if writer.capacity() == 0 {
                                record_broker_drop("remote_broker", "queue_full");
                                continue;
                            }
                            match enqueue_broker_frame(
                                &writer,
                                BrokerFrame::InboundDatagram(packet_from_bytes(
                                    addr,
                                    payload.clone(),
                                )),
                                "remote_broker",
                            ) {
                                Ok(()) => {}
                                Err(EnqueueFailure::Full) => {}
                                Err(EnqueueFailure::Closed) => {
                                    this.detach_remote();
                                    this.observe_local_inbound(addr, payload.as_ref());
                                    this.enqueue_packet(
                                        packet_from_bytes(addr, payload),
                                        "local_endpoint",
                                    );
                                }
                            }
                        } else {
                            this.observe_local_inbound(addr, payload.as_ref());
                            this.enqueue_packet(packet_from_bytes(addr, payload), "local_endpoint");
                        }
                    }
                    RouteDecision::Drop => {}
                }
            }
        });
    }

    fn route_inbound(&self, addr: SocketAddr, packet: &[u8]) -> RouteDecision {
        let remote_active = self.remote_writer.load().is_some();
        if !remote_active {
            return RouteDecision::Local;
        }

        if self.local_route.matches_addr_or_cid(addr, packet) {
            return RouteDecision::Local;
        }
        if self.remote_route.matches_addr_or_cid(addr, packet) {
            return RouteDecision::Remote;
        }
        if crate::transparent::quic::looks_like_quic_initial(packet) || is_quic_long_header(packet)
        {
            return RouteDecision::Remote;
        }
        RouteDecision::Drop
    }

    fn observe_local_inbound(&self, addr: SocketAddr, packet: &[u8]) {
        if !self.local_route.inbound_update_needed(addr, packet) {
            return;
        }
        self.local_route.observe_inbound(addr, packet);
    }

    fn observe_remote_inbound(&self, addr: SocketAddr, packet: &[u8]) {
        if !self.remote_route.inbound_update_needed(addr, packet) {
            return;
        }
        self.remote_route.observe_inbound(addr, packet);
    }

    #[cfg(unix)]
    pub(super) fn attach_remote(&self, stream: QuinnBrokerStream) -> Result<()> {
        let tokio_stream = tokio_broker_stream_from_std(stream)?;
        self.attach_remote_tokio(tokio_stream)
    }

    pub(super) fn attach_remote_tokio(&self, tokio_stream: TokioQuinnBrokerStream) -> Result<()> {
        let (read_half, write_half) = tokio::io::split(tokio_stream);
        let (write_tx, write_rx) = mpsc::channel(BROKER_FRAME_QUEUE_CAPACITY);
        {
            if self.remote_writer.load().is_some() {
                return Err(anyhow!("QUIC broker remote is already attached"));
            }
            self.remote_writer.store(Some(Arc::new(write_tx)));
        }
        self.remote_route.reset();
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

    pub(super) fn detach_remote(&self) {
        self.remote_writer.store(None);
        self.remote_route.reset();
    }
}

pub(super) struct RemoteBrokerSocket {
    io: Arc<UdpSocket>,
    inner: quinn::udp::UdpSocketState,
    recv_tx: mpsc::Sender<InjectedPacket>,
    recv_rx: Mutex<mpsc::Receiver<InjectedPacket>>,
    source_limiter: ShardedDatagramRateLimiter,
    packet_pool: Arc<PacketBufferPool>,
    filter: Arc<dyn QuinnUdpIngressFilter>,
    mode: AtomicU8,
    outbound_writer: ArcSwapOption<mpsc::Sender<BrokerFrame>>,
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
        let (recv_tx, recv_rx) = mpsc::channel(BROKER_RECV_QUEUE_CAPACITY);
        Ok(Self {
            io,
            inner,
            recv_tx,
            recv_rx: Mutex::new(recv_rx),
            source_limiter: ShardedDatagramRateLimiter::new(BROKER_SOURCE_RATE_SHARDS),
            packet_pool: Arc::new(PacketBufferPool::new(512)),
            filter,
            mode: AtomicU8::new(RemoteMode::Brokered as u8),
            outbound_writer: ArcSwapOption::from(None),
            inbound_stream: Mutex::new(Some(inherited_stream)),
        })
    }

    fn start_remote_tasks(self: &Arc<Self>) {
        let Some(stream) = self
            .inbound_stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
        let (write_tx, write_rx) = mpsc::channel(BROKER_FRAME_QUEUE_CAPACITY);
        self.outbound_writer.store(Some(Arc::new(write_tx)));
        tokio::spawn(async move {
            broker_writer_loop(write_half, write_rx).await;
        });
        let this = self.clone();
        tokio::spawn(async move {
            remote_broker_reader_loop(this, read_half).await;
        });
    }

    pub(super) fn enter_direct_mode(self: &Arc<Self>) {
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
        self.outbound_writer.store(None);
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let mut buf = this.packet_pool.take(65_535);
                buf.resize(65_535, 0);
                let recv = this.io.recv_from(buf.as_mut()).await;
                let (n, addr) = match recv {
                    Ok(value) => value,
                    Err(_) => break,
                };
                let payload = pooled_bytes_from_vec(this.packet_pool.clone(), buf, n);
                if !this.filter.allow(addr, payload.as_ref()) {
                    continue;
                }
                if !this.allow_source_datagram(addr, "remote_direct") {
                    continue;
                }
                this.enqueue_payload_bytes(addr, payload, "remote_endpoint");
            }
        });
    }

    pub(super) fn enqueue_injected_packet(&self, packet: InjectedPacket, queue: &'static str) {
        enqueue_injected_packet(&self.recv_tx, packet, queue);
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
            if self
                .local_route
                .outbound_update_needed(transmit.destination, packet)
            {
                self.local_route
                    .observe_outbound(transmit.destination, packet);
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

impl AsyncUdpSocket for RemoteBrokerSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let immediate = self.mode.load(Ordering::SeqCst) == RemoteMode::Brokered as u8;
        Box::pin(SocketPoller::new(self.io.clone(), immediate))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        if self.mode.load(Ordering::SeqCst) == RemoteMode::Brokered as u8
            && let Some(writer) = self.outbound_writer.load_full()
        {
            if writer.capacity() == 0 {
                record_broker_drop("outbound_broker", "queue_full");
                return Err(std::io::Error::new(
                    ErrorKind::WouldBlock,
                    "broker frame queue is full",
                ));
            }
            enqueue_broker_frame(
                &writer,
                BrokerFrame::OutboundTransmit(OwnedTransmit {
                    destination: transmit.destination,
                    ecn: transmit.ecn,
                    contents: self.owned_transmit_contents(transmit.contents),
                    segment_size: transmit.segment_size,
                    src_ip: transmit.src_ip,
                }),
                "outbound_broker",
            )
            .map_err(|err| match err {
                EnqueueFailure::Closed => {
                    std::io::Error::new(ErrorKind::BrokenPipe, "broker closed")
                }
                EnqueueFailure::Full => {
                    std::io::Error::new(ErrorKind::WouldBlock, "broker frame queue is full")
                }
            })?;
            return Ok(());
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

impl LocalBrokerSocket {
    fn allow_source_datagram(&self, addr: SocketAddr, queue: &'static str) -> bool {
        allow_source_datagram(&self.source_limiter, addr, queue)
    }

    fn enqueue_packet(&self, packet: InjectedPacket, queue: &'static str) {
        if self.recv_tx.capacity() == 0 {
            record_broker_drop(queue, "queue_full");
            return;
        }
        enqueue_injected_packet(&self.recv_tx, packet, queue);
    }
}

impl RemoteBrokerSocket {
    fn allow_source_datagram(&self, addr: SocketAddr, queue: &'static str) -> bool {
        allow_source_datagram(&self.source_limiter, addr, queue)
    }

    fn enqueue_payload_bytes(&self, addr: SocketAddr, payload: Bytes, queue: &'static str) {
        if self.recv_tx.capacity() == 0 {
            record_broker_drop(queue, "queue_full");
            return;
        }
        enqueue_injected_packet(&self.recv_tx, packet_from_bytes(addr, payload), queue);
    }

    fn owned_transmit_contents(&self, payload: &[u8]) -> Bytes {
        pooled_bytes_from_slice(self.packet_pool.clone(), payload)
    }
}
