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
                // Established 1-RTT traffic bypasses the per-source handshake
                // flood cap; handshakes and unknown peers stay limited below.
                // Bounded queues and QUIC flow control still bound bypassed flows.
                if !this.bypass_source_limiter(addr, payload.as_ref())
                    && !allow_source_datagram(&this.source_limiter, addr, "local")
                {
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
        decide_inbound_route(
            &self.local_route,
            &self.remote_route,
            remote_active,
            addr,
            packet,
        )
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
                // Fail-closed: direct mode has no route state to distinguish
                // established peers, so the per-source handshake cap still
                // applies to every datagram here.
                if !allow_source_datagram(&this.source_limiter, addr, "remote_direct") {
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

fn decide_inbound_route(
    local_route: &SharedRouteState,
    remote_route: &SharedRouteState,
    remote_active: bool,
    addr: SocketAddr,
    packet: &[u8],
) -> RouteDecision {
    if !remote_active {
        return RouteDecision::Local;
    }
    // CID-first: known connection IDs route to their owner before any
    // address fallback, prioritizing the child/new generation so child CIDs
    // shadow parent address entries and old sessions keep parent affinity.
    if remote_route.matches_cid(packet) {
        return RouteDecision::Remote;
    }
    if local_route.matches_cid(packet) {
        return RouteDecision::Local;
    }
    // Fresh handshakes (Initial/long header with unknown CID) go to the
    // child even when the peer address is already known on the parent, so a
    // new connection from an old peer socket reaches the new generation.
    if crate::transparent::quic::looks_like_quic_initial(packet) || is_quic_long_header(packet) {
        return RouteDecision::Remote;
    }
    // Address fallback preserves old-session affinity for non-handshake
    // traffic; truly unknown peers fail closed below.
    if local_route.matches_addr(addr) {
        return RouteDecision::Local;
    }
    if remote_route.matches_addr(addr) {
        return RouteDecision::Remote;
    }
    RouteDecision::Drop
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

fn should_bypass_source_limit(
    local_route: &SharedRouteState,
    remote_route: &SharedRouteState,
    remote_active: bool,
    _addr: SocketAddr,
    packet: &[u8],
) -> bool {
    // Handshake/long-header traffic (including QUIC Initials) always stays
    // under the per-source cap, even from a known address, so a single known
    // peer cannot flood new handshakes without bound.
    if crate::transparent::quic::looks_like_quic_initial(packet) || is_quic_long_header(packet) {
        return false;
    }
    // CID-only: a known address alone must not bypass, or a known peer
    // could flood unknown CIDs uncapped. Migration still bypasses because
    // the CID itself is known.
    if local_route.matches_cid(packet) {
        return true;
    }
    remote_active && remote_route.matches_cid(packet)
}

impl LocalBrokerSocket {
    fn bypass_source_limiter(&self, addr: SocketAddr, packet: &[u8]) -> bool {
        let remote_active = self.remote_writer.load().is_some();
        should_bypass_source_limit(
            &self.local_route,
            &self.remote_route,
            remote_active,
            addr,
            packet,
        )
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

#[cfg(test)]
mod tests {
    use super::RouteDecision;
    use super::SharedRouteState;
    use super::decide_inbound_route;
    use super::rate_limiter::ShardedDatagramRateLimiter;
    use super::should_bypass_source_limit;
    use std::net::SocketAddr;

    fn test_addr(ip_last: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([198, 51, 100, ip_last], port))
    }

    fn long_header_packet(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut packet = vec![0xC0, 0x00, 0x00, 0x00, 0x01, dcid.len() as u8];
        packet.extend_from_slice(dcid);
        packet.push(scid.len() as u8);
        packet.extend_from_slice(scid);
        packet.extend_from_slice(&[0u8; 16]);
        packet
    }

    fn short_header_packet(dcid: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x40];
        packet.extend_from_slice(dcid);
        packet
    }

    #[test]
    fn established_short_header_bypasses_while_handshake_and_unknown_stay_limited() {
        let local = SharedRouteState::default();
        let remote = SharedRouteState::default();
        let addr = test_addr(1, 5000);
        let dcid = [1u8, 2, 3, 4];
        let scid = [5u8, 6, 7, 8];

        // First inbound Initial learns addr, CID, and server CID length.
        local.observe_inbound(addr, &long_header_packet(&dcid, &scid));

        // Healthy established 1-RTT burst from the known addr/CID bypasses.
        assert!(should_bypass_source_limit(
            &local,
            &remote,
            false,
            addr,
            &short_header_packet(&dcid),
        ));

        // New handshake (long header) from the same known address stays limited.
        assert!(!should_bypass_source_limit(
            &local,
            &remote,
            false,
            addr,
            &long_header_packet(&[9u8, 9, 9, 9], &scid),
        ));

        // Unknown peer short-header with unknown CID stays limited.
        let unknown = test_addr(2, 6000);
        assert!(!should_bypass_source_limit(
            &local,
            &remote,
            false,
            unknown,
            &short_header_packet(&[9u8, 9, 9, 9]),
        ));

        // Known address with unknown CID stays limited: address alone must
        // not bypass, or a known peer could flood unknown CIDs uncapped.
        assert!(!should_bypass_source_limit(
            &local,
            &remote,
            false,
            addr,
            &short_header_packet(&[9u8, 9, 9, 9]),
        ));

        // Same CID from a migrated address still matches as established.
        let migrated = test_addr(3, 7000);
        assert!(should_bypass_source_limit(
            &local,
            &remote,
            false,
            migrated,
            &short_header_packet(&dcid),
        ));
    }

    #[test]
    fn remote_route_bypass_requires_active_remote() {
        let local = SharedRouteState::default();
        let remote = SharedRouteState::default();
        let addr = test_addr(4, 8000);
        let dcid = [11u8, 12, 13, 14];
        let scid = [15u8, 16, 17, 18];
        remote.observe_inbound(addr, &long_header_packet(&dcid, &scid));

        assert!(should_bypass_source_limit(
            &local,
            &remote,
            true,
            addr,
            &short_header_packet(&dcid),
        ));
        // Fail-closed: stale remote knowledge must not bypass once detached.
        assert!(!should_bypass_source_limit(
            &local,
            &remote,
            false,
            addr,
            &short_header_packet(&dcid),
        ));
    }

    #[test]
    fn established_burst_avoids_cap_while_unknown_handshake_flood_is_capped() {
        let local = SharedRouteState::default();
        let remote = SharedRouteState::default();
        let limiter = ShardedDatagramRateLimiter::new(32);

        let established_addr = test_addr(5, 9000);
        let dcid = [21u8, 22, 23, 24];
        let scid = [25u8, 26, 27, 28];
        local.observe_inbound(established_addr, &long_header_packet(&dcid, &scid));
        let established_packet = short_header_packet(&dcid);

        // Healthy burst: 600 established 1-RTT datagrams never hit the limiter.
        let mut established_limited = 0usize;
        for _ in 0..600 {
            if !should_bypass_source_limit(
                &local,
                &remote,
                false,
                established_addr,
                &established_packet,
            ) && !limiter.allow(established_addr)
            {
                established_limited += 1;
            }
        }
        assert_eq!(established_limited, 0);

        // Unknown-peer handshake flood: nothing bypasses, limiter caps at 512/window.
        let unknown_addr = test_addr(6, 9100);
        let handshake_packet = long_header_packet(&[31u8, 32, 33, 34], &[35u8, 36, 37, 38]);
        let mut allowed = 0usize;
        let mut limited = 0usize;
        for _ in 0..600 {
            assert!(!should_bypass_source_limit(
                &local,
                &remote,
                false,
                unknown_addr,
                &handshake_packet,
            ));
            if limiter.allow(unknown_addr) {
                allowed += 1;
            } else {
                limited += 1;
            }
        }
        assert_eq!(allowed, 512);
        assert_eq!(limited, 88);
    }

    #[test]
    fn upgrade_handoff_prefers_child_cid_and_routes_fresh_initial_to_child() {
        let local = SharedRouteState::default();
        let remote = SharedRouteState::default();
        // Single UDP client socket shared by the established parent
        // connection and the new child connection (TEST-NET-2, synthetic).
        let client_addr = test_addr(7, 9200);
        let parent_dcid = [0xA1u8, 0xA2, 0xA3, 0xA4];
        let parent_scid = [0xB1u8, 0xB2, 0xB3, 0xB4];
        let child_dcid = [0xC1u8, 0xC2, 0xC3, 0xC4];
        let child_scid = [0xD1u8, 0xD2, 0xD3, 0xD4];

        // Established parent session on the client socket.
        local.observe_inbound(client_addr, &long_header_packet(&parent_dcid, &parent_scid));
        // New child connection from the same socket; the child table also
        // knows the same peer address, so the child CID must shadow the
        // parent address entry.
        remote.observe_inbound(client_addr, &long_header_packet(&child_dcid, &child_scid));

        // Old session affinity: known parent CID stays on the parent even
        // though the address is known on both generations.
        assert_eq!(
            decide_inbound_route(
                &local,
                &remote,
                true,
                client_addr,
                &short_header_packet(&parent_dcid),
            ),
            RouteDecision::Local
        );
        // Known parent CID in a long-header retransmit also stays local,
        // proving CID precedes the handshake fallback.
        assert_eq!(
            decide_inbound_route(
                &local,
                &remote,
                true,
                client_addr,
                &long_header_packet(&parent_dcid, &parent_scid),
            ),
            RouteDecision::Local
        );
        // Child CID shadows the parent address entry (short header proves
        // the CID path, not the long-header fallback).
        assert_eq!(
            decide_inbound_route(
                &local,
                &remote,
                true,
                client_addr,
                &short_header_packet(&child_dcid),
            ),
            RouteDecision::Remote
        );
        // Fresh Initial with an unknown CID from the old peer socket reaches
        // the new generation instead of sticking to the parent address.
        let fresh_dcid = [0xE1u8, 0xE2, 0xE3, 0xE4];
        let fresh_scid = [0xF1u8, 0xF2, 0xF3, 0xF4];
        assert_eq!(
            decide_inbound_route(
                &local,
                &remote,
                true,
                client_addr,
                &long_header_packet(&fresh_dcid, &fresh_scid),
            ),
            RouteDecision::Remote
        );
        // Truly unknown short-header traffic fails closed.
        let unknown_addr = test_addr(8, 9300);
        let unknown_cid = [0x11u8, 0x22, 0x33, 0x44];
        assert_eq!(
            decide_inbound_route(
                &local,
                &remote,
                true,
                unknown_addr,
                &short_header_packet(&unknown_cid),
            ),
            RouteDecision::Drop
        );
        // Unknown-peer handshakes still go to the child for acceptance.
        assert_eq!(
            decide_inbound_route(
                &local,
                &remote,
                true,
                unknown_addr,
                &long_header_packet(&fresh_dcid, &fresh_scid),
            ),
            RouteDecision::Remote
        );
        // Without an attached child everything stays local.
        assert_eq!(
            decide_inbound_route(
                &local,
                &remote,
                false,
                client_addr,
                &short_header_packet(&child_dcid),
            ),
            RouteDecision::Local
        );
    }
}
