use super::endpoint::{QuinnEndpointSocket, QuinnUdpIngressFilter};
use super::frame::{BrokerFrame, InjectedPacket, OwnedTransmit, datagrams_for_transmit};
use super::routing::{RouteState, is_quic_long_header};
use super::stream::{QuinnBrokerStream, TokioQuinnBrokerStream, tokio_broker_stream_from_std};
use super::tasks::{
    LocalBrokerView, SendActual, broker_writer_loop, local_remote_reader_loop,
    remote_broker_reader_loop,
};
use anyhow::{Context, Result, anyhow};
use quinn::{AsyncUdpSocket, UdpPoller};
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
    let local_addr = std_socket.local_addr()?;
    let socket = Arc::new(RemoteBrokerSocket::new(
        std_socket,
        inherited_stream,
        filter,
    )?);
    socket.start_remote_tasks();
    let _ = local_addr;
    Ok(QuinnEndpointSocket::new(socket))
}

pub(super) struct LocalBrokerSocket {
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
    pub(super) fn attach_remote(&self, stream: QuinnBrokerStream) -> Result<()> {
        let tokio_stream = tokio_broker_stream_from_std(stream)?;
        self.attach_remote_tokio(tokio_stream)
    }

    pub(super) fn attach_remote_tokio(&self, tokio_stream: TokioQuinnBrokerStream) -> Result<()> {
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

    pub(super) fn detach_remote(&self) {
        *self.remote_writer.lock().expect("remote writer lock") = None;
        *self.remote_route.lock().expect("remote route lock") = RouteState::default();
    }
}

pub(super) struct RemoteBrokerSocket {
    io: Arc<UdpSocket>,
    inner: quinn::udp::UdpSocketState,
    pub(super) recv_tx: mpsc::UnboundedSender<InjectedPacket>,
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
        if self.mode.load(Ordering::SeqCst) == RemoteMode::Brokered as u8
            && let Some(writer) = self
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
