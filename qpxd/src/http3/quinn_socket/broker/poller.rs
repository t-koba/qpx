use super::super::frame::InjectedPacket;
use quinn::UdpPoller;
use std::fmt;
use std::io::IoSliceMut;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub(super) struct SocketPoller {
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
    pub(super) fn new(io: Arc<UdpSocket>, immediate: bool) -> Self {
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

pub(super) fn poll_injected_packets(
    receiver: &Mutex<mpsc::Receiver<InjectedPacket>>,
    cx: &mut TaskContext<'_>,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [quinn::udp::RecvMeta],
) -> Poll<std::io::Result<usize>> {
    let mut rx = receiver
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
