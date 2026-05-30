use super::super::frame::{BrokerFrame, InjectedPacket};
use super::rate_limiter::ShardedDatagramRateLimiter;
use bytes::Bytes;
use metrics::counter;
use std::net::SocketAddr;
use tokio::sync::mpsc;

pub(super) fn packet_from_bytes(addr: SocketAddr, payload: Bytes) -> InjectedPacket {
    InjectedPacket {
        addr,
        ecn: None,
        dst_ip: None,
        payload,
    }
}

pub(super) fn enqueue_injected_packet(
    tx: &mpsc::Sender<InjectedPacket>,
    packet: InjectedPacket,
    queue: &'static str,
) {
    match tx.try_send(packet) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => record_broker_drop(queue, "queue_full"),
        Err(mpsc::error::TrySendError::Closed(_)) => record_broker_drop(queue, "queue_closed"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EnqueueFailure {
    Full,
    Closed,
}

pub(super) fn enqueue_broker_frame(
    tx: &mpsc::Sender<BrokerFrame>,
    frame: BrokerFrame,
    queue: &'static str,
) -> std::result::Result<(), EnqueueFailure> {
    match tx.try_send(frame) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            record_broker_drop(queue, "queue_full");
            Err(EnqueueFailure::Full)
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            record_broker_drop(queue, "queue_closed");
            Err(EnqueueFailure::Closed)
        }
    }
}

pub(super) fn allow_source_datagram(
    limiter: &ShardedDatagramRateLimiter,
    addr: SocketAddr,
    queue: &'static str,
) -> bool {
    let allowed = limiter.allow(addr);
    if !allowed {
        record_broker_drop(queue, "source_rate_limited");
    }
    allowed
}

pub(super) fn record_broker_drop(queue: &'static str, reason: &'static str) {
    counter!(
        "qpx_quic_broker_dropped_datagrams_total",
        "queue" => queue,
        "reason" => reason,
    )
    .increment(1);
}
