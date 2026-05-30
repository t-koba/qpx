use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::quic::QuicConnectionId;

const TOUCH_COALESCE_MS: u64 = 1_000;

pub(in crate::reverse::h3::passthrough) struct PassthroughSession {
    pub(in crate::reverse::h3::passthrough) socket: Arc<UdpSocket>,
    pub(in crate::reverse::h3::passthrough) close_tx: watch::Sender<bool>,
    client_addr_tx: watch::Sender<SocketAddr>,
    client_addr: StdMutex<SocketAddr>,
    last_seen_ms: AtomicU64,
    touch_queued_ms: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    client_cid_len: AtomicU8,
    server_cid_len: AtomicU8,
    pub(super) cids: StdMutex<HashSet<QuicConnectionId>>,
    relay_task: StdMutex<Option<JoinHandle<()>>>,
}

impl PassthroughSession {
    pub(in crate::reverse::h3::passthrough) fn new(
        socket: Arc<UdpSocket>,
        close_tx: watch::Sender<bool>,
        client_addr: SocketAddr,
        client_addr_tx: watch::Sender<SocketAddr>,
        seen_ms: u64,
        bytes_in: u64,
        bytes_out: u64,
    ) -> Self {
        Self {
            socket,
            close_tx,
            client_addr_tx,
            client_addr: StdMutex::new(client_addr),
            last_seen_ms: AtomicU64::new(seen_ms),
            touch_queued_ms: AtomicU64::new(0),
            bytes_in: AtomicU64::new(bytes_in),
            bytes_out: AtomicU64::new(bytes_out),
            client_cid_len: AtomicU8::new(0),
            server_cid_len: AtomicU8::new(0),
            cids: StdMutex::new(HashSet::new()),
            relay_task: StdMutex::new(None),
        }
    }

    pub(in crate::reverse::h3::passthrough) fn current_client_addr(&self) -> SocketAddr {
        *self
            .client_addr
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(in crate::reverse::h3::passthrough) fn update_client_addr(
        &self,
        client_addr: SocketAddr,
    ) -> Option<SocketAddr> {
        let mut guard = self
            .client_addr
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *guard == client_addr {
            return None;
        }
        let old = *guard;
        *guard = client_addr;
        let _ = self.client_addr_tx.send(client_addr);
        Some(old)
    }

    pub(in crate::reverse::h3::passthrough) fn mark_client_seen(&self, seen_ms: u64, bytes: u64) {
        self.last_seen_ms.fetch_max(seen_ms, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(in crate::reverse::h3::passthrough) fn mark_upstream_seen(&self, seen_ms: u64) {
        self.last_seen_ms.fetch_max(seen_ms, Ordering::Relaxed);
    }

    pub(in crate::reverse::h3::passthrough) fn last_seen_ms(&self) -> u64 {
        self.last_seen_ms.load(Ordering::Relaxed)
    }

    pub(in crate::reverse::h3::passthrough) fn should_queue_touch(&self, seen_ms: u64) -> bool {
        should_queue_touch_at(&self.touch_queued_ms, seen_ms)
    }

    pub(in crate::reverse::h3::passthrough) fn client_cid_len(&self) -> Option<u8> {
        decode_cid_len(self.client_cid_len.load(Ordering::Relaxed))
    }

    pub(in crate::reverse::h3::passthrough) fn server_cid_len(&self) -> Option<u8> {
        decode_cid_len(self.server_cid_len.load(Ordering::Relaxed))
    }

    pub(in crate::reverse::h3::passthrough) fn set_client_cid_len(&self, len: u8) {
        self.client_cid_len
            .store(encode_cid_len(Some(len)), Ordering::Relaxed);
    }

    pub(in crate::reverse::h3::passthrough) fn set_server_cid_len(&self, len: u8) {
        self.server_cid_len
            .store(encode_cid_len(Some(len)), Ordering::Relaxed);
    }

    pub(in crate::reverse::h3::passthrough) fn try_reserve_upstream_bytes(
        &self,
        bytes: u64,
        max_amplification: u64,
    ) -> bool {
        loop {
            let budget = self
                .bytes_in
                .load(Ordering::Relaxed)
                .saturating_mul(max_amplification);
            let current = self.bytes_out.load(Ordering::Relaxed);
            let proposed = current.saturating_add(bytes);
            if proposed > budget {
                return false;
            }
            if self
                .bytes_out
                .compare_exchange(current, proposed, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    pub(in crate::reverse::h3::passthrough) fn bytes_in(&self) -> u64 {
        self.bytes_in.load(Ordering::Relaxed)
    }

    pub(in crate::reverse::h3::passthrough) fn bytes_out(&self) -> u64 {
        self.bytes_out.load(Ordering::Relaxed)
    }

    pub(in crate::reverse::h3::passthrough) fn set_client_cid_len_if_some(&self, len: Option<u8>) {
        if let Some(len) = len {
            self.set_client_cid_len(len);
        }
    }

    pub(in crate::reverse::h3::passthrough) fn set_server_cid_len_if_some(&self, len: Option<u8>) {
        if let Some(len) = len {
            self.set_server_cid_len(len);
        }
    }

    pub(in crate::reverse::h3::passthrough) fn snapshot_cids(&self) -> Vec<QuicConnectionId> {
        self.cids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .copied()
            .collect()
    }

    pub(in crate::reverse::h3::passthrough) fn attach_relay_task(&self, task: JoinHandle<()>) {
        *self
            .relay_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
    }

    pub(in crate::reverse::h3::passthrough) fn take_relay_task(&self) -> Option<JoinHandle<()>> {
        self.relay_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

pub(in crate::reverse::h3::passthrough) fn should_queue_touch_at(
    touch_queued_ms: &AtomicU64,
    seen_ms: u64,
) -> bool {
    let mut current = touch_queued_ms.load(Ordering::Relaxed);
    loop {
        if seen_ms <= current || seen_ms.saturating_sub(current) < TOUCH_COALESCE_MS {
            return false;
        }
        match touch_queued_ms.compare_exchange(
            current,
            seen_ms,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(next) => current = next,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::reverse::h3::passthrough) struct SessionTouch {
    pub(in crate::reverse::h3::passthrough) seen_ms: u64,
    pub(in crate::reverse::h3::passthrough) session_id: u64,
}

fn encode_cid_len(value: Option<u8>) -> u8 {
    value.unwrap_or(0)
}

fn decode_cid_len(value: u8) -> Option<u8> {
    if value == 0 { None } else { Some(value) }
}
