use crate::transport::{BidiStream, UniRecvStream};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Mutex, mpsc};

pub(super) struct WebTransportSessionIngress {
    pub(super) bidi_tx: mpsc::Sender<BidiStream>,
    pub(super) uni_tx: mpsc::Sender<UniRecvStream>,
}

pub(super) type WebTransportSessionRegistry = Arc<ShardedWebTransportSessionRegistry>;

const WEBTRANSPORT_SESSION_REGISTRY_SHARDS: usize = 64;

pub(super) struct ShardedWebTransportSessionRegistry {
    shards: Vec<Mutex<HashMap<u64, WebTransportSessionIngress>>>,
    active_sessions: AtomicU64,
}

impl ShardedWebTransportSessionRegistry {
    pub(super) fn new() -> Self {
        let mut shards = Vec::with_capacity(WEBTRANSPORT_SESSION_REGISTRY_SHARDS);
        for _ in 0..WEBTRANSPORT_SESSION_REGISTRY_SHARDS {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self {
            shards,
            active_sessions: AtomicU64::new(0),
        }
    }

    pub(super) fn shard(
        &self,
        session_id: u64,
    ) -> &Mutex<HashMap<u64, WebTransportSessionIngress>> {
        &self.shards[crate::sharding::modulo_u64(session_id, self.shards.len())]
    }

    pub(super) fn reserve(&self, max_sessions: u64) -> bool {
        max_sessions != 0
            && self
                .active_sessions
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    (current < max_sessions).then_some(current + 1)
                })
                .is_ok()
    }

    pub(super) async fn insert(&self, session_id: u64, ingress: WebTransportSessionIngress) {
        self.shard(session_id)
            .lock()
            .await
            .insert(session_id, ingress);
    }

    pub(super) async fn remove(&self, session_id: u64) {
        if self
            .shard(session_id)
            .lock()
            .await
            .remove(&session_id)
            .is_some()
        {
            self.active_sessions.fetch_sub(1, Ordering::AcqRel);
        }
    }

    pub(super) async fn bidi_sender(&self, session_id: u64) -> Option<mpsc::Sender<BidiStream>> {
        self.shard(session_id)
            .lock()
            .await
            .get(&session_id)
            .map(|entry| entry.bidi_tx.clone())
    }

    pub(super) async fn uni_sender(&self, session_id: u64) -> Option<mpsc::Sender<UniRecvStream>> {
        self.shard(session_id)
            .lock()
            .await
            .get(&session_id)
            .map(|entry| entry.uni_tx.clone())
    }
}
