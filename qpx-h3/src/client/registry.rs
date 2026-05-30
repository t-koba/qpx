use crate::transport::{BidiStream, UniRecvStream};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

pub(super) struct SessionIngress {
    pub(super) bidi_tx: mpsc::Sender<BidiStream>,
    pub(super) uni_tx: mpsc::Sender<UniRecvStream>,
}

pub(super) type SessionRegistry = Arc<ShardedSessionRegistry>;

const SESSION_REGISTRY_SHARDS: usize = 64;

pub(super) struct ShardedSessionRegistry {
    shards: Vec<Mutex<HashMap<u64, SessionIngress>>>,
}

impl ShardedSessionRegistry {
    pub(super) fn new() -> Self {
        let mut shards = Vec::with_capacity(SESSION_REGISTRY_SHARDS);
        for _ in 0..SESSION_REGISTRY_SHARDS {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self { shards }
    }

    pub(super) fn shard(&self, session_id: u64) -> &Mutex<HashMap<u64, SessionIngress>> {
        &self.shards[(session_id as usize) % self.shards.len()]
    }

    pub(super) async fn insert(&self, session_id: u64, ingress: SessionIngress) {
        self.shard(session_id)
            .lock()
            .await
            .insert(session_id, ingress);
    }

    pub(super) async fn remove(&self, session_id: u64) {
        self.shard(session_id).lock().await.remove(&session_id);
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
