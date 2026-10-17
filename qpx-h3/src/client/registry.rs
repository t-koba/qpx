use crate::transport::{BidiStream, UniRecvStream};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub(super) struct SessionIngress {
    pub(super) bidi_tx: mpsc::Sender<BidiStream>,
    pub(super) uni_tx: mpsc::Sender<UniRecvStream>,
}

pub(super) type SessionRegistry = Arc<ShardedSessionRegistry>;

const SESSION_REGISTRY_SHARDS: usize = 64;

pub(super) struct ShardedSessionRegistry {
    // These locks cover only map operations, never I/O or an await. Synchronous
    // removal lets registration guards clean up even during future cancellation.
    shards: Vec<Mutex<HashMap<u64, Arc<SessionIngress>>>>,
}

pub(super) struct SessionRegistration {
    registry: SessionRegistry,
    session_id: u64,
    ingress: Arc<SessionIngress>,
}

impl Drop for SessionRegistration {
    fn drop(&mut self) {
        let mut shard = self.registry.shard(self.session_id).lock().unwrap();
        if shard
            .get(&self.session_id)
            .is_some_and(|entry| Arc::ptr_eq(entry, &self.ingress))
        {
            shard.remove(&self.session_id);
        }
    }
}

impl ShardedSessionRegistry {
    pub(super) fn new() -> Self {
        let mut shards = Vec::with_capacity(SESSION_REGISTRY_SHARDS);
        for _ in 0..SESSION_REGISTRY_SHARDS {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self { shards }
    }

    fn shard(&self, session_id: u64) -> &Mutex<HashMap<u64, Arc<SessionIngress>>> {
        &self.shards[crate::sharding::modulo_u64(session_id, self.shards.len())]
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.lock().unwrap().len())
            .sum()
    }

    pub(super) fn register(
        self: &Arc<Self>,
        session_id: u64,
        ingress: SessionIngress,
    ) -> SessionRegistration {
        let ingress = Arc::new(ingress);
        self.shard(session_id)
            .lock()
            .unwrap()
            .insert(session_id, ingress.clone());
        SessionRegistration {
            registry: self.clone(),
            session_id,
            ingress,
        }
    }

    pub(super) fn bidi_sender(&self, session_id: u64) -> Option<mpsc::Sender<BidiStream>> {
        self.shard(session_id)
            .lock()
            .unwrap()
            .get(&session_id)
            .map(|entry| entry.bidi_tx.clone())
    }

    pub(super) fn uni_sender(&self, session_id: u64) -> Option<mpsc::Sender<UniRecvStream>> {
        self.shard(session_id)
            .lock()
            .unwrap()
            .get(&session_id)
            .map(|entry| entry.uni_tx.clone())
    }
}
