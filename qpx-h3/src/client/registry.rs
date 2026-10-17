use crate::transport::{BidiStream, UniRecvStream};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
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
        let mut shard = self.registry.shard(self.session_id);
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

    fn shard(&self, session_id: u64) -> MutexGuard<'_, HashMap<u64, Arc<SessionIngress>>> {
        // Poisoning signals a panic, not an invalid map. These critical sections
        // only perform individual map operations; no multi-step invariant needs
        // repair. Recover the guard so routing and synchronous RAII cleanup keep
        // working, including when Drop runs during unwinding.
        self.shards[crate::sharding::modulo_u64(session_id, self.shards.len())]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.lock().unwrap_or_else(PoisonError::into_inner).len())
            .sum()
    }

    pub(super) fn register(
        self: &Arc<Self>,
        session_id: u64,
        ingress: SessionIngress,
    ) -> SessionRegistration {
        let ingress = Arc::new(ingress);
        self.shard(session_id).insert(session_id, ingress.clone());
        SessionRegistration {
            registry: self.clone(),
            session_id,
            ingress,
        }
    }

    pub(super) fn bidi_sender(&self, session_id: u64) -> Option<mpsc::Sender<BidiStream>> {
        self.shard(session_id)
            .get(&session_id)
            .map(|entry| entry.bidi_tx.clone())
    }

    pub(super) fn uni_sender(&self, session_id: u64) -> Option<mpsc::Sender<UniRecvStream>> {
        self.shard(session_id)
            .get(&session_id)
            .map(|entry| entry.uni_tx.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisoned_shard_preserves_routing_and_registration_cleanup() {
        let registry = Arc::new(ShardedSessionRegistry::new());
        let (bidi_tx, first_bidi_rx) = mpsc::channel(1);
        let (uni_tx, first_uni_rx) = mpsc::channel(1);
        let first = registry.register(0, SessionIngress { bidi_tx, uni_tx });

        assert!(
            std::panic::catch_unwind(|| {
                let _guard = registry.shards[0].lock().unwrap();
                panic!("poison the session shard");
            })
            .is_err()
        );
        assert!(registry.shards[0].is_poisoned());
        assert_eq!(registry.len(), 1);
        assert!(
            registry
                .bidi_sender(0)
                .unwrap()
                .same_channel(&first.ingress.bidi_tx)
        );
        assert!(
            registry
                .uni_sender(0)
                .unwrap()
                .same_channel(&first.ingress.uni_tx)
        );

        let (bidi_tx, second_bidi_rx) = mpsc::channel(1);
        let (uni_tx, second_uni_rx) = mpsc::channel(1);
        let second = registry.register(0, SessionIngress { bidi_tx, uni_tx });
        drop(first);
        assert!(first_bidi_rx.is_closed());
        assert!(first_uni_rx.is_closed());
        assert_eq!(registry.len(), 1);
        assert!(
            registry
                .bidi_sender(0)
                .unwrap()
                .same_channel(&second.ingress.bidi_tx)
        );
        assert!(
            registry
                .uni_sender(0)
                .unwrap()
                .same_channel(&second.ingress.uni_tx)
        );

        // A poisoned lock must not cause a second panic when cleanup unwinds.
        assert!(
            std::panic::catch_unwind(move || {
                let _registration = second;
                panic!("unwind with a live registration");
            })
            .is_err()
        );
        assert_eq!(registry.len(), 0);
        assert!(second_bidi_rx.is_closed());
        assert!(second_uni_rx.is_closed());
        assert!(registry.bidi_sender(0).is_none());
        assert!(registry.uni_sender(0).is_none());
    }
}
