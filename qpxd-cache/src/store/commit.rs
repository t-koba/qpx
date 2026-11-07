//! Same-process publication coordination. Body I/O never holds this lock.
//! Entries exist only while a commit (or a waiter) references them.
//!
//! This lock is process-local: it serialises commits and primary
//! invalidations that share the same backend object in this process. It
//! cannot coordinate independent qpx processes (or distinct backend objects)
//! sharing HTTP/Redis/disk storage; those backends offer no compare-and-swap
//! for the index, so cross-process races remain possible.
use super::CacheBackend;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

type Key = (usize, String, String);
type Registry = Mutex<HashMap<Key, Arc<AsyncMutex<()>>>>;

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

struct Lease {
    key: Key,
    lock: Arc<AsyncMutex<()>>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut entries = registry().lock().unwrap_or_else(|e| e.into_inner());
        if Arc::strong_count(&self.lock) == 2 {
            entries.remove(&self.key);
        }
    }
}

pub(crate) struct CommitGuard {
    // Drop the owned lock before the lease removes the registry entry.
    _guard: OwnedMutexGuard<()>,
    _lease: Lease,
}

pub(crate) async fn lock(
    backend: &dyn CacheBackend,
    namespace: &str,
    primary: &str,
) -> CommitGuard {
    let key = (
        backend as *const dyn CacheBackend as *const () as usize,
        namespace.to_owned(),
        primary.to_owned(),
    );
    let lease = {
        let mut entries = registry().lock().unwrap_or_else(|e| e.into_inner());
        let lock = entries.entry(key.clone()).or_default().clone();
        Lease { key, lock }
    };
    let guard = lease.lock.clone().lock_owned().await;
    CommitGuard {
        _guard: guard,
        _lease: lease,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    #[tokio::test]
    async fn coordination_is_per_primary_and_cleans_cancelled_waiters() {
        let backend = crate::tests::MockBackend::new();
        let owner = lock(&backend, "ns", "primary").await;
        let key = owner._lease.key.clone();
        let mut waiter = Box::pin(lock(&backend, "ns", "primary"));
        poll_fn(|cx| {
            assert!(waiter.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // Neither unrelated primaries nor namespaces share a lock.
        drop(lock(&backend, "ns", "other").await);
        drop(lock(&backend, "other", "primary").await);
        drop(waiter);
        drop(owner);
        assert!(!registry().lock().unwrap().contains_key(&key));
        let owner = lock(&backend, "ns", "primary").await;
        let mut waiter = Box::pin(lock(&backend, "ns", "primary"));
        poll_fn(|cx| {
            assert!(waiter.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(owner);
        drop(waiter.await);
        assert!(!registry().lock().unwrap().contains_key(&key));
    }
}
