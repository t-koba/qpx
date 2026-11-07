//! Publication coordination; body I/O never holds this lock.
//! Single-instance backends use the process-local registry. Shared disk also
//! holds a backend OS lease, coordinating distinct backend objects/processes.
//! HTTP/Redis do not provide shared-writer coordination.
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
    _backend: Option<Box<dyn Send + Sync>>,
    _lease: Lease,
}

impl CommitGuard {
    pub(crate) fn is_shared(&self) -> bool {
        self._backend.is_some()
    }
}

pub(crate) async fn lock(
    backend: &dyn CacheBackend,
    namespace: &str,
    primary: &str,
) -> anyhow::Result<CommitGuard> {
    let backend_guard = backend.lock_commit(namespace, primary).await?;
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
    Ok(CommitGuard {
        _guard: guard,
        _backend: backend_guard,
        _lease: lease,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    #[tokio::test]
    async fn coordination_is_per_primary_and_cleans_cancelled_waiters() {
        let backend = crate::tests::MockBackend::new();
        let owner = lock(&backend, "ns", "primary").await.unwrap();
        let key = owner._lease.key.clone();
        let mut waiter = Box::pin(lock(&backend, "ns", "primary"));
        poll_fn(|cx| {
            assert!(waiter.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // Neither unrelated primaries nor namespaces share a lock.
        drop(lock(&backend, "ns", "other").await.unwrap());
        drop(lock(&backend, "other", "primary").await.unwrap());
        drop(waiter);
        drop(owner);
        assert!(!registry().lock().unwrap().contains_key(&key));
        let owner = lock(&backend, "ns", "primary").await.unwrap();
        let mut waiter = Box::pin(lock(&backend, "ns", "primary"));
        poll_fn(|cx| {
            assert!(waiter.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(owner);
        drop(waiter.await.unwrap());
        assert!(!registry().lock().unwrap().contains_key(&key));
    }
}
