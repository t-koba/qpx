//! Publication coordination; body I/O never holds this lock.
//! Single-instance backends use the process-local registry. Shared disk and
//! remote backends additionally hold a backend-enforced lease, coordinating
//! distinct backend objects/processes.
use super::CacheBackend;
use crate::types::CommitLease;
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
    backend_lease: Option<Arc<dyn CommitLease>>,
    _lease: Lease,
}

impl CommitGuard {
    pub(crate) fn has_backend_lease(&self) -> bool {
        self.backend_lease.is_some()
    }

    /// Releases the backend-enforced half of the lease before the process-local
    /// guard. The lease implementation also releases on drop, so cancellation
    /// never strands remote coordination.
    pub(crate) async fn release(mut self) -> anyhow::Result<()> {
        if let Some(lease) = self.backend_lease.take() {
            lease.release().await?;
        }
        Ok(())
    }
}

pub(crate) async fn lock(
    backend: &dyn CacheBackend,
    namespace: &str,
    primary: &str,
) -> anyhow::Result<CommitGuard> {
    let backend_lease = backend.lock_commit(namespace, primary).await?;
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
        backend_lease,
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
