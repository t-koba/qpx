//! Per-key single-flight coordination for connection establishment.
//!
//! When several callers concurrently miss the pool for the same key, only one
//! should establish a new connection while the others wait and then retry the
//! lookup. This is implemented with a per-key [`Notify`]: the first caller for a
//! key becomes the *leader* and receives a [`FlightGuard`]; later callers become
//! *followers* and await the leader's notification before retrying.
//!
//! The leader's guard removes the key and wakes all waiters when it is finished
//! (explicitly via [`FlightGuard::finish`] or implicitly on drop), so a leader
//! that errors or panics cannot strand followers. Followers should always apply
//! their own timeout to the wait and re-run the pool lookup on wake-up, because
//! [`Notify::notify_waiters`] only wakes callers already parked on the notify.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

type InflightMap<K> = Arc<Mutex<HashMap<K, Arc<Notify>>>>;

/// Coordinates at-most-one in-flight establishment per key.
pub(crate) struct SingleFlight<K> {
    inflight: InflightMap<K>,
}

impl<K> SingleFlight<K> {
    pub(crate) fn new() -> Self {
        Self {
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<K> Default for SingleFlight<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K> SingleFlight<K>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
{
    /// Join the in-flight group for `key`.
    ///
    /// Returns [`FlightRole::Leader`] for the first caller (which must perform the
    /// establishment and keep the returned guard until done), or
    /// [`FlightRole::Follower`] with a [`Notify`] the caller should await before
    /// retrying the pool lookup.
    pub(crate) async fn join(&self, key: &K) -> FlightRole<K> {
        let mut map = self.inflight.lock().await;
        if let Some(notify) = map.get(key) {
            FlightRole::Follower(notify.clone())
        } else {
            map.insert(key.clone(), Arc::new(Notify::new()));
            FlightRole::Leader(FlightGuard {
                inflight: Arc::clone(&self.inflight),
                key: key.clone(),
                active: true,
            })
        }
    }
}

/// Outcome of [`SingleFlight::join`].
pub(crate) enum FlightRole<K>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
{
    /// This caller won the race and must perform the work, holding the guard until
    /// the work completes (success or failure).
    Leader(FlightGuard<K>),
    /// Another caller is already establishing for this key. Await the [`Notify`]
    /// (with the caller's own timeout) and then retry the pool lookup.
    Follower(Arc<Notify>),
}

/// RAII leader guard. Removes the key and wakes all waiters on [`finish`] or drop.
///
/// [`finish`]: FlightGuard::finish
pub(crate) struct FlightGuard<K>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
{
    inflight: InflightMap<K>,
    key: K,
    active: bool,
}

impl<K> FlightGuard<K>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
{
    /// Promptly release the key and wake waiters. Prefer this over relying on drop
    /// so waiters are released without an extra task hop.
    pub(crate) async fn finish(mut self) {
        self.active = false;
        finish_key(&self.inflight, &self.key).await;
    }
}

impl<K> Drop for FlightGuard<K>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
{
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // The guard was dropped without an explicit `finish()` (e.g. an early
        // return or panic on the leader path). Clean up asynchronously so waiters
        // are not stranded.
        let inflight = Arc::clone(&self.inflight);
        let key = self.key.clone();
        tokio::spawn(async move {
            finish_key(&inflight, &key).await;
        });
    }
}

async fn finish_key<K>(inflight: &Mutex<HashMap<K, Arc<Notify>>>, key: &K)
where
    K: Eq + Hash,
{
    if let Some(notify) = inflight.lock().await.remove(key) {
        notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn only_one_leader_per_key_concurrently() {
        let flight = Arc::new(SingleFlight::<String>::new());
        let leaders = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let flight = Arc::clone(&flight);
            let leaders = Arc::clone(&leaders);
            handles.push(tokio::spawn(async move {
                match flight.join(&"k".to_string()).await {
                    FlightRole::Leader(guard) => {
                        leaders.fetch_add(1, Ordering::SeqCst);
                        // Hold leadership briefly so the others observe a follower role.
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        guard.finish().await;
                    }
                    FlightRole::Follower(notify) => {
                        let _ =
                            tokio::time::timeout(Duration::from_secs(1), notify.notified()).await;
                    }
                }
            }));
        }
        for h in handles {
            h.await.expect("task");
        }
        assert_eq!(leaders.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn leader_is_available_again_after_finish() {
        let flight = SingleFlight::<u32>::new();
        match flight.join(&1).await {
            FlightRole::Leader(guard) => guard.finish().await,
            FlightRole::Follower(_) => panic!("first caller must be leader"),
        }
        // After finish, the key is free, so the next caller is a leader again.
        assert!(matches!(flight.join(&1).await, FlightRole::Leader(_)));
    }

    #[tokio::test]
    async fn dropping_guard_releases_the_key() {
        let flight = SingleFlight::<u32>::new();
        {
            let FlightRole::Leader(_guard) = flight.join(&7).await else {
                panic!("first caller must be leader");
            };
            // _guard dropped here without finish(); drop spawns async cleanup.
        }
        // Give the spawned cleanup task a chance to run.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(matches!(flight.join(&7).await, FlightRole::Leader(_)));
    }

    #[tokio::test]
    async fn distinct_keys_are_independent_leaders() {
        let flight = SingleFlight::<u32>::new();
        let a = flight.join(&1).await;
        let b = flight.join(&2).await;
        assert!(matches!(a, FlightRole::Leader(_)));
        assert!(matches!(b, FlightRole::Leader(_)));
    }
}
