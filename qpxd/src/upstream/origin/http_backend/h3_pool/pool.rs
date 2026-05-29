use super::{
    DEFAULT_MAX_CONNECTIONS_PER_ORIGIN, DEFAULT_MAX_INFLIGHT_STREAMS_PER_CONNECTION,
    H3_ORIGIN_POOL_SHARDS, H3OriginPool, H3OriginPoolShard, H3PooledConnection,
    MAX_H3_ORIGIN_POOL_KEYS, OriginKey, connect_h3_origin, shard_index,
};
use crate::tls::CompiledUpstreamTlsTrust;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{Mutex, Notify};
use tokio::time::Duration;

impl H3OriginPool {
    pub(super) fn new() -> Self {
        let shards = (0..H3_ORIGIN_POOL_SHARDS)
            .map(|_| H3OriginPoolShard {
                connections: Mutex::new(HashMap::new()),
                connecting: Mutex::new(HashMap::new()),
            })
            .collect();
        Self {
            shards,
            max_connections_per_origin: AtomicUsize::new(DEFAULT_MAX_CONNECTIONS_PER_ORIGIN),
            max_inflight_streams_per_connection: AtomicUsize::new(
                DEFAULT_MAX_INFLIGHT_STREAMS_PER_CONNECTION,
            ),
        }
    }

    fn shard_for(&self, key: &OriginKey) -> &H3OriginPoolShard {
        &self.shards[shard_index(key, self.shards.len())]
    }

    pub(super) async fn acquire(
        &self,
        key: OriginKey,
        trust: Option<&CompiledUpstreamTlsTrust>,
        timeout_dur: Duration,
    ) -> Result<Arc<H3PooledConnection>> {
        loop {
            let max_connections_per_origin =
                self.max_connections_per_origin.load(Ordering::Relaxed);
            let max_inflight_streams_per_connection = self
                .max_inflight_streams_per_connection
                .load(Ordering::Relaxed);
            let shard = self.shard_for(&key);
            {
                let mut connections = shard.connections.lock().await;
                prune_h3_origin_pool(&mut connections);
                if let Some(existing) = connections.get(&key).and_then(|connections| {
                    least_loaded_connection(
                        connections.as_slice(),
                        max_inflight_streams_per_connection,
                    )
                }) {
                    return Ok(existing);
                }
                let saturated = if connections
                    .get(&key)
                    .map(|connections| connections.len() >= max_connections_per_origin)
                    .unwrap_or(false)
                    && let Some(existing) = connections.get(&key).and_then(|connections| {
                        connections
                            .iter()
                            .min_by_key(|conn| conn.inflight_streams.load(Ordering::Relaxed))
                            .cloned()
                    }) {
                    Some(existing)
                } else {
                    None
                };
                if let Some(saturated) = saturated {
                    drop(connections);
                    if saturated
                        .wait_for_inflight_below(max_inflight_streams_per_connection, timeout_dur)
                        .await
                    {
                        continue;
                    }
                    return Err(anyhow!(
                        "HTTP/3 origin pool is saturated for {}",
                        key.connect_authority
                    ));
                }
            }

            let notify = {
                let shard = self.shard_for(&key);
                let mut connecting = shard.connecting.lock().await;
                if let Some(notify) = connecting.get(&key) {
                    Some(notify.clone())
                } else {
                    connecting.insert(key.clone(), Arc::new(Notify::new()));
                    None
                }
            };
            if let Some(notify) = notify {
                notify.notified().await;
                continue;
            }
            break;
        }

        let connection = match connect_h3_origin(&key, trust, timeout_dur).await {
            Ok(connection) => Arc::new(connection),
            Err(err) => {
                self.finish_connecting(&key).await;
                return Err(err);
            }
        };
        let shard = self.shard_for(&key);
        let mut connections = shard.connections.lock().await;
        prune_h3_origin_pool(&mut connections);
        evict_h3_origin_pool_if_full(&mut connections, &key, self.max_keys_per_shard());
        let entry = connections.entry(key.clone()).or_default();
        if entry.len() < self.max_connections_per_origin.load(Ordering::Relaxed) {
            entry.push(connection.clone());
            drop(connections);
            self.finish_connecting(&key).await;
            return Ok(connection);
        }
        let selected = entry
            .iter()
            .min_by_key(|conn| conn.inflight_streams.load(Ordering::Relaxed))
            .cloned()
            .unwrap_or(connection);
        drop(connections);
        self.finish_connecting(&key).await;
        Ok(selected)
    }

    async fn finish_connecting(&self, key: &OriginKey) {
        let shard = self.shard_for(key);
        if let Some(notify) = shard.connecting.lock().await.remove(key) {
            notify.notify_waiters();
        }
    }

    fn max_keys_per_shard(&self) -> usize {
        MAX_H3_ORIGIN_POOL_KEYS
            .div_ceil(self.shards.len().max(1))
            .max(1)
    }
}

fn prune_h3_origin_pool(connections: &mut HashMap<OriginKey, Vec<Arc<H3PooledConnection>>>) {
    connections.retain(|_, entries| {
        entries.retain(|conn| !conn.driver.is_finished());
        !entries.is_empty()
    });
}

fn evict_h3_origin_pool_if_full(
    connections: &mut HashMap<OriginKey, Vec<Arc<H3PooledConnection>>>,
    inserting_key: &OriginKey,
    max_keys: usize,
) {
    if connections.contains_key(inserting_key) || connections.len() < max_keys {
        return;
    }
    let Some(oldest_key) = connections
        .iter()
        .filter_map(|(key, entries)| {
            entries
                .iter()
                .map(|conn| conn.created_at)
                .min()
                .map(|created_at| (key.clone(), created_at))
        })
        .min_by_key(|(_, created_at)| *created_at)
        .map(|(key, _)| key)
    else {
        return;
    };
    connections.remove(&oldest_key);
}

fn least_loaded_connection(
    connections: &[Arc<H3PooledConnection>],
    max_inflight_streams_per_connection: usize,
) -> Option<Arc<H3PooledConnection>> {
    connections
        .iter()
        .filter(|conn| {
            conn.inflight_streams.load(Ordering::Relaxed) < max_inflight_streams_per_connection
        })
        .min_by_key(|conn| {
            (
                conn.inflight_streams.load(Ordering::Relaxed),
                conn.created_at,
            )
        })
        .cloned()
}
