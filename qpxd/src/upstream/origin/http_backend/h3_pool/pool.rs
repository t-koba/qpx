use super::{
    DEFAULT_MAX_CONNECTIONS_PER_ORIGIN, DEFAULT_MAX_INFLIGHT_STREAMS_PER_CONNECTION,
    H3_ORIGIN_POOL_SHARDS, H3OriginEntry, H3OriginPool, H3OriginPoolShard, H3PooledConnection,
    MAX_H3_ORIGIN_POOL_KEYS, OriginKey, connect_h3_origin,
};
use anyhow::{Result, anyhow};
use qpx_core::tls::CompiledUpstreamTlsTrust;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant, timeout_at};

impl H3OriginPool {
    pub(crate) fn new() -> Self {
        let shards = (0..H3_ORIGIN_POOL_SHARDS)
            .map(|_| H3OriginPoolShard {
                connections: Mutex::new(HashMap::new()),
                connecting: crate::pool::SingleFlight::new(),
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
        &self.shards[qpx_http::sharding::modulo(key, self.shards.len())]
    }

    pub(super) async fn acquire(
        &self,
        key: OriginKey,
        trust: Option<&CompiledUpstreamTlsTrust>,
        timeout_dur: Duration,
    ) -> Result<Arc<H3PooledConnection>> {
        let connecting_guard = loop {
            let max_connections_per_origin =
                self.max_connections_per_origin.load(Ordering::Relaxed);
            let max_inflight_streams_per_connection = self
                .max_inflight_streams_per_connection
                .load(Ordering::Relaxed);
            let shard = self.shard_for(&key);
            {
                let mut connections = shard.connections.lock().await;
                prune_h3_origin_pool(&mut connections);
                if let Some(existing) = connections
                    .get_mut(&key)
                    .and_then(|entry| entry.next_available(max_inflight_streams_per_connection))
                {
                    super::metrics::reuse(&key);
                    return Ok(reserve_h3_origin_connection(existing));
                }
                let saturated = connections.get_mut(&key).and_then(|entry| {
                    (entry.connections.len() >= max_connections_per_origin)
                        .then(|| entry.least_loaded())
                        .flatten()
                });
                if let Some(saturated) = saturated {
                    drop(connections);
                    let waited = tokio::time::Instant::now();
                    let wait_threshold = h3_connection_stream_capacity(
                        max_inflight_streams_per_connection,
                        &saturated,
                    );
                    if saturated
                        .wait_for_inflight_below(wait_threshold, timeout_dur)
                        .await
                    {
                        super::metrics::wait(&key, waited.elapsed());
                        continue;
                    }
                    super::metrics::wait(&key, waited.elapsed());
                    return Err(anyhow!(
                        "HTTP/3 origin pool is saturated for {}",
                        key.connect_authority
                    ));
                }
            }

            match self.shard_for(&key).connecting.join(&key).await {
                crate::pool::FlightRole::Follower(notify) => {
                    let deadline = Instant::now() + timeout_dur;
                    timeout_at(deadline, notify.notified()).await.map_err(|_| {
                        anyhow!(
                            "HTTP/3 origin pool connect wait timed out for {}",
                            key.connect_authority
                        )
                    })?;
                    continue;
                }
                crate::pool::FlightRole::Leader(guard) => break guard,
            }
        };

        let open_queue_capacity = self
            .max_inflight_streams_per_connection
            .load(Ordering::Relaxed)
            .max(1);
        let connection =
            match connect_h3_origin(&key, trust, timeout_dur, open_queue_capacity).await {
                Ok(connection) => Arc::new(connection),
                Err(err) => {
                    connecting_guard.finish().await;
                    super::metrics::connection_error(&key, "connect");
                    return Err(err);
                }
            };
        let shard = self.shard_for(&key);
        let mut connections = shard.connections.lock().await;
        prune_h3_origin_pool(&mut connections);
        evict_h3_origin_pool_if_full(&mut connections, &key, self.max_keys_per_shard());
        let entry = connections.entry(key.clone()).or_default();
        if entry.connections.len() < self.max_connections_per_origin.load(Ordering::Relaxed) {
            entry.connections.push(connection.clone());
            super::metrics::connections(&key, entry.connections.len());
            drop(connections);
            connecting_guard.finish().await;
            return Ok(reserve_h3_origin_connection(connection));
        }
        let selected = entry.least_loaded().unwrap_or(connection);
        drop(connections);
        connecting_guard.finish().await;
        Ok(reserve_h3_origin_connection(selected))
    }

    fn max_keys_per_shard(&self) -> usize {
        MAX_H3_ORIGIN_POOL_KEYS
            .div_ceil(self.shards.len().max(1))
            .max(1)
    }
}

fn reserve_h3_origin_connection(connection: Arc<H3PooledConnection>) -> Arc<H3PooledConnection> {
    let inflight = connection.inflight_streams.fetch_add(1, Ordering::Relaxed) + 1;
    super::metrics::inflight(connection.origin_label.as_str(), inflight);
    connection
}

impl H3OriginEntry {
    fn next_available(
        &mut self,
        max_inflight_streams_per_connection: usize,
    ) -> Option<Arc<H3PooledConnection>> {
        if self.connections.is_empty() {
            self.cursor = 0;
            return None;
        }
        let len = self.connections.len();
        for offset in 0..len {
            let idx = (self.cursor + offset) % len;
            let conn = &self.connections[idx];
            let stream_capacity =
                h3_connection_stream_capacity(max_inflight_streams_per_connection, conn);
            let effective_load = h3_connection_effective_load(conn);
            if effective_load < stream_capacity {
                self.cursor = (idx + 1) % len;
                return Some(conn.clone());
            }
        }
        None
    }

    fn least_loaded(&mut self) -> Option<Arc<H3PooledConnection>> {
        let selected = self
            .connections
            .iter()
            .enumerate()
            .min_by_key(|(_, conn)| (h3_connection_effective_load(conn), conn.created_at))
            .map(|(idx, conn)| (idx, conn.clone()));
        if let Some((idx, conn)) = selected {
            self.cursor = (idx + 1) % self.connections.len();
            Some(conn)
        } else {
            self.cursor = 0;
            None
        }
    }
}

fn h3_connection_stream_capacity(
    max_inflight_streams_per_connection: usize,
    conn: &H3PooledConnection,
) -> usize {
    h3_connection_stream_capacity_for_limits(
        max_inflight_streams_per_connection,
        conn.open_queue_capacity,
    )
}

fn h3_connection_effective_load(conn: &H3PooledConnection) -> usize {
    conn.inflight_streams.load(Ordering::Relaxed)
}

fn h3_connection_stream_capacity_for_limits(
    max_inflight_streams_per_connection: usize,
    open_queue_capacity: usize,
) -> usize {
    max_inflight_streams_per_connection.min(open_queue_capacity)
}

fn prune_h3_origin_pool(connections: &mut HashMap<OriginKey, H3OriginEntry>) {
    connections.retain(|_, entry| {
        entry
            .connections
            .retain(|conn| !conn.driver.is_finished() && !conn.open_driver.is_finished());
        if entry.cursor >= entry.connections.len() {
            entry.cursor = 0;
        }
        !entry.connections.is_empty()
    });
}

fn evict_h3_origin_pool_if_full(
    connections: &mut HashMap<OriginKey, H3OriginEntry>,
    inserting_key: &OriginKey,
    max_keys: usize,
) {
    if let Some(oldest_key) =
        crate::pool::evict_oldest_if_full(connections, inserting_key, max_keys, |entry| {
            entry.connections.iter().map(|conn| conn.created_at).min()
        })
    {
        super::metrics::eviction(&oldest_key, "capacity");
    }
}

#[cfg(test)]
mod tests {
    use super::h3_connection_stream_capacity_for_limits;

    #[test]
    fn h3_origin_stream_capacity_is_capped_by_open_queue_capacity() {
        assert_eq!(h3_connection_stream_capacity_for_limits(512, 256), 256);
        assert_eq!(h3_connection_stream_capacity_for_limits(128, 256), 128);
    }

    #[test]
    fn h3_origin_stream_capacity_does_not_add_queue_depth_twice() {
        let reserved_streams = 127;
        let capacity = h3_connection_stream_capacity_for_limits(128, 128);

        assert!(reserved_streams < capacity);
        assert_eq!(capacity - reserved_streams, 1);
    }

    #[test]
    fn h3_origin_saturated_wait_uses_effective_stream_capacity() {
        let wait_threshold = h3_connection_stream_capacity_for_limits(512, 128);

        assert_eq!(wait_threshold, 128);
    }
}
