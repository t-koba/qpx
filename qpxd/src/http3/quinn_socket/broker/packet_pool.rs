use bytes::Bytes;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const PACKET_BUFFER_POOL_SHARDS: usize = 32;

#[derive(Debug)]
pub(super) struct PacketBufferPool {
    shards: Vec<Mutex<Vec<Vec<u8>>>>,
    max_idle: usize,
    next_shard: AtomicUsize,
}

impl PacketBufferPool {
    pub(super) fn new(max_idle: usize) -> Self {
        Self {
            shards: (0..PACKET_BUFFER_POOL_SHARDS)
                .map(|_| Mutex::new(Vec::new()))
                .collect(),
            max_idle: max_idle.max(1),
            next_shard: AtomicUsize::new(0),
        }
    }

    pub(super) fn take(&self, capacity: usize) -> Vec<u8> {
        let mut buffers = self
            .shard()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(mut buf) = buffers.pop() {
            if buf.capacity() < capacity {
                buf.reserve(capacity - buf.capacity());
            }
            buf.clear();
            return buf;
        }
        Vec::with_capacity(capacity)
    }

    fn recycle(&self, mut buf: Vec<u8>) {
        buf.clear();
        let mut buffers = self
            .shard()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let max_idle_per_shard = self.max_idle.div_ceil(self.shards.len()).max(1);
        if buffers.len() < max_idle_per_shard {
            buffers.push(buf);
        }
    }

    fn shard(&self) -> &Mutex<Vec<Vec<u8>>> {
        let idx = self.next_shard.fetch_add(1, Ordering::Relaxed) % self.shards.len();
        &self.shards[idx]
    }
}

struct PooledPacketBytes {
    pool: Arc<PacketBufferPool>,
    buf: Option<Vec<u8>>,
    len: usize,
}

impl AsRef<[u8]> for PooledPacketBytes {
    fn as_ref(&self) -> &[u8] {
        match self.buf.as_ref() {
            Some(buf) => &buf[..self.len],
            None => &[],
        }
    }
}

impl Drop for PooledPacketBytes {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.recycle(buf);
        }
    }
}

pub(super) fn pooled_bytes_from_vec(
    pool: Arc<PacketBufferPool>,
    mut buf: Vec<u8>,
    len: usize,
) -> Bytes {
    buf.truncate(len);
    Bytes::from_owner(PooledPacketBytes {
        pool,
        buf: Some(buf),
        len,
    })
}

pub(super) fn pooled_bytes_from_slice(pool: Arc<PacketBufferPool>, payload: &[u8]) -> Bytes {
    let mut buf = pool.take(payload.len());
    buf.extend_from_slice(payload);
    pooled_bytes_from_vec(pool, buf, payload.len())
}

#[cfg(test)]
mod tests {
    use crate::http3::quinn_socket::broker::packet_pool::*;

    #[test]
    fn packet_buffer_pool_reuses_without_single_global_stack() {
        let pool = Arc::new(PacketBufferPool::new(64));
        let bytes = pooled_bytes_from_slice(pool.clone(), b"packet");
        assert_eq!(bytes.as_ref(), b"packet");
        drop(bytes);

        let mut observed_idle = 0usize;
        for shard in &pool.shards {
            observed_idle += shard.lock().expect("packet pool shard lock").len();
        }
        assert_eq!(observed_idle, 1);

        let reused = pool.take(6);
        assert!(reused.capacity() >= 6);
    }
}
