use bytes::Bytes;
use std::cell::Cell;
use std::sync::{Arc, Mutex};

const PACKET_BUFFER_POOL_SHARDS: usize = 32;
const SMALL_PACKET_BUFFER_BYTES: usize = 384;

#[derive(Clone, Copy)]
enum PacketBucket {
    Small,
    Mtu,
    Large,
}

impl PacketBucket {
    fn for_capacity(capacity: usize) -> Self {
        if capacity <= SMALL_PACKET_BUFFER_BYTES {
            Self::Small
        } else if capacity <= 2048 {
            Self::Mtu
        } else {
            Self::Large
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Mtu => "mtu",
            Self::Large => "large",
        }
    }
}

#[derive(Default, Debug)]
struct PacketPoolShard {
    small: Vec<Vec<u8>>,
    mtu: Vec<Vec<u8>>,
    large: Vec<Vec<u8>>,
}

impl PacketPoolShard {
    fn stack_mut(&mut self, bucket: PacketBucket) -> &mut Vec<Vec<u8>> {
        match bucket {
            PacketBucket::Small => &mut self.small,
            PacketBucket::Mtu => &mut self.mtu,
            PacketBucket::Large => &mut self.large,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.small.len() + self.mtu.len() + self.large.len()
    }
}

#[derive(Debug)]
pub(super) struct PacketBufferPool {
    shards: Vec<Mutex<PacketPoolShard>>,
    max_idle: usize,
}

impl PacketBufferPool {
    pub(super) fn new(max_idle: usize) -> Self {
        Self {
            shards: (0..PACKET_BUFFER_POOL_SHARDS)
                .map(|_| Mutex::new(PacketPoolShard::default()))
                .collect(),
            max_idle: max_idle.max(1),
        }
    }

    pub(super) fn take(&self, capacity: usize) -> Vec<u8> {
        let bucket = PacketBucket::for_capacity(capacity);
        let mut shard = self
            .shard()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(mut buf) = shard.stack_mut(bucket).pop() {
            record_pool_event("hit", bucket);
            if buf.capacity() < capacity {
                buf.reserve(capacity - buf.capacity());
            }
            buf.clear();
            return buf;
        }
        record_pool_event("miss", bucket);
        Vec::with_capacity(capacity)
    }

    fn recycle(&self, mut buf: Vec<u8>) {
        let bucket = PacketBucket::for_capacity(buf.capacity());
        buf.clear();
        let mut shard = self
            .shard()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let max_idle_per_bucket = self
            .max_idle
            .div_ceil(self.shards.len().saturating_mul(3))
            .max(1);
        let stack = shard.stack_mut(bucket);
        if stack.len() < max_idle_per_bucket {
            stack.push(buf);
            record_pool_event("recycle", bucket);
        } else {
            record_pool_event("drop_idle", bucket);
        }
    }

    fn shard(&self) -> &Mutex<PacketPoolShard> {
        let idx = PACKET_POOL_SHARD_HINT.with(|hint| {
            let idx = hint.get() % self.shards.len();
            hint.set(idx.wrapping_add(1));
            idx
        });
        &self.shards[idx]
    }
}

thread_local! {
    static PACKET_POOL_SHARD_HINT: Cell<usize> = const { Cell::new(0) };
}

fn record_pool_event(event: &'static str, bucket: PacketBucket) {
    super::metrics::packet_pool_event(event, bucket.as_str());
}

fn record_packet_copy(payload_len: usize, bucket: PacketBucket) {
    super::metrics::packet_copy(payload_len, bucket.as_str());
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
    let bucket = PacketBucket::for_capacity(payload.len());
    record_packet_copy(payload.len(), bucket);
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
