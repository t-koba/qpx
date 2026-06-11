use metrics::counter;

pub fn writeback_body_bytes(bytes: u64) {
    counter!("qpx_cache_writeback_body_bytes_total").increment(bytes);
}
