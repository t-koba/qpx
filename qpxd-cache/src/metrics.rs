use metrics::counter;

pub fn writeback_body_bytes(bytes: u64) {
    counter!("qpx_cache_writeback_body_bytes_total").increment(bytes);
}

pub fn writeback_admission_rejected() {
    counter!("qpx_cache_writeback_admission_rejections_total").increment(1);
}
