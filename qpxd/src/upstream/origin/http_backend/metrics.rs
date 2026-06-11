use metrics::counter;

pub(super) fn direct_origin_pool_eviction() {
    counter!("qpx_direct_origin_pool_evictions_total").increment(1);
}
