pub(crate) use qpx_http::header_pool::{recycle, take};

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;
    use http::HeaderValue;

    #[test]
    fn recycled_map_retains_backing_capacity_and_drops_values() {
        let mut map = take(8);
        map.insert("x-test", HeaderValue::from_static("value"));
        let capacity = map.capacity();
        recycle(map);

        let map = take(1);
        assert!(map.is_empty());
        assert!(map.capacity() >= capacity);
    }

    #[test]
    fn oversized_map_is_not_retained() {
        let map = HeaderMap::with_capacity(257);
        let oversized_capacity = map.capacity();
        recycle(map);

        let map = take(1);
        assert!(map.capacity() < oversized_capacity);
    }
}
