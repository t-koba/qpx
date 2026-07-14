use http::HeaderMap;
use std::cell::RefCell;

const MAX_RETAINED_MAPS_PER_THREAD: usize = 64;
const MAX_RETAINED_HEADER_CAPACITY: usize = 256;

thread_local! {
    static HTTP1_HEADER_MAPS: RefCell<Vec<HeaderMap>> = const { RefCell::new(Vec::new()) };
}

pub(crate) fn take(minimum_capacity: usize) -> HeaderMap {
    HTTP1_HEADER_MAPS.with_borrow_mut(|maps| {
        let mut map = maps.pop().unwrap_or_default();
        map.reserve(minimum_capacity.saturating_sub(map.capacity()));
        map
    })
}

pub(crate) fn recycle(mut map: HeaderMap) {
    if map.capacity() > MAX_RETAINED_HEADER_CAPACITY {
        return;
    }
    map.clear();
    HTTP1_HEADER_MAPS.with_borrow_mut(|maps| {
        if maps.len() < MAX_RETAINED_MAPS_PER_THREAD {
            maps.push(map);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let map = HeaderMap::with_capacity(MAX_RETAINED_HEADER_CAPACITY + 1);
        let oversized_capacity = map.capacity();
        recycle(map);

        let map = take(1);
        assert!(map.capacity() < oversized_capacity);
    }
}
