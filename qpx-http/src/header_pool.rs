//! Per-thread reusable HTTP header maps for request and response hot paths.

use http::HeaderMap;
use std::cell::RefCell;

const MAX_RETAINED_MAPS_PER_THREAD: usize = 64;
const MAX_RETAINED_HEADER_CAPACITY: usize = 256;

thread_local! {
    static HEADER_MAPS: RefCell<Vec<HeaderMap>> = const { RefCell::new(Vec::new()) };
}

/// Takes an empty map whose backing storage can hold at least `minimum_capacity` entries.
pub fn take(minimum_capacity: usize) -> HeaderMap {
    HEADER_MAPS.with_borrow_mut(|maps| {
        let mut map = maps.pop().unwrap_or_default();
        map.reserve(minimum_capacity.saturating_sub(map.capacity()));
        map
    })
}

/// Copies a header map into reusable per-thread storage.
pub fn clone_map(source: &HeaderMap) -> HeaderMap {
    let mut target = take(source.len());
    for (name, value) in source {
        target.append(name.clone(), value.clone());
    }
    target
}

/// Clears a reasonably sized map and returns its allocation to the current thread.
pub fn recycle(mut map: HeaderMap) {
    if map.capacity() > MAX_RETAINED_HEADER_CAPACITY {
        return;
    }
    map.clear();
    HEADER_MAPS.with_borrow_mut(|maps| {
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
    fn cloned_map_preserves_repeated_fields() {
        let mut source = HeaderMap::new();
        source.append("set-cookie", HeaderValue::from_static("a=1"));
        source.append("set-cookie", HeaderValue::from_static("b=2"));

        let cloned = clone_map(&source);
        let values = cloned
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().expect("header text"))
            .collect::<Vec<_>>();
        assert_eq!(values, ["a=1", "b=2"]);
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
