//! Capacity-bounded keyed-map eviction shared by the HTTP/3 connection pools.

use std::collections::HashMap;
use std::hash::Hash;

/// When `map` is at/over `max_keys` and `inserting_key` is not already present,
/// removes and returns the key whose *oldest* member timestamp is smallest.
///
/// `oldest` returns the oldest timestamp for a value (`None` for values with no
/// members, which are skipped). Returns `None` when no eviction was needed or no
/// evictable key exists, so callers can record metrics only on an actual eviction.
pub(crate) fn evict_oldest_if_full<K, V, T>(
    map: &mut HashMap<K, V>,
    inserting_key: &K,
    max_keys: usize,
    oldest: impl Fn(&V) -> Option<T>,
) -> Option<K>
where
    K: Eq + Hash + Clone,
    T: Ord + Copy,
{
    if map.contains_key(inserting_key) || map.len() < max_keys {
        return None;
    }
    let oldest_key = map
        .iter()
        .filter_map(|(key, value)| oldest(value).map(|ts| (key.clone(), ts)))
        .min_by_key(|(_, ts)| *ts)
        .map(|(key, _)| key)?;
    map.remove(&oldest_key);
    Some(oldest_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_evict_below_capacity() {
        let mut map: HashMap<u32, Vec<u64>> = HashMap::new();
        map.insert(1, vec![10]);
        map.insert(2, vec![20]);
        assert_eq!(
            evict_oldest_if_full(&mut map, &3, 4, |v| v.iter().min().copied()),
            None
        );
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn does_not_evict_when_inserting_existing_key() {
        let mut map: HashMap<u32, Vec<u64>> = HashMap::new();
        map.insert(1, vec![10]);
        map.insert(2, vec![20]);
        assert_eq!(
            evict_oldest_if_full(&mut map, &1, 2, |v| v.iter().min().copied()),
            None
        );
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn evicts_key_with_smallest_oldest_timestamp() {
        let mut map: HashMap<u32, Vec<u64>> = HashMap::new();
        map.insert(1, vec![30, 40]);
        map.insert(2, vec![5, 50]); // oldest = 5 -> evicted
        map.insert(3, vec![15]);
        let evicted = evict_oldest_if_full(&mut map, &9, 3, |v| v.iter().min().copied());
        assert_eq!(evicted, Some(2));
        assert!(!map.contains_key(&2));
        assert_eq!(map.len(), 2);
    }
}
