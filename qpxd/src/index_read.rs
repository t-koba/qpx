use std::collections::HashMap;
use std::hash::Hash;
use std::sync::RwLock;

pub(crate) fn read_cloned<K, V>(map: &RwLock<HashMap<K, V>>, key: &K) -> Option<V>
where
    K: Eq + Hash,
    V: Clone,
{
    map.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(key)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::read_cloned;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    #[test]
    fn recovers_a_poisoned_map_read() {
        let map = Arc::new(RwLock::new(HashMap::from([(1, 2)])));
        let writer = Arc::clone(&map);
        assert!(
            std::thread::spawn(move || {
                let _guard = writer.write().unwrap();
                panic!("poison the index map");
            })
            .join()
            .is_err()
        );

        assert_eq!(read_cloned(&map, &1), Some(2));
    }
}
