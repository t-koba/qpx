pub(crate) fn modulo_u64(key: u64, shards: usize) -> usize {
    (key % shards.max(1) as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::modulo_u64;

    #[test]
    fn modulo_u64_handles_empty_shard_count() {
        assert_eq!(modulo_u64(42, 0), 0);
    }

    #[test]
    fn modulo_u64_uses_the_full_key() {
        assert_eq!(modulo_u64(1u64 << 32, 3), 1);
    }

    #[test]
    fn modulo_u64_selects_expected_shard() {
        assert_eq!(modulo_u64(67, 64), 3);
    }
}
