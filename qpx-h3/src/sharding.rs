pub(crate) fn modulo_u64(key: u64, shards: usize) -> usize {
    (key as usize) % shards.max(1)
}

#[cfg(test)]
mod tests {
    use super::modulo_u64;

    #[test]
    fn modulo_u64_handles_empty_shard_count() {
        assert_eq!(modulo_u64(42, 0), 0);
    }

    #[test]
    fn modulo_u64_selects_expected_shard() {
        assert_eq!(modulo_u64(67, 64), 3);
    }
}
