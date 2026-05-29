use super::text_pattern::{extract_domain_suffix, host_matches_suffix, is_exact_pattern};
use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---- BitMask ----

#[test]
fn bitmask_empty_has_no_bits_set() {
    let mask = BitMask::empty(130);
    assert!(bit_is_empty(&mask.words));
    assert_eq!(mask.len, 130);
    assert_eq!(mask.words.len(), 3); // ceil(130/64) = 3
}

#[test]
fn bitmask_full_masks_tail_bits() {
    let mask = BitMask::full(65);
    assert_eq!(mask.words.len(), 2);
    assert_eq!(mask.words[0], u64::MAX);
    // Only bit 0 should be set in the second word (65 - 64 = 1 bit)
    assert_eq!(mask.words[1], 1);
}

#[test]
fn bitmask_set_and_read() {
    let mut mask = BitMask::empty(128);
    mask.set(0);
    mask.set(63);
    mask.set(64);
    mask.set(127);
    assert_eq!(mask.words[0], (1u64 << 0) | (1u64 << 63));
    assert_eq!(mask.words[1], (1u64 << 0) | (1u64 << 63));
}

#[test]
fn bitmask_set_out_of_range_is_noop() {
    let mut mask = BitMask::empty(4);
    mask.set(100); // should not panic
    assert!(bit_is_empty(&mask.words));
}

// ---- bit operations ----

#[test]
fn bit_or_assign_combines_words() {
    let mut dst = vec![0b0011u64];
    let src = vec![0b1100u64];
    bit_or_assign(&mut dst, &src);
    assert_eq!(dst, vec![0b1111u64]);
}

#[test]
fn bit_and_assign_intersects_words() {
    let mut dst = vec![0b1111u64];
    let src = vec![0b1010u64];
    bit_and_assign(&mut dst, &src);
    assert_eq!(dst, vec![0b1010u64]);
}

#[test]
fn bit_is_empty_detects_zero() {
    assert!(bit_is_empty(&[0, 0, 0]));
    assert!(!bit_is_empty(&[0, 1, 0]));
}

// ---- for_each_set_bit ----

#[test]
fn for_each_set_bit_iterates_correct_indices() {
    let words = vec![(1u64 << 2) | (1u64 << 5), 1u64 << 0]; // bits 2, 5, 64
    let mut collected = Vec::new();
    for_each_set_bit(&words, 128, &mut |idx| {
        collected.push(idx);
        false
    });
    assert_eq!(collected, vec![2, 5, 64]);
}

#[test]
fn for_each_set_bit_respects_limit() {
    let words = vec![u64::MAX]; // all 64 bits set
    let mut collected = Vec::new();
    for_each_set_bit(&words, 3, &mut |idx| {
        collected.push(idx);
        false
    });
    assert_eq!(collected, vec![0, 1, 2]);
}

// ---- DomainSuffixTrie ----

#[test]
fn domain_suffix_trie_matches_suffix() {
    let mut interner = StringInterner::default();
    let mut trie = DomainSuffixTrie::new(4);
    trie.insert(Arc::from("example.com"), 0, &mut interner);
    trie.insert(Arc::from("other.net"), 1, &mut interner);

    let mut out = vec![0u64; 1];
    trie.or_matches("www.example.com", &mut out);
    // Bit 0 should be set
    assert_ne!(out[0] & (1 << 0), 0);
    // Bit 1 should NOT be set
    assert_eq!(out[0] & (1 << 1), 0);
}

#[test]
fn domain_suffix_trie_no_match() {
    let mut interner = StringInterner::default();
    let mut trie = DomainSuffixTrie::new(4);
    trie.insert(Arc::from("example.com"), 0, &mut interner);

    let mut out = vec![0u64; 1];
    trie.or_matches("www.notmatch.org", &mut out);
    assert!(bit_is_empty(&out));
}

#[test]
fn domain_suffix_trie_skips_tld() {
    // Patterns like "*.com" should not match — TLD-only has < 2 labels
    let mut interner = StringInterner::default();
    let mut trie = DomainSuffixTrie::new(4);
    trie.insert(Arc::from("com"), 0, &mut interner);

    let mut out = vec![0u64; 1];
    trie.or_matches("com", &mut out);
    // "com" has 1 label < 2, so or_matches returns early
    assert!(bit_is_empty(&out));
}

// ---- IpRadixTrie ----

#[test]
fn ip_radix_trie_v4_match() {
    let mut trie = IpRadixTrie::default();
    let cidr: IpCidr = "10.0.0.0/8".parse().unwrap();
    trie.insert(&cidr, 0);

    let mut out = vec![0u64; 1];
    trie.or_matches(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), &mut out);
    assert_ne!(out[0] & (1 << 0), 0);

    let mut out2 = vec![0u64; 1];
    trie.or_matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), &mut out2);
    assert!(bit_is_empty(&out2));
}

#[test]
fn ip_radix_trie_v6_match() {
    let mut trie = IpRadixTrie::default();
    let cidr: IpCidr = "2001:db8::/32".parse().unwrap();
    trie.insert(&cidr, 0);

    let mut out = vec![0u64; 1];
    trie.or_matches(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        &mut out,
    );
    assert_ne!(out[0] & (1 << 0), 0);

    let mut out2 = vec![0u64; 1];
    trie.or_matches(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1)),
        &mut out2,
    );
    assert!(bit_is_empty(&out2));
}

// ---- TokenMaskIndex ----

#[test]
fn token_mask_index_exact_and_any() {
    let mut idx = TokenMaskIndex::new(4, true);
    // Rule 0: any method
    idx.insert_values(0, &[]);
    // Rule 1: GET only
    idx.insert_values(1, &[Arc::from("GET")]);

    let mut out = vec![0u64; 1];
    idx.fill_mask(&mut out, Some("GET"));
    // Both rule 0 (any) and rule 1 (GET) should be set
    assert_ne!(out[0] & (1 << 0), 0);
    assert_ne!(out[0] & (1 << 1), 0);

    let mut out2 = vec![0u64; 1];
    idx.fill_mask(&mut out2, Some("POST"));
    // Rule 0 (any) should be set, rule 1 (GET) should NOT
    assert_ne!(out2[0] & (1 << 0), 0);
    assert_eq!(out2[0] & (1 << 1), 0);
}

// ---- StringInterner ----

#[test]
fn string_interner_deduplicates() {
    let mut interner = StringInterner::default();
    let a = interner.intern("hello");
    let b = interner.intern("hello");
    assert!(Arc::ptr_eq(&a, &b));
}

// ---- helper functions ----

#[test]
fn is_exact_pattern_rejects_globs() {
    assert!(is_exact_pattern("example.com"));
    assert!(!is_exact_pattern("*.example.com"));
    assert!(!is_exact_pattern("test[0]"));
}

#[test]
fn extract_domain_suffix_strips_wildcard() {
    assert_eq!(extract_domain_suffix("*.example.com"), Some("example.com"));
    assert_eq!(extract_domain_suffix("example.com"), None);
    assert_eq!(extract_domain_suffix("*."), None);
}

#[test]
fn host_matches_suffix_boundary_check() {
    assert!(host_matches_suffix("www.example.com", "example.com"));
    assert!(!host_matches_suffix("notexample.com", "example.com"));
    assert!(!host_matches_suffix("example.com", "example.com")); // equal length
}
