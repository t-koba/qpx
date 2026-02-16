use anyhow::Result;
use cidr::IpCidr;
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct BitMask {
    pub words: Vec<u64>,
    pub len: usize,
}

impl BitMask {
    pub fn empty(len: usize) -> Self {
        Self {
            words: vec![0; bit_words(len)],
            len,
        }
    }

    pub fn full(len: usize) -> Self {
        let mut words = vec![u64::MAX; bit_words(len)];
        if let Some(last) = words.last_mut() {
            let used = len % 64;
            if used != 0 {
                *last = (1u64 << used) - 1;
            }
        }
        Self { words, len }
    }

    pub fn set(&mut self, idx: usize) {
        if idx >= self.len {
            return;
        }
        let word = idx / 64;
        let bit = idx % 64;
        self.words[word] |= 1u64 << bit;
    }
}

impl Default for BitMask {
    fn default() -> Self {
        Self::empty(0)
    }
}

#[derive(Debug, Clone)]
pub struct DomainSuffixTrie {
    root: DomainSuffixNode,
    bit_len: usize,
}

#[derive(Debug, Clone, Default)]
struct DomainSuffixNode {
    terminal: BitMask,
    children: HashMap<Arc<str>, DomainSuffixNode>,
}

#[derive(Debug, Clone)]
pub struct TextPatternMatcher {
    exact: HashSet<Arc<str>>,
    suffix: Vec<Arc<str>>,
    glob: Option<GlobSet>,
    lowercase_input: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TextPrefilterHint {
    pub any: bool,
    pub complex: bool,
    pub exact: Vec<Arc<str>>,
    pub suffix: Vec<Arc<str>>,
}

#[derive(Debug, Clone)]
pub struct MatchPrefilterHint {
    pub method_values: Vec<Arc<str>>,
    pub dst_ports: Vec<u16>,
    pub src_cidrs: Vec<IpCidr>,
    pub host: TextPrefilterHint,
    pub sni: TextPrefilterHint,
    pub path: TextPrefilterHint,
}

#[derive(Debug, Clone)]
pub struct TokenMaskIndex {
    any: BitMask,
    map: HashMap<Arc<str>, BitMask>,
    uppercase_input: bool,
}

#[derive(Debug, Clone)]
pub struct TextMaskIndex {
    any: BitMask,
    complex: BitMask,
    exact: HashMap<Arc<str>, BitMask>,
    suffix: DomainSuffixTrie,
    lowercase_input: bool,
    allow_suffix: bool,
}

#[derive(Debug, Clone)]
pub struct MatchPrefilterContext<'a> {
    pub method: Option<&'a str>,
    pub dst_port: Option<u16>,
    pub src_ip: Option<IpAddr>,
    pub host: Option<&'a str>,
    pub sni: Option<&'a str>,
    pub path: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct MatchPrefilterIndex {
    rule_count: usize,
    all: BitMask,

    method_index: TokenMaskIndex,

    port_any: BitMask,
    port_map: HashMap<u16, BitMask>,

    src_ip_any: BitMask,
    src_ip_trie: IpRadixTrie,

    host_index: TextMaskIndex,
    sni_index: TextMaskIndex,
    path_index: TextMaskIndex,
}

#[derive(Debug, Clone, Default)]
struct IpRadixTrie {
    v4: IpTrieNode,
    v6: IpTrieNode,
}

#[derive(Debug, Clone, Default)]
struct IpTrieNode {
    rule_ids: Vec<usize>,
    zero: Option<Box<IpTrieNode>>,
    one: Option<Box<IpTrieNode>>,
}

thread_local! {
    static PREFILTER_CANDIDATES: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    static PREFILTER_SCRATCH: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

impl DomainSuffixTrie {
    pub fn new(bit_len: usize) -> Self {
        Self {
            root: DomainSuffixNode::default(),
            bit_len,
        }
    }

    pub fn insert(&mut self, suffix: Arc<str>, rule_idx: usize, interner: &mut StringInterner) {
        let mut node = &mut self.root;
        for label in suffix.split('.').rev() {
            let label = interner.intern(label);
            node = node.children.entry(label).or_default();
            if node.terminal.len == 0 {
                node.terminal = BitMask::empty(self.bit_len);
            }
        }

        if node.terminal.len == 0 {
            node.terminal = BitMask::empty(self.bit_len);
        }
        node.terminal.set(rule_idx);
    }

    pub fn or_matches(&self, host: &str, out: &mut [u64]) {
        let mut remaining_labels = host.as_bytes().iter().filter(|b| **b == b'.').count() + 1;
        if remaining_labels < 2 {
            return;
        }

        let mut node = &self.root;
        for label in host.rsplit('.') {
            remaining_labels -= 1;
            let Some(next) = node.children.get(label) else {
                break;
            };
            node = next;
            if remaining_labels > 0 && node.terminal.len != 0 {
                bit_or_assign(out, &node.terminal.words);
            }
        }
    }
}

impl TextPatternMatcher {
    pub fn matches(&self, input: &str) -> bool {
        let normalized_owned;
        let normalized = if self.lowercase_input {
            normalized_owned = input.to_ascii_lowercase();
            normalized_owned.as_str()
        } else {
            input
        };

        if !self.exact.is_empty() && self.exact.contains(normalized) {
            return true;
        }

        if !self.suffix.is_empty()
            && self
                .suffix
                .iter()
                .any(|suffix| host_matches_suffix(normalized, suffix.as_ref()))
        {
            return true;
        }

        if let Some(glob) = &self.glob {
            return glob.is_match(normalized);
        }
        false
    }
}

impl TokenMaskIndex {
    pub fn new(bit_len: usize, uppercase_input: bool) -> Self {
        Self {
            any: BitMask::empty(bit_len),
            map: HashMap::new(),
            uppercase_input,
        }
    }

    pub fn insert_values(&mut self, idx: usize, values: &[Arc<str>]) {
        if values.is_empty() {
            self.any.set(idx);
            return;
        }
        for value in values {
            self.map
                .entry(value.clone())
                .or_insert_with(|| BitMask::empty(self.any.len))
                .set(idx);
        }
    }

    pub fn fill_mask(&self, out: &mut [u64], value: Option<&str>) {
        out.copy_from_slice(&self.any.words);
        let Some(value) = value else {
            return;
        };

        let normalized;
        let key = if self.uppercase_input && !is_ascii_uppercase_token(value) {
            normalized = value.to_ascii_uppercase();
            normalized.as_str()
        } else {
            value
        };

        if let Some(mask) = self.map.get(key) {
            bit_or_assign(out, &mask.words);
        }
    }
}

impl TextMaskIndex {
    pub fn new(bit_len: usize, lowercase_input: bool, allow_suffix: bool) -> Self {
        Self {
            any: BitMask::empty(bit_len),
            complex: BitMask::empty(bit_len),
            exact: HashMap::new(),
            suffix: DomainSuffixTrie::new(bit_len),
            lowercase_input,
            allow_suffix,
        }
    }

    pub fn insert_hint(
        &mut self,
        idx: usize,
        hint: &TextPrefilterHint,
        interner: &mut StringInterner,
    ) {
        if hint.any {
            self.any.set(idx);
        }
        if hint.complex {
            self.complex.set(idx);
        }
        for exact in &hint.exact {
            self.exact
                .entry(exact.clone())
                .or_insert_with(|| BitMask::empty(self.any.len))
                .set(idx);
        }
        if self.allow_suffix {
            for suffix in &hint.suffix {
                self.suffix.insert(suffix.clone(), idx, interner);
            }
        }
    }

    pub fn fill_mask(&self, out: &mut [u64], value: Option<&str>) {
        out.copy_from_slice(&self.any.words);
        bit_or_assign(out, &self.complex.words);

        let Some(value) = value else {
            return;
        };

        let normalized;
        let key = if self.lowercase_input {
            normalized = value.to_ascii_lowercase();
            normalized.as_str()
        } else {
            value
        };

        if let Some(mask) = self.exact.get(key) {
            bit_or_assign(out, &mask.words);
        }
        if self.allow_suffix {
            self.suffix.or_matches(key, out);
        }
    }
}

impl MatchPrefilterIndex {
    pub fn new(bit_len: usize) -> Self {
        Self {
            rule_count: bit_len,
            all: BitMask::full(bit_len),
            method_index: TokenMaskIndex::new(bit_len, true),
            port_any: BitMask::empty(bit_len),
            port_map: HashMap::new(),
            src_ip_any: BitMask::empty(bit_len),
            src_ip_trie: IpRadixTrie::default(),
            host_index: TextMaskIndex::new(bit_len, true, true),
            sni_index: TextMaskIndex::new(bit_len, true, true),
            path_index: TextMaskIndex::new(bit_len, false, false),
        }
    }

    pub fn insert_hint(
        &mut self,
        idx: usize,
        hint: &MatchPrefilterHint,
        interner: &mut StringInterner,
    ) {
        self.method_index
            .insert_values(idx, hint.method_values.as_slice());

        if hint.dst_ports.is_empty() {
            self.port_any.set(idx);
        } else {
            for port in &hint.dst_ports {
                self.port_map
                    .entry(*port)
                    .or_insert_with(|| BitMask::empty(self.rule_count))
                    .set(idx);
            }
        }

        if hint.src_cidrs.is_empty() {
            self.src_ip_any.set(idx);
        } else {
            for cidr in &hint.src_cidrs {
                self.src_ip_trie.insert(cidr, idx);
            }
        }

        self.host_index.insert_hint(idx, &hint.host, interner);
        self.sni_index.insert_hint(idx, &hint.sni, interner);
        self.path_index.insert_hint(idx, &hint.path, interner);
    }

    pub fn find_first<R>(
        &self,
        ctx: &MatchPrefilterContext<'_>,
        mut visitor: impl FnMut(usize) -> Option<R>,
    ) -> Option<R> {
        let mut found = None;
        self.for_each_candidate(ctx, |idx| {
            if let Some(value) = visitor(idx) {
                found = Some(value);
                return true;
            }
            false
        });
        found
    }

    pub(crate) fn for_each_candidate(
        &self,
        ctx: &MatchPrefilterContext<'_>,
        mut visitor: impl FnMut(usize) -> bool,
    ) -> bool {
        if self.rule_count == 0 {
            return false;
        }

        PREFILTER_CANDIDATES.with(|candidate_words| {
            PREFILTER_SCRATCH.with(|scratch_words| {
                let mut candidates = candidate_words.borrow_mut();
                let mut scratch = scratch_words.borrow_mut();
                self.fill_candidate_words(ctx, &mut candidates, &mut scratch);
                if bit_is_empty(candidates.as_slice()) {
                    return false;
                }
                for_each_set_bit(candidates.as_slice(), self.rule_count, &mut visitor)
            })
        })
    }

    fn fill_candidate_words(
        &self,
        ctx: &MatchPrefilterContext<'_>,
        candidates: &mut Vec<u64>,
        scratch: &mut Vec<u64>,
    ) {
        candidates.resize(self.all.words.len(), 0);
        scratch.resize(self.all.words.len(), 0);
        candidates.as_mut_slice().copy_from_slice(&self.all.words);

        self.fill_method_mask(scratch.as_mut_slice(), ctx.method);
        bit_and_assign(candidates.as_mut_slice(), scratch.as_slice());
        if bit_is_empty(candidates.as_slice()) {
            return;
        }

        self.fill_port_mask(scratch.as_mut_slice(), ctx.dst_port);
        bit_and_assign(candidates.as_mut_slice(), scratch.as_slice());
        if bit_is_empty(candidates.as_slice()) {
            return;
        }

        self.fill_src_ip_mask(scratch.as_mut_slice(), ctx.src_ip);
        bit_and_assign(candidates.as_mut_slice(), scratch.as_slice());
        if bit_is_empty(candidates.as_slice()) {
            return;
        }

        self.fill_host_mask(scratch.as_mut_slice(), ctx.host);
        bit_and_assign(candidates.as_mut_slice(), scratch.as_slice());
        if bit_is_empty(candidates.as_slice()) {
            return;
        }

        self.fill_sni_mask(scratch.as_mut_slice(), ctx.sni);
        bit_and_assign(candidates.as_mut_slice(), scratch.as_slice());
        if bit_is_empty(candidates.as_slice()) {
            return;
        }

        self.fill_path_mask(scratch.as_mut_slice(), ctx.path);
        bit_and_assign(candidates.as_mut_slice(), scratch.as_slice());
    }

    fn fill_method_mask(&self, out: &mut [u64], method: Option<&str>) {
        self.method_index.fill_mask(out, method);
    }

    fn fill_port_mask(&self, out: &mut [u64], port: Option<u16>) {
        out.copy_from_slice(&self.port_any.words);
        if let Some(port) = port {
            if let Some(mask) = self.port_map.get(&port) {
                bit_or_assign(out, &mask.words);
            }
        }
    }

    fn fill_src_ip_mask(&self, out: &mut [u64], ip: Option<IpAddr>) {
        out.copy_from_slice(&self.src_ip_any.words);
        if let Some(ip) = ip {
            self.src_ip_trie.or_matches(ip, out);
        }
    }

    fn fill_host_mask(&self, out: &mut [u64], host: Option<&str>) {
        self.host_index.fill_mask(out, host);
    }

    fn fill_sni_mask(&self, out: &mut [u64], sni: Option<&str>) {
        self.sni_index.fill_mask(out, sni);
    }

    fn fill_path_mask(&self, out: &mut [u64], path: Option<&str>) {
        self.path_index.fill_mask(out, path);
    }
}

impl IpRadixTrie {
    fn insert(&mut self, cidr: &IpCidr, rule_idx: usize) {
        let prefix_len = cidr.network_length() as usize;
        match cidr.first_address() {
            IpAddr::V4(ip) => self.v4.insert(&ip.octets(), prefix_len, rule_idx),
            IpAddr::V6(ip) => self.v6.insert(&ip.octets(), prefix_len, rule_idx),
        }
    }

    fn or_matches(&self, ip: IpAddr, out: &mut [u64]) {
        match ip {
            IpAddr::V4(ip) => self.v4.or_matches(&ip.octets(), 32, out),
            IpAddr::V6(ip) => self.v6.or_matches(&ip.octets(), 128, out),
        }
    }
}

impl IpTrieNode {
    fn insert(&mut self, bytes: &[u8], prefix_len: usize, rule_idx: usize) {
        let mut node = self;
        for bit_index in 0..prefix_len {
            let bit = get_addr_bit(bytes, bit_index);
            node = if bit == 0 {
                node.zero
                    .get_or_insert_with(|| Box::new(IpTrieNode::default()))
                    .as_mut()
            } else {
                node.one
                    .get_or_insert_with(|| Box::new(IpTrieNode::default()))
                    .as_mut()
            };
        }
        node.rule_ids.push(rule_idx);
    }

    fn or_matches(&self, bytes: &[u8], total_bits: usize, out: &mut [u64]) {
        let mut node = self;
        or_indices(out, &node.rule_ids);

        for bit_index in 0..total_bits {
            let bit = get_addr_bit(bytes, bit_index);
            let next = if bit == 0 {
                node.zero.as_deref()
            } else {
                node.one.as_deref()
            };
            let Some(next_node) = next else {
                break;
            };
            node = next_node;
            or_indices(out, &node.rule_ids);
        }
    }
}

fn get_addr_bit(bytes: &[u8], bit_idx: usize) -> u8 {
    let byte_idx = bit_idx / 8;
    let shift = 7 - (bit_idx % 8);
    (bytes[byte_idx] >> shift) & 1
}

#[derive(Debug, Default)]
pub struct StringInterner {
    map: HashMap<String, Arc<str>>,
}

impl StringInterner {
    pub fn intern(&mut self, value: &str) -> Arc<str> {
        if let Some(existing) = self.map.get(value) {
            return existing.clone();
        }
        let arc: Arc<str> = Arc::from(value);
        self.map.insert(value.to_string(), arc.clone());
        arc
    }

    pub fn intern_lower(&mut self, value: &str) -> Arc<str> {
        let normalized = value.to_ascii_lowercase();
        self.intern(normalized.as_str())
    }

    pub fn intern_upper(&mut self, value: &str) -> Arc<str> {
        let normalized = value.to_ascii_uppercase();
        self.intern(normalized.as_str())
    }
}

fn for_each_set_bit<F>(words: &[u64], limit: usize, visitor: &mut F) -> bool
where
    F: FnMut(usize) -> bool,
{
    for (word_idx, word) in words.iter().copied().enumerate() {
        let mut active = word;
        while active != 0 {
            let bit = active.trailing_zeros() as usize;
            let idx = (word_idx * 64) + bit;
            if idx >= limit {
                return false;
            }
            if visitor(idx) {
                return true;
            }
            active &= active - 1;
        }
    }
    false
}

fn bit_words(len: usize) -> usize {
    len.div_ceil(64)
}

fn bit_or_assign(dst: &mut [u64], src: &[u64]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d |= *s;
    }
}

fn bit_and_assign(dst: &mut [u64], src: &[u64]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d &= *s;
    }
}

fn bit_is_empty(words: &[u64]) -> bool {
    words.iter().all(|word| *word == 0)
}

fn set_bit(words: &mut [u64], idx: usize) {
    let word = idx / 64;
    let bit = idx % 64;
    words[word] |= 1u64 << bit;
}

fn or_indices(words: &mut [u64], indices: &[usize]) {
    for idx in indices {
        set_bit(words, *idx);
    }
}

fn is_exact_pattern(item: &str) -> bool {
    !item.contains('*')
        && !item.contains('?')
        && !item.contains('[')
        && !item.contains(']')
        && !item.contains('{')
        && !item.contains('}')
}

fn extract_domain_suffix(pattern: &str) -> Option<&str> {
    let rest = pattern.strip_prefix("*.")?;
    if rest.is_empty() || !is_exact_pattern(rest) {
        return None;
    }
    Some(rest)
}

fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    if host.len() <= suffix.len() {
        return false;
    }
    if !host.ends_with(suffix) {
        return false;
    }
    let boundary = host.len() - suffix.len();
    host.as_bytes().get(boundary.wrapping_sub(1)).copied() == Some(b'.')
}

pub(crate) fn is_ascii_uppercase_token(value: &str) -> bool {
    value.as_bytes().iter().all(|b| !b.is_ascii_lowercase())
}

fn build_globset(items: &[String]) -> Result<Option<GlobSet>> {
    if items.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for item in items {
        builder.add(Glob::new(item)?);
    }
    Ok(Some(builder.build()?))
}

pub(crate) fn compile_text_patterns(
    items: &[String],
    lowercase: bool,
    allow_domain_suffix: bool,
    interner: &mut StringInterner,
) -> Result<(Option<TextPatternMatcher>, TextPrefilterHint)> {
    if items.is_empty() {
        return Ok((
            None,
            TextPrefilterHint {
                any: true,
                ..Default::default()
            },
        ));
    }

    let mut exact = HashSet::new();
    let mut suffix = Vec::new();
    let mut suffix_seen = HashSet::new();
    let mut complex = Vec::new();
    let mut hint = TextPrefilterHint {
        any: false,
        ..Default::default()
    };

    for item in items {
        let normalized = if lowercase {
            item.to_ascii_lowercase()
        } else {
            item.clone()
        };

        if is_exact_pattern(&normalized) {
            let value = interner.intern(normalized.as_str());
            if exact.insert(value.clone()) {
                hint.exact.push(value);
            }
            continue;
        }

        if allow_domain_suffix {
            if let Some(suffix_text) = extract_domain_suffix(&normalized) {
                let suffix_interned = interner.intern(suffix_text);
                if suffix_seen.insert(suffix_interned.clone()) {
                    suffix.push(suffix_interned.clone());
                    hint.suffix.push(suffix_interned);
                }
                continue;
            }
        }

        hint.complex = true;
        complex.push(normalized);
    }

    Ok((
        Some(TextPatternMatcher {
            exact,
            suffix,
            glob: build_globset(&complex)?,
            lowercase_input: lowercase,
        }),
        hint,
    ))
}

pub(crate) fn dedup_uppercase_arc(items: &[String], interner: &mut StringInterner) -> Vec<Arc<str>> {
    let mut out = Vec::with_capacity(items.len());
    let mut seen: HashSet<Arc<str>> = HashSet::new();
    for item in items {
        let interned = interner.intern_upper(item);
        if seen.insert(interned.clone()) {
            out.push(interned);
        }
    }
    out
}

#[cfg(test)]
mod tests {
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
}

