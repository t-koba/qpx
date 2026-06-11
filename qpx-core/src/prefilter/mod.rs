//! Prefilter indexes for quickly narrowing candidate rule sets.
//!
//! These types are public because compiled rules are shared across crates, but
//! they are implementation-facing rather than user-facing schema objects.

#![allow(missing_docs)]

use cidr::IpCidr;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

mod bit_mask;
mod domain_trie;
mod text_pattern;

pub use bit_mask::BitMask;
pub use text_pattern::{TextMatchMode, TextMatchTrace, TextPatternMatcher, TextPrefilterHint};
pub(crate) use text_pattern::{compile_text_patterns, dedup_uppercase_arc};

use bit_mask::{bit_and_assign, bit_is_empty, bit_or_assign, for_each_set_bit, or_indices};
use domain_trie::DomainSuffixTrie;

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

    pub fn for_each_candidate(
        &self,
        ctx: &MatchPrefilterContext<'_>,
        mut visitor: impl FnMut(usize) -> bool,
    ) -> bool {
        if self.rule_count == 0 {
            return false;
        }

        PREFILTER_CANDIDATES.with(|candidate_words| {
            PREFILTER_SCRATCH.with(|scratch_words| {
                if let (Ok(mut candidates), Ok(mut scratch)) = (
                    candidate_words.try_borrow_mut(),
                    scratch_words.try_borrow_mut(),
                ) {
                    self.fill_candidate_words(ctx, &mut candidates, &mut scratch);
                    if bit_is_empty(candidates.as_slice()) {
                        return false;
                    }
                    return for_each_set_bit(candidates.as_slice(), self.rule_count, &mut visitor);
                }
                let mut candidates = Vec::new();
                let mut scratch = Vec::new();
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
        if let Some(port) = port
            && let Some(mask) = self.port_map.get(&port)
        {
            bit_or_assign(out, &mask.words);
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

pub(crate) fn is_ascii_uppercase_token(value: &str) -> bool {
    value.as_bytes().iter().all(|b| !b.is_ascii_lowercase())
}

#[cfg(test)]
mod tests;
