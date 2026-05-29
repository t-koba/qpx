use std::collections::HashMap;
use std::sync::Arc;

use super::StringInterner;
use super::bit_mask::{BitMask, bit_or_assign};

#[derive(Debug, Clone)]
pub(super) struct DomainSuffixTrie {
    root: DomainSuffixNode,
    bit_len: usize,
}

#[derive(Debug, Clone, Default)]
struct DomainSuffixNode {
    terminal: BitMask,
    children: HashMap<Arc<str>, DomainSuffixNode>,
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
