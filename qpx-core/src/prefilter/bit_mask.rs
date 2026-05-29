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

pub(super) fn for_each_set_bit<F>(words: &[u64], limit: usize, visitor: &mut F) -> bool
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

pub(super) fn bit_words(len: usize) -> usize {
    len.div_ceil(64)
}

pub(super) fn bit_or_assign(dst: &mut [u64], src: &[u64]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d |= *s;
    }
}

pub(super) fn bit_and_assign(dst: &mut [u64], src: &[u64]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d &= *s;
    }
}

pub(super) fn bit_is_empty(words: &[u64]) -> bool {
    words.iter().all(|word| *word == 0)
}

pub(super) fn set_bit(words: &mut [u64], idx: usize) {
    let word = idx / 64;
    let bit = idx % 64;
    words[word] |= 1u64 << bit;
}

pub(super) fn or_indices(words: &mut [u64], indices: &[usize]) {
    for idx in indices {
        set_bit(words, *idx);
    }
}
