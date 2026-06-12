#[cfg(feature = "digest-auth")]
use base64::Engine;
#[cfg(feature = "digest-auth")]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(feature = "digest-auth")]
use ring::rand::{SecureRandom, SystemRandom};
#[cfg(feature = "digest-auth")]
use sha2::Digest as _;
#[cfg(feature = "digest-auth")]
use std::collections::{HashMap, VecDeque};
#[cfg(feature = "digest-auth")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "digest-auth")]
use std::time::{Duration, Instant};

#[cfg(feature = "digest-auth")]
use super::util::shard_index;
#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone)]
pub(super) struct NonceStore {
    ttl: Duration,
    max_entries_per_shard: usize,
    shards: Arc<[Mutex<NonceStoreInner>]>,
}

#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone)]
struct NonceState {
    created: Instant,
    opaque: String,
    last_nc: u32,
    generation: u64,
}

#[cfg(feature = "digest-auth")]
#[derive(Debug)]
struct NonceStoreInner {
    nonces: HashMap<String, NonceState>,
    queue: VecDeque<(String, u64)>,
    next_generation: u64,
}

#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DigestChallengeNonce {
    pub(super) nonce: String,
    pub(super) opaque: String,
}

#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NonceCheck {
    Valid(u32),
    Stale,
    Invalid,
}

#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DigestAlgorithm {
    Sha256,
    Sha256Sess,
}

#[cfg(feature = "digest-auth")]
impl NonceStore {
    const DEFAULT_MAX_ENTRIES: usize = 65_536;
    const SHARDS: usize = 32;

    pub(super) fn new(ttl: Duration) -> Self {
        Self::with_max_entries(ttl, Self::DEFAULT_MAX_ENTRIES)
    }

    #[cfg(test)]
    pub(super) fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        let (shard_count, max_entries_per_shard) = shard_layout(max_entries, Self::SHARDS);
        Self {
            ttl,
            max_entries_per_shard,
            shards: build_nonce_shards(shard_count),
        }
    }

    #[cfg(not(test))]
    fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        let (shard_count, max_entries_per_shard) = shard_layout(max_entries, Self::SHARDS);
        Self {
            ttl,
            max_entries_per_shard,
            shards: build_nonce_shards(shard_count),
        }
    }

    fn random_token() -> Option<String> {
        let mut buf = [0u8; 16];
        if SystemRandom::new().fill(&mut buf).is_err() {
            return None;
        }
        Some(BASE64.encode(buf))
    }

    pub(super) fn issue_opaque() -> Option<String> {
        Self::random_token()
    }

    #[cfg(test)]
    pub(super) fn issue_digest_nonce(&self) -> String {
        self.issue_digest_challenge()
            .map(|challenge| challenge.nonce)
            .unwrap_or_default()
    }

    pub(super) fn issue_digest_challenge(&self) -> Option<DigestChallengeNonce> {
        let nonce = Self::random_token()?;
        let opaque = Self::issue_opaque()?;
        let now = Instant::now();
        let mut guard = self.shards[shard_index(&nonce, self.shards.len())]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::cleanup_expired_locked(&mut guard, self.ttl, now);
        Self::evict_to_capacity_locked(&mut guard, self.max_entries_per_shard.saturating_sub(1));
        let generation = guard.next_generation;
        guard.next_generation = guard.next_generation.wrapping_add(1);
        guard.nonces.insert(
            nonce.clone(),
            NonceState {
                created: now,
                opaque: opaque.clone(),
                last_nc: 0,
                generation,
            },
        );
        guard.queue.push_back((nonce.clone(), generation));
        Some(DigestChallengeNonce { nonce, opaque })
    }

    #[cfg(test)]
    pub(super) fn parse_digest_nc(&self, nonce: &str, nc_hex: &str) -> Option<u32> {
        match self.check_digest_nonce(nonce, None, nc_hex) {
            NonceCheck::Valid(nc) => Some(nc),
            NonceCheck::Stale | NonceCheck::Invalid => None,
        }
    }

    pub(super) fn validate_digest_nonce(
        &self,
        nonce: &str,
        opaque: &str,
        nc_hex: &str,
    ) -> NonceCheck {
        if opaque.is_empty() {
            return NonceCheck::Invalid;
        }
        self.check_digest_nonce(nonce, Some(opaque), nc_hex)
    }

    fn check_digest_nonce(&self, nonce: &str, opaque: Option<&str>, nc_hex: &str) -> NonceCheck {
        let Some(nc) = parse_nc(nc_hex) else {
            return NonceCheck::Invalid;
        };
        let mut guard = self.shards[shard_index(nonce, self.shards.len())]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let Some(state) = guard.nonces.get(nonce) else {
            return NonceCheck::Invalid;
        };
        if now.duration_since(state.created) >= self.ttl {
            guard.nonces.remove(nonce);
            return NonceCheck::Stale;
        }
        if let Some(opaque) = opaque
            && state.opaque != opaque
        {
            return NonceCheck::Invalid;
        }
        if nc == 0 || nc <= state.last_nc {
            return NonceCheck::Invalid;
        }
        NonceCheck::Valid(nc)
    }

    pub(super) fn mark_digest_nc_used(&self, nonce: &str, nc: u32) -> bool {
        let mut guard = self.shards[shard_index(nonce, self.shards.len())]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();

        let Some(state) = guard.nonces.get_mut(nonce) else {
            return false;
        };
        if now.duration_since(state.created) >= self.ttl {
            guard.nonces.remove(nonce);
            return false;
        }
        if nc == 0 || nc <= state.last_nc {
            return false;
        }
        state.last_nc = nc;
        true
    }

    fn cleanup_expired_locked(guard: &mut NonceStoreInner, ttl: Duration, now: Instant) {
        while let Some((nonce, generation)) = guard.queue.front() {
            let should_pop = match guard.nonces.get(nonce) {
                Some(state)
                    if state.generation == *generation
                        && now.duration_since(state.created) >= ttl =>
                {
                    guard.nonces.remove(nonce);
                    true
                }
                Some(state) if state.generation == *generation => false,
                _ => true,
            };
            if !should_pop {
                break;
            }
            guard.queue.pop_front();
        }
    }

    fn evict_to_capacity_locked(guard: &mut NonceStoreInner, target_len: usize) {
        while guard.nonces.len() > target_len {
            let Some((nonce, generation)) = guard.queue.pop_front() else {
                break;
            };
            if guard
                .nonces
                .get(nonce.as_str())
                .is_some_and(|state| state.generation == generation)
            {
                guard.nonces.remove(nonce.as_str());
            }
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .nonces
                    .len()
            })
            .sum()
    }

    #[cfg(test)]
    pub(super) fn queue_len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .queue
                    .len()
            })
            .sum()
    }
}

#[cfg(feature = "digest-auth")]
fn shard_layout(max_entries: usize, max_shards: usize) -> (usize, usize) {
    let max_entries = max_entries.max(1);
    let shard_count = max_shards.max(1).min(max_entries);
    let per_shard = (max_entries / shard_count).max(1);
    (shard_count, per_shard)
}

#[cfg(feature = "digest-auth")]
fn build_nonce_shards(count: usize) -> Arc<[Mutex<NonceStoreInner>]> {
    let mut shards = Vec::with_capacity(count.max(1));
    for _ in 0..count.max(1) {
        shards.push(Mutex::new(NonceStoreInner::default()));
    }
    shards.into()
}

#[cfg(feature = "digest-auth")]
impl Default for NonceStoreInner {
    fn default() -> Self {
        Self {
            nonces: HashMap::new(),
            queue: VecDeque::new(),
            next_generation: 1,
        }
    }
}

#[cfg(feature = "digest-auth")]
fn parse_nc(nc_hex: &str) -> Option<u32> {
    if nc_hex.len() != 8 {
        return None;
    }
    u32::from_str_radix(nc_hex, 16).ok()
}

#[cfg(feature = "digest-auth")]
pub(super) fn parse_digest(input: &str) -> Option<HashMap<String, String>> {
    let mut out = HashMap::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for ch in input.chars() {
        if in_quotes {
            current.push(ch);
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = false;
            }
            continue;
        }

        match ch {
            '"' => {
                in_quotes = true;
                current.push(ch);
            }
            ',' => {
                if !insert_digest_param(&mut out, current.as_str()) {
                    return None;
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if in_quotes || escaped {
        return None;
    }
    if !insert_digest_param(&mut out, current.as_str()) {
        return None;
    }
    Some(out)
}

#[cfg(feature = "digest-auth")]
fn insert_digest_param(out: &mut HashMap<String, String>, raw: &str) -> bool {
    let raw = raw.trim();
    if raw.is_empty() {
        return true;
    }
    let Some((key, value)) = raw.split_once('=') else {
        return false;
    };
    let key = key.trim();
    if key.is_empty() {
        return false;
    }
    let value = value.trim();
    let value = if value.starts_with('"') {
        let Some(value) = unquote_http_quoted_string(value) else {
            return false;
        };
        value
    } else {
        if value.contains('"') {
            return false;
        }
        value.to_string()
    };
    out.insert(key.to_ascii_lowercase(), value).is_none()
}

#[cfg(feature = "digest-auth")]
fn unquote_http_quoted_string(raw: &str) -> Option<String> {
    let mut s = raw.trim();
    if let Some(rest) = s.strip_prefix('"') {
        s = rest;
    } else {
        return None;
    }
    if let Some(rest) = s.strip_suffix('"') {
        s = rest;
    } else {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut escape = false;
    for ch in s.chars() {
        if escape {
            out.push(ch);
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        out.push(ch);
    }
    if escape {
        return None;
    }
    Some(out)
}

#[cfg(feature = "digest-auth")]
pub(super) fn sha256_hex(input: &[u8]) -> String {
    let digest = sha2::Sha256::digest(input);
    hex_lower(digest.as_slice())
}

#[cfg(feature = "digest-auth")]
pub(super) fn parse_sha256_ha1(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let hex = if raw.len() > 8 && raw[..8].eq_ignore_ascii_case("sha-256:") {
        &raw[8..]
    } else {
        raw
    };
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    if !hex.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex.to_ascii_lowercase())
}

#[cfg(feature = "digest-auth")]
fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(feature = "digest-auth")]
pub(super) fn constant_time_eq_hex_lower(expected_lower: &str, actual: &str) -> bool {
    let a = expected_lower.as_bytes();
    let b = actual.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&expected, &byte) in a.iter().zip(b.iter()) {
        let lower = if (b'A'..=b'F').contains(&byte) {
            byte.saturating_add(32)
        } else {
            byte
        };
        diff |= expected ^ lower;
    }
    diff == 0
}
