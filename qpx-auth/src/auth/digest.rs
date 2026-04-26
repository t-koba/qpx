#[cfg(feature = "digest-auth")]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(feature = "digest-auth")]
use base64::Engine;
#[cfg(feature = "digest-auth")]
use ring::rand::{SecureRandom, SystemRandom};
#[cfg(feature = "digest-auth")]
use sha2::Digest as _;
#[cfg(feature = "digest-auth")]
use std::collections::HashMap;
#[cfg(feature = "digest-auth")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "digest-auth")]
use std::time::{Duration, Instant};

#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone)]
pub(super) struct NonceStore {
    ttl: Duration,
    max_entries: usize,
    inner: Arc<Mutex<HashMap<String, NonceState>>>,
}

#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone)]
struct NonceState {
    created: Instant,
    last_nc: u32,
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

    pub(super) fn new(ttl: Duration) -> Self {
        Self::with_max_entries(ttl, Self::DEFAULT_MAX_ENTRIES)
    }

    #[cfg(test)]
    pub(super) fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries: max_entries.max(1),
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg(not(test))]
    fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries: max_entries.max(1),
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn random_token() -> String {
        let mut buf = [0u8; 16];
        SystemRandom::new()
            .fill(&mut buf)
            .expect("secure random nonce generation");
        BASE64.encode(buf)
    }

    pub(super) fn issue_opaque() -> String {
        Self::random_token()
    }

    pub(super) fn issue_digest_nonce(&self) -> String {
        let nonce = Self::random_token();
        let mut guard = self.inner.lock().expect("nonce mutex");
        Self::cleanup_expired_locked(&mut guard, self.ttl);
        while guard.len() >= self.max_entries {
            let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, state)| state.created)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            guard.remove(&oldest_key);
        }
        guard.insert(
            nonce.clone(),
            NonceState {
                created: Instant::now(),
                last_nc: 0,
            },
        );
        nonce
    }

    pub(super) fn parse_digest_nc(&self, nonce: &str, nc_hex: &str) -> Option<u32> {
        let mut guard = self.inner.lock().expect("nonce mutex");
        Self::cleanup_expired_locked(&mut guard, self.ttl);

        let state = guard.get(nonce)?;
        if nc_hex.len() != 8 {
            return None;
        }
        let Ok(nc) = u32::from_str_radix(nc_hex, 16) else {
            return None;
        };
        if nc == 0 || nc <= state.last_nc {
            return None;
        }
        Some(nc)
    }

    pub(super) fn mark_digest_nc_used(&self, nonce: &str, nc: u32) -> bool {
        let mut guard = self.inner.lock().expect("nonce mutex");
        Self::cleanup_expired_locked(&mut guard, self.ttl);

        let Some(state) = guard.get_mut(nonce) else {
            return false;
        };
        if nc == 0 || nc <= state.last_nc {
            return false;
        }
        state.last_nc = nc;
        true
    }

    fn cleanup_expired_locked(guard: &mut HashMap<String, NonceState>, ttl: Duration) {
        let now = Instant::now();
        guard.retain(|_, state| now.duration_since(state.created) < ttl);
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.inner.lock().expect("nonce mutex").len()
    }
}

#[cfg(feature = "digest-auth")]
pub(super) fn parse_digest(input: &str) -> HashMap<String, String> {
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
                insert_digest_param(&mut out, current.as_str());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    insert_digest_param(&mut out, current.as_str());
    out
}

#[cfg(feature = "digest-auth")]
fn insert_digest_param(out: &mut HashMap<String, String>, raw: &str) {
    let raw = raw.trim();
    if raw.is_empty() {
        return;
    }
    let Some((key, value)) = raw.split_once('=') else {
        return;
    };
    let key = key.trim();
    if key.is_empty() {
        return;
    }
    let value = value.trim();
    let value = if value.starts_with('"') {
        unquote_http_quoted_string(value)
    } else {
        value.to_string()
    };
    out.insert(key.to_ascii_lowercase(), value);
}

#[cfg(feature = "digest-auth")]
fn unquote_http_quoted_string(raw: &str) -> String {
    let mut s = raw.trim();
    if let Some(rest) = s.strip_prefix('"') {
        s = rest;
    }
    if let Some(rest) = s.strip_suffix('"') {
        s = rest;
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
    out
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
