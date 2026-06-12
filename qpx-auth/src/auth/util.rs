#[cfg(any(feature = "ldap-auth", feature = "digest-auth"))]
use std::hash::{Hash, Hasher};

#[cfg(any(feature = "ldap-auth", feature = "digest-auth"))]
pub(super) fn shard_index<T: Hash + ?Sized>(value: &T, shards: usize) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    (hasher.finish() as usize) % shards.max(1)
}

#[cfg(feature = "basic-auth")]
pub(super) fn sha256_digest(input: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    Sha256::digest(input).into()
}

#[cfg(feature = "basic-auth")]
pub(super) fn constant_time_eq_digest(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (&left, &right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(all(test, feature = "basic-auth"))]
pub(super) fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq_digest(&sha256_digest(a), &sha256_digest(b))
}

pub(super) fn escape_quoted_header_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\r' | '\n' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}
