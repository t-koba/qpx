#[cfg(feature = "sha2-hash")]
use sha2::Digest as _;

#[cfg(feature = "sha2-hash")]
pub(super) fn sha256_hex(input: &[u8]) -> String {
    let digest = sha2::Sha256::digest(input);
    hex_lower(digest.as_slice())
}

#[cfg(not(feature = "sha2-hash"))]
pub(super) fn sha256_hex(input: &[u8]) -> String {
    // Cache keys only need to be stable and have a low collision rate.
    // Avoid pulling in SHA-256 when feature `sha2-hash` is disabled.
    use std::hash::{Hash as _, Hasher as _};

    fn domain_hash(domain: u8, input: &[u8]) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        domain.hash(&mut hasher);
        input.hash(&mut hasher);
        hasher.finish()
    }

    let h0 = domain_hash(0, input);
    let h1 = domain_hash(1, input);
    let h2 = domain_hash(2, input);
    let h3 = domain_hash(3, input);
    format!("{h0:016x}{h1:016x}{h2:016x}{h3:016x}")
}

#[cfg(feature = "sha2-hash")]
fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}
