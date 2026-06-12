//! Shared HTTP runtime primitives extracted from `qpxd` so they can be reused by
//! sibling crates (e.g. `qpxd-cache`) without depending on the whole daemon.
//!
//! This crate is grown incrementally as modules with self-contained dependencies
//! are lifted out of `qpxd`; consumers import them directly from this crate.

pub mod body;
pub mod protocol;
pub mod sharding;
pub mod tls;

/// Milliseconds since the Unix epoch (wall clock). Shared so cache/health code
/// need not depend on `qpxd`'s runtime module.
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
