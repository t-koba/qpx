//! Shared HTTP runtime primitives extracted from `qpxd` so they can be reused by
//! sibling crates (e.g. `qpxd-cache`) without depending on the whole daemon.
//!
//! This crate is grown incrementally as modules with self-contained dependencies
//! are lifted out of `qpxd`; consumers import them directly from this crate.

pub mod accept_query;
pub mod api_metadata;
pub mod body;
pub mod compression_dictionary;
pub mod connect_ip;
pub mod content_disposition;
pub mod cookie_policy;
pub mod digest_fields;
pub mod forwarded;
pub mod hsts;
pub mod prefer;
pub mod problem;
pub mod protocol;
pub mod proxy_status;
pub mod sharding;
pub mod structured_fields;
pub mod tls;

/// Milliseconds since the Unix epoch (wall clock). Shared so cache/health code
/// need not depend on `qpxd`'s runtime module.
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
