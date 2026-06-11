//! Shared HTTP protocol helpers (status/semantics, address formatting, and the
//! leaf HTTP/1 client handshake) used by `qpxd` and sibling crates.

pub mod address;
pub mod common;
pub mod semantics;
