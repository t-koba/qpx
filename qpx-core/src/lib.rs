//! Core configuration, protocol, security, and matching primitives shared by
//! the qpx workspace.
//!
//! This crate intentionally contains no proxy runtime loop. It owns stable data
//! shapes and helpers that are consumed by `qpxd`, `qpxf`, `qpxr`, and related
//! crates: canonical configuration loading, matcher compilation, redaction,
//! secure local-file handling, IPC framing, shared-memory rings, and TLS
//! material management.

#![recursion_limit = "256"]
#![warn(missing_docs)]

/// Canonical configuration types, defaults, merge logic, and validation.
pub mod config;
/// Environment-variable substitution helpers for configuration loading.
pub mod envsubst;
/// Shared exporter configuration and queue policy types.
pub mod exporter;
/// IPC framing and shared metadata protocol definitions.
#[cfg(feature = "ipc-support")]
pub mod ipc;
/// Rule matcher compilation and evaluation primitives.
pub mod matchers;
/// Request prefilter helpers used to avoid evaluating impossible rule matches.
pub mod prefilter;
/// Header, query, and JSON redaction helpers shared by audit/export paths.
pub mod redaction;
/// Compiled rule-side utilities such as header mutations and observation flags.
pub mod rules;
/// Secure file creation/opening helpers for sensitive generated material.
pub mod secure_file;
/// Shared-memory ring buffer used by capture/export paths.
#[cfg(feature = "ipc-support")]
pub mod shm_ring;

/// TLS configuration, certificate, trust, and MITM CA helpers.
pub mod tls;
/// RFC 6570 URI template parsing, expansion, and reverse matching.
pub mod uri_template;
