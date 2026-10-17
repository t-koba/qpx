pub mod base_fields;
pub mod common;
pub(crate) mod forwarded;
pub mod header_control;
pub(crate) mod io_prefix;
pub mod l7;
pub mod preflight;
pub mod sse;
mod trailer_body;
pub mod upgrade;
pub mod websocket;

/// Records an absolute-form OPTIONS target with an empty path and no query.
/// `http::Uri` normalizes that target to a trailing slash, so this marker preserves the
/// empty-path semantics until the final proxy can generate the required asterisk-form target.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EmptyPathAbsoluteOptions;
