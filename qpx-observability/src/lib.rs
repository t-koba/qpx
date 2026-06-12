//! Observability support for qpx services.

#![warn(missing_docs)]

/// Access log middleware and context extensions.
pub mod access_log;
/// Generic request handler abstraction used by observability middleware.
pub mod handler;
mod logging;
mod metrics;
mod tracing_support;

pub use handler::{RequestHandler, handler_fn};
pub use logging::{LogGuards, init_logging};
pub use metrics::start_metrics;
use thiserror::Error;
pub use tracing_support::{extract_trace_context, inject_trace_context, otel_enabled};

/// Result type used by observability setup routines.
pub type ObservabilityResult<T> = std::result::Result<T, ObservabilityError>;

/// Error returned by observability setup routines.
#[derive(Debug, Error)]
pub enum ObservabilityError {
    /// Backend setup failed.
    #[error("observability setup failed")]
    Backend(#[source] anyhow::Error),
}

impl From<anyhow::Error> for ObservabilityError {
    fn from(source: anyhow::Error) -> Self {
        Self::Backend(source)
    }
}
