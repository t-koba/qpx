//! Streaming execution with closed request headers.
//!
//! Custom executors use [`CgiRequest::cgi_environment`] or
//! [`CgiRequest::persistent_environment`] and consume the returned final artifact.
//! HTTP headers are write-only ingress, not an inspection API:
//!
//! ```compile_fail,E0599
//! use qpxf::executor::CgiRequest;
//! fn raw(req: &CgiRequest) { let _ = req.http_headers.get("content-length"); }
//! ```
//! ```compile_fail,E0616
//! use qpxf::executor::CgiRequest;
//! fn raw(req: CgiRequest) { let _ = req.http_headers.0; }
//! ```
//! ```compile_fail,E0277
//! use qpxf::executor::CgiRequest;
//! fn raw(req: CgiRequest) { for _ in req.http_headers {} }
//! ```
//! ```compile_fail,E0277
//! use qpxf::executor::CgiRequest;
//! fn raw(req: CgiRequest) { let _ = serde_json::to_string(&req.http_headers); }
//! ```
//! ```compile_fail,E0061
//! use qpxf::executor::CgiRequest;
//! fn read_host_environment(req: &CgiRequest) {
//!     let _ = req.cgi_environment(&["PATH".to_owned()]);
//! }
//! ```

pub mod cgi;
pub mod persistent;
mod response;
#[cfg(feature = "wasm")]
pub mod wasm;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub use qpx_core::execution::{CgiRequest, RequestHeaders};
pub use response::{CgiResponse, CgiResponseHead, CgiResponseHeaders};

/// A running execution instance: stdin is fed by the IPC server, stdout/stderr
/// are streamed back to the IPC client.
pub struct Execution {
    /// Existing backend stdout limit, also bounding pre-commit response staging.
    pub max_stdout_bytes: usize,
    pub stdin: mpsc::Sender<Bytes>,
    pub stdout: mpsc::Receiver<Bytes>,
    pub stderr: mpsc::Receiver<Bytes>,
    pub abort: oneshot::Sender<()>,
    pub done: JoinHandle<Result<()>>,
}

/// Trait for request executors (CGI, WASM, etc.).
// async-trait emits `#[must_use]` on the boxed future, which is already `#[must_use]`;
// newer clippy reports it as `double_must_use`.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait Executor: Send + Sync {
    async fn start(&self, req: CgiRequest) -> Result<Execution>;
}
