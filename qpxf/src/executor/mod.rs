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
#[cfg(feature = "wasm")]
pub mod wasm;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::fmt::Write;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub use qpx_core::execution::{CgiRequest, RequestHeaders};

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

/// A CGI-style response from an executor.
#[derive(Debug, Clone)]
pub struct CgiResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

pub type CgiResponseHead = (u16, Vec<(String, String)>, usize);

impl CgiResponse {
    /// Serialize this response into raw CGI output (Status header + headers + body).
    pub fn to_cgi_output(&self) -> Bytes {
        // Pre-calculate capacity to avoid repeated allocations.
        let header_size: usize = self
            .headers
            .iter()
            .map(|(k, v)| k.len() + v.len() + 4)
            .sum::<usize>()
            + 20; // "Status: NNN\r\n" + "\r\n"
        let mut out = String::with_capacity(header_size);
        let _ = write!(out, "Status: {}\r\n", self.status);
        for (k, v) in &self.headers {
            let _ = write!(out, "{}: {}\r\n", k, v);
        }
        out.push_str("\r\n");
        let mut bytes = Vec::with_capacity(out.len() + self.body.len());
        bytes.extend_from_slice(out.as_bytes());
        bytes.extend_from_slice(&self.body);
        Bytes::from(bytes)
    }

    /// Parse CGI output (stdout) into a CgiResponse.
    pub fn parse_cgi_output(data: &[u8]) -> Result<Self> {
        let (status, headers, body_start) = Self::parse_cgi_head(data)?;
        let body = Bytes::copy_from_slice(&data[body_start..]);
        Ok(CgiResponse {
            status,
            headers,
            body,
        })
    }

    /// Parse the CGI response header block without materializing the body.
    pub fn parse_cgi_head(data: &[u8]) -> Result<CgiResponseHead> {
        let header_end = find_header_end(data)
            .ok_or_else(|| anyhow::anyhow!("CGI output missing header terminator"))?;
        let header_section = std::str::from_utf8(&data[..header_end])?;
        let body_start = if data[header_end..].starts_with(b"\r\n\r\n") {
            header_end + 4
        } else if data[header_end..].starts_with(b"\n\n") {
            header_end + 2
        } else {
            return Err(anyhow::anyhow!("CGI output has invalid header terminator"));
        };

        let mut status = 200u16;
        let mut headers = Vec::new();
        for line in header_section.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                if key.is_empty() || http::HeaderName::from_bytes(key.as_bytes()).is_err() {
                    return Err(anyhow::anyhow!("CGI output contains invalid header name"));
                }
                if key.eq_ignore_ascii_case("Status") {
                    if let Some(code) = value.split_whitespace().next() {
                        status = code.parse()?;
                        if !(100..=599).contains(&status) {
                            return Err(anyhow::anyhow!("CGI output status is out of range"));
                        }
                    } else {
                        return Err(anyhow::anyhow!("CGI output Status header is empty"));
                    }
                } else {
                    headers.push((key.to_string(), value.to_string()));
                }
            } else {
                return Err(anyhow::anyhow!("CGI output contains malformed header line"));
            }
        }
        Ok((status, headers, body_start))
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    (0..data.len()).find(|&i| data[i..].starts_with(b"\r\n\r\n") || data[i..].starts_with(b"\n\n"))
}

/// Trait for request executors (CGI, WASM, etc.).
// async-trait emits `#[must_use]` on the boxed future, which is already `#[must_use]`;
// newer clippy reports it as `double_must_use`.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait Executor: Send + Sync {
    async fn start(&self, req: CgiRequest) -> Result<Execution>;
}

#[cfg(test)]
mod tests {
    use super::CgiResponse;

    #[test]
    fn parse_cgi_output_rejects_missing_header_terminator() {
        let err = CgiResponse::parse_cgi_output(b"Status: 200 OK\r\nContent-Type: text/plain")
            .expect_err("missing header terminator must fail");
        assert!(err.to_string().contains("header terminator"));
    }

    #[test]
    fn parse_cgi_output_rejects_malformed_header_line() {
        let err = CgiResponse::parse_cgi_output(b"not a header\r\n\r\nbody")
            .expect_err("malformed header line must fail");
        assert!(err.to_string().contains("malformed header"));
    }

    #[test]
    fn parse_cgi_output_rejects_invalid_status() {
        let err = CgiResponse::parse_cgi_output(b"Status: nope\r\n\r\nbody")
            .expect_err("invalid Status must fail");
        assert!(err.to_string().contains("invalid digit"));
    }

    #[test]
    fn parse_cgi_output_rejects_non_http_status_class() {
        let err = CgiResponse::parse_cgi_output(b"Status: 700 Weird\r\n\r\nbody")
            .expect_err("non-HTTP status class must fail");
        assert!(err.to_string().contains("out of range"));
    }
}
