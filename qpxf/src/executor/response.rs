//! CGI response parsing and terminal output; raw header pairs stay in this module.

use anyhow::Result;
use bytes::Bytes;
use qpx_core::ipc::meta::{IpcResponseHeaders, IpcResponseMeta};
use std::fmt::{self, Write};

/// Write-only headers for a CGI response. Construct pairs here, then emit the
/// complete response with [`CgiResponse::to_cgi_output`]. This is not a header
/// inspection API and does not validate or canonicalize values.
///
/// ```compile_fail,E0616
/// use qpxf::executor::CgiResponse;
/// fn raw(response: CgiResponse) { let _ = response.headers.0; }
/// ```
/// ```compile_fail,E0599
/// use qpxf::executor::CgiResponseHeaders;
/// fn read(headers: &CgiResponseHeaders) { let _ = headers.get("Content-Length"); }
/// ```
/// ```compile_fail,E0599
/// use qpxf::executor::CgiResponseHeaders;
/// fn read(headers: &CgiResponseHeaders) { let _ = headers.iter(); }
/// ```
/// ```compile_fail,E0277
/// use qpxf::executor::CgiResponseHeaders;
/// fn iterate(headers: CgiResponseHeaders) { for _ in headers {} }
/// ```
/// ```compile_fail,E0277
/// use qpxf::executor::CgiResponseHeaders;
/// fn serialize(headers: CgiResponseHeaders) { let _ = serde_json::to_string(&headers); }
/// ```
#[derive(Clone, Default)]
pub struct CgiResponseHeaders(Vec<(String, String)>);

impl CgiResponseHeaders {
    /// Accept ordered CGI header pairs without validation or normalization.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self(pairs)
    }

    /// Append a CGI header without validation or normalization.
    pub fn push(&mut self, pair: (String, String)) {
        self.0.push(pair);
    }
}

impl fmt::Debug for CgiResponseHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CgiResponseHeaders").finish_non_exhaustive()
    }
}

/// A CGI-style response from an executor.
#[derive(Debug, Clone)]
pub struct CgiResponse {
    pub status: u16,
    pub headers: CgiResponseHeaders,
    pub body: Bytes,
}

/// Parsed CGI response head. Only the body offset and a consuming IPC transfer
/// are exposed; ordinary headers cannot be inspected separately.
///
/// ```compile_fail,E0308
/// use qpxf::executor::CgiResponseHead;
/// fn unpack(head: CgiResponseHead) { let (status, headers, offset) = head; }
/// ```
/// ```compile_fail,E0616
/// use qpxf::executor::CgiResponseHead;
/// fn raw(head: CgiResponseHead) { let _ = head.headers; }
/// ```
/// ```compile_fail,E0277
/// use qpxf::executor::CgiResponseHead;
/// fn serialize(head: CgiResponseHead) { let _ = serde_json::to_string(&head); }
/// ```
pub struct CgiResponseHead {
    status: u16,
    headers: CgiResponseHeaders,
    body_offset: usize,
}

impl CgiResponseHead {
    /// Byte offset of the body in the input passed to `parse_cgi_head`.
    pub fn body_offset(&self) -> usize {
        self.body_offset
    }

    /// Transfer this parsed response into the closed IPC metadata carrier,
    /// preserving header spelling, values, order and duplicates without validation.
    pub fn into_ipc_response(self) -> (IpcResponseMeta, usize) {
        (
            IpcResponseMeta {
                status: self.status,
                headers: IpcResponseHeaders::from_pairs(self.headers.0),
            },
            self.body_offset,
        )
    }
}

impl CgiResponse {
    /// Serialize this response into raw CGI output (Status header + headers + body).
    pub fn to_cgi_output(&self) -> Bytes {
        // Pre-calculate capacity to avoid repeated allocations.
        let header_size: usize = self
            .headers
            .0
            .iter()
            .map(|(k, v)| k.len() + v.len() + 4)
            .sum::<usize>()
            + 20; // "Status: NNN\r\n" + "\r\n"
        let mut out = String::with_capacity(header_size);
        let _ = write!(out, "Status: {}\r\n", self.status);
        for (k, v) in &self.headers.0 {
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
        let head = Self::parse_cgi_head(data)?;
        let body = Bytes::copy_from_slice(&data[head.body_offset..]);
        Ok(CgiResponse {
            status: head.status,
            headers: head.headers,
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
        Ok(CgiResponseHead {
            status,
            headers: CgiResponseHeaders::from_pairs(headers),
            body_offset: body_start,
        })
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    (0..data.len()).find(|&i| data[i..].starts_with(b"\r\n\r\n") || data[i..].starts_with(b"\n\n"))
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
