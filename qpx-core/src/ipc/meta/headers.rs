use crate::execution::RequestHeaders;
use crate::http_content_length::{ContentLengthError, declared_content_length_in_named_values};
use http::{Uri, response::Builder};
use std::fmt;

/// Ordered IPC request fields. Construction is write-only; semantic projections
/// never lend raw field values. Only the enclosing metadata is serializable.
///
/// ```compile_fail
/// use qpx_core::ipc::meta::IpcRequestHeaders;
/// let fields = IpcRequestHeaders::default();
/// let _ = fields.0;
/// ```
/// ```compile_fail
/// use qpx_core::ipc::meta::IpcRequestHeaders;
/// for pair in IpcRequestHeaders::default() {}
/// ```
/// ```compile_fail
/// use qpx_core::ipc::meta::IpcRequestHeaders;
/// let _ = IpcRequestHeaders::default().iter();
/// ```
/// ```compile_fail
/// use qpx_core::ipc::meta::IpcRequestHeaders;
/// serde_json::to_string(&IpcRequestHeaders::default()).unwrap();
/// ```
#[derive(Clone, Default)]
pub struct IpcRequestHeaders(Vec<(String, String)>);

impl fmt::Debug for IpcRequestHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IpcRequestHeaders { .. }")
    }
}

impl IpcRequestHeaders {
    /// Retain exact spelling, order and duplicates for the IPC wire.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self(pairs)
    }

    /// Append a field without exposing the stored fields.
    pub fn push(&mut self, pair: (String, String)) {
        self.0.push(pair);
    }

    fn first(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// First Host, falling back to URI authority when it cannot name a route.
    pub fn route_host(&self, uri: &Uri) -> Option<String> {
        self.first("host")
            .and_then(host_only)
            .or_else(|| uri.authority().and_then(|a| host_only(a.as_str())))
    }

    /// CGI server tuple: first Host, then URI authority, then localhost:80.
    /// A present but malformed Host does not select the URI instead.
    pub fn server_name_and_port(&self, uri: &Uri) -> (String, u16) {
        let (name, port) = self
            .first("host")
            .or_else(|| uri.authority().map(|a| a.as_str()))
            .map(host_port)
            .unwrap_or((None, None));
        (
            name.unwrap_or_else(|| "localhost".to_string()),
            port.unwrap_or(80),
        )
    }

    /// First case-insensitive Content-Type, or empty when absent.
    pub fn content_type(&self) -> String {
        self.first("content-type").unwrap_or_default().to_string()
    }

    /// Validate every Content-Length using the HTTP declared-length owner.
    pub fn declared_content_length(&self) -> Result<Option<u64>, ContentLengthError> {
        declared_content_length_in_named_values(
            self.0.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        )
    }

    /// Consume fields into the closed CGI request carrier, preserving its
    /// lowercase names and ordered duplicate joins (including Cookie's `; `).
    pub fn into_cgi_headers(self) -> RequestHeaders {
        RequestHeaders::from_http_pairs(self.0)
    }
}

/// Ordered IPC response fields, applied only to the HTTP response builder.
///
/// ```compile_fail
/// use qpx_core::ipc::meta::IpcResponseHeaders;
/// let _ = IpcResponseHeaders::default().0;
/// ```
/// ```compile_fail
/// use qpx_core::ipc::meta::IpcResponseHeaders;
/// for pair in IpcResponseHeaders::default() {}
/// ```
/// ```compile_fail
/// use qpx_core::ipc::meta::IpcResponseHeaders;
/// let _ = IpcResponseHeaders::default().iter();
/// ```
/// ```compile_fail
/// use qpx_core::ipc::meta::IpcResponseHeaders;
/// serde_json::to_string(&IpcResponseHeaders::default()).unwrap();
/// ```
#[derive(Clone, Default)]
pub struct IpcResponseHeaders(Vec<(String, String)>);

impl fmt::Debug for IpcResponseHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IpcResponseHeaders { .. }")
    }
}

impl IpcResponseHeaders {
    /// Retain exact spelling, order and duplicates for the IPC wire.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self(pairs)
    }

    /// Append a field without exposing the stored fields.
    pub fn push(&mut self, pair: (String, String)) {
        self.0.push(pair);
    }

    /// Append in occurrence order, retaining the builder's deferred errors.
    pub fn apply_to_response(self, mut builder: Builder) -> Builder {
        for (name, value) in self.0 {
            builder = builder.header(name, value);
        }
        builder
    }
}

// Serde is available only at the metadata wire boundary, not on carriers.
pub(super) mod request_wire {
    use super::IpcRequestHeaders;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        headers: &IpcRequestHeaders,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        headers.0.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<IpcRequestHeaders, D::Error> {
        Vec::deserialize(deserializer).map(IpcRequestHeaders)
    }
}

pub(super) mod response_wire {
    use super::IpcResponseHeaders;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        headers: &IpcResponseHeaders,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        headers.0.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<IpcResponseHeaders, D::Error> {
        Vec::deserialize(deserializer).map(IpcResponseHeaders)
    }
}

fn host_only(authority: &str) -> Option<String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    if let Some(v6) = authority.strip_prefix('[') {
        let end = v6.find(']')?;
        return Some(v6[..end].to_string());
    }
    Some(
        authority
            .split_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority)
            .to_string(),
    )
}

fn host_port(authority: &str) -> (Option<String>, Option<u16>) {
    let authority = authority.trim();
    if authority.is_empty() {
        return (None, None);
    }
    if let Some(v6) = authority.strip_prefix('[') {
        let end = match v6.find(']') {
            Some(v) => v,
            None => return (None, None),
        };
        let host = v6[..end].to_string();
        let rest = &v6[end + 1..];
        let port = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
        return (Some(host), port);
    }
    let (host, port) = authority
        .split_once(':')
        .map(|(h, p)| (h.to_string(), p.parse::<u16>().ok()))
        .unwrap_or((authority.to_string(), None));
    (Some(host), port)
}
