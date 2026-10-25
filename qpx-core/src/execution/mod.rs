//! Closed execution request headers and terminal, protocol-specific environments.
//!
//! Executors consume a complete environment artifact, not a header map. Policies
//! remain separate for CGI, persistent gateways and WASI. `CgiRequest` and
//! `WasmRequest` are reexported by their executors; this dependency-neutral owner
//! keeps the WASI handoff opaque even when qpxf's WASM feature is disabled.
//!
//! Custom executors select the appropriate request projection and call the
//! artifact's `into_variables()` only when handing the complete environment to
//! their runtime. CGI artifacts contain one value per variable; persistent and
//! WASI artifacts retain duplicate variable names and their projection order.
//! They are final execution environments, not a general header inspection API.
//!
//! CGI admits at most 100 fields *after* filtering reserved content and
//! hop-by-hop fields. Persistent gateways truncate HashMap iteration at 100
//! *before* the same filtering. WASI is uncapped and also projects content fields
//! as `HTTP_*`. No backend sorts fields or promises a stable HashMap order.
use std::collections::{HashMap, HashSet};
use std::fmt;

mod cgi;
mod persistent;
mod wasi;
pub use cgi::cgi_env_passthrough_is_reserved;

/// HTTP fields owned by an execution request. Only write-only ingress is public.
/// Debug never prints names or values; no stable HashMap order is promised.
#[derive(Clone, Default)]
pub struct RequestHeaders(HashMap<String, String>);

impl fmt::Debug for RequestHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestHeaders { .. }")
    }
}

impl RequestHeaders {
    /// Accept already-collapsed HTTP fields, retaining names and HashMap iteration.
    /// This is ingress only: there is deliberately no inverse conversion.
    pub fn from_http_fields(fields: HashMap<String, String>) -> Self {
        Self(fields)
    }

    /// Accept ordered HTTP pairs, lowercasing names and joining duplicate fields.
    /// Cookies join with `; `; other fields join with `, ` in occurrence order.
    pub fn from_http_pairs(fields: Vec<(String, String)>) -> Self {
        let mut out: HashMap<String, String> = HashMap::new();
        for (k, v) in fields {
            let key = k.to_ascii_lowercase();
            if let Some(existing) = out.get_mut(&key) {
                existing.push_str(if key == "cookie" { "; " } else { ", " });
                existing.push_str(&v);
            } else {
                out.insert(key, v);
            }
        }
        Self(out)
    }
}

/// A CGI-style request passed to an executor.
#[derive(Debug, Clone)]
pub struct CgiRequest {
    /// CGI SCRIPT_NAME.
    pub script_name: String,
    /// CGI PATH_INFO.
    pub path_info: String,
    /// CGI QUERY_STRING.
    pub query_string: String,
    /// HTTP request method.
    pub request_method: String,
    /// Parsed request content type.
    pub content_type: String,
    /// Request body length (zero when undeclared).
    pub content_length: usize,
    /// Declared body length, retaining absent versus explicit zero.
    pub declared_content_length: Option<usize>,
    /// CGI SERVER_PROTOCOL.
    pub server_protocol: String,
    /// CGI SERVER_NAME.
    pub server_name: String,
    /// CGI SERVER_PORT.
    pub server_port: u16,
    /// Client address.
    pub remote_addr: Option<String>,
    /// Client port.
    pub remote_port: Option<u16>,
    /// Opaque, write-only HTTP header ingress.
    pub http_headers: RequestHeaders,
    /// The matched route prefix (if any), used for prefix-stripping in executors.
    pub matched_prefix: Option<String>,
    /// Verified identity environment, never client headers.
    pub identity_env: HashMap<String, String>,
}

/// CGI-style request metadata for one WASM execution.
#[derive(Debug, Clone)]
pub struct WasmRequest {
    /// CGI `SCRIPT_NAME`.
    pub script_name: String,
    /// CGI `PATH_INFO`.
    pub path_info: String,
    /// CGI `QUERY_STRING`.
    pub query_string: String,
    /// CGI `REQUEST_METHOD`.
    pub request_method: String,
    /// Request content type.
    pub content_type: String,
    /// Request content length.
    pub content_length: usize,
    /// CGI `SERVER_PROTOCOL`.
    pub server_protocol: String,
    /// CGI `SERVER_NAME`.
    pub server_name: String,
    /// CGI `SERVER_PORT`.
    pub server_port: u16,
    /// Client remote address.
    pub remote_addr: Option<String>,
    /// Client remote port.
    pub remote_port: Option<u16>,
    /// Opaque, write-only HTTP header ingress.
    pub http_headers: RequestHeaders,
    /// Verified identity environment supplied through QPX-IPC, never client headers.
    pub identity_env: HashMap<String, String>,
}

/// Request-derived process-CGI environment (one value per variable).
/// qpxf's built-in adapter separately applies configured host passthrough. This is
/// a terminal execution artifact, not a raw HTTP-header representation.
pub struct CgiEnvironment(HashMap<String, String>);

impl CgiEnvironment {
    /// Consume the final variables for transport to the execution runtime.
    pub fn into_variables(self) -> HashMap<String, String> {
        self.0
    }
}

/// Fully projected final environment for FastCGI/SCGI (ordered, possibly repeated variables).
/// This is a terminal execution artifact, not a raw HTTP-header representation.
pub struct PersistentEnvironment(Vec<(String, String)>);

impl PersistentEnvironment {
    /// Consume the final variables for transport to the execution runtime.
    pub fn into_variables(self) -> Vec<(String, String)> {
        self.0
    }
}

/// Fully projected final environment for WASI (ordered, possibly repeated variables).
/// This is a terminal execution artifact, not a raw HTTP-header representation.
pub struct WasiEnvironment(Vec<(String, String)>);

impl WasiEnvironment {
    /// Consume the final variables for transport to the execution runtime.
    pub fn into_variables(self) -> Vec<(String, String)> {
        self.0
    }
}

impl CgiRequest {
    /// Transfer ownership to WASI without exposing or re-projecting headers.
    pub fn into_wasm_request(self) -> WasmRequest {
        WasmRequest {
            script_name: self.script_name,
            path_info: self.path_info,
            query_string: self.query_string,
            request_method: self.request_method,
            content_type: self.content_type,
            content_length: self.content_length,
            server_protocol: self.server_protocol,
            server_name: self.server_name,
            server_port: self.server_port,
            remote_addr: self.remote_addr,
            remote_port: self.remote_port,
            http_headers: self.http_headers,
            identity_env: self.identity_env,
        }
    }
}

fn parse_connection_tokens(headers: &HashMap<String, String>) -> HashSet<String> {
    let mut out = HashSet::new();
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("connection") {
            continue;
        }
        for token in value.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                out.insert(token.to_ascii_lowercase());
            }
        }
    }
    out
}

/// Check if a header name is a hop-by-hop or sensitive header.
fn is_cgi_reserved_header(name: &str) -> bool {
    matches!(name, "content-length" | "content-type")
}

/// Check if a header name is a hop-by-hop or sensitive header.
fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-authentication-info"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}
