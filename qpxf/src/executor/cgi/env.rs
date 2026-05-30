use super::CgiExecutor;
use crate::executor::CgiRequest;
use std::collections::{HashMap, HashSet};

/// Maximum number of HTTP_* headers to pass through to CGI environment.
const MAX_HTTP_HEADERS: usize = 100;

impl CgiExecutor {
    pub(super) fn build_env(&self, req: &CgiRequest) -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert("GATEWAY_INTERFACE".into(), "CGI/1.1".into());
        env.insert("SERVER_PROTOCOL".into(), req.server_protocol.clone());
        env.insert(
            "SERVER_SOFTWARE".into(),
            concat!("qpxf/", env!("CARGO_PKG_VERSION")).into(),
        );
        env.insert("REQUEST_METHOD".into(), req.request_method.clone());
        env.insert("QUERY_STRING".into(), req.query_string.clone());
        env.insert("SCRIPT_NAME".into(), req.script_name.clone());
        env.insert("PATH_INFO".into(), req.path_info.clone());
        env.insert("SERVER_NAME".into(), req.server_name.clone());
        env.insert("SERVER_PORT".into(), req.server_port.to_string());
        if let Some(addr) = req.remote_addr.as_ref() {
            env.insert("REMOTE_ADDR".into(), addr.clone());
        }
        if let Some(port) = req.remote_port {
            env.insert("REMOTE_PORT".into(), port.to_string());
        }

        if !req.content_type.is_empty() {
            env.insert("CONTENT_TYPE".into(), req.content_type.clone());
        }
        if let Some(content_length) = req.declared_content_length
            && content_length > 0
        {
            env.insert("CONTENT_LENGTH".into(), content_length.to_string());
        }

        // HTTP_* headers (RFC 3875 §4.1.18) with count limit.
        let connection_tokens = parse_connection_tokens(&req.http_headers);
        let mut header_count = 0;
        for (key, value) in &req.http_headers {
            if header_count >= MAX_HTTP_HEADERS {
                break;
            }
            // Skip hop-by-hop and sensitive headers.
            let lower = key.to_ascii_lowercase();
            if is_cgi_reserved_header(&lower)
                || is_hop_by_hop_header(&lower)
                || connection_tokens.contains(lower.as_str())
            {
                continue;
            }
            let env_key = format!("HTTP_{}", key.to_uppercase().replace('-', "_"));
            env.insert(env_key, value.clone());
            header_count += 1;
        }

        // Pass through allowed environment variables from the host.
        for var in &self.env_passthrough {
            if cgi_env_passthrough_is_reserved(var) {
                continue;
            }
            if let Ok(val) = std::env::var(var) {
                env.entry(var.clone()).or_insert(val);
            }
        }

        env
    }
}

fn parse_connection_tokens(headers: &HashMap<String, String>) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(value) = headers.get("connection") else {
        return out;
    };
    for token in value.split(',') {
        let token = token.trim();
        if !token.is_empty() {
            out.insert(token.to_ascii_lowercase());
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

pub(crate) fn cgi_env_passthrough_is_reserved(name: &str) -> bool {
    let upper = name.trim().to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "AUTH_TYPE"
            | "CONTENT_LENGTH"
            | "CONTENT_TYPE"
            | "GATEWAY_INTERFACE"
            | "PATH_INFO"
            | "PATH_TRANSLATED"
            | "QUERY_STRING"
            | "REMOTE_ADDR"
            | "REMOTE_HOST"
            | "REMOTE_IDENT"
            | "REMOTE_PORT"
            | "REMOTE_USER"
            | "REQUEST_METHOD"
            | "SCRIPT_NAME"
            | "SERVER_NAME"
            | "SERVER_PORT"
            | "SERVER_PROTOCOL"
            | "SERVER_SOFTWARE"
    ) || upper.starts_with("HTTP_")
}
