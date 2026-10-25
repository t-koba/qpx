use super::{
    CgiEnvironment, CgiRequest, is_cgi_reserved_header, is_hop_by_hop_header,
    parse_connection_tokens,
};
use std::collections::HashMap;

/// Maximum number of HTTP_* headers to pass through to CGI environment.
const MAX_HTTP_HEADERS: usize = 100;

impl CgiRequest {
    /// Project the request-derived process-CGI environment.
    /// qpxf's configured host passthrough remains in its trusted executor adapter.
    /// Identity precedes content and HTTP fields.
    pub fn cgi_environment(&self) -> CgiEnvironment {
        let req = self;
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
        for (name, value) in &req.identity_env {
            env.insert(name.clone(), value.clone());
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
        let connection_tokens = parse_connection_tokens(&req.http_headers.0);
        let mut header_count = 0;
        for (key, value) in &req.http_headers.0 {
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

        CgiEnvironment(env)
    }
}

/// Whether host passthrough would overwrite a CGI or identity variable.
pub fn cgi_env_passthrough_is_reserved(name: &str) -> bool {
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
