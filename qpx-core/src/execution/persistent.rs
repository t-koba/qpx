use super::{
    CgiRequest, PersistentEnvironment, is_cgi_reserved_header, is_hop_by_hop_header,
    parse_connection_tokens,
};

impl CgiRequest {
    /// Project the complete FastCGI/SCGI gateway environment for the supplied body length.
    /// Retains duplicate environment keys and truncates source fields before filtering.
    pub fn persistent_environment(&self, body_len: Option<usize>) -> PersistentEnvironment {
        let req = self;
        let mut env = Vec::new();
        push_env(&mut env, "GATEWAY_INTERFACE", "CGI/1.1".to_string());
        push_env(&mut env, "SERVER_PROTOCOL", req.server_protocol.clone());
        push_env(
            &mut env,
            "SERVER_SOFTWARE",
            concat!("qpxf/", env!("CARGO_PKG_VERSION")).to_string(),
        );
        push_env(&mut env, "REQUEST_METHOD", req.request_method.clone());
        push_env(&mut env, "QUERY_STRING", req.query_string.clone());
        push_env(&mut env, "SCRIPT_NAME", req.script_name.clone());
        push_env(&mut env, "PATH_INFO", req.path_info.clone());
        push_env(&mut env, "SERVER_NAME", req.server_name.clone());
        push_env(&mut env, "SERVER_PORT", req.server_port.to_string());
        if let Some(body_len) = body_len {
            push_env(&mut env, "CONTENT_LENGTH", body_len.to_string());
        }
        if !req.content_type.is_empty() {
            push_env(&mut env, "CONTENT_TYPE", req.content_type.clone());
        }
        if let Some(addr) = req.remote_addr.as_ref() {
            push_env(&mut env, "REMOTE_ADDR", addr.clone());
        }
        if let Some(port) = req.remote_port {
            push_env(&mut env, "REMOTE_PORT", port.to_string());
        }
        for (name, value) in &req.identity_env {
            push_env(&mut env, name.clone(), value.clone());
        }

        let connection_tokens = parse_connection_tokens(&req.http_headers.0);
        for (key, value) in req.http_headers.0.iter().take(100) {
            let lower = key.to_ascii_lowercase();
            if is_cgi_reserved_header(&lower)
                || is_hop_by_hop_header(&lower)
                || connection_tokens.contains(lower.as_str())
            {
                continue;
            }
            push_env(
                &mut env,
                format!("HTTP_{}", key.to_uppercase().replace('-', "_")),
                value.clone(),
            );
        }
        PersistentEnvironment(env)
    }
}

fn push_env(env: &mut Vec<(String, String)>, name: impl Into<String>, value: String) {
    env.push((name.into(), value));
}
