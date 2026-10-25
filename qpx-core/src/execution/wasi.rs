use super::{WasiEnvironment, WasmRequest, is_hop_by_hop_header, parse_connection_tokens};
use std::collections::HashMap;

impl WasmRequest {
    /// Project the complete WASI environment, preserving order and duplicate variables.
    /// Unlike process CGI, HTTP_CONTENT_LENGTH/TYPE are retained and fields are uncapped.
    pub fn wasi_environment(&self, extra_env: &HashMap<String, String>) -> WasiEnvironment {
        let req = self;
        let mut builder = WasiEnvironment(Vec::new());
        builder.env("GATEWAY_INTERFACE", "CGI/1.1");
        builder.env("SERVER_PROTOCOL", &req.server_protocol);
        builder.env(
            "SERVER_SOFTWARE",
            concat!("qpxf/", env!("CARGO_PKG_VERSION")),
        );
        builder.env("REQUEST_METHOD", &req.request_method);
        builder.env("QUERY_STRING", &req.query_string);
        builder.env("SCRIPT_NAME", &req.script_name);
        builder.env("PATH_INFO", &req.path_info);
        builder.env("SERVER_NAME", &req.server_name);
        builder.env("SERVER_PORT", req.server_port.to_string());
        if let Some(addr) = req.remote_addr.as_ref() {
            builder.env("REMOTE_ADDR", addr);
        }
        if let Some(port) = req.remote_port {
            builder.env("REMOTE_PORT", port.to_string());
        }
        if !req.content_type.is_empty() {
            builder.env("CONTENT_TYPE", &req.content_type);
        }
        if req.content_length > 0 {
            builder.env("CONTENT_LENGTH", req.content_length.to_string());
        }
        for (key, value) in &req.identity_env {
            builder.env(key, value);
        }
        let connection_tokens = parse_connection_tokens(&req.http_headers.0);
        for (key, value) in &req.http_headers.0 {
            let lower = key.to_ascii_lowercase();
            if is_hop_by_hop_header(&lower) || connection_tokens.contains(lower.as_str()) {
                continue;
            }
            let env_key = format!("HTTP_{}", key.to_uppercase().replace('-', "_"));
            builder.env(&env_key, value);
        }
        for (key, value) in extra_env {
            if wasm_extra_env_is_reserved(key) {
                continue;
            }
            builder.env(key, value);
        }
        builder
    }
}

fn wasm_extra_env_is_reserved(name: &str) -> bool {
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

impl WasiEnvironment {
    fn env(&mut self, name: impl AsRef<str>, value: impl AsRef<str>) {
        self.0
            .push((name.as_ref().to_owned(), value.as_ref().to_owned()));
    }
}
