use super::ClientConnInfo;
use crate::http::body::Body;
use hyper::Request;
use qpx_core::ipc::meta::IpcRequestMeta;
use std::collections::{HashMap, HashSet};

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

fn parse_connection_tokens(headers: &hyper::HeaderMap) -> HashSet<String> {
    let mut out = HashSet::new();
    for value in headers.get_all("connection") {
        let Ok(s) = value.to_str() else {
            continue;
        };
        for token in s.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                out.insert(token.to_ascii_lowercase());
            }
        }
    }
    out
}

pub(super) fn build_ipc_meta(req: &Request<Body>, conn: ClientConnInfo) -> IpcRequestMeta {
    let mut headers = Vec::new();
    let connection_tokens = parse_connection_tokens(req.headers());
    let mut has_host = false;
    for (name, value) in req.headers() {
        let name_str = name.as_str();
        if is_hop_by_hop_header(name_str) {
            continue;
        }
        if connection_tokens.contains(name_str) {
            continue;
        }
        if let Ok(val_str) = value.to_str() {
            if name_str.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            headers.push((name_str.to_string(), val_str.to_string()));
        }
    }
    // HTTP/2 and HTTP/3 requests carry the authority in the URI/metadata rather than a Host
    // header. CGI expects HTTP_HOST, so synthesize it when missing.
    if !has_host && let Some(authority) = req.uri().authority() {
        headers.push(("host".to_string(), authority.as_str().to_string()));
    }

    let mut params = HashMap::new();
    if let Some(remote) = conn.remote_addr {
        params.insert("REMOTE_ADDR".to_string(), remote.ip().to_string());
        params.insert("REMOTE_PORT".to_string(), remote.port().to_string());
    }

    IpcRequestMeta {
        method: req.method().as_str().to_string(),
        uri: req.uri().to_string(),
        server_protocol: crate::http::protocol::common::http_version_label(req.version())
            .to_string(),
        headers,
        params,
        req_body_shm_path: None,
        req_body_shm_size_bytes: None,
        res_body_shm_path: None,
        res_body_shm_size_bytes: None,
        shm_reusable: false,
    }
}
