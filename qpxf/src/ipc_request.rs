use anyhow::{anyhow, Result};
use http::Uri;
use std::collections::HashMap;
use std::sync::Arc;

use crate::executor::{CgiRequest, Executor};
use crate::router::Router;
use qpx_core::ipc::meta::{IpcRequestMeta, IpcResponseMeta};

pub(crate) struct IpcPlainResponse {
    pub(crate) status: u16,
    pub(crate) body: &'static [u8],
}

impl IpcPlainResponse {
    pub(crate) const fn new(status: u16, body: &'static [u8]) -> Self {
        Self { status, body }
    }

    pub(crate) fn meta(&self) -> IpcResponseMeta {
        plaintext_meta(self.status)
    }
}

pub(crate) struct IpcRequestPlan {
    pub(crate) executor: Arc<dyn Executor>,
    pub(crate) cgi_req: CgiRequest,
    pub(crate) expected_stdin_bytes: Option<usize>,
}

pub(crate) fn plaintext_meta(status: u16) -> IpcResponseMeta {
    IpcResponseMeta {
        status,
        headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
    }
}

pub(crate) fn declared_content_length(headers: &[(String, String)]) -> Option<usize> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
}

pub(crate) fn meta_params_bytes(meta: &IpcRequestMeta) -> usize {
    meta.params
        .iter()
        .map(|(k, v)| k.len().saturating_add(v.len()))
        .sum()
}

pub(crate) fn plan_ipc_request(
    meta: IpcRequestMeta,
    router: &Router,
    max_params_bytes: usize,
    max_stdin_bytes: usize,
) -> Result<std::result::Result<IpcRequestPlan, IpcPlainResponse>> {
    if meta_params_bytes(&meta) > max_params_bytes {
        return Ok(Err(IpcPlainResponse::new(413, b"params too large")));
    }

    let uri: Uri = meta
        .uri
        .parse()
        .map_err(|e| anyhow!("invalid IPC request URI '{}': {e}", meta.uri))?;
    let script_name = uri.path().to_string();
    let query_string = uri.query().unwrap_or("").to_string();
    let header_host = meta
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str());
    let route_host = header_host
        .and_then(host_only)
        .or_else(|| uri.authority().and_then(|a| host_only(a.as_str())));

    let (executor, matched_prefix) = match router.route(script_name.as_str(), route_host.as_deref())
    {
        Some(v) => v,
        None => return Ok(Err(IpcPlainResponse::new(404, b"no handler matched"))),
    };

    let header_host = header_host.or_else(|| uri.authority().map(|a| a.as_str()));
    let (server_name, server_port) = header_host
        .map(host_port)
        .unwrap_or((Some("localhost".to_string()), Some(80)));

    let declared_stdin_bytes = declared_content_length(&meta.headers);
    let content_type = meta
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let remote_addr = meta.params.get("REMOTE_ADDR").cloned();
    let remote_port = meta.params.get("REMOTE_PORT").and_then(|p| p.parse().ok());
    let cgi_req = CgiRequest {
        script_name,
        path_info: String::new(),
        query_string,
        request_method: meta.method,
        content_type,
        content_length: declared_stdin_bytes.unwrap_or(0),
        server_protocol: "HTTP/1.1".to_string(),
        server_name: server_name.unwrap_or_else(|| "localhost".to_string()),
        server_port: server_port.unwrap_or(80),
        remote_addr,
        remote_port,
        http_headers: cgi_header_map(meta.headers),
        matched_prefix,
    };

    if cgi_req.content_length > max_stdin_bytes {
        return Ok(Err(IpcPlainResponse::new(413, b"request body too large")));
    }

    Ok(Ok(IpcRequestPlan {
        executor,
        cgi_req,
        expected_stdin_bytes: declared_stdin_bytes,
    }))
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

fn cgi_header_map(headers: Vec<(String, String)>) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    for (k, v) in headers {
        let key = k.to_ascii_lowercase();
        if let Some(existing) = out.get_mut(&key) {
            let sep = if key == "cookie" { "; " } else { ", " };
            existing.push_str(sep);
            existing.push_str(&v);
        } else {
            out.insert(key, v);
        }
    }
    out
}
