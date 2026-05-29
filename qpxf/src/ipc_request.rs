use anyhow::{Result, anyhow};
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

pub(crate) fn declared_content_length(headers: &[(String, String)]) -> Result<Option<usize>> {
    let mut parsed = None;
    for (_, value) in headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        for part in value.split(',') {
            let raw = part.trim();
            if raw.is_empty() || raw.starts_with('-') {
                return Err(anyhow!("invalid Content-Length value"));
            }
            let len = raw
                .parse::<u64>()
                .map_err(|_| anyhow!("invalid Content-Length value"))?;
            let len = usize::try_from(len).map_err(|_| anyhow!("Content-Length too large"))?;
            match parsed {
                Some(existing) if existing != len => {
                    return Err(anyhow!("conflicting Content-Length values"));
                }
                Some(_) => {}
                None => parsed = Some(len),
            }
        }
    }
    Ok(parsed)
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
    let request_path = uri.path().to_string();
    let query_string = uri.query().unwrap_or("").to_string();
    let header_host = meta
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str());
    let route_host = header_host
        .and_then(host_only)
        .or_else(|| uri.authority().and_then(|a| host_only(a.as_str())));

    let (executor, matched_prefix) =
        match router.route(request_path.as_str(), route_host.as_deref()) {
            Some(v) => v,
            None => return Ok(Err(IpcPlainResponse::new(404, b"no handler matched"))),
        };
    let (script_name, path_info) =
        split_script_name_path_info(request_path.as_str(), matched_prefix.as_deref());

    let header_host = header_host.or_else(|| uri.authority().map(|a| a.as_str()));
    let (server_name, server_port) = header_host
        .map(host_port)
        .unwrap_or((Some("localhost".to_string()), Some(80)));

    let declared_stdin_bytes = match declared_content_length(&meta.headers) {
        Ok(value) => value,
        Err(_) => return Ok(Err(IpcPlainResponse::new(400, b"invalid content-length"))),
    };
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
        path_info,
        query_string,
        request_method: meta.method,
        content_type,
        content_length: declared_stdin_bytes.unwrap_or(0),
        declared_content_length: declared_stdin_bytes,
        server_protocol: meta.server_protocol,
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

fn split_script_name_path_info(path: &str, matched_prefix: Option<&str>) -> (String, String) {
    let prefix = matched_prefix.unwrap_or("");
    if !prefix.is_empty() && prefix != "/" && !prefix.ends_with('/') {
        let normalized = prefix.trim_end_matches('/').to_string();
        if path == normalized {
            return (normalized, String::new());
        }
        if let Some(path_info) = path.strip_prefix(normalized.as_str())
            && path_info.starts_with('/')
        {
            return (normalized, path_info.to_string());
        }
    }

    let suffix = path.strip_prefix(prefix).unwrap_or(path);
    let suffix = suffix.strip_prefix('/').unwrap_or(suffix);
    if suffix.is_empty() {
        return (normalize_script_name(prefix, path), String::new());
    }
    let script_tail_end = suffix.find('/').unwrap_or(suffix.len());
    let script_tail = &suffix[..script_tail_end];
    let path_info = suffix[script_tail_end..].to_string();
    let script_name = if prefix.is_empty() || prefix == "/" {
        format!("/{script_tail}")
    } else {
        format!("{}/{}", prefix.trim_end_matches('/'), script_tail)
    };
    (script_name, path_info)
}

fn normalize_script_name(prefix: &str, fallback: &str) -> String {
    if prefix == "/" {
        "/".to_string()
    } else if prefix.is_empty() {
        if fallback.is_empty() {
            "/".to_string()
        } else {
            fallback.to_string()
        }
    } else {
        prefix.trim_end_matches('/').to_string()
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

#[cfg(test)]
mod tests {
    use super::{declared_content_length, split_script_name_path_info};

    #[test]
    fn declared_content_length_accepts_repeated_equal_values() {
        let headers = vec![
            ("Content-Length".to_string(), "5".to_string()),
            ("content-length".to_string(), "5, 5".to_string()),
        ];
        assert_eq!(declared_content_length(&headers).expect("length"), Some(5));
    }

    #[test]
    fn declared_content_length_rejects_conflicting_values() {
        let headers = vec![
            ("Content-Length".to_string(), "5".to_string()),
            ("content-length".to_string(), "6".to_string()),
        ];
        assert!(declared_content_length(&headers).is_err());
    }

    #[test]
    fn declared_content_length_rejects_invalid_values() {
        let headers = vec![("Content-Length".to_string(), "nope".to_string())];
        assert!(declared_content_length(&headers).is_err());
    }

    #[test]
    fn splits_script_name_and_path_info_after_matched_prefix() {
        let (script_name, path_info) =
            split_script_name_path_info("/cgi-bin/app/foo/bar", Some("/cgi-bin/"));
        assert_eq!(script_name, "/cgi-bin/app");
        assert_eq!(path_info, "/foo/bar");
    }

    #[test]
    fn treats_non_slash_terminated_prefix_as_script_name() {
        let (script_name, path_info) =
            split_script_name_path_info("/cgi-bin/nested/app/foo", Some("/cgi-bin/nested/app"));
        assert_eq!(script_name, "/cgi-bin/nested/app");
        assert_eq!(path_info, "/foo");
    }

    #[test]
    fn exact_non_slash_terminated_prefix_is_script_name() {
        let (script_name, path_info) =
            split_script_name_path_info("/cgi-bin/nested/app", Some("/cgi-bin/nested/app"));
        assert_eq!(script_name, "/cgi-bin/nested/app");
        assert_eq!(path_info, "");
    }

    #[test]
    fn splits_without_matched_prefix() {
        let (script_name, path_info) = split_script_name_path_info("/app/foo", None);
        assert_eq!(script_name, "/app");
        assert_eq!(path_info, "/foo");
    }
}
