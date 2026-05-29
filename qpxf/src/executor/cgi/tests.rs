use super::*;
use crate::config::CgiBackendConfig;
use std::collections::HashMap;

#[test]
fn resolve_script_uses_longest_existing_script_under_prefix() {
    let root = temp_cgi_root();
    create_script(&root.join("nested").join("app"));
    let executor = test_executor(&root);
    let req = test_request("/cgi-bin/nested", "/app/foo", Some("/cgi-bin"));

    let resolved = executor.resolve_script(&req).expect("resolve script");

    assert_eq!(
        resolved.path,
        root.join("nested").join("app").canonicalize().unwrap()
    );
    assert_eq!(resolved.script_name, "/cgi-bin/nested/app");
    assert_eq!(resolved.path_info, "/foo");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn resolve_script_allows_route_prefix_to_identify_script() {
    let root = temp_cgi_root();
    create_script(&root.join("app"));
    let executor = test_executor(&root);
    let req = test_request("/cgi-bin/app/foo", "", Some("/cgi-bin/app"));

    let resolved = executor.resolve_script(&req).expect("resolve script");

    assert_eq!(resolved.path, root.join("app").canonicalize().unwrap());
    assert_eq!(resolved.script_name, "/cgi-bin/app");
    assert_eq!(resolved.path_info, "/foo");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn build_env_does_not_duplicate_content_headers_as_http_vars() {
    let root = temp_cgi_root();
    let executor = test_executor(&root);
    let mut req = test_request("/cgi-bin/app", "", None);
    req.content_type = "text/plain".to_string();
    req.content_length = 5;
    req.declared_content_length = Some(5);
    req.http_headers.insert(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    );
    req.http_headers
        .insert("content-length".to_string(), "99".to_string());

    let env = executor.build_env(&req);

    assert_eq!(
        env.get("CONTENT_TYPE").map(String::as_str),
        Some("text/plain")
    );
    assert_eq!(env.get("CONTENT_LENGTH").map(String::as_str), Some("5"));
    assert!(!env.contains_key("HTTP_CONTENT_TYPE"));
    assert!(!env.contains_key("HTTP_CONTENT_LENGTH"));
    let _ = std::fs::remove_dir_all(root);
}

fn test_executor(root: &Path) -> CgiExecutor {
    CgiExecutor::new(&CgiBackendConfig {
        root: root.to_path_buf(),
        timeout_ms: 1000,
        env_passthrough: Vec::new(),
        max_stdout_bytes: 1024,
        max_stderr_bytes: 1024,
    })
    .expect("cgi executor")
}

fn test_request(script_name: &str, path_info: &str, matched_prefix: Option<&str>) -> CgiRequest {
    CgiRequest {
        script_name: script_name.to_string(),
        path_info: path_info.to_string(),
        query_string: String::new(),
        request_method: "GET".to_string(),
        content_type: String::new(),
        content_length: 0,
        declared_content_length: Some(0),
        server_protocol: "HTTP/1.1".to_string(),
        server_name: "localhost".to_string(),
        server_port: 80,
        remote_addr: None,
        remote_port: None,
        http_headers: HashMap::new(),
        matched_prefix: matched_prefix.map(str::to_string),
    }
}

fn create_script(path: &Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create script parent");
        set_secure_dir(parent);
    }
    std::fs::write(path, b"#!/bin/sh\n").expect("write script");
    set_secure_file(path);
}

fn temp_cgi_root() -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("qpxf-cgi-resolve-{ts}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&root).expect("create root");
    set_secure_dir(&root);
    root
}

#[cfg(unix)]
fn set_secure_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("chmod dir");
}

#[cfg(not(unix))]
fn set_secure_dir(_path: &Path) {}

#[cfg(unix)]
fn set_secure_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod file");
}

#[cfg(not(unix))]
fn set_secure_file(_path: &Path) {}
