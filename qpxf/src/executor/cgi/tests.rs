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
        identity_env: HashMap::new(),
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

#[cfg(unix)]
#[tokio::test]
async fn timeout_remains_effective_while_inherited_output_pipes_drain() {
    let root = temp_cgi_root();
    let script = root.join("app");
    create_script(&script);
    std::fs::write(&script, b"#!/bin/sh\nsleep 2 &\nexit 0\n").unwrap();
    let mut executor = test_executor(&root);
    executor.timeout = Duration::from_millis(40);
    let mut execution = executor
        .start(test_request("/app", "", None))
        .await
        .expect("start CGI");

    let result = timeout(Duration::from_millis(500), execution.done).await;
    let _ = std::fs::remove_dir_all(root);
    let err = result
        .expect("configured timeout must cover inherited output pipes")
        .expect("execution task")
        .expect_err("CGI must time out");
    assert!(
        err.to_string().contains("CGI timed out after 40ms"),
        "{err}"
    );
    assert_eq!(
        execution.stdout.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    );
    assert_eq!(
        execution.stderr.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    );
}

// Only emit output once the direct child has been reaped. This synchronizes the
// tests with the drain phase rather than assuming a sleep lets child.wait finish.
#[cfg(unix)]
fn create_drain_script(root: &Path, output: &str) {
    let script = root.join("app");
    create_script(&script);
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nparent=$$\n(\n\
             i=0\n\
             while kill -0 \"$parent\" 2>/dev/null; do\n\
               i=$((i + 1))\n\
               [ \"$i\" -lt 200 ] || exit 1\n\
               sleep 0.01\n\
             done\n\
             {output}\n\
             ) &\nexit 0\n"
        ),
    )
    .expect("write drain script");
}

#[cfg(unix)]
#[tokio::test]
async fn abort_remains_effective_while_inherited_output_pipes_drain() {
    let root = temp_cgi_root();
    create_drain_script(&root, "printf draining; sleep 2");
    let mut executor = test_executor(&root);
    executor.timeout = Duration::from_secs(5);
    let mut execution = executor
        .start(test_request("/app", "", None))
        .await
        .expect("start CGI");
    let ready = timeout(Duration::from_secs(1), execution.stdout.recv())
        .await
        .expect("descendant must observe direct child exit")
        .expect("drain marker");
    assert_eq!(ready, Bytes::from_static(b"draining"));
    execution.abort.send(()).expect("send abort during drain");

    let result = timeout(Duration::from_millis(500), execution.done).await;
    let _ = std::fs::remove_dir_all(root);
    let err = result
        .expect("abort must interrupt inherited output drain")
        .expect("execution task")
        .expect_err("CGI must abort");
    assert_eq!(err.to_string(), "CGI request aborted");
    assert_eq!(
        execution.stdout.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    );
    assert_eq!(
        execution.stderr.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn output_pump_errors_after_child_exit_are_propagated() {
    for (stream, redirect) in [("stdout", ""), ("stderr", ">&2")] {
        let root = temp_cgi_root();
        create_drain_script(&root, &format!("printf 123456789 {redirect}"));
        let mut executor = test_executor(&root);
        executor.max_stdout_bytes = 8;
        executor.max_stderr_bytes = 8;
        let execution = executor
            .start(test_request("/app", "", None))
            .await
            .expect("start CGI");

        let result = timeout(Duration::from_millis(500), execution.done).await;
        let _ = std::fs::remove_dir_all(root);
        let err = result
            .expect("output pump failure must end execution")
            .expect("execution task")
            .expect_err("output limit failure must not be lost after child exit");
        assert_eq!(err.to_string(), format!("cgi {stream} exceeded size limit"));
    }
}
