use super::*;
use crate::config::CgiBackendConfig;
use std::collections::HashMap;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use tokio::io::AsyncReadExt;

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
    write_script(path, b"#!/bin/sh\n");
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
    write_script(&script, b"#!/bin/sh\nsleep 2 &\nexit 0\n");
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
    let body = format!(
        "#!/bin/sh\nparent=$$\n(\n\
         i=0\n\
         while kill -0 \"$parent\" 2>/dev/null; do\n\
           i=$((i + 1))\n\
           [ \"$i\" -lt 200 ] || exit 1\n\
           sleep 0.01\n\
         done\n\
         {output}\n\
         ) &\nexit 0\n"
    );
    write_script(&script, body.as_bytes());
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

// Writes a script through a short-lived helper process.
//
// The test process must never hold a writable descriptor for a script it is
// about to execute. A descriptor copied by a concurrent fork stays open for
// writing in that child, and the exec then fails with ETXTBSY. Writing the
// script from a helper process keeps the writable descriptor out of this
// process's descriptor table, so the window disappears instead of moving.
#[cfg(unix)]
fn write_script(path: &Path, contents: &[u8]) {
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg("cat > \"$1\"")
        .arg("qpxf-cgi-script-writer")
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn script writer");
    child
        .stdin
        .take()
        .expect("script writer stdin")
        .write_all(contents)
        .expect("write script");
    let status = child.wait().expect("wait for script writer");
    assert!(status.success(), "the script writer must succeed");
}

#[cfg(not(unix))]
fn write_script(path: &Path, contents: &[u8]) {
    std::fs::write(path, contents).expect("write script");
}

// A helper process that keeps the CGI script open for writing, so the script
// cannot be executed while the holder runs (ETXTBSY). The holder releases the
// script when the release marker appears and records that it did so.
#[cfg(target_os = "linux")]
struct BusyScriptHolder {
    _child: std::process::Child,
    ready_path: PathBuf,
    release_path: PathBuf,
    released_path: PathBuf,
}

#[cfg(target_os = "linux")]
impl BusyScriptHolder {
    fn start(script: &Path, root: &Path) -> Self {
        let ready_path = root.join("holder.ready");
        let release_path = root.join("holder.release");
        let released_path = root.join("holder.released");
        let child = std::process::Command::new("sh")
            .arg("-c")
            .arg(
                "exec 9>>\"$1\"\n\
                 : > \"$2\"\n\
                 while [ ! -e \"$3\" ]; do sleep 0.002; done\n\
                 exec 9>&-\n\
                 : > \"$4\"\n",
            )
            .arg("qpxf-cgi-busy-holder")
            .arg(script)
            .arg(&ready_path)
            .arg(&release_path)
            .arg(&released_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn script busy holder");
        let holder = Self {
            _child: child,
            ready_path,
            release_path,
            released_path,
        };
        holder.wait_until_ready();
        holder
    }

    fn wait_for(&self, path: &Path, what: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the script busy holder did not {what}"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn wait_until_ready(&self) {
        self.wait_for(&self.ready_path, "take the script");
    }

    fn wait_until_released(&self) {
        self.wait_for(&self.released_path, "release the script");
    }

    fn release(&self) {
        std::fs::write(&self.release_path, b"release").expect("write release marker");
    }
}

// The ETXTBSY-on-exec behavior the two tests below observe is Linux's. The
// product executes the script itself, through /proc/self/fd/N, so the kernel
// refuses the exec while another process holds the script open for writing.
// macOS hands the script to the interpreter through a descriptor instead of
// executing it, so the kernel never reports ETXTBSY for it.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn etxtbsy_spawn_is_retried_until_the_script_is_released() {
    let root = temp_cgi_root();
    let executor = test_executor(&root);
    // The script path must be the canonical one: the executor validates the
    // script's parent against its canonical root.
    let script = executor.canonical_root.join("app");
    create_script(&script);
    write_script(&script, b"#!/bin/sh\nprintf busy-ok\n");

    let holder = BusyScriptHolder::start(&script, &root);

    let req = test_request("/app", "", None);
    let env = executor.build_env(&req);
    let prepared =
        prepare_cgi_script_for_spawn(&executor.canonical_root, &script).expect("prepare script");

    // The first attempt fails with ETXTBSY because the holder has the script
    // open for writing. The attempt releases the holder and waits until the
    // descriptor is closed, so the retry succeeds without depending on timing.
    let mut attempts = 0usize;
    let mut child = spawn_cgi_child(
        || {
            attempts += 1;
            let result = spawn_prepared_cgi_child(&prepared, &env);
            if result.is_err() {
                holder.release();
                holder.wait_until_released();
            }
            result
        },
        ETXTBSY_MAX_ATTEMPTS,
        ETXTBSY_RETRY_DELAY,
        executor.timeout,
    )
    .await
    .expect("the spawn must succeed after the ETXTBSY retry");
    assert_eq!(
        attempts, 2,
        "the first attempt must fail and the retry must succeed"
    );

    let mut output = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        let mut chunk = [0u8; 64];
        loop {
            let read = stdout.read(&mut chunk).await.expect("read CGI stdout");
            if read == 0 {
                break;
            }
            output.extend_from_slice(&chunk[..read]);
        }
    }
    let status = child.wait().await.expect("wait for the CGI child");
    assert!(status.success(), "the CGI script must succeed");
    assert_eq!(String::from_utf8_lossy(&output), "busy-ok");
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_persistent_etxtbsy_fails_with_the_spawn_error_after_the_retry_budget() {
    let root = temp_cgi_root();
    let script = root.join("app");
    create_script(&script);
    write_script(&script, b"#!/bin/sh\nprintf busy-ok\n");

    let holder = BusyScriptHolder::start(&script, &root);

    let executor = test_executor(&root);
    let started = executor.start(test_request("/app", "", None)).await;
    holder.release();
    holder.wait_until_released();

    let err = started
        .err()
        .expect("a persistent ETXTBSY must not be retried forever");
    let message = err.to_string();
    assert!(
        message.starts_with("failed to spawn CGI script:"),
        "{message}"
    );
    assert!(
        message.contains(&format!("os error {}", libc::ETXTBSY)),
        "{message}"
    );
    let _ = std::fs::remove_dir_all(root);
}

// The spawn failure a caller sees does not depend on the platform's exec
// behavior: a script whose interpreter does not exist fails to spawn with
// the same error everywhere. The kernel resolves the shebang on Linux, and
// the executor reads the shebang itself on macOS.
#[cfg(unix)]
#[tokio::test]
async fn a_missing_interpreter_fails_the_spawn_with_the_script_spawn_error() {
    let root = temp_cgi_root();
    let script = root.join("app");
    create_script(&script);
    write_script(&script, b"#!/nonexistent/qpxf-missing-interpreter\n");

    let executor = test_executor(&root);
    let err = executor
        .start(test_request("/app", "", None))
        .await
        .err()
        .expect("a missing interpreter must fail the spawn");
    let message = err.to_string();
    assert!(
        message.starts_with("failed to spawn CGI script:"),
        "{message}"
    );
    assert!(
        message.contains(&format!("os error {}", libc::ENOENT)),
        "{message}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[tokio::test]
async fn a_non_etxtbsy_spawn_error_is_not_retried() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    let result = spawn_cgi_child(
        || {
            counter.fetch_add(1, Ordering::SeqCst);
            Err::<tokio::process::Child, std::io::Error>(std::io::Error::from_raw_os_error(
                libc::ENOENT,
            ))
        },
        ETXTBSY_MAX_ATTEMPTS,
        ETXTBSY_RETRY_DELAY,
        Duration::from_secs(1),
    )
    .await;

    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        result
            .expect_err("the spawn error must surface")
            .raw_os_error(),
        Some(libc::ENOENT)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_persistent_etxtbsy_is_retried_only_within_the_attempt_budget() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    let started = std::time::Instant::now();
    let result = spawn_cgi_child(
        || {
            counter.fetch_add(1, Ordering::SeqCst);
            Err::<tokio::process::Child, std::io::Error>(std::io::Error::from_raw_os_error(
                libc::ETXTBSY,
            ))
        },
        ETXTBSY_MAX_ATTEMPTS,
        ETXTBSY_RETRY_DELAY,
        Duration::from_secs(1),
    )
    .await;

    assert_eq!(attempts.load(Ordering::SeqCst), ETXTBSY_MAX_ATTEMPTS);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        result
            .expect_err("the spawn error must surface")
            .raw_os_error(),
        Some(libc::ETXTBSY)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn the_script_fixture_never_holds_the_script_open_in_this_process() {
    let root = temp_cgi_root();
    let script = root.join("app");
    if let Some(parent) = script.parent() {
        std::fs::create_dir_all(parent).expect("create script parent");
        set_secure_dir(parent);
    }

    // A script that is open for writing in this process can be inherited by a
    // child forked while the write is in flight, and the exec of that script
    // then fails with ETXTBSY. The fixture writes the script from a helper
    // process instead, so this process never holds the script open. The body
    // is made large so that a watcher sampling the descriptor table during the
    // write reliably observes an in-process write.
    let body = format!("#!/bin/sh\n{}", "# padding\n".repeat(400_000));
    let observed = Arc::new(AtomicUsize::new(0));
    let counter = observed.clone();
    let watched = script.clone();
    let stop = Arc::new(AtomicUsize::new(0));
    let stop_flag = stop.clone();
    let watcher = std::thread::spawn(move || {
        while stop_flag.load(Ordering::SeqCst) == 0 {
            if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let Ok(target) =
                        std::fs::read_link(format!("/proc/self/fd/{}", name.to_string_lossy()))
                    else {
                        continue;
                    };
                    if target == watched {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
    });

    write_script(&script, body.as_bytes());
    stop.store(1, Ordering::SeqCst);
    watcher.join().expect("join descriptor watcher");

    assert_eq!(
        observed.load(Ordering::SeqCst),
        0,
        "the fixture must not open the script for writing in this process"
    );
    let _ = std::fs::remove_dir_all(root);
}
