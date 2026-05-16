use super::{CgiRequest, CgiResponse, Execution, Executor};
use crate::config::CgiBackendConfig;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use bytes::BytesMut;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, timeout};
use tracing::warn;

/// Maximum number of HTTP_* headers to pass through to CGI environment.
const MAX_HTTP_HEADERS: usize = 100;

pub struct CgiExecutor {
    root: PathBuf,
    /// Canonicalized root path for containment checks.
    canonical_root: PathBuf,
    timeout: Duration,
    env_passthrough: Vec<String>,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

struct ResolvedCgiScript {
    path: PathBuf,
    script_name: String,
    path_info: String,
}

struct PreparedCgiScript {
    command_path: PathBuf,
    label_path: PathBuf,
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "dragonfly"
    ))]
    _file: std::fs::File,
}

impl PreparedCgiScript {
    fn command_path(&self) -> &Path {
        &self.command_path
    }

    fn label_path(&self) -> &Path {
        &self.label_path
    }
}

impl CgiExecutor {
    pub fn new(config: &CgiBackendConfig) -> Result<Self> {
        let canonical_root = config.root.canonicalize().map_err(|e| {
            anyhow!(
                "failed to canonicalize CGI root '{}': {}",
                config.root.display(),
                e
            )
        })?;
        validate_secure_cgi_root(&canonical_root)?;

        Ok(Self {
            root: config.root.clone(),
            canonical_root,
            timeout: Duration::from_millis(config.timeout_ms),
            env_passthrough: config.env_passthrough.clone(),
            max_stdout_bytes: config.max_stdout_bytes,
            max_stderr_bytes: config.max_stderr_bytes,
        })
    }

    fn build_env(&self, req: &CgiRequest) -> HashMap<String, String> {
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
        if req.content_length > 0 {
            env.insert("CONTENT_LENGTH".into(), req.content_length.to_string());
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
            if is_hop_by_hop_header(&lower) || connection_tokens.contains(lower.as_str()) {
                continue;
            }
            let env_key = format!("HTTP_{}", key.to_uppercase().replace('-', "_"));
            env.insert(env_key, value.clone());
            header_count += 1;
        }

        // Pass through allowed environment variables from the host.
        for var in &self.env_passthrough {
            if let Ok(val) = std::env::var(var) {
                env.insert(var.clone(), val);
            }
        }

        env
    }

    fn resolve_script(&self, req: &CgiRequest) -> Result<ResolvedCgiScript> {
        let request_path = format!("{}{}", req.script_name, req.path_info);
        let matched_prefix = req.matched_prefix.as_deref().unwrap_or("");
        let suffix = request_path
            .strip_prefix(matched_prefix)
            .unwrap_or(request_path.as_str())
            .trim_start_matches('/');

        let mut candidates = Vec::new();
        candidates.push(ScriptSearchCandidate {
            url_prefix: matched_prefix.to_string(),
            relative_path: suffix.to_string(),
        });

        if let Some((prefix_parent, prefix_tail)) = split_url_parent_tail(matched_prefix) {
            let relative_path = if suffix.is_empty() {
                prefix_tail.to_string()
            } else {
                format!("{prefix_tail}/{suffix}")
            };
            candidates.push(ScriptSearchCandidate {
                url_prefix: prefix_parent.to_string(),
                relative_path,
            });
        }

        let fallback = request_path.trim_start_matches('/');
        if !fallback.is_empty() {
            candidates.push(ScriptSearchCandidate {
                url_prefix: String::new(),
                relative_path: fallback.to_string(),
            });
        }

        let mut last_err = None;
        for candidate in dedupe_script_candidates(candidates) {
            match self.resolve_script_candidate(&candidate) {
                Ok(resolved) => return Ok(resolved),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("script not found")))
    }

    fn resolve_script_candidate(
        &self,
        candidate: &ScriptSearchCandidate,
    ) -> Result<ResolvedCgiScript> {
        let segments = clean_relative_segments(candidate.relative_path.as_str())?;
        for script_len in (1..=segments.len()).rev() {
            let script_relative = segments[..script_len].join("/");
            let script_path = self.root.join(&script_relative);
            let Ok(canonical) = script_path.canonicalize() else {
                continue;
            };
            if !canonical.starts_with(&self.canonical_root) {
                return Err(anyhow!(
                    "script path escapes CGI root: {} is not under {}",
                    canonical.display(),
                    self.canonical_root.display()
                ));
            }
            if let Err(err) = validate_secure_cgi_script(&self.canonical_root, &canonical) {
                last_existing_script_error(&script_path, err)?;
            }
            let script_name = join_url_path(candidate.url_prefix.as_str(), &script_relative);
            let path_info = if script_len < segments.len() {
                format!("/{}", segments[script_len..].join("/"))
            } else {
                String::new()
            };
            return Ok(ResolvedCgiScript {
                path: canonical,
                script_name,
                path_info,
            });
        }
        Err(anyhow!(
            "script not found under CGI root for path '{}'",
            candidate.relative_path
        ))
    }
}

struct ScriptSearchCandidate {
    url_prefix: String,
    relative_path: String,
}

fn last_existing_script_error<T>(path: &Path, err: anyhow::Error) -> Result<T> {
    Err(anyhow!(
        "candidate CGI script is not secure: {}: {err}",
        path.display()
    ))
}

fn clean_relative_segments(relative: &str) -> Result<Vec<&str>> {
    let mut segments = Vec::new();
    for segment in relative.split('/') {
        if segment.is_empty() {
            continue;
        }
        if segment == "." || segment == ".." {
            return Err(anyhow!("path traversal detected in script path"));
        }
        segments.push(segment);
    }
    if segments.is_empty() {
        return Err(anyhow!("empty script path"));
    }
    Ok(segments)
}

fn split_url_parent_tail(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        return None;
    }
    let (parent, tail) = trimmed.rsplit_once('/').unwrap_or(("", trimmed));
    if tail.is_empty() {
        None
    } else {
        Some((parent, tail))
    }
}

fn join_url_path(prefix: &str, relative: &str) -> String {
    let relative = relative.trim_matches('/');
    if prefix.is_empty() || prefix == "/" {
        format!("/{relative}")
    } else if relative.is_empty() {
        prefix.to_string()
    } else {
        format!("{}/{}", prefix.trim_end_matches('/'), relative)
    }
}

fn dedupe_script_candidates(candidates: Vec<ScriptSearchCandidate>) -> Vec<ScriptSearchCandidate> {
    let mut out = Vec::new();
    for candidate in candidates {
        if candidate.relative_path.trim_matches('/').is_empty() {
            continue;
        }
        if out.iter().any(|existing: &ScriptSearchCandidate| {
            existing.url_prefix == candidate.url_prefix
                && existing.relative_path == candidate.relative_path
        }) {
            continue;
        }
        out.push(candidate);
    }
    out
}

#[cfg(unix)]
fn validate_secure_cgi_root(root: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(root)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(anyhow!(
            "CGI root is not a secure directory: {}",
            root.display()
        ));
    }
    reject_untrusted_cgi_path(root, &meta, "CGI root")
}

#[cfg(not(unix))]
fn validate_secure_cgi_root(_root: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_secure_cgi_script(root: &Path, script: &Path) -> Result<()> {
    validate_secure_cgi_root(root)?;
    let parent = script
        .parent()
        .ok_or_else(|| anyhow!("CGI script has no parent: {}", script.display()))?;
    let relative_parent = parent.strip_prefix(root).map_err(|_| {
        anyhow!(
            "CGI script parent escapes root: {} is not under {}",
            parent.display(),
            root.display()
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative_parent.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(anyhow!(
                "CGI script parent contains unsupported path component: {}",
                parent.display()
            ));
        };
        current.push(name);
        let meta = std::fs::symlink_metadata(&current)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(anyhow!(
                "CGI script parent component is not a secure directory: {}",
                current.display()
            ));
        }
        reject_untrusted_cgi_path(&current, &meta, "CGI script parent")?;
    }

    let meta = std::fs::symlink_metadata(script)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(anyhow!(
            "CGI script is not a regular file: {}",
            script.display()
        ));
    }
    reject_untrusted_cgi_path(script, &meta, "CGI script")
}

#[cfg(not(unix))]
fn validate_secure_cgi_script(_root: &Path, _script: &Path) -> Result<()> {
    Ok(())
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "dragonfly"
))]
fn prepare_cgi_script_for_spawn(root: &Path, script: &Path) -> Result<PreparedCgiScript> {
    use std::os::fd::AsRawFd;

    validate_secure_cgi_script(root, script)?;
    let file = open_cgi_script_fd(script)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(anyhow!(
            "CGI script fd is not a regular file: {}",
            script.display()
        ));
    }
    reject_untrusted_cgi_path(script, &meta, "CGI script fd")?;
    clear_close_on_exec(file.as_raw_fd())?;
    let fd_path = cgi_fd_exec_path(file.as_raw_fd());
    if !fd_path.exists() {
        return Err(anyhow!(
            "CGI fd execution path is unavailable: {}",
            fd_path.display()
        ));
    }
    Ok(PreparedCgiScript {
        command_path: fd_path,
        label_path: script.to_path_buf(),
        _file: file,
    })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "dragonfly"
)))]
fn prepare_cgi_script_for_spawn(root: &Path, script: &Path) -> Result<PreparedCgiScript> {
    validate_secure_cgi_script(root, script)?;
    Ok(PreparedCgiScript {
        command_path: script.to_path_buf(),
        label_path: script.to_path_buf(),
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn cgi_fd_exec_path(fd: std::os::fd::RawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{fd}"))
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
fn cgi_fd_exec_path(fd: std::os::fd::RawFd) -> PathBuf {
    PathBuf::from(format!("/dev/fd/{fd}"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_cgi_script_fd(script: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(script)
        .map_err(|err| anyhow!("failed to open CGI script '{}': {err}", script.display()))
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
fn open_cgi_script_fd(script: &Path) -> Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(script.as_os_str().as_bytes())
        .map_err(|_| anyhow!("CGI script path contains NUL byte: {}", script.display()))?;
    // SAFETY: c_path is a valid NUL-terminated path. open returns either a valid owned fd
    // or -1 with errno set; File::from_raw_fd takes ownership only after success.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_EXEC | libc::O_NOFOLLOW) };
    if fd < 0 {
        return Err(anyhow!(
            "failed to open CGI script '{}': {}",
            script.display(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fd was returned by open above and is uniquely owned here.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "dragonfly"
))]
fn clear_close_on_exec(fd: std::os::fd::RawFd) -> Result<()> {
    // SAFETY: fcntl with F_GETFD only reads descriptor flags for a valid fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).map_err(Into::into);
    }
    // SAFETY: fcntl with F_SETFD updates descriptor flags for the same valid fd.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).map_err(Into::into);
    }
    Ok(())
}

#[cfg(unix)]
fn reject_untrusted_cgi_path(path: &Path, meta: &std::fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid has no preconditions and only reads the current process credentials.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing {label} not owned by root or current user: {}",
            path.display()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(anyhow!(
            "refusing group/world-writable {label}: {}",
            path.display()
        ));
    }
    Ok(())
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

#[async_trait]
impl Executor for CgiExecutor {
    async fn start(&self, req: CgiRequest) -> Result<Execution> {
        fn immediate(output: Bytes) -> Execution {
            let (stdin_tx, _stdin_rx) = mpsc::channel::<Bytes>(1);
            let (stdout_tx, stdout_rx) = mpsc::channel::<Bytes>(1);
            let (_stderr_tx, stderr_rx) = mpsc::channel::<Bytes>(1);
            let (abort_tx, _abort_rx) = oneshot::channel::<()>();
            let done = tokio::spawn(async move {
                let _ = stdout_tx.send(output).await;
                Ok(())
            });
            Execution {
                stdin: stdin_tx,
                stdout: stdout_rx,
                stderr: stderr_rx,
                abort: abort_tx,
                done,
            }
        }

        let mut req = req;
        let script_path = match self.resolve_script(&req) {
            Ok(resolved) => {
                req.script_name = resolved.script_name;
                req.path_info = resolved.path_info;
                resolved.path
            }
            Err(_) => {
                return Ok(immediate(
                    CgiResponse {
                        status: 404,
                        headers: vec![("Content-Type".into(), "text/plain".into())],
                        body: Bytes::from_static(b"script not found"),
                    }
                    .to_cgi_output(),
                ));
            }
        };

        let env = self.build_env(&req);
        let prepared_script = prepare_cgi_script_for_spawn(&self.canonical_root, &script_path)?;

        let mut child = Command::new(prepared_script.command_path())
            .env_clear()
            .envs(&env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("failed to spawn CGI script: {}", e))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("CGI child stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("CGI child stdout unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("CGI child stderr unavailable"))?;

        let (stdin_tx, stdin_rx) = mpsc::channel::<Bytes>(16);
        let (stdout_tx, stdout_rx) = mpsc::channel::<Bytes>(16);
        let (stderr_tx, stderr_rx) = mpsc::channel::<Bytes>(16);
        let (abort_tx, abort_rx) = oneshot::channel::<()>();

        let max_stdout = self.max_stdout_bytes;
        let max_stderr = self.max_stderr_bytes;
        let timeout_dur = self.timeout;
        let script_label = prepared_script.label_path().to_path_buf();

        let done = tokio::spawn(async move {
            async fn pump_reader<R: tokio::io::AsyncRead + Unpin>(
                mut reader: R,
                tx: mpsc::Sender<Bytes>,
                limit: usize,
                label: &'static str,
            ) -> Result<()> {
                let mut total = 0usize;
                let mut buf = BytesMut::with_capacity(8192);
                loop {
                    buf.reserve(8192);
                    let n = reader.read_buf(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    total = total.saturating_add(n);
                    if total > limit {
                        return Err(anyhow!("cgi {} exceeded size limit", label));
                    }
                    // No extra copy: freeze the just-read bytes and send them downstream.
                    tx.send(buf.split_to(n).freeze())
                        .await
                        .map_err(|_| anyhow!("cgi {} receiver dropped", label))?;
                }
                Ok(())
            }

            async fn pump_stdin(
                mut stdin: tokio::process::ChildStdin,
                mut rx: mpsc::Receiver<Bytes>,
            ) -> Result<()> {
                while let Some(chunk) = rx.recv().await {
                    stdin.write_all(&chunk).await?;
                }
                Ok(())
            }

            let (err_tx, mut err_rx) = mpsc::channel::<anyhow::Error>(1);

            let stdin_task = {
                let err_tx = err_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = pump_stdin(stdin, stdin_rx).await {
                        let _ = err_tx.send(e).await;
                    }
                })
            };
            let stdout_task = {
                let err_tx = err_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = pump_reader(stdout, stdout_tx, max_stdout, "stdout").await {
                        let _ = err_tx.send(e).await;
                    }
                })
            };
            let stderr_task = {
                let err_tx = err_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = pump_reader(stderr, stderr_tx, max_stderr, "stderr").await {
                        let _ = err_tx.send(e).await;
                    }
                })
            };
            drop(err_tx);

            let mut abort_rx = abort_rx;
            let status = tokio::select! {
                _ = &mut abort_rx => Err(anyhow!("CGI request aborted")),
                Some(e) = err_rx.recv() => Err(e),
                res = timeout(timeout_dur, child.wait()) => match res {
                    Ok(Ok(status)) => Ok(status),
                    Ok(Err(e)) => Err(anyhow!("CGI wait failed: {}", e)),
                    Err(_) => Err(anyhow!("CGI timed out after {:?}", timeout_dur)),
                },
            };

            match status {
                Ok(exit_status) => {
                    // Ensure output tasks complete and flush remaining buffered data.
                    stdin_task.abort();
                    let _ = stdin_task.await;
                    let _ = stdout_task.await;
                    let _ = stderr_task.await;
                    if !exit_status.success() {
                        warn!(
                            script = %script_label.display(),
                            exit_code = exit_status.code(),
                            "CGI script exited with error"
                        );
                    }
                    Ok(())
                }
                Err(e) => {
                    let _ = child.start_kill();
                    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
                    stdin_task.abort();
                    stdout_task.abort();
                    stderr_task.abort();
                    let _ = stdin_task.await;
                    let _ = stdout_task.await;
                    let _ = stderr_task.await;
                    Err(e)
                }
            }
        });

        Ok(Execution {
            stdin: stdin_tx,
            stdout: stdout_rx,
            stderr: stderr_rx,
            abort: abort_tx,
            done,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn test_request(
        script_name: &str,
        path_info: &str,
        matched_prefix: Option<&str>,
    ) -> CgiRequest {
        CgiRequest {
            script_name: script_name.to_string(),
            path_info: path_info.to_string(),
            query_string: String::new(),
            request_method: "GET".to_string(),
            content_type: String::new(),
            content_length: 0,
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
}
