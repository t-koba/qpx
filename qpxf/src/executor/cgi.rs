use super::{CgiRequest, CgiResponse, Execution, Executor};
use crate::config::CgiBackendConfig;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use bytes::BytesMut;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, Duration};
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

impl CgiExecutor {
    pub fn new(config: &CgiBackendConfig) -> Result<Self> {
        let canonical_root = config.root.canonicalize().map_err(|e| {
            anyhow!(
                "failed to canonicalize CGI root '{}': {}",
                config.root.display(),
                e
            )
        })?;

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
        env.insert("SERVER_SOFTWARE".into(), "qpxf/0.1".into());
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

    /// Resolve the script path from SCRIPT_NAME, stripping the matched prefix
    /// and enforcing root containment.
    fn resolve_script_path(&self, req: &CgiRequest) -> Result<PathBuf> {
        // Determine the relative path: strip matched prefix from script_name.
        let relative = if let Some(prefix) = &req.matched_prefix {
            req.script_name
                .strip_prefix(prefix.as_str())
                .unwrap_or(&req.script_name)
        } else {
            &req.script_name
        };
        let relative = relative.strip_prefix('/').unwrap_or(relative);

        // Reject paths containing `..` components before canonicalization.
        if relative.contains("..") {
            return Err(anyhow!("path traversal detected in script name"));
        }

        let script_path = self.root.join(relative);

        if !script_path.exists() {
            return Err(anyhow!("script not found: {}", script_path.display()));
        }

        // Canonicalize to resolve symlinks and verify containment.
        let canonical = script_path.canonicalize().map_err(|e| {
            anyhow!(
                "failed to canonicalize script path '{}': {}",
                script_path.display(),
                e
            )
        })?;

        if !canonical.starts_with(&self.canonical_root) {
            return Err(anyhow!(
                "script path escapes CGI root: {} is not under {}",
                canonical.display(),
                self.canonical_root.display()
            ));
        }

        Ok(canonical)
    }
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

        let script_path = match self.resolve_script_path(&req) {
            Ok(p) => p,
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

        let mut child = Command::new(&script_path)
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
        let script_label = script_path.clone();

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
