mod env;
mod output;
#[cfg(test)]
mod tests;

use self::output::validate_secure_cgi_script;
use self::output::{prepare_cgi_script_for_spawn, validate_secure_cgi_root};
use super::{CgiRequest, CgiResponse, Execution, Executor};
use crate::config::CgiBackendConfig;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, timeout};
use tracing::warn;

pub(crate) use env::cgi_env_passthrough_is_reserved;

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
}

impl CgiExecutor {
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

        let mut command = Command::new(prepared_script.command_path());
        command.args(prepared_script.command_args());
        let mut child = command
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
            let started = std::time::Instant::now();
            let _active = crate::metrics::BackendActiveGuard::new("cgi");
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
                        crate::metrics::backend_request("cgi", "error");
                        crate::metrics::broken_response("cgi", "exit_status");
                    } else {
                        crate::metrics::backend_request("cgi", "ok");
                    }
                    crate::metrics::response_wait("cgi", started.elapsed());
                    Ok(())
                }
                Err(e) => {
                    let err_text = e.to_string();
                    let _ = child.start_kill();
                    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
                    stdin_task.abort();
                    stdout_task.abort();
                    stderr_task.abort();
                    let _ = stdin_task.await;
                    let _ = stdout_task.await;
                    let _ = stderr_task.await;
                    if err_text.contains("timed out") {
                        crate::metrics::backend_request("cgi", "timeout");
                        crate::metrics::timeout("cgi", "request");
                    } else {
                        crate::metrics::backend_request("cgi", "error");
                        crate::metrics::broken_response("cgi", "request_error");
                    }
                    crate::metrics::response_wait("cgi", started.elapsed());
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
