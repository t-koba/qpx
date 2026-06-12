mod fastcgi_io;
mod pool;
mod scgi_io;
#[cfg(test)]
mod tests;

use self::fastcgi_io::{FastCgiOutputChannels, FastCgiOutputLimits, FastCgiStreamingStdin};
use self::pool::FastCgiConnectionPool;
use self::scgi_io::{
    PersistentStdinBody, ensure_unknown_scgi_stdin_is_empty, run_scgi_streaming,
    run_scgi_streaming_stdin,
};
use super::{CgiRequest, Execution, Executor};
use crate::config::{FastCgiBackendConfig, ScgiBackendConfig};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::time::{Duration, timeout};

pub struct FastCgiExecutor {
    timeout: Duration,
    pool: Arc<FastCgiConnectionPool>,
    script_name_prefixes: Arc<[String]>,
    max_stdin_bytes: usize,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

impl FastCgiExecutor {
    pub fn new(config: &FastCgiBackendConfig) -> Result<Self> {
        Ok(Self {
            timeout: Duration::from_millis(config.timeout_ms),
            pool: Arc::new(FastCgiConnectionPool::new(
                config.address.clone(),
                config.pool.max_concurrency,
                config.pool.max_idle,
            )?),
            script_name_prefixes: Arc::from(config.script_name_prefixes.clone()),
            max_stdin_bytes: config.max_stdin_bytes,
            max_stdout_bytes: config.max_stdout_bytes,
            max_stderr_bytes: config.max_stderr_bytes,
        })
    }
}

#[async_trait]
impl Executor for FastCgiExecutor {
    async fn start(&self, mut req: CgiRequest) -> Result<Execution> {
        let (stdin_tx, stdin_rx) = mpsc::channel::<Bytes>(16);
        let (stdout_tx, stdout_rx) = mpsc::channel::<Bytes>(16);
        let (stderr_tx, stderr_rx) = mpsc::channel::<Bytes>(16);
        let (abort_tx, mut abort_rx) = oneshot::channel::<()>();

        let timeout_dur = self.timeout;
        let pool = self.pool.clone();
        let script_name_prefixes = self.script_name_prefixes.clone();
        let max_stdin = self.max_stdin_bytes;
        let max_stdout = self.max_stdout_bytes;
        let max_stderr = self.max_stderr_bytes;

        let done = tokio::spawn(async move {
            apply_script_name_prefixes(&mut req, &script_name_prefixes);
            let declared_len = req.declared_content_length;
            let env = build_gateway_env(&req, declared_len);
            let future = pool.execute_streaming_stdin(FastCgiStreamingStdin {
                env,
                stdin_rx,
                expected_stdin_bytes: declared_len,
                max_stdin_bytes: max_stdin,
                output_limits: FastCgiOutputLimits {
                    stdout: max_stdout,
                    stderr: max_stderr,
                },
                output_channels: FastCgiOutputChannels {
                    stdout: stdout_tx,
                    stderr: stderr_tx,
                },
            });
            tokio::select! {
                result = timeout(timeout_dur, future) => {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => return Err(err).context("fastcgi backend request failed"),
                        Err(_) => {
                            crate::metrics::backend_request("fastcgi", "timeout");
                            crate::metrics::timeout("fastcgi", "request");
                            return Err(anyhow!("fastcgi backend request timed out"));
                        }
                    }
                }
                _ = &mut abort_rx => {
                    crate::metrics::backend_request("fastcgi", "aborted");
                    return Ok(());
                }
            }
            Ok(())
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

pub struct ScgiExecutor {
    inner: PersistentExecutor,
}

impl ScgiExecutor {
    pub fn new(config: &ScgiBackendConfig) -> Result<Self> {
        Ok(Self {
            inner: PersistentExecutor::new(
                config.address.clone(),
                config.timeout_ms,
                config.max_concurrency,
                config.script_name_prefixes.clone(),
                config.max_stdin_bytes,
                config.max_stdout_bytes,
                config.max_stderr_bytes,
            )?,
        })
    }
}

#[async_trait]
impl Executor for ScgiExecutor {
    async fn start(&self, req: CgiRequest) -> Result<Execution> {
        self.inner.start(req).await
    }
}

struct PersistentExecutor {
    address: String,
    timeout: Duration,
    semaphore: Arc<Semaphore>,
    script_name_prefixes: Arc<[String]>,
    max_stdin_bytes: usize,
    max_stdout_bytes: usize,
}

impl PersistentExecutor {
    fn new(
        address: String,
        timeout_ms: u64,
        max_concurrency: usize,
        script_name_prefixes: Vec<String>,
        max_stdin_bytes: usize,
        max_stdout_bytes: usize,
        _max_stderr_bytes: usize,
    ) -> Result<Self> {
        if address.trim().is_empty() {
            return Err(anyhow!("persistent backend address must not be empty"));
        }
        Ok(Self {
            address,
            timeout: Duration::from_millis(timeout_ms),
            semaphore: Arc::new(Semaphore::new(max_concurrency)),
            script_name_prefixes: Arc::from(script_name_prefixes),
            max_stdin_bytes,
            max_stdout_bytes,
        })
    }

    async fn start(&self, mut req: CgiRequest) -> Result<Execution> {
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Bytes>(16);
        let (stdout_tx, stdout_rx) = mpsc::channel::<Bytes>(16);
        let (stderr_tx, stderr_rx) = mpsc::channel::<Bytes>(16);
        let (abort_tx, mut abort_rx) = oneshot::channel::<()>();

        let address = self.address.clone();
        let timeout_dur = self.timeout;
        let semaphore = self.semaphore.clone();
        let script_name_prefixes = self.script_name_prefixes.clone();
        let max_stdin = self.max_stdin_bytes;
        let max_stdout = self.max_stdout_bytes;
        let done = tokio::spawn(async move {
            let started = std::time::Instant::now();
            let _active = crate::metrics::BackendActiveGuard::new("scgi");
            let permit = semaphore
                .acquire_owned()
                .await
                .map_err(|_| anyhow!("persistent backend semaphore closed"))?;
            let _permit = permit;
            apply_script_name_prefixes(&mut req, &script_name_prefixes);
            let declared_len = req.declared_content_length;
            if let Some(declared_len) = declared_len {
                let env = build_gateway_env(&req, Some(declared_len));
                let future = run_scgi_streaming_stdin(
                    address.as_str(),
                    env,
                    stdin_rx,
                    declared_len,
                    max_stdin,
                    max_stdout,
                    stdout_tx,
                );
                tokio::select! {
                    result = timeout(timeout_dur, future) => {
                        match result {
                            Ok(Ok(())) => {
                                crate::metrics::backend_request("scgi", "ok");
                            }
                            Ok(Err(err)) => {
                                crate::metrics::backend_request("scgi", "error");
                                crate::metrics::broken_response("scgi", "request_error");
                                return Err(err).context("persistent backend request failed");
                            }
                            Err(_) => {
                                crate::metrics::backend_request("scgi", "timeout");
                                crate::metrics::timeout("scgi", "request");
                                return Err(anyhow!("persistent backend request timed out"));
                            }
                        }
                    }
                    _ = &mut abort_rx => {
                        crate::metrics::backend_request("scgi", "aborted");
                        return Ok(());
                    }
                }
            } else {
                tokio::select! {
                    result = ensure_unknown_scgi_stdin_is_empty(&mut stdin_rx) => {
                        if let Err(err) = result {
                            crate::metrics::backend_request("scgi", "error");
                            crate::metrics::broken_response("scgi", "invalid_stdin");
                            return Err(err);
                        }
                    }
                    _ = &mut abort_rx => {
                        crate::metrics::backend_request("scgi", "aborted");
                        return Ok(());
                    }
                };
                let body = PersistentStdinBody::Memory(Bytes::new());
                let env = build_gateway_env(&req, Some(0));
                let future = run_scgi_streaming(address.as_str(), env, body, max_stdout, stdout_tx);
                match timeout(timeout_dur, future).await {
                    Ok(Ok(())) => {
                        crate::metrics::backend_request("scgi", "ok");
                    }
                    Ok(Err(err)) => {
                        crate::metrics::backend_request("scgi", "error");
                        crate::metrics::broken_response("scgi", "request_error");
                        return Err(err).context("persistent backend request failed");
                    }
                    Err(_) => {
                        crate::metrics::backend_request("scgi", "timeout");
                        crate::metrics::timeout("scgi", "request");
                        return Err(anyhow!("persistent backend request timed out"));
                    }
                }
            }
            drop(stderr_tx);
            crate::metrics::response_wait("scgi", started.elapsed());
            Ok(())
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

fn apply_script_name_prefixes(req: &mut CgiRequest, prefixes: &[String]) {
    if prefixes.is_empty() {
        return;
    }
    let request_path = format!("{}{}", req.script_name, req.path_info);
    let Some(prefix) = prefixes
        .iter()
        .filter(|prefix| script_prefix_matches(request_path.as_str(), prefix.as_str()))
        .max_by_key(|prefix| prefix.len())
    else {
        return;
    };
    req.script_name = prefix.clone();
    req.path_info = request_path
        .strip_prefix(prefix.as_str())
        .unwrap_or_default()
        .to_string();
}

fn script_prefix_matches(path: &str, prefix: &str) -> bool {
    path == prefix || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/'))
}

fn build_gateway_env(req: &CgiRequest, body_len: Option<usize>) -> Vec<(String, String)> {
    let mut env = Vec::new();
    push_env(&mut env, "GATEWAY_INTERFACE", "CGI/1.1".to_string());
    push_env(&mut env, "SERVER_PROTOCOL", req.server_protocol.clone());
    push_env(
        &mut env,
        "SERVER_SOFTWARE",
        concat!("qpxf/", env!("CARGO_PKG_VERSION")).to_string(),
    );
    push_env(&mut env, "REQUEST_METHOD", req.request_method.clone());
    push_env(&mut env, "QUERY_STRING", req.query_string.clone());
    push_env(&mut env, "SCRIPT_NAME", req.script_name.clone());
    push_env(&mut env, "PATH_INFO", req.path_info.clone());
    push_env(&mut env, "SERVER_NAME", req.server_name.clone());
    push_env(&mut env, "SERVER_PORT", req.server_port.to_string());
    if let Some(body_len) = body_len {
        push_env(&mut env, "CONTENT_LENGTH", body_len.to_string());
    }
    if !req.content_type.is_empty() {
        push_env(&mut env, "CONTENT_TYPE", req.content_type.clone());
    }
    if let Some(addr) = req.remote_addr.as_ref() {
        push_env(&mut env, "REMOTE_ADDR", addr.clone());
    }
    if let Some(port) = req.remote_port {
        push_env(&mut env, "REMOTE_PORT", port.to_string());
    }

    let connection_tokens = parse_connection_tokens(&req.http_headers);
    for (key, value) in req.http_headers.iter().take(100) {
        let lower = key.to_ascii_lowercase();
        if is_cgi_reserved_header(&lower)
            || is_hop_by_hop_header(&lower)
            || connection_tokens.contains(lower.as_str())
        {
            continue;
        }
        push_env(
            &mut env,
            format!("HTTP_{}", key.to_uppercase().replace('-', "_")),
            value.clone(),
        );
    }
    env
}

fn push_env(env: &mut Vec<(String, String)>, name: impl Into<String>, value: String) {
    env.push((name.into(), value));
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

fn is_cgi_reserved_header(name: &str) -> bool {
    matches!(name, "content-length" | "content-type")
}

pub(super) async fn stream_read_limited<R>(
    stream: &mut R,
    limit: usize,
    label: &str,
    tx: mpsc::Sender<Bytes>,
) -> Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut sent = 0usize;
    let mut buf = BytesMut::with_capacity(8192);
    loop {
        buf.clear();
        buf.reserve(8192);
        let read = stream.read_buf(&mut buf).await?;
        if read == 0 {
            return Ok(());
        }
        send_limited_chunk(&tx, buf.split().freeze(), &mut sent, limit, label).await?;
    }
}

pub(super) async fn send_limited_chunk(
    tx: &mpsc::Sender<Bytes>,
    chunk: Bytes,
    sent: &mut usize,
    limit: usize,
    label: &str,
) -> Result<()> {
    if chunk.is_empty() {
        return Ok(());
    }
    let next = sent.saturating_add(chunk.len());
    if next > limit {
        return Err(anyhow!(
            "persistent backend {label} exceeds configured limit"
        ));
    }
    *sent = next;
    tx.send(chunk)
        .await
        .map_err(|_| anyhow!("persistent backend {label} receiver closed"))
}
