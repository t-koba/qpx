use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::sync::oneshot;
use tokio::time::{Duration, timeout};
use tracing::warn;

use crate::executor::{CgiResponse, Execution};
use crate::ipc_request::{IpcPlainResponse, plaintext_meta, plan_ipc_request};
use crate::router::Router;

use qpx_core::ipc::meta::{IpcRequestMeta, IpcResponseMeta};
use qpx_core::ipc::protocol::{read_frame, write_frame};
use qpx_core::shm_ring::ShmRingBuffer;

const MAX_IPC_SHM_RING_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdinReadOutcome {
    Complete,
    TooLarge,
    TimedOut,
    Truncated,
}

impl StdinReadOutcome {
    fn error_response(self) -> Option<(u16, &'static [u8])> {
        match self {
            Self::Complete => None,
            Self::TooLarge => Some((413, b"request body too large")),
            Self::TimedOut => Some((408, b"request body timed out")),
            Self::Truncated => Some((400, b"request body truncated")),
        }
    }
}

#[derive(Clone)]
pub struct ConnectionContext {
    pub router: Arc<Router>,
    pub semaphore: Arc<Semaphore>,
    pub input_idle: Duration,
    pub conn_idle: Duration,
    pub max_requests_per_connection: usize,
    pub max_params_bytes: usize,
    pub max_stdin_bytes: usize,
}

pub async fn handle_connection<S>(mut stream: S, ctx: ConnectionContext) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ConnectionContext {
        router,
        semaphore,
        input_idle,
        conn_idle,
        max_requests_per_connection,
        max_params_bytes,
        max_stdin_bytes,
    } = ctx;
    let mut handled_requests: usize = 0;
    loop {
        // 1) Read the metadata frame from qpxd.
        let meta: IpcRequestMeta = match timeout(conn_idle, read_frame(&mut stream)).await {
            Ok(Ok(meta)) => meta,
            Ok(Err(err)) => {
                if is_unexpected_eof(&err) {
                    return Ok(());
                }
                return Err(err);
            }
            Err(_) => return Ok(()), // idle
        };

        let uses_shm = meta_uses_shm(&meta);
        if uses_shm {
            handle_one_request_shm(
                &mut stream,
                meta,
                &router,
                &semaphore,
                input_idle,
                max_params_bytes,
                max_stdin_bytes,
            )
            .await?;
            handled_requests = handled_requests.saturating_add(1);
            if handled_requests >= max_requests_per_connection {
                return Ok(());
            }
            continue;
        }
        // TCP-streaming mode uses connection-close (EOF) semantics, so keep-alive isn't possible.
        return handle_one_request_tcp(
            stream,
            meta,
            TcpRequestContext {
                router,
                semaphore,
                input_idle,
                output_idle: conn_idle,
                max_params_bytes,
                max_stdin_bytes,
            },
        )
        .await;
    }
}

fn meta_uses_shm(meta: &IpcRequestMeta) -> bool {
    meta.req_body_shm_path.is_some()
        || meta.req_body_shm_size_bytes.is_some()
        || meta.res_body_shm_path.is_some()
        || meta.res_body_shm_size_bytes.is_some()
}

fn is_unexpected_eof(err: &anyhow::Error) -> bool {
    err.downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof)
}

fn validate_ipc_shm_token(token: &str, expected_prefix: &str) -> Result<()> {
    qpx_core::ipc::shm::validate_ipc_shm_token(token, expected_prefix)
}

async fn drain_req_ring(req_path: &Path, ring: &mut ShmRingBuffer, input_idle: Duration) {
    loop {
        match ring.try_pop() {
            Ok(Some(data)) => {
                if data.is_empty() {
                    break;
                }
            }
            Ok(None) => {
                let waited = timeout(input_idle, ring.wait_for_data()).await;
                if waited.is_err() || waited.is_ok_and(|r| r.is_err()) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = std::fs::remove_file(req_path);
}

async fn push_ring_bytes(
    ring: &mut ShmRingBuffer,
    bytes: &[u8],
    wait_timeout: Duration,
) -> Result<()> {
    loop {
        match ring.try_push(bytes) {
            Ok(true) => return Ok(()),
            Ok(false) => timeout(wait_timeout, ring.wait_for_space(bytes.len())).await??,
            Err(e) => return Err(e),
        }
    }
}

async fn push_ring_eof(ring: &mut ShmRingBuffer, wait_timeout: Duration) -> Result<()> {
    push_ring_bytes(ring, &[], wait_timeout).await
}

async fn write_shm_plain_response<S>(
    stream: &mut S,
    ring: &mut ShmRingBuffer,
    response: &IpcPlainResponse,
    wait_timeout: Duration,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_frame(stream, &response.meta()).await?;
    push_ring_bytes(ring, response.body, wait_timeout).await?;
    push_ring_eof(ring, wait_timeout).await
}

async fn handle_one_request_shm<S>(
    stream: &mut S,
    mut meta: IpcRequestMeta,
    router: &Arc<Router>,
    semaphore: &Arc<Semaphore>,
    input_idle: Duration,
    max_params_bytes: usize,
    max_stdin_bytes: usize,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let req_token = meta.req_body_shm_path.take().ok_or_else(|| {
        anyhow!("req_body_shm_path is required when shared memory IPC is enabled")
    })?;
    let req_size = meta.req_body_shm_size_bytes.take().ok_or_else(|| {
        anyhow!("req_body_shm_size_bytes is required when shared memory IPC is enabled")
    })?;
    let res_token = meta.res_body_shm_path.take().ok_or_else(|| {
        anyhow!("res_body_shm_path is required when shared memory IPC is enabled")
    })?;
    let res_size = meta.res_body_shm_size_bytes.take().ok_or_else(|| {
        anyhow!("res_body_shm_size_bytes is required when shared memory IPC is enabled")
    })?;

    if req_size == 0
        || res_size == 0
        || req_size > MAX_IPC_SHM_RING_BYTES
        || res_size > MAX_IPC_SHM_RING_BYTES
    {
        return Err(anyhow!(
            "IPC shared memory ring size is out of allowed range"
        ));
    }

    validate_ipc_shm_token(req_token.as_str(), "ipc_req_")?;
    validate_ipc_shm_token(res_token.as_str(), "ipc_res_")?;
    let (req_path, mut req_ring) =
        qpx_core::ipc::shm::create_or_open_ipc_ring(req_token.as_str(), "ipc_req_", req_size)?;
    let (res_path, mut res_ring) =
        qpx_core::ipc::shm::create_or_open_ipc_ring(res_token.as_str(), "ipc_res_", res_size)?;

    // Per-request SHM doorbells should not leak named kernel objects (notably on macOS).
    if let Err(e) = req_ring.unlink_doorbells() {
        warn!(error = ?e, "failed to unlink IPC request SHM doorbells");
    }
    if let Err(e) = res_ring.unlink_doorbells() {
        warn!(error = ?e, "failed to unlink IPC response SHM doorbells");
    }

    let plan = match plan_ipc_request(meta, router, max_params_bytes, max_stdin_bytes)? {
        Ok(plan) => plan,
        Err(response) => {
            let _ = write_shm_plain_response(stream, &mut res_ring, &response, input_idle).await;
            drain_req_ring(&req_path, &mut req_ring, input_idle).await;
            let _ = std::fs::remove_file(&res_path);
            return Ok(());
        }
    };

    let _permit = match Arc::clone(semaphore).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let response = IpcPlainResponse::new(503, b"overloaded");
            let _ = write_shm_plain_response(stream, &mut res_ring, &response, input_idle).await;
            drain_req_ring(&req_path, &mut req_ring, input_idle).await;
            let _ = std::fs::remove_file(&res_path);
            return Ok(());
        }
    };

    let expected_stdin_bytes = plan.expected_stdin_bytes;
    let exec = match plan.executor.start(plan.cgi_req).await {
        Ok(exec) => exec,
        Err(e) => {
            write_frame(stream, &plaintext_meta(502)).await?;
            let msg = format!("executor start error: {}", e);
            let _ = push_ring_bytes(&mut res_ring, msg.as_bytes(), input_idle).await;
            let _ = push_ring_eof(&mut res_ring, input_idle).await;
            drain_req_ring(&req_path, &mut req_ring, input_idle).await;
            let _ = std::fs::remove_file(&res_path);
            return Ok(());
        }
    };

    let Execution {
        stdin: exec_stdin,
        stdout: mut exec_stdout,
        stderr: mut exec_stderr,
        abort: exec_abort,
        done: exec_done,
    } = exec;

    // Drain request body into executor stdin concurrently with header parsing.
    let req_path_task = req_path.clone();
    let input_idle_for_task = input_idle;
    let max_stdin_bytes_for_task = max_stdin_bytes;
    let (stdin_result_tx, stdin_result_rx) = oneshot::channel::<StdinReadOutcome>();
    let stdin_task = tokio::spawn(async move {
        let mut stdin_bytes: usize = 0;
        let mut stdin_result_tx = Some(stdin_result_tx);
        let mut ring = req_ring;
        let mut outcome = StdinReadOutcome::Complete;
        if expected_stdin_bytes == Some(0) {
            if let Some(tx) = stdin_result_tx.take() {
                let _ = tx.send(outcome);
            }
            drop(ring);
            let _ = std::fs::remove_file(req_path_task);
            return;
        }
        loop {
            match ring.try_pop() {
                Ok(Some(data)) => {
                    if data.is_empty() {
                        if expected_stdin_bytes.is_some_and(|expected| stdin_bytes < expected) {
                            outcome = StdinReadOutcome::Truncated;
                        }
                        break; // EOF
                    }
                    stdin_bytes = stdin_bytes.saturating_add(data.len());
                    if stdin_bytes > max_stdin_bytes_for_task {
                        outcome = StdinReadOutcome::TooLarge;
                        break;
                    }
                    if exec_stdin.send(Bytes::from(data)).await.is_err() {
                        break;
                    }
                    if expected_stdin_bytes.is_some_and(|expected| stdin_bytes >= expected) {
                        break;
                    }
                }
                Ok(None) => {
                    let waited = timeout(input_idle_for_task, ring.wait_for_data()).await;
                    if waited.is_err() || waited.is_ok_and(|r| r.is_err()) {
                        outcome = StdinReadOutcome::TimedOut;
                        break;
                    }
                }
                Err(_) => {
                    outcome = StdinReadOutcome::Truncated;
                    break;
                }
            }
        }
        if let Some(tx) = stdin_result_tx.take() {
            let _ = tx.send(outcome);
        }
        drop(ring);
        let _ = std::fs::remove_file(req_path_task);
    });

    // Read until headers are fully accumulated
    let mut header_buf = BytesMut::new();
    let stdin_result_rx = stdin_result_rx;
    tokio::pin!(stdin_result_rx);
    let mut stdin_result_rx_active = true;
    let parsed_res = loop {
        tokio::select! {
            res = &mut stdin_result_rx, if stdin_result_rx_active => {
                match res {
                    Ok(outcome) if outcome.error_response().is_some() => {
                        let (status, body) = outcome.error_response().expect("error response");
                        let res_meta = IpcResponseMeta {
                            status,
                            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                        };
                        write_frame(stream, &res_meta).await?;
                        let _ = push_ring_bytes(&mut res_ring, body, input_idle).await;
                        let _ = push_ring_eof(&mut res_ring, input_idle).await;
                        let _ = exec_abort.send(());
                        let _ = stdin_task.await;
                        let _ = exec_done.await;
                        let _ = std::fs::remove_file(&res_path);
                        return Ok(());
                    }
                    Ok(_) => {
                        stdin_result_rx_active = false;
                    }
                    Err(_) => {
                        stdin_result_rx_active = false;
                    }
                }
            }
            chunk = exec_stdout.recv() => {
                let Some(chunk) = chunk else {
                    break None;
                };
                header_buf.extend_from_slice(&chunk);

                let eof_idx = header_buf
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .or_else(|| header_buf.windows(2).position(|window| window == b"\n\n"));

                if eof_idx.is_some() || header_buf.len() > 65536 {
                    match CgiResponse::parse_cgi_output(&header_buf) {
                        Ok(resp) => break Some(resp),
                        Err(_) => break None,
                    }
                }
            }
        }
    };

    if stdin_result_rx_active {
        match (&mut stdin_result_rx).await {
            Ok(outcome) if outcome.error_response().is_some() => {
                let (status, body) = outcome.error_response().expect("error response");
                let res_meta = IpcResponseMeta {
                    status,
                    headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                };
                write_frame(stream, &res_meta).await?;
                let _ = push_ring_bytes(&mut res_ring, body, input_idle).await;
                let _ = push_ring_eof(&mut res_ring, input_idle).await;
                let _ = exec_abort.send(());
                let _ = stdin_task.await;
                let _ = exec_done.await;
                let _ = std::fs::remove_file(&res_path);
                return Ok(());
            }
            Ok(_) | Err(_) => {}
        }
    }

    let (res_meta, body_leftover) = if let Some(parsed) = parsed_res {
        (
            IpcResponseMeta {
                status: parsed.status,
                headers: parsed.headers,
            },
            parsed.body,
        )
    } else {
        let meta = IpcResponseMeta {
            status: 502,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
        };
        write_frame(stream, &meta).await?;
        let _ = push_ring_bytes(
            &mut res_ring,
            b"bad gateway (invalid CGI headers)",
            input_idle,
        )
        .await;
        let _ = push_ring_eof(&mut res_ring, input_idle).await;
        let _ = exec_abort.send(());
        let _ = stdin_task.await;
        let _ = exec_done.await;
        let _ = std::fs::remove_file(&res_path);
        return Ok(());
    };

    // Write IpcResponseMeta
    write_frame(stream, &res_meta).await?;

    // Handle initial leftover stdout body bytes
    if !body_leftover.is_empty() {
        let _ = push_ring_bytes(&mut res_ring, body_leftover.as_ref(), input_idle).await;
    }

    // Task to forward executor STDOUT to response ring
    let res_path_task = res_path.clone();
    let stdout_task = tokio::spawn(async move {
        let mut ring = res_ring;
        while let Some(chunk) = exec_stdout.recv().await {
            if push_ring_bytes(&mut ring, &chunk, input_idle)
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = push_ring_eof(&mut ring, input_idle).await;
        drop(ring);
        let _ = std::fs::remove_file(res_path_task);
    });

    let stderr_task = tokio::spawn(async move {
        while let Some(chunk) = exec_stderr.recv().await {
            if !chunk.is_empty() {
                if let Ok(msg) = std::str::from_utf8(&chunk) {
                    warn!("CGI STDERR: {}", msg.trim_end());
                } else {
                    warn!("CGI STDERR (binary): {} bytes", chunk.len());
                }
            }
        }
    });

    let _ = exec_done.await;
    let _ = stdin_task.await;
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    Ok(())
}

async fn write_frame_with_timeout<S, T>(
    stream: &mut S,
    value: &T,
    write_timeout: Duration,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    timeout(write_timeout, write_frame(stream, value))
        .await
        .map_err(|_| anyhow!("IPC TCP response metadata write timed out"))??;
    Ok(())
}

async fn write_all_with_timeout<S>(
    stream: &mut S,
    bytes: &[u8],
    write_timeout: Duration,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    timeout(write_timeout, stream.write_all(bytes))
        .await
        .map_err(|_| anyhow!("IPC TCP response body write timed out"))??;
    Ok(())
}

async fn write_tcp_plain_response<S>(
    stream: &mut S,
    response: &IpcPlainResponse,
    output_idle: Duration,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_frame_with_timeout(stream, &response.meta(), output_idle).await?;
    write_all_with_timeout(stream, response.body, output_idle).await
}

struct TcpRequestContext {
    router: Arc<Router>,
    semaphore: Arc<Semaphore>,
    input_idle: Duration,
    output_idle: Duration,
    max_params_bytes: usize,
    max_stdin_bytes: usize,
}

async fn handle_one_request_tcp<S>(
    mut stream: S,
    meta: IpcRequestMeta,
    ctx: TcpRequestContext,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let TcpRequestContext {
        router,
        semaphore,
        input_idle,
        output_idle,
        max_params_bytes,
        max_stdin_bytes,
    } = ctx;
    let plan = match plan_ipc_request(meta, &router, max_params_bytes, max_stdin_bytes)? {
        Ok(plan) => plan,
        Err(response) => {
            write_tcp_plain_response(&mut stream, &response, output_idle).await?;
            let mut buf = [0u8; 65536];
            loop {
                let n = match timeout(input_idle, stream.read(&mut buf)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                };
                let _ = n; // discard
            }
            return Ok(());
        }
    };

    let _permit = match Arc::clone(&semaphore).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let response = IpcPlainResponse::new(503, b"overloaded");
            write_tcp_plain_response(&mut stream, &response, output_idle).await?;
            return Ok(());
        }
    };

    let expected_stdin_bytes = plan.expected_stdin_bytes;
    let exec = match plan.executor.start(plan.cgi_req).await {
        Ok(exec) => exec,
        Err(e) => {
            write_frame_with_timeout(&mut stream, &plaintext_meta(502), output_idle).await?;
            let msg = format!("executor start error: {}", e);
            write_all_with_timeout(&mut stream, msg.as_bytes(), output_idle).await?;
            return Ok(());
        }
    };

    let Execution {
        stdin: exec_stdin,
        stdout: mut exec_stdout,
        stderr: mut exec_stderr,
        abort: exec_abort,
        done: exec_done,
    } = exec;

    let (mut rx, mut tx) = tokio::io::split(stream);

    // Drain request body into executor stdin concurrently with header parsing.
    let (stdin_result_tx, stdin_result_rx) = oneshot::channel::<StdinReadOutcome>();
    let stdin_task = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        let mut stdin_bytes: usize = 0;
        let mut stdin_result_tx = Some(stdin_result_tx);
        let mut outcome = StdinReadOutcome::Complete;
        if expected_stdin_bytes == Some(0) {
            let _ = stdin_result_tx.take().and_then(|tx| tx.send(outcome).ok());
            return;
        }
        loop {
            let n = match timeout(input_idle, rx.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    if expected_stdin_bytes.is_some_and(|expected| stdin_bytes < expected) {
                        outcome = StdinReadOutcome::Truncated;
                    }
                    break;
                }
                Ok(Ok(n)) => n,
                Ok(Err(_)) => {
                    outcome = StdinReadOutcome::Truncated;
                    break;
                }
                Err(_) => {
                    outcome = StdinReadOutcome::TimedOut;
                    break;
                }
            };
            stdin_bytes = stdin_bytes.saturating_add(n);
            if stdin_bytes > max_stdin_bytes {
                outcome = StdinReadOutcome::TooLarge;
                break;
            }
            if exec_stdin
                .send(Bytes::copy_from_slice(&buf[..n]))
                .await
                .is_err()
            {
                break;
            }
            if expected_stdin_bytes.is_some_and(|expected| stdin_bytes >= expected) {
                break;
            }
        }
        if let Some(tx) = stdin_result_tx.take() {
            let _ = tx.send(outcome);
        }
    });

    let mut header_buf = BytesMut::new();
    let stdin_result_rx = stdin_result_rx;
    tokio::pin!(stdin_result_rx);
    let mut stdin_result_rx_active = true;
    let parsed_res = loop {
        tokio::select! {
            res = &mut stdin_result_rx, if stdin_result_rx_active => {
                match res {
                    Ok(outcome) if outcome.error_response().is_some() => {
                        let (status, body) = outcome.error_response().expect("error response");
                        let res_meta = IpcResponseMeta {
                            status,
                            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                        };
                        write_frame_with_timeout(&mut tx, &res_meta, output_idle).await?;
                        let _ = write_all_with_timeout(&mut tx, body, output_idle).await;
                        let _ = exec_abort.send(());
                        let _ = stdin_task.await;
                        let _ = exec_done.await;
                        return Ok(());
                    }
                    Ok(_) => {
                        stdin_result_rx_active = false;
                    }
                    Err(_) => {
                        stdin_result_rx_active = false;
                    }
                }
            }
            chunk = exec_stdout.recv() => {
                let Some(chunk) = chunk else {
                    break None;
                };
                header_buf.extend_from_slice(&chunk);

                let eof_idx = header_buf
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .or_else(|| header_buf.windows(2).position(|window| window == b"\n\n"));

                if eof_idx.is_some() || header_buf.len() > 65536 {
                    match CgiResponse::parse_cgi_output(&header_buf) {
                        Ok(resp) => break Some(resp),
                        Err(_) => break None,
                    }
                }
            }
        }
    };

    if stdin_result_rx_active {
        match (&mut stdin_result_rx).await {
            Ok(outcome) if outcome.error_response().is_some() => {
                let (status, body) = outcome.error_response().expect("error response");
                let res_meta = IpcResponseMeta {
                    status,
                    headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                };
                write_frame_with_timeout(&mut tx, &res_meta, output_idle).await?;
                let _ = write_all_with_timeout(&mut tx, body, output_idle).await;
                let _ = exec_abort.send(());
                let _ = stdin_task.await;
                let _ = exec_done.await;
                return Ok(());
            }
            Ok(_) | Err(_) => {}
        }
    }

    let (res_meta, body_leftover) = if let Some(parsed) = parsed_res {
        (
            IpcResponseMeta {
                status: parsed.status,
                headers: parsed.headers,
            },
            parsed.body,
        )
    } else {
        // Executor ended before headers were completed.
        let meta = IpcResponseMeta {
            status: 502,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
        };
        write_frame_with_timeout(&mut tx, &meta, output_idle).await?;
        write_all_with_timeout(&mut tx, b"bad gateway (no output)", output_idle).await?;
        return Ok(());
    };

    // Write IpcResponseMeta
    write_frame_with_timeout(&mut tx, &res_meta, output_idle).await?;

    // Handle initial leftover stdout body bytes
    if !body_leftover.is_empty() {
        write_all_with_timeout(&mut tx, &body_leftover, output_idle).await?;
    }

    // Task to forward executor STDOUT to stream
    let stdout_task = tokio::spawn(async move {
        while let Some(chunk) = exec_stdout.recv().await {
            if write_all_with_timeout(&mut tx, &chunk, output_idle)
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let stderr_task = tokio::spawn(async move {
        while let Some(chunk) = exec_stderr.recv().await {
            if !chunk.is_empty() {
                if let Ok(msg) = std::str::from_utf8(&chunk) {
                    warn!("CGI STDERR: {}", msg.trim_end());
                } else {
                    warn!("CGI STDERR (binary): {} bytes", chunk.len());
                }
            }
        }
    });

    let _ = exec_done.await;
    let _ = stdin_task.await;
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    Ok(())
}
