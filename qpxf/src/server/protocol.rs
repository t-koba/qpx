use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use memchr::memmem;
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
use qpx_core::ipc::protocol::write_frame;
use qpx_core::shm_ring::ShmRingBuffer;

const MAX_IPC_SHM_RING_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

struct ParsedCgiOutputHead {
    meta: IpcResponseMeta,
    body_leftover: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdinReadOutcome {
    Complete,
    LengthMismatch,
    TooLarge,
    TimedOut,
    Truncated,
}

impl StdinReadOutcome {
    fn error_response(self) -> Option<(u16, &'static [u8])> {
        match self {
            Self::Complete => None,
            Self::LengthMismatch => Some((400, b"request body length mismatch")),
            Self::TooLarge => Some((413, b"request body too large")),
            Self::TimedOut => Some((408, b"request body timed out")),
            Self::Truncated => Some((400, b"request body truncated")),
        }
    }
}
pub(super) fn meta_uses_shm(meta: &IpcRequestMeta) -> bool {
    meta.req_body_shm_path.is_some()
        || meta.req_body_shm_size_bytes.is_some()
        || meta.res_body_shm_path.is_some()
        || meta.res_body_shm_size_bytes.is_some()
}

fn validate_ipc_shm_token(token: &str, expected_prefix: &str) -> Result<()> {
    Ok(qpx_core::ipc::shm::validate_ipc_shm_token(
        token,
        expected_prefix,
    )?)
}

fn remove_ipc_shm_path(path: impl AsRef<Path>) {
    let path = path.as_ref();
    qpx_core::ipc::shm::unregister_ipc_shm_path(path);
    let _ = std::fs::remove_file(path);
}

fn release_ipc_shm_path(path: impl AsRef<Path>, reusable: bool) {
    let path = path.as_ref();
    if reusable {
        qpx_core::ipc::shm::unregister_ipc_shm_path(path);
    } else {
        remove_ipc_shm_path(path);
    }
}

async fn drain_req_ring(
    req_path: &Path,
    ring: &mut ShmRingBuffer,
    input_idle: Duration,
    reusable: bool,
    max_drain_bytes: usize,
) {
    let mut data = Vec::new();
    let mut drained = 0usize;
    loop {
        match ring.try_pop_into(&mut data) {
            Ok(true) => {
                if data.is_empty() {
                    break;
                }
                drained = drained.saturating_add(data.len());
                if drained > max_drain_bytes {
                    warn!(
                        drained,
                        max_drain_bytes, "IPC SHM rejected request drain exceeded limit"
                    );
                    break;
                }
            }
            Ok(false) => {
                let waited = timeout(input_idle, ring.wait_for_data()).await;
                if waited.is_err() || waited.is_ok_and(|r| r.is_err()) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    release_ipc_shm_path(req_path, reusable);
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
            Err(e) => return Err(e.into()),
        }
    }
}

async fn push_ring_eof(ring: &mut ShmRingBuffer, wait_timeout: Duration) -> Result<()> {
    push_ring_bytes(ring, &[], wait_timeout).await
}

fn log_executor_stderr_chunk(chunk: &[u8]) {
    if !chunk.is_empty() {
        warn!(bytes = chunk.len(), "CGI STDERR chunk suppressed");
    }
}

fn text_plain_meta(status: u16) -> IpcResponseMeta {
    IpcResponseMeta {
        status,
        headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
    }
}

async fn abort_execution(
    exec_abort: oneshot::Sender<()>,
    stdin_task: tokio::task::JoinHandle<()>,
    exec_done: tokio::task::JoinHandle<Result<()>>,
) {
    let _ = exec_abort.send(());
    let _ = stdin_task.await;
    let _ = exec_done.await;
}

fn consume_cgi_stdout_header(
    header_buf: &mut BytesMut,
    chunk: Bytes,
) -> Result<Option<ParsedCgiOutputHead>> {
    let prefix_len = header_buf.len().min(3);
    let prefix = &header_buf[header_buf.len().saturating_sub(prefix_len)..];
    let header_prefix = header_buf.len() - prefix_len;
    let terminator = find_cgi_header_terminator(prefix, chunk.as_ref())
        .and_then(|(idx, len)| idx.checked_add(len).map(|end| (idx, len, end)));
    if let Some((idx, len, end_in_scan)) = terminator {
        let absolute_end = header_prefix + idx;
        let chunk_header_end = end_in_scan.saturating_sub(prefix_len).min(chunk.len());
        if absolute_end + len > 65536 {
            return Err(anyhow!("CGI output headers exceeded 65536 bytes"));
        }
        header_buf.extend_from_slice(&chunk[..chunk_header_end]);
        let (status, headers, _) = CgiResponse::parse_cgi_head(header_buf.as_ref())?;
        return Ok(Some(ParsedCgiOutputHead {
            meta: IpcResponseMeta { status, headers },
            body_leftover: chunk.slice(chunk_header_end..),
        }));
    }

    if header_buf.len().saturating_add(chunk.len()) > 65536 {
        return Err(anyhow!("CGI output headers exceeded 65536 bytes"));
    }
    header_buf.extend_from_slice(chunk.as_ref());
    Ok(None)
}

fn find_cgi_header_terminator(prefix: &[u8], chunk: &[u8]) -> Option<(usize, usize)> {
    let prefix_len = prefix.len();
    let byte_at = |idx: usize| -> u8 {
        if idx < prefix_len {
            prefix[idx]
        } else {
            chunk[idx - prefix_len]
        }
    };
    for idx in 0..prefix_len {
        let remaining = prefix_len + chunk.len() - idx;
        if remaining < 2 {
            break;
        }
        if byte_at(idx) == b'\n' && byte_at(idx + 1) == b'\n' {
            return Some((idx, 2));
        }
        if remaining >= 4
            && byte_at(idx) == b'\r'
            && byte_at(idx + 1) == b'\n'
            && byte_at(idx + 2) == b'\r'
            && byte_at(idx + 3) == b'\n'
        {
            return Some((idx, 4));
        }
    }
    if let Some(pos) = memmem::find(chunk, b"\n\n") {
        return Some((prefix_len + pos, 2));
    }
    if let Some(pos) = memmem::find(chunk, b"\r\n\r\n") {
        return Some((prefix_len + pos, 4));
    }
    None
}

fn stdin_chunk_exceeds_declared_length(
    expected_stdin_bytes: Option<usize>,
    stdin_bytes: usize,
    chunk_len: usize,
) -> bool {
    expected_stdin_bytes.is_some_and(|expected| chunk_len > expected.saturating_sub(stdin_bytes))
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

pub(super) struct ShmRequestContext<'a> {
    pub(super) router: &'a Arc<Router>,
    pub(super) semaphore: &'a Arc<Semaphore>,
    pub(super) input_idle: Duration,
    pub(super) max_params_bytes: usize,
    pub(super) max_stdin_bytes: usize,
    pub(super) allow_shm_reuse: bool,
}

pub(super) async fn handle_one_request_shm<S>(
    stream: &mut S,
    mut meta: IpcRequestMeta,
    ctx: ShmRequestContext<'_>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let ShmRequestContext {
        router,
        semaphore,
        input_idle,
        max_params_bytes,
        max_stdin_bytes,
        allow_shm_reuse,
    } = ctx;
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
    let shm_reusable = meta.shm_reusable && allow_shm_reuse;
    let (req_path, mut req_ring) =
        qpx_core::ipc::shm::create_or_open_ipc_ring(req_token.as_str(), "ipc_req_", req_size)?;
    let (res_path, mut res_ring) =
        qpx_core::ipc::shm::create_or_open_ipc_ring(res_token.as_str(), "ipc_res_", res_size)?;

    if !shm_reusable {
        // Per-request SHM doorbells should not leak named kernel objects (notably on macOS).
        if let Err(e) = req_ring.unlink_doorbells() {
            warn!(error = ?e, "failed to unlink IPC request SHM doorbells");
        }
        if let Err(e) = res_ring.unlink_doorbells() {
            warn!(error = ?e, "failed to unlink IPC response SHM doorbells");
        }
    }

    let plan = match plan_ipc_request(meta, router, max_params_bytes, max_stdin_bytes)? {
        Ok(plan) => plan,
        Err(response) => {
            let _ = write_shm_plain_response(stream, &mut res_ring, &response, input_idle).await;
            drain_req_ring(
                &req_path,
                &mut req_ring,
                input_idle,
                shm_reusable,
                max_stdin_bytes,
            )
            .await;
            release_ipc_shm_path(&res_path, shm_reusable);
            return Ok(());
        }
    };

    let _permit = match Arc::clone(semaphore).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let response = IpcPlainResponse::new(503, b"overloaded");
            let _ = write_shm_plain_response(stream, &mut res_ring, &response, input_idle).await;
            drain_req_ring(
                &req_path,
                &mut req_ring,
                input_idle,
                shm_reusable,
                max_stdin_bytes,
            )
            .await;
            release_ipc_shm_path(&res_path, shm_reusable);
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
            drain_req_ring(
                &req_path,
                &mut req_ring,
                input_idle,
                shm_reusable,
                max_stdin_bytes,
            )
            .await;
            release_ipc_shm_path(&res_path, shm_reusable);
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
            release_ipc_shm_path(req_path_task, shm_reusable);
            return;
        }
        let mut data = Vec::new();
        loop {
            match ring.try_pop_into(&mut data) {
                Ok(true) => {
                    if data.is_empty() {
                        if expected_stdin_bytes.is_some_and(|expected| stdin_bytes < expected) {
                            outcome = StdinReadOutcome::Truncated;
                        }
                        break; // EOF
                    }
                    if stdin_chunk_exceeds_declared_length(
                        expected_stdin_bytes,
                        stdin_bytes,
                        data.len(),
                    ) {
                        outcome = StdinReadOutcome::LengthMismatch;
                        break;
                    }
                    stdin_bytes = stdin_bytes.saturating_add(data.len());
                    if stdin_bytes > max_stdin_bytes {
                        outcome = StdinReadOutcome::TooLarge;
                        break;
                    }
                    let cap = data.capacity();
                    let chunk = Bytes::from(std::mem::replace(&mut data, Vec::with_capacity(cap)));
                    if exec_stdin.send(chunk).await.is_err() {
                        break;
                    }
                    if expected_stdin_bytes.is_some_and(|expected| stdin_bytes >= expected) {
                        break;
                    }
                }
                Ok(false) => {
                    let waited = timeout(input_idle, ring.wait_for_data()).await;
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
        release_ipc_shm_path(req_path_task, shm_reusable);
    });

    // Read until headers are fully accumulated
    let mut header_buf = BytesMut::new();
    tokio::pin!(stdin_result_rx);
    let mut stdin_result_rx_active = true;
    let parsed_res = loop {
        tokio::select! {
            res = &mut stdin_result_rx, if stdin_result_rx_active => {
                match res {
                    Ok(outcome) => {
                        if let Some((status, body)) = outcome.error_response() {
                            let res_meta = text_plain_meta(status);
                            write_frame(stream, &res_meta).await?;
                            let _ = push_ring_bytes(&mut res_ring, body, input_idle).await;
                            let _ = push_ring_eof(&mut res_ring, input_idle).await;
                            abort_execution(exec_abort, stdin_task, exec_done).await;
                            release_ipc_shm_path(&res_path, shm_reusable);
                            return Ok(());
                        }
                        stdin_result_rx_active = false;
                    }
                    _ => {
                        stdin_result_rx_active = false;
                    }
                }
            }
            chunk = exec_stdout.recv() => {
                let Some(chunk) = chunk else {
                    break None;
                };
                match consume_cgi_stdout_header(&mut header_buf, chunk) {
                    Ok(Some(parsed)) => break Some(parsed),
                    Ok(None) => {}
                    Err(_) => break None,
                }
            }
        }
    };

    if stdin_result_rx_active {
        if let Ok(outcome) = (&mut stdin_result_rx).await {
            if let Some((status, body)) = outcome.error_response() {
                let res_meta = text_plain_meta(status);
                write_frame(stream, &res_meta).await?;
                let _ = push_ring_bytes(&mut res_ring, body, input_idle).await;
                let _ = push_ring_eof(&mut res_ring, input_idle).await;
                abort_execution(exec_abort, stdin_task, exec_done).await;
                release_ipc_shm_path(&res_path, shm_reusable);
                return Ok(());
            }
        }
    }

    let (res_meta, body_leftover) = if let Some(parsed) = parsed_res {
        (parsed.meta, parsed.body_leftover)
    } else {
        let meta = text_plain_meta(502);
        write_frame(stream, &meta).await?;
        let _ = push_ring_bytes(
            &mut res_ring,
            b"bad gateway (invalid CGI headers)",
            input_idle,
        )
        .await;
        let _ = push_ring_eof(&mut res_ring, input_idle).await;
        abort_execution(exec_abort, stdin_task, exec_done).await;
        release_ipc_shm_path(&res_path, shm_reusable);
        return Ok(());
    };

    // Write IpcResponseMeta
    write_frame(stream, &res_meta).await?;

    // Handle initial leftover stdout body bytes
    if !body_leftover.is_empty()
        && push_ring_bytes(&mut res_ring, body_leftover.as_ref(), input_idle)
            .await
            .is_err()
    {
        abort_execution(exec_abort, stdin_task, exec_done).await;
        release_ipc_shm_path(&res_path, shm_reusable);
        return Ok(());
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
        release_ipc_shm_path(res_path_task, shm_reusable);
    });

    let stderr_task = tokio::spawn(async move {
        while let Some(chunk) = exec_stderr.recv().await {
            log_executor_stderr_chunk(&chunk);
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

pub(super) struct TcpRequestContext {
    pub(super) router: Arc<Router>,
    pub(super) semaphore: Arc<Semaphore>,
    pub(super) input_idle: Duration,
    pub(super) output_idle: Duration,
    pub(super) max_params_bytes: usize,
    pub(super) max_stdin_bytes: usize,
}

pub(super) async fn handle_one_request_tcp<S>(
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
            let mut drained = 0usize;
            loop {
                let n = match timeout(input_idle, stream.read(&mut buf)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                };
                drained = drained.saturating_add(n);
                if drained > max_stdin_bytes {
                    warn!(
                        drained,
                        max_stdin_bytes, "IPC TCP rejected request drain exceeded limit"
                    );
                    break;
                }
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
        let mut stdin_bytes: usize = 0;
        let mut stdin_result_tx = Some(stdin_result_tx);
        let mut outcome = StdinReadOutcome::Complete;
        if expected_stdin_bytes == Some(0) {
            let _ = stdin_result_tx.take().and_then(|tx| tx.send(outcome).ok());
            return;
        }
        let mut buf = BytesMut::with_capacity(65536);
        loop {
            buf.clear();
            buf.reserve(65536);
            let n = match timeout(input_idle, rx.read_buf(&mut buf)).await {
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
            if stdin_chunk_exceeds_declared_length(expected_stdin_bytes, stdin_bytes, n) {
                outcome = StdinReadOutcome::LengthMismatch;
                break;
            }
            stdin_bytes = stdin_bytes.saturating_add(n);
            if stdin_bytes > max_stdin_bytes {
                outcome = StdinReadOutcome::TooLarge;
                break;
            }
            if exec_stdin.send(buf.split().freeze()).await.is_err() {
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
    tokio::pin!(stdin_result_rx);
    let mut stdin_result_rx_active = true;
    let parsed_res = loop {
        tokio::select! {
            res = &mut stdin_result_rx, if stdin_result_rx_active => {
                match res {
                    Ok(outcome) => {
                        if let Some((status, body)) = outcome.error_response() {
                            let res_meta = text_plain_meta(status);
                            write_frame_with_timeout(&mut tx, &res_meta, output_idle).await?;
                            let _ = write_all_with_timeout(&mut tx, body, output_idle).await;
                            abort_execution(exec_abort, stdin_task, exec_done).await;
                            return Ok(());
                        }
                        stdin_result_rx_active = false;
                    }
                    _ => {
                        stdin_result_rx_active = false;
                    }
                }
            }
            chunk = exec_stdout.recv() => {
                let Some(chunk) = chunk else {
                    break None;
                };
                match consume_cgi_stdout_header(&mut header_buf, chunk) {
                    Ok(Some(parsed)) => break Some(parsed),
                    Ok(None) => {}
                    Err(_) => break None,
                }
            }
        }
    };

    if stdin_result_rx_active {
        if let Ok(outcome) = (&mut stdin_result_rx).await {
            if let Some((status, body)) = outcome.error_response() {
                let res_meta = text_plain_meta(status);
                write_frame_with_timeout(&mut tx, &res_meta, output_idle).await?;
                let _ = write_all_with_timeout(&mut tx, body, output_idle).await;
                abort_execution(exec_abort, stdin_task, exec_done).await;
                return Ok(());
            }
        }
    }

    let (res_meta, body_leftover) = if let Some(parsed) = parsed_res {
        (parsed.meta, parsed.body_leftover)
    } else {
        // Executor ended before headers were completed.
        let meta = text_plain_meta(502);
        write_frame_with_timeout(&mut tx, &meta, output_idle).await?;
        write_all_with_timeout(&mut tx, b"bad gateway (no output)", output_idle).await?;
        abort_execution(exec_abort, stdin_task, exec_done).await;
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
            log_executor_stderr_chunk(&chunk);
        }
    });

    let _ = exec_done.await;
    let _ = stdin_task.await;
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_stdin_length_rejects_oversized_chunk_before_executor_send() {
        assert!(!stdin_chunk_exceeds_declared_length(Some(5), 0, 5));
        assert!(!stdin_chunk_exceeds_declared_length(Some(5), 3, 2));
        assert!(stdin_chunk_exceeds_declared_length(Some(5), 0, 6));
        assert!(stdin_chunk_exceeds_declared_length(Some(5), 4, 2));
        assert!(!stdin_chunk_exceeds_declared_length(None, usize::MAX, 1));
    }

    #[test]
    fn cgi_header_terminator_detects_boundary_and_chunk_local_sequences() {
        assert_eq!(
            find_cgi_header_terminator(b"X\r\n", b"\r\nbody"),
            Some((1, 4))
        );
        assert_eq!(
            find_cgi_header_terminator(b"", b"Status: 200\r\n\r\nbody"),
            Some((11, 4))
        );
        assert_eq!(find_cgi_header_terminator(b"X\n", b"\nbody"), Some((1, 2)));
        assert_eq!(find_cgi_header_terminator(b"", b"Status: 200"), None);
    }
}
