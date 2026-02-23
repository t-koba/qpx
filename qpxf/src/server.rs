use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use http::Uri;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tracing::warn;

use crate::executor::{CgiRequest, CgiResponse, Execution};
use crate::router::Router;

use qpx_core::ipc::meta::{IpcRequestMeta, IpcResponseMeta};
use qpx_core::ipc::protocol::{read_frame, write_frame};
use qpx_core::shm_ring::ShmRingBuffer;

const MAX_IPC_SHM_RING_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

#[allow(clippy::too_many_arguments)]
pub async fn handle_connection<S>(
    mut stream: S,
    router: Arc<Router>,
    semaphore: Arc<Semaphore>,
    input_idle: Duration,
    conn_idle: Duration,
    max_requests_per_connection: usize,
    max_params_bytes: usize,
    max_stdin_bytes: usize,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
            router,
            semaphore,
            input_idle,
            max_params_bytes,
            max_stdin_bytes,
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

fn meta_params_bytes(meta: &IpcRequestMeta) -> usize {
    meta.params
        .iter()
        .map(|(k, v)| k.len().saturating_add(v.len()))
        .sum()
}

fn is_unexpected_eof(err: &anyhow::Error) -> bool {
    err.downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof)
}

fn ensure_secure_dir(dir: &Path) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(dir) {
        if meta.file_type().is_symlink() {
            return Err(anyhow!("refusing symlink directory: {}", dir.display()));
        }
        if !meta.is_dir() {
            return Err(anyhow!("path is not a directory: {}", dir.display()));
        }
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| anyhow!("failed to create directory {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            anyhow!(
                "failed to set permissions on directory {}: {e}",
                dir.display()
            )
        })?;
    }
    Ok(())
}

fn ipc_shm_dir() -> Result<PathBuf> {
    let base = ShmRingBuffer::default_shm_dir();
    ensure_secure_dir(&base)?;
    let ipc = base.join("ipc");
    ensure_secure_dir(&ipc)?;
    Ok(ipc)
}

fn validate_ipc_shm_token(token: &str, expected_prefix: &str) -> Result<()> {
    if token.len() > 255 {
        return Err(anyhow!("IPC SHM token is too long"));
    }
    if !token.is_ascii() {
        return Err(anyhow!("IPC SHM token must be ASCII"));
    }
    if token.contains('/') || token.contains('\\') || token.contains("..") {
        return Err(anyhow!("IPC SHM token contains forbidden path characters"));
    }
    if !token.starts_with(expected_prefix) || !token.ends_with(".shm") {
        return Err(anyhow!("IPC SHM token has unexpected format"));
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(anyhow!("IPC SHM token contains invalid characters"));
    }
    Ok(())
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

async fn push_ring_bytes(ring: &mut ShmRingBuffer, bytes: &[u8]) -> Result<()> {
    loop {
        match ring.try_push(bytes) {
            Ok(true) => return Ok(()),
            Ok(false) => ring.wait_for_space(bytes.len()).await?,
            Err(e) => return Err(e),
        }
    }
}

async fn push_ring_eof(ring: &mut ShmRingBuffer) -> Result<()> {
    push_ring_bytes(ring, &[]).await
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
    let shm_dir = ipc_shm_dir()?;
    let req_path = shm_dir.join(req_token);
    let res_path = shm_dir.join(res_token);

    let mut req_ring = ShmRingBuffer::create_or_open(&req_path, req_size)?;
    let mut res_ring = ShmRingBuffer::create_or_open(&res_path, res_size)?;

    // Per-request SHM doorbells should not leak named kernel objects (notably on macOS).
    if let Err(e) = req_ring.unlink_doorbells() {
        warn!(error = ?e, "failed to unlink IPC request SHM doorbells");
    }
    if let Err(e) = res_ring.unlink_doorbells() {
        warn!(error = ?e, "failed to unlink IPC response SHM doorbells");
    }

    if meta_params_bytes(&meta) > max_params_bytes {
        let res_meta = IpcResponseMeta {
            status: 413,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
        };
        write_frame(stream, &res_meta).await?;
        let _ = push_ring_bytes(&mut res_ring, b"params too large").await;
        let _ = push_ring_eof(&mut res_ring).await;
        drain_req_ring(&req_path, &mut req_ring, input_idle).await;
        let _ = std::fs::remove_file(&res_path);
        return Ok(());
    }

    let uri: Uri = meta
        .uri
        .parse()
        .map_err(|e| anyhow!("invalid IPC request URI '{}': {e}", meta.uri))?;
    let script_name = uri.path().to_string();
    let query_string = uri.query().unwrap_or("").to_string();
    let header_host = meta
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str());
    let route_host = header_host
        .and_then(host_only)
        .or_else(|| uri.authority().and_then(|a| host_only(a.as_str())));

    let (executor, matched_prefix) = match router.route(script_name.as_str(), route_host.as_deref())
    {
        Some(v) => v,
        None => {
            let res_meta = IpcResponseMeta {
                status: 404,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            };
            write_frame(stream, &res_meta).await?;
            let _ = push_ring_bytes(&mut res_ring, b"no handler matched").await;
            let _ = push_ring_eof(&mut res_ring).await;
            drain_req_ring(&req_path, &mut req_ring, input_idle).await;
            let _ = std::fs::remove_file(&res_path);
            return Ok(());
        }
    };

    let _permit = match Arc::clone(semaphore).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let res_meta = IpcResponseMeta {
                status: 503,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            };
            write_frame(stream, &res_meta).await?;
            let _ = push_ring_bytes(&mut res_ring, b"overloaded").await;
            let _ = push_ring_eof(&mut res_ring).await;
            drain_req_ring(&req_path, &mut req_ring, input_idle).await;
            let _ = std::fs::remove_file(&res_path);
            return Ok(());
        }
    };

    let header_host = header_host.or_else(|| uri.authority().map(|a| a.as_str()));
    let (server_name, server_port) = header_host
        .map(host_port)
        .unwrap_or((Some("localhost".to_string()), Some(80)));

    let cgi_req = CgiRequest {
        script_name: script_name.clone(),
        path_info: String::new(),
        query_string: query_string.clone(),
        request_method: meta.method.clone(),
        content_type: meta
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default(),
        content_length: meta
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0),
        server_protocol: "HTTP/1.1".to_string(),
        server_name: server_name.unwrap_or_else(|| "localhost".to_string()),
        server_port: server_port.unwrap_or(80),
        remote_addr: meta.params.get("REMOTE_ADDR").cloned(),
        remote_port: meta.params.get("REMOTE_PORT").and_then(|p| p.parse().ok()),
        http_headers: cgi_header_map(meta.headers),
        matched_prefix: matched_prefix.clone(),
    };

    if cgi_req.content_length > max_stdin_bytes {
        let res_meta = IpcResponseMeta {
            status: 413,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
        };
        write_frame(stream, &res_meta).await?;
        let _ = push_ring_bytes(&mut res_ring, b"request body too large").await;
        let _ = push_ring_eof(&mut res_ring).await;
        drain_req_ring(&req_path, &mut req_ring, input_idle).await;
        let _ = std::fs::remove_file(&res_path);
        return Ok(());
    }

    let exec = match executor.start(cgi_req).await {
        Ok(exec) => exec,
        Err(e) => {
            let res_meta = IpcResponseMeta {
                status: 502,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            };
            write_frame(stream, &res_meta).await?;
            let msg = format!("executor start error: {}", e);
            let _ = push_ring_bytes(&mut res_ring, msg.as_bytes()).await;
            let _ = push_ring_eof(&mut res_ring).await;
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
    let (too_large_tx, too_large_rx) = oneshot::channel::<()>();
    let stdin_task = tokio::spawn(async move {
        let mut stdin_open = true;
        let mut stdin_bytes: usize = 0;
        let mut too_large_tx = Some(too_large_tx);
        let mut ring = req_ring;
        loop {
            match ring.try_pop() {
                Ok(Some(data)) => {
                    if data.is_empty() {
                        break; // EOF
                    }
                    stdin_bytes = stdin_bytes.saturating_add(data.len());
                    if stdin_bytes > max_stdin_bytes_for_task {
                        if let Some(tx) = too_large_tx.take() {
                            let _ = tx.send(());
                        }
                        stdin_open = false;
                        continue; // drain to EOF
                    }
                    if stdin_open && exec_stdin.send(Bytes::from(data)).await.is_err() {
                        stdin_open = false;
                    }
                }
                Ok(None) => {
                    let waited = timeout(input_idle_for_task, ring.wait_for_data()).await;
                    if waited.is_err() || waited.is_ok_and(|r| r.is_err()) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        drop(ring);
        let _ = std::fs::remove_file(req_path_task);
    });

    // Read until headers are fully accumulated
    let mut header_buf = BytesMut::new();
    let too_large_rx = too_large_rx;
    tokio::pin!(too_large_rx);
    let mut too_large_rx_active = true;
    let parsed_res = loop {
        tokio::select! {
            res = &mut too_large_rx, if too_large_rx_active => {
                match res {
                    Ok(()) => {
                        let res_meta = IpcResponseMeta {
                            status: 413,
                            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                        };
                        write_frame(stream, &res_meta).await?;
                        let _ = push_ring_bytes(&mut res_ring, b"request body too large").await;
                        let _ = push_ring_eof(&mut res_ring).await;
                        let _ = exec_abort.send(());
                        let _ = stdin_task.await;
                        let _ = exec_done.await;
                        let _ = std::fs::remove_file(&res_path);
                        return Ok(());
                    }
                    Err(_) => {
                        too_large_rx_active = false;
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
        let _ = push_ring_bytes(&mut res_ring, b"bad gateway (invalid CGI headers)").await;
        let _ = push_ring_eof(&mut res_ring).await;
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
        let _ = push_ring_bytes(&mut res_ring, body_leftover.as_ref()).await;
    }

    // Task to forward executor STDOUT to response ring
    let res_path_task = res_path.clone();
    let stdout_task = tokio::spawn(async move {
        let mut ring = res_ring;
        while let Some(chunk) = exec_stdout.recv().await {
            if push_ring_bytes(&mut ring, &chunk).await.is_err() {
                break;
            }
        }
        let _ = push_ring_eof(&mut ring).await;
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

async fn handle_one_request_tcp<S>(
    mut stream: S,
    meta: IpcRequestMeta,
    router: Arc<Router>,
    semaphore: Arc<Semaphore>,
    input_idle: Duration,
    max_params_bytes: usize,
    max_stdin_bytes: usize,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if meta_params_bytes(&meta) > max_params_bytes {
        let res_meta = IpcResponseMeta {
            status: 413,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
        };
        write_frame(&mut stream, &res_meta).await?;
        stream.write_all(b"params too large").await?;
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

    let uri: Uri = meta
        .uri
        .parse()
        .map_err(|e| anyhow!("invalid IPC request URI '{}': {e}", meta.uri))?;
    let script_name = uri.path().to_string();
    let query_string = uri.query().unwrap_or("").to_string();
    let header_host = meta
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str());
    let route_host = header_host
        .and_then(host_only)
        .or_else(|| uri.authority().and_then(|a| host_only(a.as_str())));

    let (executor, matched_prefix) = match router.route(script_name.as_str(), route_host.as_deref())
    {
        Some(v) => v,
        None => {
            let res_meta = IpcResponseMeta {
                status: 404,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            };
            write_frame(&mut stream, &res_meta).await?;
            stream.write_all(b"no handler matched").await?;
            return Ok(());
        }
    };

    let header_host = header_host.or_else(|| uri.authority().map(|a| a.as_str()));
    let (server_name, server_port) = header_host
        .map(host_port)
        .unwrap_or((Some("localhost".to_string()), Some(80)));

    let cgi_req = CgiRequest {
        script_name: script_name.clone(),
        path_info: String::new(),
        query_string: query_string.clone(),
        request_method: meta.method.clone(),
        content_type: meta
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default(),
        content_length: meta
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0),
        server_protocol: "HTTP/1.1".to_string(),
        server_name: server_name.unwrap_or_else(|| "localhost".to_string()),
        server_port: server_port.unwrap_or(80),
        remote_addr: meta.params.get("REMOTE_ADDR").cloned(),
        remote_port: meta.params.get("REMOTE_PORT").and_then(|p| p.parse().ok()),
        http_headers: cgi_header_map(meta.headers),
        matched_prefix: matched_prefix.clone(),
    };

    let _permit = match Arc::clone(&semaphore).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let res_meta = IpcResponseMeta {
                status: 503,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            };
            write_frame(&mut stream, &res_meta).await?;
            stream.write_all(b"overloaded").await?;
            return Ok(());
        }
    };

    if cgi_req.content_length > max_stdin_bytes {
        let res_meta = IpcResponseMeta {
            status: 413,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
        };
        write_frame(&mut stream, &res_meta).await?;
        stream.write_all(b"request body too large").await?;
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

    let exec = match executor.start(cgi_req).await {
        Ok(exec) => exec,
        Err(e) => {
            let res_meta = IpcResponseMeta {
                status: 502,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            };
            write_frame(&mut stream, &res_meta).await?;
            let msg = format!("executor start error: {}", e);
            stream.write_all(msg.as_bytes()).await?;
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
    let (too_large_tx, too_large_rx) = oneshot::channel::<()>();
    let stdin_task = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        let mut stdin_open = true;
        let mut stdin_bytes: usize = 0;
        let mut too_large_tx = Some(too_large_tx);
        loop {
            let n = match timeout(input_idle, rx.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                _ => break,
            };
            stdin_bytes = stdin_bytes.saturating_add(n);
            if stdin_bytes > max_stdin_bytes {
                if let Some(tx) = too_large_tx.take() {
                    let _ = tx.send(());
                }
                stdin_open = false;
                continue; // drain to EOF
            }
            if stdin_open
                && exec_stdin
                    .send(Bytes::copy_from_slice(&buf[..n]))
                    .await
                    .is_err()
            {
                stdin_open = false;
            }
        }
    });

    let mut header_buf = BytesMut::new();
    let too_large_rx = too_large_rx;
    tokio::pin!(too_large_rx);
    let mut too_large_rx_active = true;
    let parsed_res = loop {
        tokio::select! {
            res = &mut too_large_rx, if too_large_rx_active => {
                match res {
                    Ok(()) => {
                        let res_meta = IpcResponseMeta {
                            status: 413,
                            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                        };
                        write_frame(&mut tx, &res_meta).await?;
                        let _ = tx.write_all(b"request body too large").await;
                        let _ = exec_abort.send(());
                        let _ = stdin_task.await;
                        let _ = exec_done.await;
                        return Ok(());
                    }
                    Err(_) => {
                        too_large_rx_active = false;
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
        write_frame(&mut tx, &meta).await?;
        tx.write_all(b"bad gateway (no output)").await?;
        return Ok(());
    };

    // Write IpcResponseMeta
    write_frame(&mut tx, &res_meta).await?;

    // Handle initial leftover stdout body bytes
    if !body_leftover.is_empty() {
        tx.write_all(&body_leftover).await?;
    }

    // Task to forward executor STDOUT to stream
    let stdout_task = tokio::spawn(async move {
        while let Some(chunk) = exec_stdout.recv().await {
            if tx.write_all(&chunk).await.is_err() {
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
