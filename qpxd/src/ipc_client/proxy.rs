use super::backend::IpcBackend;
use super::meta::build_ipc_meta;
use super::pool::{PooledIpcConnection, checkin_stream, checkout_stream};
use super::shm::{
    IPC_DOWNSTREAM_ABORT_POLL_INTERVAL, IpcShmPair, SHM_RING_SIZE, abort_shm_request_writer,
    downstream_body_closed, maybe_cleanup_ipc_shm_dir, read_shm_response_meta_after_body_writer,
    take_or_finish_req_ring, write_request_body_to_shm,
};
use super::{ClientConnInfo, IpcUpstream};
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use hyper::{Request, Response, StatusCode};
use qpx_core::config::IpcMode;
use qpx_core::ipc::meta::IpcResponseMeta;
use qpx_core::ipc::protocol::{read_frame, write_frame};
use qpx_http::body::{Body, Sender};
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};
use tracing::warn;
use url::Url;

pub(crate) async fn proxy_ipc(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    url: &Url,
    _proxy_name: &str,
) -> Result<Response<Body>> {
    let mode = IpcMode::Tcp;
    let backend = match url.scheme() {
        "ipc" => {
            let host = url.host_str().ok_or_else(|| anyhow!("missing IPC host"))?;
            let port = url.port().unwrap_or(9000);
            IpcBackend::Tcp {
                host: host.to_string(),
                port,
            }
        }
        #[cfg(unix)]
        "ipc+unix" => IpcBackend::Unix {
            path: PathBuf::from(url.path()),
        },
        _ => return Err(anyhow!("unsupported IPC url scheme: {}", url.scheme())),
    };
    proxy_ipc_backend(
        pools.ipc.clone(),
        req,
        IpcBackendRequest {
            backend: &backend,
            mode,
            conn: ClientConnInfo::default(),
            max_request_bytes: None,
            max_response_bytes: None,
            timeout_dur: Duration::from_secs(30),
        },
    )
    .await
}

pub(crate) async fn proxy_ipc_upstream(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    upstream: &IpcUpstream,
    _proxy_name: &str,
    conn: ClientConnInfo,
    route_timeout: Duration,
) -> Result<Response<Body>> {
    let timeout_dur = upstream.effective_timeout(route_timeout);
    proxy_ipc_backend(
        pools.ipc.clone(),
        req,
        IpcBackendRequest {
            backend: &upstream.backend,
            mode: upstream.mode.clone(),
            conn,
            max_request_bytes: upstream.max_request_bytes,
            max_response_bytes: upstream.max_response_bytes,
            timeout_dur,
        },
    )
    .await
}

struct IpcBackendRequest<'a> {
    backend: &'a IpcBackend,
    mode: IpcMode,
    conn: ClientConnInfo,
    max_request_bytes: Option<usize>,
    max_response_bytes: Option<usize>,
    timeout_dur: Duration,
}

async fn proxy_ipc_backend(
    ipc_pool: Arc<crate::ipc_client::IpcConnectionPool>,
    mut req: Request<Body>,
    backend_request: IpcBackendRequest<'_>,
) -> Result<Response<Body>> {
    let IpcBackendRequest {
        backend,
        mode,
        conn,
        max_request_bytes,
        max_response_bytes,
        timeout_dur,
    } = backend_request;
    let mut meta = build_ipc_meta(&req, conn);

    let (pool_key, mut conn) = checkout_stream(&ipc_pool, backend, timeout_dur).await?;
    let mut pending_req_ring = None;
    let mut body_writer = None;

    if mode == IpcMode::Shm {
        let shm_dir = qpx_core::ipc::shm::ipc_shm_dir()?;
        maybe_cleanup_ipc_shm_dir(&shm_dir);
        if conn.shm.is_none() {
            conn.shm = Some(IpcShmPair::create()?);
        }
        let shm = conn
            .shm
            .as_mut()
            .ok_or_else(|| anyhow!("IPC SHM pair missing after setup"))?;
        shm.reset();
        meta.req_body_shm_path = Some(shm.req_token.clone());
        meta.req_body_shm_size_bytes = Some(SHM_RING_SIZE);
        meta.res_body_shm_path = Some(shm.res_token.clone());
        meta.res_body_shm_size_bytes = Some(SHM_RING_SIZE);
        meta.shm_reusable = true;
    }

    write_frame(&mut conn.stream, &meta).await?;

    if mode == IpcMode::Shm {
        let req_ring = conn
            .shm
            .as_mut()
            .ok_or_else(|| anyhow!("IPC SHM pair missing before request body writer"))?
            .take_req_ring()?;
        let handle = tokio::spawn(async move {
            write_request_body_to_shm(req.body_mut(), req_ring, max_request_bytes, timeout_dur)
                .await
        });
        body_writer = Some(handle);
    } else {
        write_tcp_request_body(&mut req, &mut conn, max_request_bytes, timeout_dur).await?;
    }

    let res_meta: IpcResponseMeta = if let Some(writer) = body_writer.as_mut() {
        let (meta, req_ring) =
            read_shm_response_meta_after_body_writer(&mut conn.stream, writer).await?;
        pending_req_ring = req_ring;
        meta
    } else {
        read_frame(&mut conn.stream).await?
    };

    let mut builder = Response::builder().status(validate_ipc_response_status(res_meta.status)?);
    for (k, v) in res_meta.headers {
        builder = builder.header(k, v);
    }

    let (mut sender, body) = Body::channel_with_capacity(16);

    if mode == IpcMode::Shm {
        let mut shm = conn
            .shm
            .take()
            .ok_or_else(|| anyhow!("IPC SHM pair missing before response body reader"))?;
        let mut res_ring = shm.take_res_ring()?;
        let mut body_writer = body_writer
            .take()
            .ok_or_else(|| anyhow!("IPC SHM request body writer missing"))?;
        let ipc_pool = ipc_pool.clone();
        tokio::spawn(async move {
            let mut reusable = true;
            let mut seen = 0usize;
            let mut data = Vec::new();
            loop {
                match res_ring.try_pop_into(&mut data) {
                    Ok(true) => {
                        if data.is_empty() {
                            break;
                        }
                        seen = match seen.checked_add(data.len()) {
                            Some(seen) => seen,
                            None => {
                                sender.abort();
                                reusable = false;
                                break;
                            }
                        };
                        if let Some(limit) = max_response_bytes
                            && seen > limit
                        {
                            sender.abort();
                            reusable = false;
                            break;
                        }
                        let cap = data.capacity();
                        let chunk =
                            Bytes::from(std::mem::replace(&mut data, Vec::with_capacity(cap)));
                        if sender.send_data(chunk).await.is_err() {
                            reusable = false;
                            break;
                        }
                    }
                    Ok(false) => {
                        tokio::select! {
                            wait = timeout(timeout_dur, res_ring.wait_for_data()) => {
                                match wait {
                                    Ok(Ok(())) => {}
                                    Ok(Err(_)) => {
                                        reusable = false;
                                        break;
                                    }
                                    Err(_) => {
                                        sender.abort();
                                        reusable = false;
                                        break;
                                    }
                                }
                            }
                            _ = tokio::time::sleep(IPC_DOWNSTREAM_ABORT_POLL_INTERVAL) => {
                                if downstream_body_closed(&mut sender).await {
                                    reusable = false;
                                    break;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        reusable = false;
                        break;
                    }
                }
            }
            if reusable {
                match take_or_finish_req_ring(pending_req_ring, &mut body_writer).await {
                    Ok(req_ring) => {
                        shm.restore_req_ring(req_ring);
                        shm.restore_res_ring(res_ring);
                        checkin_stream(
                            &ipc_pool,
                            pool_key,
                            PooledIpcConnection {
                                stream: conn.stream,
                                shm: Some(shm),
                                active_permit: conn.active_permit.take(),
                            },
                        )
                        .await;
                        return;
                    }
                    Err(err) => {
                        warn!(error = ?err, "IPC SHM request body writer prevented connection reuse");
                    }
                }
            }
            abort_shm_request_writer(&mut body_writer);
        });
    } else {
        spawn_tcp_response_reader(sender, conn, max_response_bytes, timeout_dur);
    }

    Ok(builder.body(body)?)
}

fn spawn_tcp_response_reader(
    mut sender: Sender,
    mut conn: PooledIpcConnection,
    max_response_bytes: Option<usize>,
    timeout_dur: Duration,
) {
    tokio::spawn(async move {
        let mut seen = 0usize;
        let mut buf = BytesMut::with_capacity(65536);
        loop {
            buf.clear();
            buf.reserve(65536);
            let read = tokio::select! {
                read = timeout(timeout_dur, conn.stream.read_buf(&mut buf)) => {
                    read.inspect_err(|_| sender.abort()).ok()
                }
                _ = tokio::time::sleep(IPC_DOWNSTREAM_ABORT_POLL_INTERVAL) => {
                    if downstream_body_closed(&mut sender).await {
                        None
                    } else {
                        continue;
                    }
                }
            };
            match read {
                None | Some(Ok(0)) | Some(Err(_)) => break,
                Some(Ok(n)) => {
                    let Some(next_seen) = seen.checked_add(n) else {
                        sender.abort();
                        break;
                    };
                    seen = next_seen;
                    if max_response_bytes.is_some_and(|limit| seen > limit) {
                        sender.abort();
                        break;
                    }
                    if sender.send_data(buf.split().freeze()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
}

async fn write_tcp_request_body(
    req: &mut Request<Body>,
    conn: &mut PooledIpcConnection,
    max_request_bytes: Option<usize>,
    timeout_dur: Duration,
) -> Result<()> {
    let mut seen = 0usize;
    while let Some(chunk) = timeout(timeout_dur, req.body_mut().data())
        .await
        .map_err(|_| anyhow!("IPC TCP request body read timed out"))?
    {
        let data = chunk?;
        seen = seen
            .checked_add(data.len())
            .ok_or_else(|| anyhow!("IPC request body size overflow"))?;
        if let Some(limit) = max_request_bytes
            && seen > limit
        {
            return Err(anyhow!("IPC request body exceeds max_request_bytes"));
        }
        timeout(timeout_dur, conn.stream.write_all(&data))
            .await
            .map_err(|_| anyhow!("IPC TCP request body write timed out"))??;
    }
    timeout(timeout_dur, conn.stream.shutdown())
        .await
        .map_err(|_| anyhow!("IPC TCP request body shutdown timed out"))??;
    Ok(())
}

pub(super) fn validate_ipc_response_status(status: u16) -> Result<StatusCode> {
    if !(100..=599).contains(&status) {
        return Err(anyhow!("IPC response status is out of range: {status}"));
    }
    StatusCode::from_u16(status).map_err(|err| anyhow!("invalid IPC response status: {err}"))
}
