use crate::http::body::Body;
use anyhow::{Result, anyhow};
use qpx_core::ipc::meta::IpcResponseMeta;
use qpx_core::ipc::protocol::read_frame;
use qpx_core::shm_ring::ShmRingBuffer;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use tokio::io::AsyncRead;
use tokio::time::{Duration, timeout};

pub(super) const SHM_RING_SIZE: usize = 1024 * 1024;
pub(super) const IPC_DOWNSTREAM_ABORT_POLL_INTERVAL: Duration = Duration::from_millis(250);
static IPC_SHM_LAST_CLEANUP_UNIX_SECS: AtomicU64 = AtomicU64::new(0);

pub(super) fn maybe_cleanup_ipc_shm_dir(dir: &Path) {
    qpx_core::ipc::shm::maybe_cleanup_stale_ipc_shm_files(
        dir,
        &IPC_SHM_LAST_CLEANUP_UNIX_SECS,
        60,
        3600,
    );
}

pub(super) fn remove_ipc_shm_path(path: impl AsRef<Path>) {
    let path = path.as_ref();
    qpx_core::ipc::shm::unregister_ipc_shm_path(path);
    let _ = std::fs::remove_file(path);
}

const SHM_PUSH_CHUNK_BYTES: usize = 64 * 1024;

async fn push_request_ring_bytes(
    ring: &mut ShmRingBuffer,
    bytes: &[u8],
    timeout_dur: Duration,
) -> Result<()> {
    loop {
        match ring.try_push(bytes) {
            Ok(true) => return Ok(()),
            Ok(false) => {
                timeout(timeout_dur, ring.wait_for_space(bytes.len()))
                    .await
                    .map_err(|_| anyhow!("IPC SHM request body writer timed out"))??;
            }
            Err(err) => return Err(err),
        }
    }
}

pub(super) async fn write_request_body_to_shm(
    body: &mut Body,
    mut req_ring: ShmRingBuffer,
    max_request_bytes: Option<usize>,
    timeout_dur: Duration,
) -> Result<ShmRingBuffer> {
    let mut seen = 0usize;
    while let Some(chunk) = timeout(timeout_dur, body.data())
        .await
        .map_err(|_| anyhow!("IPC request body read timed out"))?
    {
        let data = chunk.map_err(|err| anyhow!("IPC request body read failed: {}", err))?;
        seen = seen
            .checked_add(data.len())
            .ok_or_else(|| anyhow!("IPC request body size overflow"))?;
        if let Some(limit) = max_request_bytes
            && seen > limit
        {
            return Err(anyhow!(
                "IPC request body exceeds max_request_bytes ({})",
                limit
            ));
        }
        for part in data.chunks(SHM_PUSH_CHUNK_BYTES) {
            push_request_ring_bytes(&mut req_ring, part, timeout_dur).await?;
        }
    }
    push_request_ring_bytes(&mut req_ring, &[], timeout_dur).await?;
    Ok(req_ring)
}

fn finish_shm_body_writer_result(
    body_result: std::result::Result<Result<ShmRingBuffer>, tokio::task::JoinError>,
) -> Result<ShmRingBuffer> {
    match body_result {
        Ok(Ok(ring)) => Ok(ring),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(anyhow!("IPC SHM request body writer ended unexpectedly")),
    }
}

pub(super) async fn read_shm_response_meta_after_body_writer<S>(
    stream: &mut S,
    body_writer: &mut tokio::task::JoinHandle<Result<ShmRingBuffer>>,
) -> Result<(IpcResponseMeta, Option<ShmRingBuffer>)>
where
    S: AsyncRead + Unpin,
{
    let pending_meta = tokio::select! {
        res = read_frame(stream) => Some(res?),
        body_result = body_writer => {
            let ring = finish_shm_body_writer_result(body_result)?;
            let meta = read_frame(stream).await?;
            return Ok((meta, Some(ring)));
        }
    };

    if let Some(meta) = pending_meta {
        Ok((meta, None))
    } else {
        unreachable!("tokio::select! always yields one branch")
    }
}

async fn finish_shm_request_writer(
    body_writer: &mut tokio::task::JoinHandle<Result<ShmRingBuffer>>,
) -> Result<ShmRingBuffer> {
    finish_shm_body_writer_result(body_writer.await)
}

pub(super) fn abort_shm_request_writer(
    body_writer: &mut tokio::task::JoinHandle<Result<ShmRingBuffer>>,
) {
    if !body_writer.is_finished() {
        body_writer.abort();
    }
}

pub(super) async fn take_or_finish_req_ring(
    req_ring: Option<ShmRingBuffer>,
    body_writer: &mut tokio::task::JoinHandle<Result<ShmRingBuffer>>,
) -> Result<ShmRingBuffer> {
    match req_ring {
        Some(ring) => Ok(ring),
        None if body_writer.is_finished() => finish_shm_request_writer(body_writer).await,
        None => Err(anyhow!("IPC SHM request body writer still running")),
    }
}

pub(super) async fn downstream_body_closed(sender: &mut crate::http::body::Sender) -> bool {
    sender.is_closed()
}

pub(super) struct IpcShmPair {
    pub(super) req_token: String,
    pub(super) res_token: String,
    req_path: PathBuf,
    res_path: PathBuf,
    req_ring: Option<ShmRingBuffer>,
    res_ring: Option<ShmRingBuffer>,
}

impl IpcShmPair {
    pub(super) fn create() -> Result<Self> {
        let uuid = uuid::Uuid::new_v4().to_string();
        let req_token = format!("ipc_req_{uuid}.shm");
        let res_token = format!("ipc_res_{uuid}.shm");
        let (req_path, req_ring) =
            qpx_core::ipc::shm::create_or_open_ipc_ring(&req_token, "ipc_req_", SHM_RING_SIZE)?;
        let (res_path, res_ring) =
            qpx_core::ipc::shm::create_or_open_ipc_ring(&res_token, "ipc_res_", SHM_RING_SIZE)?;
        Ok(Self {
            req_token,
            res_token,
            req_path,
            res_path,
            req_ring: Some(req_ring),
            res_ring: Some(res_ring),
        })
    }

    pub(super) fn reset(&mut self) {
        if let Some(ring) = self.req_ring.as_mut() {
            ring.reset();
        }
        if let Some(ring) = self.res_ring.as_mut() {
            ring.reset();
        }
    }

    pub(super) fn take_req_ring(&mut self) -> Result<ShmRingBuffer> {
        self.req_ring
            .take()
            .ok_or_else(|| anyhow!("IPC SHM request ring missing after setup"))
    }

    pub(super) fn take_res_ring(&mut self) -> Result<ShmRingBuffer> {
        self.res_ring
            .take()
            .ok_or_else(|| anyhow!("IPC SHM response ring missing after setup"))
    }

    pub(super) fn restore_req_ring(&mut self, ring: ShmRingBuffer) {
        self.req_ring = Some(ring);
    }

    pub(super) fn restore_res_ring(&mut self, ring: ShmRingBuffer) {
        self.res_ring = Some(ring);
    }

    fn cleanup_handles(&mut self) {
        if let Some(ring) = self.req_ring.take() {
            let _ = ring.unlink_doorbells();
        } else if let Ok(ring) = ShmRingBuffer::create_or_open(&self.req_path, SHM_RING_SIZE) {
            let _ = ring.unlink_doorbells();
        }
        if let Some(ring) = self.res_ring.take() {
            let _ = ring.unlink_doorbells();
        } else if let Ok(ring) = ShmRingBuffer::create_or_open(&self.res_path, SHM_RING_SIZE) {
            let _ = ring.unlink_doorbells();
        }
        remove_ipc_shm_path(&self.req_path);
        remove_ipc_shm_path(&self.res_path);
    }
}

impl Drop for IpcShmPair {
    fn drop(&mut self) {
        self.cleanup_handles();
    }
}
