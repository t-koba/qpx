use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use qpx_http::body::Body;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::time::timeout;

const CACHE_BODY_MEMORY_BYTES: usize = 64 * 1024;
const CACHE_BODY_FILE_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct CachedBodyStream {
    pub(crate) len: u64,
    pub(crate) body: Body,
}

#[derive(Debug, Clone)]
pub enum CachedBody {
    Memory(Bytes),
    File(Arc<CachedBodyFile>),
}

#[derive(Debug)]
pub struct CachedBodyFile {
    path: PathBuf,
    len: u64,
}

impl Drop for CachedBodyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Default for CachedBody {
    fn default() -> Self {
        Self::Memory(Bytes::new())
    }
}

impl CachedBody {
    pub(crate) fn from_bytes(bytes: Bytes) -> Self {
        Self::Memory(bytes)
    }

    pub(crate) fn from_spooled_file(path: PathBuf, len: u64) -> Self {
        Self::File(Arc::new(CachedBodyFile { path, len }))
    }

    pub(crate) fn len(&self) -> u64 {
        match self {
            Self::Memory(bytes) => bytes.len() as u64,
            Self::File(file) => file.len,
        }
    }

    pub(crate) fn to_body(&self) -> Body {
        match self {
            Self::Memory(bytes) => Body::from(bytes.clone()),
            Self::File(file) => file.body(None, None),
        }
    }

    pub(crate) fn slice_to_body(&self, start: u64, end_inclusive: u64) -> Body {
        match self {
            Self::Memory(bytes) => {
                let start = start as usize;
                let end = end_inclusive as usize;
                Body::from(bytes.slice(start..end + 1))
            }
            Self::File(file) => file.body(Some((start, end_inclusive)), None),
        }
    }

    pub(crate) async fn from_body_limited(
        mut body: Body,
        max_body_bytes: usize,
        body_read_timeout: Duration,
    ) -> Result<Self> {
        let mut chunks = Vec::new();
        let mut file: Option<(TokioFile, PathBuf)> = None;
        let mut size = 0usize;
        while let Some(chunk) = timeout(body_read_timeout, body.data())
            .await
            .map_err(|_| anyhow!("cache object body read timed out"))?
        {
            let chunk = chunk?;
            let next = size
                .checked_add(chunk.len())
                .ok_or_else(|| anyhow!("cache object length overflow"))?;
            if next > max_body_bytes {
                return Err(anyhow!(
                    "cache object exceeds configured limit: {} bytes",
                    max_body_bytes
                ));
            }
            size = next;
            if file.is_none() && size <= CACHE_BODY_MEMORY_BYTES {
                chunks.push(chunk);
                continue;
            }
            if file.is_none() {
                let (mut spool, path) = create_cache_body_spool()?;
                for existing in chunks.drain(..) {
                    spool.write_all(existing.as_ref()).await?;
                }
                file = Some((spool, path));
            }
            if let Some((spool, _)) = file.as_mut() {
                spool.write_all(chunk.as_ref()).await?;
            }
        }
        if let Some((mut spool, path)) = file {
            spool.flush().await?;
            drop(spool);
            return Ok(Self::File(Arc::new(CachedBodyFile {
                path,
                len: size as u64,
            })));
        }
        Ok(Self::Memory(bytes_from_chunks(chunks)))
    }
}

impl CachedBodyFile {
    fn body(
        self: &Arc<Self>,
        range: Option<(u64, u64)>,
        trailers: Option<http::HeaderMap>,
    ) -> Body {
        let (mut sender, body) = Body::channel_with_capacity(16);
        let file_ref = self.clone();
        tokio::spawn(async move {
            let result = async {
                let mut file = TokioFile::open(&file_ref.path).await?;
                let mut remaining = match range {
                    Some((start, end)) => {
                        use tokio::io::AsyncSeekExt;
                        file.seek(std::io::SeekFrom::Start(start)).await?;
                        end.saturating_sub(start).saturating_add(1)
                    }
                    None => file_ref.len,
                };
                let mut buf = BytesMut::with_capacity(CACHE_BODY_FILE_CHUNK_BYTES);
                while remaining > 0 {
                    let want = remaining.min(CACHE_BODY_FILE_CHUNK_BYTES as u64) as usize;
                    buf.clear();
                    buf.reserve(want);
                    let read = (&mut file).take(want as u64).read_buf(&mut buf).await?;
                    if read == 0 {
                        break;
                    }
                    remaining = remaining.saturating_sub(read as u64);
                    if sender.send_data(buf.split().freeze()).await.is_err() {
                        return Ok::<_, anyhow::Error>(());
                    }
                }
                if let Some(trailers) = trailers {
                    sender.send_trailers(trailers).await?;
                }
                Ok(())
            }
            .await;
            if result.is_err() {
                sender.abort();
            }
        });
        body
    }
}

pub(crate) fn bounded_cache_body_stream(
    mut source: Body,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> (Body, oneshot::Receiver<Result<u64>>) {
    let (mut sender, body) = Body::channel_with_capacity(16);
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let result = async {
            let mut size = 0usize;
            while let Some(chunk) = timeout(body_read_timeout, source.data())
                .await
                .map_err(|_| anyhow!("cache object body read timed out"))?
            {
                let chunk = chunk?;
                let next = size
                    .checked_add(chunk.len())
                    .ok_or_else(|| anyhow!("cache object length overflow"))?;
                if next > max_body_bytes {
                    return Err(anyhow!(
                        "cache object exceeds configured limit: {} bytes",
                        max_body_bytes
                    ));
                }
                size = next;
                if sender.send_data(chunk).await.is_err() {
                    return Ok(size as u64);
                }
            }
            Ok(size as u64)
        }
        .await;
        if result.is_err() {
            sender.abort();
        }
        let _ = tx.send(result);
    });
    (body, rx)
}

fn create_cache_body_spool() -> Result<(TokioFile, PathBuf)> {
    let (file, path) = qpx_core::secure_file::create_secure_temp_file("qpx-cache-body", ".body")?;
    Ok((TokioFile::from_std(file), path))
}

fn bytes_from_chunks(chunks: Vec<Bytes>) -> Bytes {
    if chunks.is_empty() {
        return Bytes::new();
    }
    if chunks.len() == 1 {
        return chunks.into_iter().next().unwrap_or_default();
    }
    let len = chunks.iter().map(Bytes::len).sum();
    let mut out = Vec::with_capacity(len);
    for chunk in chunks {
        out.extend_from_slice(chunk.as_ref());
    }
    Bytes::from(out)
}
