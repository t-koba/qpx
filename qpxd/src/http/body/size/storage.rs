use super::{Body, OBSERVED_BODY_FILE_CHUNK_BYTES};
use crate::http::rpc::{PrecomputedRpcBodySummary, RpcBodySummaryObserver};
#[cfg(test)]
use anyhow::Context;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use http::HeaderMap;
#[cfg(test)]
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File as TokioFile;
use tokio::io::AsyncReadExt;

#[derive(Clone, Copy, Debug)]
pub(super) struct ObservedBodySize(pub(super) u64);

#[derive(Clone, Debug)]
pub(super) struct ObservedBodyBytes {
    pub(super) storage: ObservedBodyStorage,
    pub(super) len: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ObservedBodyReader {
    pub(super) body: ObservedBodyBytes,
}

#[derive(Clone, Debug)]
pub(super) enum ObservedBodyStorage {
    Memory(Arc<[Bytes]>),
    File(Arc<ObservedBodyFile>),
}

#[derive(Debug)]
pub(super) struct ObservedBodyFile {
    pub(super) path: PathBuf,
}

#[derive(Clone, Debug)]
pub(super) struct ObservedBodyTrailers(pub(super) HeaderMap);

impl Drop for ObservedBodyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl ObservedBodyBytes {
    pub(super) async fn read_prefix_async(&self, max_bytes: usize) -> Result<Bytes> {
        match &self.storage {
            ObservedBodyStorage::Memory(chunks) => Ok(bytes_prefix_from_chunks(chunks, max_bytes)),
            ObservedBodyStorage::File(file) => {
                read_observed_body_spool_prefix_async(file.path.clone(), self.len, max_bytes).await
            }
        }
    }

    #[cfg(test)]
    pub(super) fn read_all(&self) -> Result<Bytes> {
        match &self.storage {
            ObservedBodyStorage::Memory(chunks) => Ok(bytes_from_chunks(chunks)),
            ObservedBodyStorage::File(file) => {
                read_observed_body_spool(file.path.clone(), self.len)
            }
        }
    }

    pub(super) fn replay_body(&self, trailers: Option<HeaderMap>) -> Body {
        match &self.storage {
            ObservedBodyStorage::Memory(chunks) => {
                Body::replay_chunks(chunks.iter().cloned().collect(), trailers)
            }
            ObservedBodyStorage::File(file) => file.body(trailers),
        }
    }
}

pub(super) fn feed_rpc_summary_observer(
    observer: &mut Option<RpcBodySummaryObserver>,
    chunk: &[u8],
) {
    if let Some(inner) = observer
        && !inner.feed(chunk)
    {
        *observer = None;
    }
}

pub(super) fn finish_rpc_summary_observer(
    observer: Option<RpcBodySummaryObserver>,
) -> Option<PrecomputedRpcBodySummary> {
    observer.and_then(RpcBodySummaryObserver::finish)
}

pub(super) fn should_precompute_rpc_summary(reason: &str) -> bool {
    reason.starts_with("rpc.")
}

impl ObservedBodyReader {
    pub(crate) fn len(&self) -> u64 {
        self.body.len
    }

    pub(crate) async fn read_prefix(&self, max_bytes: usize) -> Result<Bytes> {
        self.body.read_prefix_async(max_bytes).await
    }

    pub(crate) async fn feed_chunks<F>(&self, mut feed: F) -> Result<()>
    where
        F: FnMut(&[u8]) -> Result<()>,
    {
        match &self.body.storage {
            ObservedBodyStorage::Memory(chunks) => {
                for chunk in chunks.iter() {
                    feed(chunk.as_ref())?;
                }
                Ok(())
            }
            ObservedBodyStorage::File(file) => {
                let mut input = TokioFile::open(&file.path).await?;
                let mut buf = vec![0u8; OBSERVED_BODY_FILE_CHUNK_BYTES];
                loop {
                    let read = input.read(&mut buf).await?;
                    if read == 0 {
                        return Ok(());
                    }
                    feed(&buf[..read])?;
                }
            }
        }
    }

    pub(crate) async fn with_blocking_reader<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut dyn std::io::Read) -> Result<T> + Send + 'static,
    {
        let storage = self.body.storage.clone();
        tokio::task::spawn_blocking(move || match storage {
            ObservedBodyStorage::Memory(chunks) => {
                let mut reader = ObservedMemoryReader::new(chunks);
                f(&mut reader)
            }
            ObservedBodyStorage::File(file) => {
                let mut input = std::fs::File::open(&file.path)?;
                f(&mut input)
            }
        })
        .await?
    }
}

pub(super) struct ObservedMemoryReader {
    pub(super) chunks: Arc<[Bytes]>,
    pub(super) chunk_idx: usize,
    pub(super) offset: usize,
}

impl ObservedMemoryReader {
    fn new(chunks: Arc<[Bytes]>) -> Self {
        Self {
            chunks,
            chunk_idx: 0,
            offset: 0,
        }
    }
}

impl std::io::Read for ObservedMemoryReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.chunk_idx < self.chunks.len() {
            let chunk = &self.chunks[self.chunk_idx];
            if self.offset >= chunk.len() {
                self.chunk_idx += 1;
                self.offset = 0;
                continue;
            }
            let available = &chunk[self.offset..];
            let take = available.len().min(out.len());
            out[..take].copy_from_slice(&available[..take]);
            self.offset += take;
            return Ok(take);
        }
        Ok(0)
    }
}

impl ObservedBodyFile {
    fn body(self: &Arc<Self>, trailers: Option<HeaderMap>) -> Body {
        let (mut sender, body) = Body::channel_with_capacity(16);
        let file_ref = self.clone();
        tokio::spawn(async move {
            let result = async {
                let mut file = TokioFile::open(&file_ref.path).await?;
                let mut buf = BytesMut::with_capacity(OBSERVED_BODY_FILE_CHUNK_BYTES);
                loop {
                    buf.clear();
                    buf.reserve(OBSERVED_BODY_FILE_CHUNK_BYTES);
                    let read = file.read_buf(&mut buf).await?;
                    if read == 0 {
                        if let Some(trailers) = trailers {
                            sender.send_trailers(trailers).await?;
                        }
                        return Ok::<_, anyhow::Error>(());
                    }
                    if sender.send_data(buf.split().freeze()).await.is_err() {
                        return Ok(());
                    }
                }
            }
            .await;
            if result.is_err() {
                sender.abort();
            }
        });
        body
    }
}

#[cfg(test)]
pub(super) fn bytes_from_chunks(chunks: &[Bytes]) -> Bytes {
    if chunks.is_empty() {
        return Bytes::new();
    }
    if chunks.len() == 1 {
        return chunks[0].clone();
    }
    let size = chunks.iter().map(Bytes::len).sum();
    let mut out = Vec::with_capacity(size);
    for chunk in chunks {
        out.extend_from_slice(chunk);
    }
    Bytes::from(out)
}

pub(super) fn bytes_prefix_from_chunks(chunks: &[Bytes], max_bytes: usize) -> Bytes {
    if max_bytes == 0 || chunks.is_empty() {
        return Bytes::new();
    }
    if chunks.len() == 1 {
        return chunks[0].slice(..chunks[0].len().min(max_bytes));
    }
    let mut remaining = max_bytes;
    let mut out = Vec::with_capacity(max_bytes.min(chunks.iter().map(Bytes::len).sum()));
    for chunk in chunks {
        if remaining == 0 {
            break;
        }
        let take = chunk.len().min(remaining);
        out.extend_from_slice(&chunk[..take]);
        remaining -= take;
    }
    Bytes::from(out)
}

#[cfg(test)]
pub(super) fn read_observed_body_spool(path: PathBuf, len: u64) -> Result<Bytes> {
    let mut input = std::fs::File::open(&path)?;
    let capacity = usize::try_from(len).context("observed body spool is too large")?;
    let mut out = Vec::with_capacity(capacity);
    input.read_to_end(&mut out)?;
    if out.len() as u64 != len {
        return Err(anyhow::anyhow!("observed body spool length changed"));
    }
    Ok(Bytes::from(out))
}

pub(super) async fn read_observed_body_spool_prefix_async(
    path: PathBuf,
    len: u64,
    max_bytes: usize,
) -> Result<Bytes> {
    let mut input = TokioFile::open(&path).await?;
    let mut out = vec![0_u8; (len.min(max_bytes as u64)) as usize];
    if !out.is_empty() {
        input.read_exact(&mut out).await?;
    }
    Ok(Bytes::from(out))
}
