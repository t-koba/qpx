use anyhow::{Result, anyhow};
use bytes::Bytes;
use crossbeam_channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender};
use flate2::Compression;
use flate2::write::GzEncoder;
use http::HeaderMap;
use qpx_core::config::ResponseCompressionModuleConfig;
use qpx_http::body::Body;
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::{Duration, timeout};
use tracing::warn;

use super::metrics;

const COMPRESSION_PIPELINE_DEPTH: usize = 4;
const COMPRESSION_WORKER_QUEUE_FACTOR: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ContentEncoding {
    Gzip,
    Brotli,
    Zstd,
}

impl ContentEncoding {
    pub(super) fn http_name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Brotli => "br",
            Self::Zstd => "zstd",
        }
    }
}

#[derive(Default)]
struct CompressionSink {
    buf: Vec<u8>,
}

impl CompressionSink {
    fn take(&mut self) -> Option<Bytes> {
        (!self.buf.is_empty()).then(|| Bytes::from(std::mem::take(&mut self.buf)))
    }

    fn into_bytes(self) -> Option<Bytes> {
        (!self.buf.is_empty()).then(|| Bytes::from(self.buf))
    }
}

impl Write for CompressionSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum StreamingCompressionEncoder {
    Gzip {
        encoder: GzEncoder<CompressionSink>,
        low_latency_flush: bool,
    },
    Brotli {
        encoder: Box<brotli::CompressorWriter<CompressionSink>>,
        low_latency_flush: bool,
    },
    Zstd {
        encoder: zstd::stream::write::Encoder<'static, CompressionSink>,
        low_latency_flush: bool,
    },
}

impl StreamingCompressionEncoder {
    fn new(encoding: ContentEncoding, config: &ResponseCompressionModuleConfig) -> Result<Self> {
        Ok(match encoding {
            ContentEncoding::Gzip => Self::Gzip {
                encoder: GzEncoder::new(
                    CompressionSink::default(),
                    Compression::new(config.gzip_level),
                ),
                low_latency_flush: config.low_latency_flush,
            },
            ContentEncoding::Brotli => Self::Brotli {
                encoder: Box::new(brotli::CompressorWriter::new(
                    CompressionSink::default(),
                    4096,
                    config.brotli_level,
                    22,
                )),
                low_latency_flush: config.low_latency_flush,
            },
            ContentEncoding::Zstd => Self::Zstd {
                encoder: zstd::stream::write::Encoder::new(
                    CompressionSink::default(),
                    config.zstd_level,
                )?,
                low_latency_flush: config.low_latency_flush,
            },
        })
    }

    fn write_chunk(&mut self, input: &[u8]) -> Result<Option<Bytes>> {
        match self {
            Self::Gzip {
                encoder,
                low_latency_flush,
            } => {
                encoder.write_all(input)?;
                if *low_latency_flush {
                    encoder.flush()?;
                }
                Ok(encoder.get_mut().take())
            }
            Self::Brotli {
                encoder,
                low_latency_flush,
            } => {
                encoder.write_all(input)?;
                if *low_latency_flush {
                    encoder.flush()?;
                }
                Ok(encoder.get_mut().take())
            }
            Self::Zstd {
                encoder,
                low_latency_flush,
            } => {
                encoder.write_all(input)?;
                if *low_latency_flush {
                    encoder.flush()?;
                }
                Ok(encoder.get_mut().take())
            }
        }
    }

    fn finish(self) -> Result<Option<Bytes>> {
        Ok(match self {
            Self::Gzip { encoder, .. } => encoder.finish()?.into_bytes(),
            Self::Brotli { encoder, .. } => encoder.into_inner().into_bytes(),
            Self::Zstd { encoder, .. } => encoder.finish()?.into_bytes(),
        })
    }
}

enum CompressionInput {
    Chunks(Vec<Bytes>),
    Finish(Option<HeaderMap>),
}

enum CompressionJobResult {
    Chunks(Vec<Bytes>),
    Finish {
        chunk: Option<Bytes>,
        trailers: Option<HeaderMap>,
    },
    Error(anyhow::Error),
}

pub(super) struct CompressionPool {
    workers: Vec<CrossbeamSender<CompressionJob>>,
    slots: Arc<Semaphore>,
    next_session_id: AtomicU64,
}

impl CompressionPool {
    pub(super) fn new(worker_count: usize) -> Self {
        let worker_count = worker_count.clamp(1, 256);
        let queue_capacity = worker_count.saturating_mul(64).max(64);
        let mut workers = Vec::with_capacity(worker_count);
        for worker_id in 0..worker_count {
            let (jobs, receiver) = crossbeam_channel::bounded(
                queue_capacity
                    .saturating_mul(COMPRESSION_WORKER_QUEUE_FACTOR)
                    .max(1),
            );
            spawn_compression_worker(worker_id, receiver);
            workers.push(jobs);
        }
        Self {
            workers,
            slots: Arc::new(Semaphore::new(queue_capacity)),
            next_session_id: AtomicU64::new(1),
        }
    }

    async fn start_session(
        &self,
        encoder: StreamingCompressionEncoder,
    ) -> Result<CompressionSession> {
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let worker_idx = qpx_http::sharding::modulo_u64(session_id, self.workers.len());
        let jobs = self.workers[worker_idx].clone();
        jobs.try_send(CompressionJob {
            session_id,
            input: CompressionJobInput::Start { encoder },
            _permit: None,
        })
        .map_err(|_| anyhow!("response compression pool unavailable"))?;
        let (result_tx, result_rx) = mpsc::channel(COMPRESSION_PIPELINE_DEPTH.max(1));
        Ok(CompressionSession {
            session_id,
            jobs,
            slots: self.slots.clone(),
            result_tx,
            result_rx: tokio::sync::Mutex::new(result_rx),
        })
    }
}

struct CompressionJob {
    session_id: u64,
    input: CompressionJobInput,
    _permit: Option<OwnedSemaphorePermit>,
}

enum CompressionJobInput {
    Start {
        encoder: StreamingCompressionEncoder,
    },
    Data {
        input: CompressionInput,
        result_tx: mpsc::Sender<CompressionJobResult>,
    },
    Cancel,
}

struct CompressionWorkerSession {
    encoder: StreamingCompressionEncoder,
}

fn spawn_compression_worker(worker_id: usize, receiver: CrossbeamReceiver<CompressionJob>) {
    let _ = thread::Builder::new()
        .name(format!("qpx-compress-{worker_id}"))
        .spawn(move || {
            let mut sessions: HashMap<u64, CompressionWorkerSession> = HashMap::new();
            while let Ok(job) = receiver.recv() {
                process_compression_job(&mut sessions, job);
            }
        });
}

fn process_compression_job(
    sessions: &mut HashMap<u64, CompressionWorkerSession>,
    job: CompressionJob,
) {
    match job.input {
        CompressionJobInput::Start { encoder } => {
            sessions.insert(job.session_id, CompressionWorkerSession { encoder });
        }
        CompressionJobInput::Data { input, result_tx } => match input {
            CompressionInput::Chunks(chunks) => {
                let Some(session) = sessions.get_mut(&job.session_id) else {
                    send_compression_worker_result(
                        &result_tx,
                        CompressionJobResult::Error(anyhow!(
                            "response compression session not found"
                        )),
                    );
                    return;
                };
                let input_bytes: usize = chunks.iter().map(Bytes::len).sum();
                metrics::record_compression_job("chunks", chunks.len(), input_bytes);
                let mut out = Vec::new();
                for chunk in chunks {
                    match session.encoder.write_chunk(chunk.as_ref()) {
                        Ok(Some(compressed)) => out.push(compressed),
                        Ok(None) => {}
                        Err(err) => {
                            sessions.remove(&job.session_id);
                            metrics::record_compression_error("chunks");
                            send_compression_worker_result(
                                &result_tx,
                                CompressionJobResult::Error(err),
                            );
                            return;
                        }
                    }
                }
                metrics::record_compression_output("chunks", &out);
                if !send_compression_worker_result(&result_tx, CompressionJobResult::Chunks(out)) {
                    sessions.remove(&job.session_id);
                }
            }
            CompressionInput::Finish(trailers) => {
                let Some(session) = sessions.remove(&job.session_id) else {
                    send_compression_worker_result(
                        &result_tx,
                        CompressionJobResult::Error(anyhow!(
                            "response compression session not found"
                        )),
                    );
                    return;
                };
                match session.encoder.finish() {
                    Ok(chunk) => {
                        if let Some(chunk) = chunk.as_ref() {
                            metrics::record_compression_output_bytes("finish", chunk.len());
                        }
                        send_compression_worker_result(
                            &result_tx,
                            CompressionJobResult::Finish { chunk, trailers },
                        );
                    }
                    Err(err) => {
                        metrics::record_compression_error("finish");
                        send_compression_worker_result(
                            &result_tx,
                            CompressionJobResult::Error(err),
                        );
                    }
                }
            }
        },
        CompressionJobInput::Cancel => {
            sessions.remove(&job.session_id);
        }
    }
}

fn send_compression_worker_result(
    result_tx: &mpsc::Sender<CompressionJobResult>,
    result: CompressionJobResult,
) -> bool {
    result_tx.try_send(result).is_ok()
}

struct CompressionSession {
    session_id: u64,
    jobs: CrossbeamSender<CompressionJob>,
    slots: Arc<Semaphore>,
    result_tx: mpsc::Sender<CompressionJobResult>,
    result_rx: tokio::sync::Mutex<mpsc::Receiver<CompressionJobResult>>,
}

impl CompressionSession {
    async fn start(
        encoding: ContentEncoding,
        config: &ResponseCompressionModuleConfig,
        pool: Arc<CompressionPool>,
    ) -> Result<Self> {
        let encoder = StreamingCompressionEncoder::new(encoding, config)?;
        pool.start_session(encoder).await
    }

    async fn process_chunks(&self, chunks: Vec<Bytes>) -> Result<CompressionJobResult> {
        self.process(CompressionInput::Chunks(chunks)).await
    }

    async fn finish(&self, trailers: Option<HeaderMap>) -> Result<CompressionJobResult> {
        self.process(CompressionInput::Finish(trailers)).await
    }

    async fn cancel(&self) {
        let _ = self.jobs.try_send(CompressionJob {
            session_id: self.session_id,
            input: CompressionJobInput::Cancel,
            _permit: None,
        });
    }

    async fn process(&self, input: CompressionInput) -> Result<CompressionJobResult> {
        let waited_at = Instant::now();
        let permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("response compression pool unavailable"))?;
        metrics::record_slot_wait(waited_at.elapsed());
        let job = CompressionJob {
            session_id: self.session_id,
            input: CompressionJobInput::Data {
                input,
                result_tx: self.result_tx.clone(),
            },
            _permit: Some(permit),
        };
        self.jobs
            .try_send(job)
            .map_err(|_| anyhow!("response compression pool unavailable"))?;
        self.result_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow!("response compression worker stopped"))
    }
}

async fn send_compression_result(
    sender: &mut qpx_http::body::Sender,
    result: CompressionJobResult,
) -> Result<bool> {
    match result {
        CompressionJobResult::Chunks(chunks) => {
            for chunk in chunks {
                sender
                    .send_data(chunk)
                    .await
                    .map_err(|err| anyhow!("response compression output failed: {err}"))?;
            }
            Ok(false)
        }
        CompressionJobResult::Finish { chunk, trailers } => {
            if let Some(chunk) = chunk {
                sender
                    .send_data(chunk)
                    .await
                    .map_err(|err| anyhow!("response compression output failed: {err}"))?;
            }
            if let Some(trailers) = trailers {
                sender
                    .send_trailers(trailers)
                    .await
                    .map_err(|err| anyhow!("response compression trailer output failed: {err}"))?;
            }
            Ok(true)
        }
        CompressionJobResult::Error(err) => Err(err),
    }
}

async fn flush_compression_batch(
    session: &CompressionSession,
    sender: &mut qpx_http::body::Sender,
    batch: &mut Vec<Bytes>,
) -> Result<bool> {
    if batch.is_empty() {
        return Ok(false);
    }
    let mut submit = Vec::with_capacity(COMPRESSION_PIPELINE_DEPTH);
    std::mem::swap(&mut submit, batch);
    let result = session.process_chunks(submit).await?;
    send_compression_result(sender, result).await
}

pub(super) fn stream_compressed_body(
    mut body: Body,
    encoding: ContentEncoding,
    config: &ResponseCompressionModuleConfig,
    pool: Arc<CompressionPool>,
    body_read_timeout: Duration,
    body_channel_capacity: usize,
) -> Body {
    let (mut sender, out) = Body::channel_with_capacity(body_channel_capacity);
    let max_body_bytes = config.max_body_bytes;
    let config = config.clone();
    tokio::spawn(async move {
        let session = match CompressionSession::start(encoding, &config, pool).await {
            Ok(session) => session,
            Err(err) => {
                warn!(
                    error = ?err,
                    encoding = encoding.http_name(),
                    "failed to start response compression session"
                );
                sender.abort();
                return;
            }
        };
        let result: Result<()> = async {
            let mut seen = 0usize;
            let mut batch = Vec::with_capacity(COMPRESSION_PIPELINE_DEPTH);
            loop {
                let next = timeout(body_read_timeout, body.data())
                    .await
                    .map_err(|_| anyhow!("response compression body read timed out"))?;
                let Some(chunk) = next else {
                    break;
                };
                let chunk = chunk.map_err(|err| anyhow!(err))?;
                seen = seen
                    .checked_add(chunk.len())
                    .ok_or_else(|| anyhow!("body length overflow"))?;
                if seen > max_body_bytes {
                    return Err(anyhow!(
                        "body exceeds configured compression limit: {} bytes",
                        max_body_bytes
                    ));
                }
                batch.push(chunk);
                if (config.low_latency_flush || batch.len() >= COMPRESSION_PIPELINE_DEPTH)
                    && flush_compression_batch(&session, &mut sender, &mut batch).await?
                {
                    return Ok(());
                }
            }
            if flush_compression_batch(&session, &mut sender, &mut batch).await? {
                return Ok(());
            }
            let trailers = timeout(body_read_timeout, body.trailers())
                .await
                .map_err(|_| anyhow!("response compression trailers read timed out"))?
                .map_err(|err| anyhow!(err))?;
            let result = session.finish(trailers).await?;
            let _ = send_compression_result(&mut sender, result).await?;
            Ok(())
        }
        .await;

        if let Err(err) = result {
            session.cancel().await;
            warn!(
                error = ?err,
                encoding = encoding.http_name(),
                "streaming response compression failed"
            );
            sender.abort();
        }
    });
    out
}
