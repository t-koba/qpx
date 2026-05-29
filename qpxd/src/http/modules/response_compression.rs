use super::headers::parse_module_settings;
use super::{
    BodyAccess, HttpModule, HttpModuleCapabilities, HttpModuleContext, HttpModuleEvent,
    HttpModuleFactory, HttpModuleRequestView, HttpModuleStage, ModuleStages,
};
use crate::http::body::Body;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use crossbeam_channel::{Receiver as CrossbeamReceiver, Sender as CrossbeamSender};
use flate2::Compression;
use flate2::write::GzEncoder;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use hyper::Response;
use qpx_core::config::{HttpModuleConfig, ResponseCompressionModuleConfig};
use std::io::{self, Write};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::{Duration, timeout};
use tracing::warn;

mod accept;

use self::accept::{accept_encoding_q, append_vary_accept_encoding, parse_accept_encoding};

pub(super) struct ResponseCompressionModuleFactory;
const COMPRESSION_PIPELINE_DEPTH: usize = 4;

impl HttpModuleFactory for ResponseCompressionModuleFactory {
    fn build(&self, spec: &HttpModuleConfig) -> Result<Arc<dyn HttpModule>> {
        Ok(Arc::new(ResponseCompressionModule::new(
            parse_module_settings(spec)?,
        )))
    }
}

#[derive(Clone)]
struct ResponseCompressionModule {
    config: ResponseCompressionModuleConfig,
    pool: Arc<CompressionPool>,
}

impl ResponseCompressionModule {
    fn new(config: ResponseCompressionModuleConfig) -> Self {
        let pool = Arc::new(CompressionPool::new(config.worker_count));
        Self { config, pool }
    }

    async fn compress(
        &self,
        ctx: &HttpModuleContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        let request = ctx
            .frozen_request()
            .ok_or_else(|| anyhow!("response compression missing frozen request"))?;
        let Some(encoding) = select_response_encoding(&request, &self.config, &response)? else {
            return Ok(response);
        };
        let (mut parts, body) = response.into_parts();
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.remove(ETAG);
        parts.headers.insert(
            CONTENT_ENCODING,
            HeaderValue::from_static(encoding.http_name()),
        );
        append_vary_accept_encoding(&mut parts.headers);
        let body_read_timeout = Duration::from_millis(
            ctx.runtime_state()
                .plan
                .limits
                .timeouts
                .upstream_http_timeout_ms
                .max(1),
        );
        let body = stream_compressed_body(
            body,
            encoding,
            &self.config,
            self.pool.clone(),
            body_read_timeout,
            ctx.runtime_state().plan.limits.body.body_channel_capacity,
        );
        Ok(Response::from_parts(parts, body))
    }
}

#[async_trait]
impl HttpModule for ResponseCompressionModule {
    fn order(&self) -> i16 {
        100
    }

    fn capabilities(&self) -> HttpModuleCapabilities {
        let mut capabilities =
            HttpModuleCapabilities::headers_only(ModuleStages::DOWNSTREAM_RESPONSE);
        capabilities.body_access = BodyAccess::Streaming;
        capabilities.mutates_response_headers = true;
        capabilities.needs_frozen_request = true;
        capabilities
    }

    async fn call<'a>(
        &self,
        stage: HttpModuleStage,
        ctx: &mut HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> Result<HttpModuleEvent<'a>> {
        let HttpModuleStage::DownstreamResponse = stage else {
            return Ok(event);
        };
        let HttpModuleEvent::DownstreamResponse(response) = event else {
            return Err(anyhow!(
                "response_compression received invalid downstream_response event"
            ));
        };
        Ok(HttpModuleEvent::DownstreamResponse(
            self.compress(ctx, response).await?,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContentEncoding {
    Gzip,
    Brotli,
    Zstd,
}

impl ContentEncoding {
    fn http_name(self) -> &'static str {
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
    Gzip(GzEncoder<CompressionSink>),
    Brotli(Box<brotli::CompressorWriter<CompressionSink>>),
    Zstd(zstd::stream::write::Encoder<'static, CompressionSink>),
}

impl StreamingCompressionEncoder {
    fn new(encoding: ContentEncoding, config: &ResponseCompressionModuleConfig) -> Result<Self> {
        Ok(match encoding {
            ContentEncoding::Gzip => Self::Gzip(GzEncoder::new(
                CompressionSink::default(),
                Compression::new(config.gzip_level),
            )),
            ContentEncoding::Brotli => Self::Brotli(Box::new(brotli::CompressorWriter::new(
                CompressionSink::default(),
                4096,
                config.brotli_level,
                22,
            ))),
            ContentEncoding::Zstd => Self::Zstd(zstd::stream::write::Encoder::new(
                CompressionSink::default(),
                config.zstd_level,
            )?),
        })
    }

    fn write_chunk(&mut self, input: &[u8]) -> Result<Option<Bytes>> {
        match self {
            Self::Gzip(encoder) => {
                encoder.write_all(input)?;
                Ok(encoder.get_mut().take())
            }
            Self::Brotli(encoder) => {
                encoder.write_all(input)?;
                Ok(encoder.get_mut().take())
            }
            Self::Zstd(encoder) => {
                encoder.write_all(input)?;
                Ok(encoder.get_mut().take())
            }
        }
    }

    fn finish(self) -> Result<Option<Bytes>> {
        Ok(match self {
            Self::Gzip(encoder) => encoder.finish()?.into_bytes(),
            Self::Brotli(encoder) => encoder.into_inner().into_bytes(),
            Self::Zstd(encoder) => encoder.finish()?.into_bytes(),
        })
    }
}

enum CompressionInput {
    Chunk(Bytes),
    Finish,
}

enum CompressionStreamInput {
    Chunk(Bytes),
    Finish(Option<HeaderMap>),
    Error(anyhow::Error),
}

struct CompressionPool {
    jobs: CrossbeamSender<CompressionJob>,
    slots: Arc<Semaphore>,
}

impl CompressionPool {
    fn new(worker_count: usize) -> Self {
        let worker_count = worker_count.clamp(1, 256);
        let queue_capacity = worker_count.saturating_mul(64).max(64);
        let (jobs, receiver) = crossbeam_channel::unbounded();
        for worker_id in 0..worker_count {
            spawn_compression_worker(worker_id, receiver.clone());
        }
        Self {
            jobs,
            slots: Arc::new(Semaphore::new(queue_capacity)),
        }
    }

    async fn start_session(
        &self,
        encoder: StreamingCompressionEncoder,
    ) -> Result<CompressionSession> {
        Ok(CompressionSession {
            jobs: self.jobs.clone(),
            slots: self.slots.clone(),
            encoder: Arc::new(StdMutex::new(Some(encoder))),
        })
    }
}

struct CompressionJob {
    encoder: Arc<StdMutex<Option<StreamingCompressionEncoder>>>,
    input: CompressionInput,
    result: oneshot::Sender<Result<Option<Bytes>>>,
    _permit: OwnedSemaphorePermit,
}

fn spawn_compression_worker(worker_id: usize, receiver: CrossbeamReceiver<CompressionJob>) {
    let _ = thread::Builder::new()
        .name(format!("qpx-compress-{worker_id}"))
        .spawn(move || {
            while let Ok(job) = receiver.recv() {
                let result = process_compression_job(job.encoder, job.input);
                let _ = job.result.send(result);
            }
        });
}

fn process_compression_job(
    encoder: Arc<StdMutex<Option<StreamingCompressionEncoder>>>,
    input: CompressionInput,
) -> Result<Option<Bytes>> {
    let mut guard = encoder
        .lock()
        .map_err(|_| anyhow!("response compression encoder lock poisoned"))?;
    match input {
        CompressionInput::Chunk(chunk) => match guard.as_mut() {
            Some(encoder) => encoder.write_chunk(chunk.as_ref()),
            None => Err(anyhow!("response compression encoder state missing")),
        },
        CompressionInput::Finish => match guard.take() {
            Some(encoder) => encoder.finish(),
            None => Err(anyhow!("response compression encoder state missing")),
        },
    }
}

struct CompressionSession {
    jobs: CrossbeamSender<CompressionJob>,
    slots: Arc<Semaphore>,
    encoder: Arc<StdMutex<Option<StreamingCompressionEncoder>>>,
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

    async fn process_chunk(&self, chunk: Bytes) -> Result<Option<Bytes>> {
        self.process(CompressionInput::Chunk(chunk)).await
    }

    async fn finish(&self) -> Result<Option<Bytes>> {
        self.process(CompressionInput::Finish).await
    }

    async fn process(&self, input: CompressionInput) -> Result<Option<Bytes>> {
        let permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("response compression pool unavailable"))?;
        let (result, receiver) = oneshot::channel();
        let job = CompressionJob {
            encoder: self.encoder.clone(),
            input,
            result,
            _permit: permit,
        };
        self.jobs
            .send(job)
            .map_err(|_| anyhow!("response compression pool unavailable"))?;
        receiver
            .await
            .map_err(|_| anyhow!("response compression worker stopped"))?
    }
}

fn stream_compressed_body(
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
    let (reader_tx, mut input_rx) = mpsc::channel::<CompressionStreamInput>(
        body_channel_capacity.max(COMPRESSION_PIPELINE_DEPTH),
    );
    tokio::spawn(async move {
        let mut seen = 0usize;
        loop {
            let chunk = timeout(body_read_timeout, body.data()).await;
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => {
                    let _ = reader_tx
                        .send(CompressionStreamInput::Error(anyhow!(
                            "response compression body read timed out"
                        )))
                        .await;
                    return;
                }
            };
            let Some(chunk) = chunk else {
                break;
            };
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(err) => {
                    let _ = reader_tx
                        .send(CompressionStreamInput::Error(anyhow!(err)))
                        .await;
                    return;
                }
            };
            seen = match seen.checked_add(chunk.len()) {
                Some(value) => value,
                None => {
                    let _ = reader_tx
                        .send(CompressionStreamInput::Error(anyhow!(
                            "body length overflow"
                        )))
                        .await;
                    return;
                }
            };
            if seen > max_body_bytes {
                let _ = reader_tx
                    .send(CompressionStreamInput::Error(anyhow!(
                        "body exceeds configured compression limit: {} bytes",
                        max_body_bytes
                    )))
                    .await;
                return;
            }
            if reader_tx
                .send(CompressionStreamInput::Chunk(chunk))
                .await
                .is_err()
            {
                return;
            }
        }
        let trailers = match timeout(body_read_timeout, body.trailers()).await {
            Ok(Ok(trailers)) => trailers,
            Ok(Err(err)) => {
                let _ = reader_tx
                    .send(CompressionStreamInput::Error(anyhow!(err)))
                    .await;
                return;
            }
            Err(_) => {
                let _ = reader_tx
                    .send(CompressionStreamInput::Error(anyhow!(
                        "response compression trailers read timed out"
                    )))
                    .await;
                return;
            }
        };
        let _ = reader_tx
            .send(CompressionStreamInput::Finish(trailers))
            .await;
    });
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
            while let Some(input) = input_rx.recv().await {
                if sender.is_closed() {
                    return Ok(());
                }
                match input {
                    CompressionStreamInput::Chunk(chunk) => {
                        if let Some(compressed) = session.process_chunk(chunk).await? {
                            sender.send_data(compressed).await?;
                        }
                    }
                    CompressionStreamInput::Finish(trailers) => {
                        if let Some(compressed) = session.finish().await? {
                            sender.send_data(compressed).await?;
                        }
                        if sender.is_closed() {
                            return Ok(());
                        }
                        if let Some(trailers) = trailers {
                            sender.send_trailers(trailers).await?;
                        }
                        return Ok(());
                    }
                    CompressionStreamInput::Error(err) => return Err(err),
                }
            }
            Err(anyhow!(
                "response compression input stream ended before finish"
            ))
        }
        .await;

        if let Err(err) = result {
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

fn select_response_encoding(
    request: &HttpModuleRequestView<'_>,
    config: &ResponseCompressionModuleConfig,
    response: &Response<Body>,
) -> Result<Option<ContentEncoding>> {
    if request.method() == Method::HEAD
        || (request.method() == Method::CONNECT && response.status().is_success())
        || response.status().is_informational()
        || response.status() == StatusCode::NO_CONTENT
        || response.status() == StatusCode::RESET_CONTENT
        || response.status() == StatusCode::NOT_MODIFIED
        || response.headers().contains_key(CONTENT_ENCODING)
        || response.headers().contains_key(CONTENT_RANGE)
    {
        return Ok(None);
    }

    let content_length = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    let Some(content_length) = content_length else {
        return Ok(None);
    };
    if content_length < config.min_body_bytes || content_length > config.max_body_bytes {
        return Ok(None);
    }
    if !config.force_compress_event_stream && is_event_stream_headers(response.headers()) {
        return Ok(None);
    }
    if !content_type_allowed(response.headers(), &config.content_types) {
        return Ok(None);
    }

    let preferences = parse_accept_encoding(request.headers());
    let supported = [
        (ContentEncoding::Brotli, config.brotli),
        (ContentEncoding::Zstd, config.zstd),
        (ContentEncoding::Gzip, config.gzip),
    ];
    let mut best = None;
    for (encoding, enabled) in supported {
        if !enabled {
            continue;
        }
        let q = accept_encoding_q(encoding.http_name(), &preferences);
        if q <= 0 {
            continue;
        }
        match best {
            Some((best_q, _)) if q <= best_q => {}
            _ => best = Some((q, encoding)),
        }
    }
    Ok(best.map(|(_, encoding)| encoding))
}

pub(crate) fn is_event_stream_headers(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or(value).trim())
        .map(|value| value.eq_ignore_ascii_case("text/event-stream"))
        .unwrap_or(false)
}

fn content_type_allowed(headers: &HeaderMap, configured: &[String]) -> bool {
    let Some(content_type) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or(value).trim())
    else {
        return false;
    };
    let mut iter: Box<dyn Iterator<Item = &str>> = if configured.is_empty() {
        Box::new(
            [
                "text/*",
                "application/json",
                "application/javascript",
                "application/xml",
                "application/xhtml+xml",
                "image/svg+xml",
            ]
            .iter()
            .copied(),
        )
    } else {
        Box::new(configured.iter().map(String::as_str))
    };
    iter.any(|pattern| mime_pattern_matches(pattern, content_type))
}

fn mime_pattern_matches(pattern: &str, content_type: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return content_type
            .strip_prefix(prefix)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false);
    }
    pattern.eq_ignore_ascii_case(content_type)
}

#[cfg(test)]
mod tests;
