use super::{
    parse_module_settings, HttpModule, HttpModuleContext, HttpModuleFactory, HttpModuleRequestView,
};
use crate::http::body::Body;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, VARY};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use hyper::Response;
use qpx_core::config::{HttpModuleConfig, ResponseCompressionModuleConfig};
use std::io::{self, Write};
use std::sync::{mpsc as std_mpsc, Arc, Mutex as StdMutex, OnceLock};
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};
use tracing::warn;

pub(super) struct ResponseCompressionModuleFactory;

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
}

impl ResponseCompressionModule {
    fn new(config: ResponseCompressionModuleConfig) -> Self {
        Self { config }
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
        let body_read_timeout =
            Duration::from_millis(ctx.runtime.config.runtime.upstream_http_timeout_ms.max(1));
        let body = stream_compressed_body(body, encoding, &self.config, body_read_timeout);
        Ok(Response::from_parts(parts, body))
    }
}

#[async_trait]
impl HttpModule for ResponseCompressionModule {
    fn order(&self) -> i16 {
        100
    }

    async fn on_downstream_response(
        &self,
        ctx: &mut HttpModuleContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        self.compress(ctx, response).await
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

type SharedCompressionEncoder = Arc<StdMutex<Option<StreamingCompressionEncoder>>>;

enum CompressionJob {
    Chunk {
        encoder: SharedCompressionEncoder,
        chunk: Bytes,
        result: oneshot::Sender<Result<Option<Bytes>>>,
    },
    Finish {
        encoder: SharedCompressionEncoder,
        result: oneshot::Sender<Result<Option<Bytes>>>,
    },
}

struct CompressionPool {
    sender: std_mpsc::Sender<CompressionJob>,
}

impl CompressionPool {
    fn global() -> &'static Self {
        static POOL: OnceLock<CompressionPool> = OnceLock::new();
        POOL.get_or_init(Self::new)
    }

    fn new() -> Self {
        let (sender, receiver) = std_mpsc::channel();
        let receiver = Arc::new(StdMutex::new(receiver));
        let workers = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1)
            .clamp(1, 8);
        for idx in 0..workers {
            let receiver = receiver.clone();
            std::thread::Builder::new()
                .name(format!("qpx-compress-{idx}"))
                .spawn(move || compression_pool_worker(receiver))
                .expect("compression worker thread spawn must succeed");
        }
        Self { sender }
    }

    async fn submit<F>(&self, build: F) -> Result<Option<Bytes>>
    where
        F: FnOnce(oneshot::Sender<Result<Option<Bytes>>>) -> CompressionJob,
    {
        let (result_tx, result_rx) = oneshot::channel();
        let job = build(result_tx);
        self.sender
            .send(job)
            .map_err(|_| anyhow!("response compression pool unavailable"))?;
        result_rx
            .await
            .map_err(|_| anyhow!("response compression worker terminated unexpectedly"))?
    }
}

fn compression_pool_worker(receiver: Arc<StdMutex<std_mpsc::Receiver<CompressionJob>>>) {
    loop {
        let job = {
            receiver
                .lock()
                .expect("compression pool receiver poisoned")
                .recv()
        };
        let Ok(job) = job else {
            return;
        };
        match job {
            CompressionJob::Chunk {
                encoder,
                chunk,
                result,
            } => {
                let mut guard = encoder.lock().expect("compression encoder poisoned");
                let outcome = match guard.as_mut() {
                    Some(encoder) => encoder.write_chunk(chunk.as_ref()),
                    None => Err(anyhow!("response compression encoder state missing")),
                };
                if outcome.is_err() {
                    *guard = None;
                }
                drop(guard);
                let _ = result.send(outcome);
            }
            CompressionJob::Finish { encoder, result } => {
                let mut guard = encoder.lock().expect("compression encoder poisoned");
                let outcome = match guard.take() {
                    Some(encoder) => encoder.finish(),
                    None => Err(anyhow!("response compression encoder state missing")),
                };
                drop(guard);
                let _ = result.send(outcome);
            }
        }
    }
}

struct CompressionSession {
    encoder: SharedCompressionEncoder,
}

impl CompressionSession {
    fn new(encoding: ContentEncoding, config: &ResponseCompressionModuleConfig) -> Result<Self> {
        Ok(Self {
            encoder: Arc::new(StdMutex::new(Some(StreamingCompressionEncoder::new(
                encoding, config,
            )?))),
        })
    }

    async fn write_chunk(&self, chunk: Bytes) -> Result<Option<Bytes>> {
        CompressionPool::global()
            .submit(|result| CompressionJob::Chunk {
                encoder: self.encoder.clone(),
                chunk,
                result,
            })
            .await
    }

    async fn finish(self) -> Result<Option<Bytes>> {
        CompressionPool::global()
            .submit(|result| CompressionJob::Finish {
                encoder: self.encoder,
                result,
            })
            .await
    }
}

fn stream_compressed_body(
    mut body: Body,
    encoding: ContentEncoding,
    config: &ResponseCompressionModuleConfig,
    body_read_timeout: Duration,
) -> Body {
    let (mut sender, out) = Body::channel();
    let max_body_bytes = config.max_body_bytes;
    let session = CompressionSession::new(encoding, config);
    tokio::spawn(async move {
        let session = match session {
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
            loop {
                let chunk = tokio::select! {
                    _ = sender.closed() => return Ok(()),
                    chunk = timeout(body_read_timeout, body.data()) => match chunk {
                        Ok(chunk) => chunk,
                        Err(_) => return Err(anyhow!("response compression body read timed out")),
                    },
                };
                let Some(chunk) = chunk else {
                    break;
                };
                let chunk = chunk?;
                seen = seen
                    .checked_add(chunk.len())
                    .ok_or_else(|| anyhow!("body length overflow"))?;
                if seen > max_body_bytes {
                    return Err(anyhow!(
                        "body exceeds configured compression limit: {} bytes",
                        max_body_bytes
                    ));
                }
                if sender.is_closed() {
                    return Ok(());
                }
                let compressed = session.write_chunk(chunk).await?;
                if let Some(compressed) = compressed {
                    sender.send_data(compressed).await?;
                }
                if sender.is_closed() {
                    return Ok(());
                }
            }
            let trailers = tokio::select! {
                _ = sender.closed() => return Ok(()),
                trailers = timeout(body_read_timeout, body.trailers()) => match trailers {
                    Ok(trailers) => trailers?,
                    Err(_) => return Err(anyhow!("response compression trailers read timed out")),
                },
            };
            let compressed = session.finish().await?;
            if let Some(compressed) = compressed {
                sender.send_data(compressed).await?;
            }
            if let Some(trailers) = trailers {
                sender.send_trailers(trailers).await?;
            }
            Ok(())
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
        || response.status().is_informational()
        || response.status() == StatusCode::NO_CONTENT
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

fn parse_accept_encoding(headers: &HeaderMap) -> Vec<(String, i32)> {
    let mut out = Vec::new();
    for value in headers.get_all("accept-encoding") {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let mut segments = part.split(';');
            let name = segments
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            let mut q = 1000i32;
            for segment in segments {
                let segment = segment.trim();
                if let Some(raw) = segment.strip_prefix("q=") {
                    q = parse_quality(raw);
                }
            }
            out.push((name, q));
        }
    }
    out
}

fn parse_quality(raw: &str) -> i32 {
    let raw = raw.trim();
    if raw.eq("1") || raw.eq("1.0") || raw.eq("1.00") || raw.eq("1.000") {
        return 1000;
    }
    if raw.eq("0") || raw.eq("0.0") || raw.eq("0.00") || raw.eq("0.000") {
        return 0;
    }
    let Ok(value) = raw.parse::<f32>() else {
        return 0;
    };
    (value.clamp(0.0, 1.0) * 1000.0) as i32
}

fn accept_encoding_q(name: &str, values: &[(String, i32)]) -> i32 {
    let wildcard = values
        .iter()
        .find_map(|(value, q)| (value == "*").then_some(*q))
        .unwrap_or(0);
    values
        .iter()
        .find_map(|(value, q)| (value == name).then_some(*q))
        .unwrap_or(wildcard)
}

fn append_vary_accept_encoding(headers: &mut HeaderMap) {
    let existing = headers
        .get_all(VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if existing.iter().any(|token| token == "accept-encoding") {
        return;
    }
    headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
}
