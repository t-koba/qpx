use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use hyper::{Request, Uri};
use qpx_http::body::Body;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;

const RETRY_TEMPLATE_MEMORY_BYTES: usize = 64 * 1024;
const RETRY_TEMPLATE_FILE_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub(super) struct ReverseRequestTemplate {
    method: http::Method,
    uri: Uri,
    version: http::Version,
    headers: http::HeaderMap,
    body: ReverseRequestTemplateBody,
}

#[derive(Clone)]
enum ReverseRequestTemplateBody {
    Memory { chunks: Arc<[Bytes]> },
    File { file: Arc<SpooledTemplateFile> },
}

struct SpooledTemplateFile {
    path: PathBuf,
}

impl Drop for SpooledTemplateFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Clone)]
pub(super) struct ReverseRequestHeadTemplate {
    method: http::Method,
    uri: Uri,
    version: http::Version,
    headers: http::HeaderMap,
}

#[derive(Clone)]
pub(super) struct ReverseReplayRecorder {
    state: Arc<Mutex<ReverseReplayRecorderState>>,
}

enum ReverseReplayRecorderState {
    Pending(Option<oneshot::Receiver<Result<ReverseRequestTemplate>>>),
    Ready(Arc<ReverseRequestTemplate>),
    Failed,
}

impl ReverseRequestTemplate {
    #[cfg(test)]
    pub(super) async fn from_request(
        req: Request<Body>,
        max_body_bytes: usize,
        body_read_timeout: Duration,
    ) -> Result<Self> {
        let (parts, body) = req.into_parts();
        let body = collect_body_template(body, max_body_bytes, body_read_timeout).await?;
        Ok(Self {
            method: parts.method,
            uri: parts.uri,
            version: parts.version,
            headers: parts.headers,
            body,
        })
    }

    pub(super) fn build(&self) -> Result<Request<Body>> {
        let mut req = Request::builder()
            .method(self.method.clone())
            .uri(self.uri.clone())
            .version(self.version)
            .body(self.body.build())?;
        *req.headers_mut() = self.headers.clone();
        Ok(req)
    }
}

impl ReverseReplayRecorder {
    pub(super) fn wrap_first_request(
        req: Request<Body>,
        max_body_bytes: usize,
        body_read_timeout: Duration,
        channel_capacity: usize,
    ) -> (Request<Body>, Self) {
        let (parts, body) = req.into_parts();
        let head = ReverseRequestHeadTemplate::from_parts(&parts);
        let (mut sender, replay_body) = Body::channel_with_capacity(channel_capacity.max(1));
        let (result_tx, result_rx) = oneshot::channel();
        tokio::spawn(async move {
            let result =
                stream_and_record_body(body, head, max_body_bytes, body_read_timeout, &mut sender)
                    .await;
            if result.is_err() {
                sender.abort();
            }
            let _ = result_tx.send(result);
        });
        (
            Request::from_parts(parts, replay_body),
            Self {
                state: Arc::new(Mutex::new(ReverseReplayRecorderState::Pending(Some(
                    result_rx,
                )))),
            },
        )
    }

    pub(super) async fn template(&self) -> Option<Arc<ReverseRequestTemplate>> {
        let receiver = {
            let mut state = self.state.lock().await;
            match &mut *state {
                ReverseReplayRecorderState::Ready(template) => return Some(template.clone()),
                ReverseReplayRecorderState::Failed => return None,
                ReverseReplayRecorderState::Pending(receiver) => receiver.take(),
            }
        };
        let receiver = receiver?;
        let result = receiver.await.ok().and_then(Result::ok).map(Arc::new);
        let mut state = self.state.lock().await;
        match result {
            Some(template) => {
                *state = ReverseReplayRecorderState::Ready(template.clone());
                Some(template)
            }
            None => {
                *state = ReverseReplayRecorderState::Failed;
                None
            }
        }
    }
}

impl ReverseRequestTemplateBody {
    fn build(&self) -> Body {
        match self {
            Self::Memory { chunks } => Body::replay_chunks(chunks.iter().cloned().collect(), None),
            Self::File { file } => file.body(),
        }
    }
}

struct TemplateBodyRecorder {
    chunks: Vec<Bytes>,
    file: Option<(TokioFile, PathBuf)>,
    seen: usize,
    max_body_bytes: usize,
}

impl TemplateBodyRecorder {
    fn new(max_body_bytes: usize) -> Self {
        Self {
            chunks: Vec::new(),
            file: None,
            seen: 0,
            max_body_bytes,
        }
    }

    async fn record_chunk(&mut self, chunk: &Bytes) -> Result<()> {
        let next = self
            .seen
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("reverse request body length overflow"))?;
        if next > self.max_body_bytes {
            return Err(anyhow!(
                "reverse retry template body exceeds limit: {} bytes",
                self.max_body_bytes
            ));
        }
        self.seen = next;
        if self.file.is_none() && self.seen <= RETRY_TEMPLATE_MEMORY_BYTES {
            self.chunks.push(chunk.clone());
            return Ok(());
        }
        if self.file.is_none() {
            let (mut spool, path) = create_template_spool().await?;
            for existing in self.chunks.drain(..) {
                spool.write_all(existing.as_ref()).await?;
            }
            self.file = Some((spool, path));
        }
        if let Some((spool, _)) = self.file.as_mut() {
            spool.write_all(chunk.as_ref()).await?;
        }
        Ok(())
    }

    async fn finish(self) -> Result<ReverseRequestTemplateBody> {
        if let Some((mut spool, path)) = self.file {
            spool.flush().await?;
            drop(spool);
            return Ok(ReverseRequestTemplateBody::File {
                file: Arc::new(SpooledTemplateFile { path }),
            });
        }
        Ok(ReverseRequestTemplateBody::Memory {
            chunks: Arc::from(self.chunks),
        })
    }
}

async fn stream_and_record_body(
    mut body: Body,
    head: ReverseRequestHeadTemplate,
    max_body_bytes: usize,
    body_read_timeout: Duration,
    sender: &mut qpx_http::body::Sender,
) -> Result<ReverseRequestTemplate> {
    let mut recorder = TemplateBodyRecorder::new(max_body_bytes);
    while let Some(frame) = timeout(body_read_timeout, body.data())
        .await
        .map_err(|_| anyhow!("reverse request body read timed out"))?
    {
        let chunk = frame?;
        recorder.record_chunk(&chunk).await?;
        sender
            .send_data(chunk)
            .await
            .map_err(|err| anyhow!("reverse first-attempt body relay failed: {err}"))?;
    }
    if let Some(trailers) = body.trailers().await? {
        sender
            .send_trailers(trailers)
            .await
            .map_err(|err| anyhow!("reverse first-attempt trailer relay failed: {err}"))?;
    }
    let body = recorder.finish().await?;
    Ok(ReverseRequestTemplate {
        method: head.method,
        uri: head.uri,
        version: head.version,
        headers: head.headers,
        body,
    })
}

impl SpooledTemplateFile {
    fn body(self: &Arc<Self>) -> Body {
        let (mut sender, body) = Body::channel_with_capacity(16);
        let path = self.path.clone();
        tokio::spawn(async move {
            let result = async {
                let mut file = TokioFile::open(path).await?;
                let mut buf = BytesMut::with_capacity(RETRY_TEMPLATE_FILE_CHUNK_BYTES);
                loop {
                    buf.clear();
                    buf.reserve(RETRY_TEMPLATE_FILE_CHUNK_BYTES);
                    let read = file.read_buf(&mut buf).await?;
                    if read == 0 {
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

impl ReverseRequestHeadTemplate {
    pub(super) fn from_parts(parts: &http::request::Parts) -> Self {
        Self {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            version: parts.version,
            headers: parts.headers.clone(),
        }
    }

    pub(super) fn build_with_body(&self, body: Body) -> Result<Request<Body>> {
        let mut req = Request::builder()
            .method(self.method.clone())
            .uri(self.uri.clone())
            .version(self.version)
            .body(body)?;
        *req.headers_mut() = self.headers.clone();
        Ok(req)
    }
}

pub(super) fn request_is_retryable(
    req: &Request<Body>,
    method: &http::Method,
    body_threshold_bytes: usize,
) -> bool {
    req.version() == http::Version::HTTP_11
        && is_retryable_method(method)
        && (!request_may_have_body(req)
            || content_length(req).is_some_and(|len| len <= body_threshold_bytes as u64))
}

fn is_retryable_method(method: &http::Method) -> bool {
    matches!(
        *method,
        http::Method::GET
            | http::Method::HEAD
            | http::Method::OPTIONS
            | http::Method::TRACE
            | http::Method::PUT
            | http::Method::DELETE
    )
}

fn request_may_have_body(req: &Request<Body>) -> bool {
    if req.headers().contains_key(TRANSFER_ENCODING) {
        return true;
    }
    for value in req.headers().get_all(CONTENT_LENGTH) {
        let Ok(raw) = value.to_str() else {
            return true;
        };
        let Ok(parsed) = raw.trim().parse::<u64>() else {
            return true;
        };
        if parsed > 0 {
            return true;
        }
    }
    false
}

fn content_length(req: &Request<Body>) -> Option<u64> {
    if req.headers().contains_key(TRANSFER_ENCODING) {
        return None;
    }
    let values = req.headers().get_all(CONTENT_LENGTH);
    let mut parsed = None;
    for value in values {
        let raw = value.to_str().ok()?;
        let len = raw.trim().parse::<u64>().ok()?;
        match parsed {
            Some(existing) if existing != len => return None,
            Some(_) => {}
            None => parsed = Some(len),
        }
    }
    parsed
}

#[cfg(test)]
async fn collect_body_template(
    mut body: Body,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<ReverseRequestTemplateBody> {
    let mut chunks = Vec::new();
    let mut file: Option<(TokioFile, PathBuf)> = None;
    let mut seen = 0usize;
    while let Some(frame) = timeout(body_read_timeout, body.data())
        .await
        .map_err(|_| anyhow!("reverse request body read timed out"))?
    {
        let chunk = frame?;
        let next = seen
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("reverse request body length overflow"))?;
        if next > max_body_bytes {
            return Err(anyhow!(
                "reverse retry template body exceeds limit: {} bytes",
                max_body_bytes
            ));
        }
        seen = next;
        if file.is_none() && seen <= RETRY_TEMPLATE_MEMORY_BYTES {
            chunks.push(chunk);
            continue;
        }
        if file.is_none() {
            let (mut spool, path) = create_template_spool().await?;
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
        return Ok(ReverseRequestTemplateBody::File {
            file: Arc::new(SpooledTemplateFile { path }),
        });
    }
    Ok(ReverseRequestTemplateBody::Memory {
        chunks: Arc::from(chunks),
    })
}

async fn create_template_spool() -> Result<(TokioFile, PathBuf)> {
    let (file, path) =
        qpx_core::secure_file::create_secure_temp_file("qpx-retry-template", ".body")?;
    Ok((TokioFile::from_std(file), path))
}

#[cfg(test)]
mod tests {
    use crate::reverse::transport::request_template::*;
    use bytes::Bytes;
    use tokio::time::Duration;

    #[tokio::test]
    async fn reverse_request_template_times_out_idle_body() {
        let (_sender, body) = Body::channel();
        let req = Request::builder()
            .method(http::Method::POST)
            .uri("http://example.test/upload")
            .body(body)
            .expect("request");

        let err = match ReverseRequestTemplate::from_request(req, 1024, Duration::from_millis(10))
            .await
        {
            Ok(_) => panic!("idle body must time out"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("timed out"));
    }

    #[test]
    fn pre_header_retry_allows_small_declared_body_within_threshold() {
        let req = Request::builder()
            .method(http::Method::PUT)
            .uri("http://example.test/upload")
            .header(CONTENT_LENGTH, "16")
            .body(Body::from("0123456789abcdef"))
            .expect("request");
        assert!(request_is_retryable(&req, &http::Method::PUT, 16));
        assert!(!request_is_retryable(&req, &http::Method::PUT, 15));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn reverse_request_template_spools_large_body_outside_memory() {
        let payload = vec![b'x'; RETRY_TEMPLATE_MEMORY_BYTES + 1];
        let req = Request::builder()
            .method(http::Method::PUT)
            .uri("http://example.test/upload")
            .header(CONTENT_LENGTH, payload.len().to_string())
            .body(Body::from(payload.clone()))
            .expect("request");

        let template =
            ReverseRequestTemplate::from_request(req, payload.len(), Duration::from_secs(1))
                .await
                .expect("template");
        let path = match &template.body {
            ReverseRequestTemplateBody::File { file } => file.path.clone(),
            ReverseRequestTemplateBody::Memory { .. } => panic!("large template should spool"),
        };
        assert!(path.exists());

        for _ in 0..2 {
            let req = template.build().expect("build");
            let body = qpx_http::body::to_bytes(req.into_body())
                .await
                .expect("read body");
            assert_eq!(body.as_ref(), payload.as_slice());
        }

        drop(template);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn reverse_replay_recorder_streams_first_attempt_before_eof() {
        let (mut source_sender, source_body) = Body::channel_with_capacity(1);
        let req = Request::builder()
            .method(http::Method::PUT)
            .uri("http://example.test/upload")
            .body(source_body)
            .expect("request");
        let (mut first_req, recorder) = ReverseReplayRecorder::wrap_first_request(
            req,
            RETRY_TEMPLATE_MEMORY_BYTES,
            Duration::from_secs(1),
            1,
        );
        source_sender
            .send_data(Bytes::from_static(b"first"))
            .await
            .expect("send first chunk");
        let first_chunk = first_req
            .body_mut()
            .data()
            .await
            .expect("first attempt should stream before eof")
            .expect("first chunk");
        assert_eq!(first_chunk, Bytes::from_static(b"first"));
        source_sender
            .send_data(Bytes::from_static(b"second"))
            .await
            .expect("send second chunk");
        drop(source_sender);
        let second_chunk = first_req
            .body_mut()
            .data()
            .await
            .expect("second chunk")
            .expect("second chunk");
        assert_eq!(second_chunk, Bytes::from_static(b"second"));
        assert!(first_req.body_mut().data().await.is_none());

        let template = recorder.template().await.expect("recorded template");
        let mut replay = template.build().expect("replay").into_body();
        let replay_first = replay
            .data()
            .await
            .expect("replay first")
            .expect("replay first");
        let replay_second = replay
            .data()
            .await
            .expect("replay second")
            .expect("replay second");
        assert_eq!(replay_first, Bytes::from_static(b"first"));
        assert_eq!(replay_second, Bytes::from_static(b"second"));
        assert!(replay.data().await.is_none());
    }
}
