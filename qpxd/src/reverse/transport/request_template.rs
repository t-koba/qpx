use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use hyper::Uri;
use qpx_core::http_message::{Headers, OrdinaryHeaderName, Request as OwnerRequest};
use qpx_http::body::Body;
use qpx_http::body::spool::SpoolFile;
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
    headers: Headers,
    body: ReverseRequestTemplateBody,
}

#[derive(Clone)]
enum ReverseRequestTemplateBody {
    Memory { chunks: Arc<[Bytes]> },
    File { file: Arc<SpooledTemplateFile> },
}

struct SpooledTemplateFile {
    guard: SpoolFile<TokioFile>,
}

#[derive(Clone)]
pub(super) struct ReverseRequestHeadTemplate {
    method: http::Method,
    uri: Uri,
    version: http::Version,
    headers: Headers,
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
    pub(super) fn without_body(req: &OwnerRequest<Body>) -> Self {
        Self {
            method: req.method().clone(),
            uri: req.uri().clone(),
            version: req.version(),
            headers: req.headers().clone(),
            body: ReverseRequestTemplateBody::Memory {
                chunks: Arc::from([]),
            },
        }
    }

    #[cfg(test)]
    pub(super) async fn from_request(
        req: OwnerRequest<Body>,
        max_body_bytes: usize,
        body_read_timeout: Duration,
    ) -> Result<Self> {
        let (head, body) = req.into_head_and_body();
        let body = collect_body_template(body, max_body_bytes, body_read_timeout).await?;
        Ok(Self {
            method: head.method().clone(),
            uri: head.uri().clone(),
            version: head.version(),
            headers: head.headers().clone(),
            body,
        })
    }

    pub(super) fn build(&self) -> Result<OwnerRequest<Body>> {
        let mut req = OwnerRequest::new(self.body.build());
        *req.method_mut() = self.method.clone();
        *req.uri_mut() = self.uri.clone();
        *req.version_mut() = self.version;
        *req.headers_mut() = self.headers.clone();
        Ok(req)
    }
}

impl ReverseReplayRecorder {
    pub(super) fn wrap_first_request(
        req: OwnerRequest<Body>,
        max_body_bytes: usize,
        body_read_timeout: Duration,
        channel_capacity: usize,
    ) -> (OwnerRequest<Body>, Self) {
        let (head, body) = req.into_head_and_body();
        let head_template = ReverseRequestHeadTemplate::from_head(&head);
        let (mut sender, replay_body) = Body::channel_with_capacity(channel_capacity.max(1));
        let (result_tx, result_rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = stream_and_record_body(
                body,
                head_template,
                max_body_bytes,
                body_read_timeout,
                &mut sender,
            )
            .await;
            if result.is_err() {
                sender.abort();
            }
            let _ = result_tx.send(result);
        });
        (
            head.map_body(|()| replay_body),
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
    file: Option<SpoolFile<TokioFile>>,
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
            // The guard exists from the moment the spool file is created, so a
            // write failure below drops it and unlinks the file.
            let mut spool = create_template_spool().await?;
            for existing in self.chunks.drain(..) {
                spool.handle_mut().write_all(existing.as_ref()).await?;
            }
            self.file = Some(spool);
        }
        if let Some(spool) = self.file.as_mut() {
            spool.handle_mut().write_all(chunk.as_ref()).await?;
        }
        Ok(())
    }

    async fn finish(self) -> Result<ReverseRequestTemplateBody> {
        if let Some(mut spool) = self.file {
            spool.handle_mut().flush().await?;
            spool.close();
            return Ok(ReverseRequestTemplateBody::File {
                file: Arc::new(SpooledTemplateFile { guard: spool }),
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
    if let Some(trailers) = timeout(body_read_timeout, body.trailers())
        .await
        .map_err(|_| anyhow!("reverse request trailers read timed out"))??
    {
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
        let path = self.guard.path().to_path_buf();
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
    pub(super) fn from_head(head: &OwnerRequest<()>) -> Self {
        Self {
            method: head.method().clone(),
            uri: head.uri().clone(),
            version: head.version(),
            headers: head.headers().clone(),
        }
    }

    pub(super) fn build_with_body(&self, body: Body) -> Result<OwnerRequest<Body>> {
        let mut req = OwnerRequest::new(body);
        *req.method_mut() = self.method.clone();
        *req.uri_mut() = self.uri.clone();
        *req.version_mut() = self.version;
        *req.headers_mut() = self.headers.clone();
        Ok(req)
    }
}

pub(super) fn request_is_retryable(
    req: &OwnerRequest<Body>,
    method: &http::Method,
    body_threshold_bytes: usize,
) -> bool {
    if req.version() != http::Version::HTTP_11 || !is_retryable_method(method) {
        return false;
    }
    if !http_body::Body::is_end_stream(req.body()) {
        // A body that has not ended may carry anything, and the length it
        // declares is the one the threshold applies to.
        return content_length(req).is_some_and(|len| len <= body_threshold_bytes as u64);
    }
    if req.headers().contains_key(
        &OrdinaryHeaderName::try_from(http::header::TRANSFER_ENCODING)
            .expect("transfer-encoding is ordinary"),
    ) {
        // A chunked body has no declared length, so the threshold cannot be
        // applied to it and the request is not retried.
        return false;
    }
    // The declaration answers both questions this decision asks - whether
    // the request may carry a body, and whether that body is within the
    // threshold - so it is read once and both answers come from that read.
    let declared = req.headers().declared_content_length();
    if !declaration_allows_a_body(declared) {
        return true;
    }
    match declared {
        Ok(Some(length)) => length <= body_threshold_bytes as u64,
        Ok(None) | Err(_) => false,
    }
}

fn is_retryable_method(method: &http::Method) -> bool {
    qpx_http::protocol::method::method_semantics(method).idempotent
}

pub(super) fn request_may_have_body(req: &OwnerRequest<Body>) -> bool {
    if !http_body::Body::is_end_stream(req.body())
        || req.headers().contains_key(
            &OrdinaryHeaderName::try_from(http::header::TRANSFER_ENCODING)
                .expect("transfer-encoding is ordinary"),
        )
    {
        return true;
    }
    declaration_allows_a_body(req.headers().declared_content_length())
}

/// Whether the declaration says the request may carry a body.
///
/// A declaration the grammar does not have names no length, so the request
/// is treated as one that may carry a body.
fn declaration_allows_a_body(
    declared: Result<Option<u64>, qpx_core::http_content_length::ContentLengthError>,
) -> bool {
    match declared {
        Ok(Some(length)) => length > 0,
        Ok(None) => false,
        Err(_) => true,
    }
}

fn content_length(req: &OwnerRequest<Body>) -> Option<u64> {
    if req.headers().contains_key(
        &OrdinaryHeaderName::try_from(http::header::TRANSFER_ENCODING)
            .expect("transfer-encoding is ordinary"),
    ) {
        return None;
    }
    req.headers().declared_content_length().ok().flatten()
}

#[cfg(test)]
async fn collect_body_template(
    mut body: Body,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<ReverseRequestTemplateBody> {
    let mut chunks = Vec::new();
    let mut file: Option<SpoolFile<TokioFile>> = None;
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
            let mut spool = create_template_spool().await?;
            for existing in chunks.drain(..) {
                spool.handle_mut().write_all(existing.as_ref()).await?;
            }
            file = Some(spool);
        }
        if let Some(spool) = file.as_mut() {
            spool.handle_mut().write_all(chunk.as_ref()).await?;
        }
    }
    if let Some(mut spool) = file {
        spool.handle_mut().flush().await?;
        spool.close();
        return Ok(ReverseRequestTemplateBody::File {
            file: Arc::new(SpooledTemplateFile { guard: spool }),
        });
    }
    Ok(ReverseRequestTemplateBody::Memory {
        chunks: Arc::from(chunks),
    })
}

async fn create_template_spool() -> Result<SpoolFile<TokioFile>> {
    let (file, path) =
        qpx_core::secure_file::create_secure_temp_file("qpx-retry-template", ".body")?;
    Ok(SpoolFile::new(
        TokioFile::from_std(file),
        path,
        "request",
        "retry_template",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};

    #[tokio::test]
    async fn reverse_request_template_times_out_idle_body() {
        let (_sender, body) = Body::channel();
        let req = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::POST)
                .uri("http://example.test/upload")
                .body(body)
                .expect("request"),
        );

        let err = match ReverseRequestTemplate::from_request(req, 1024, Duration::from_millis(10))
            .await
        {
            Ok(_) => panic!("idle body must time out"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn bodyless_template_replays_without_a_recorder_task() {
        let req = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::GET)
                .uri("http://example.test/resource")
                .header("x-test", "value")
                .body(Body::empty())
                .expect("request"),
        );

        let replay = ReverseRequestTemplate::without_body(&req)
            .build()
            .expect("replay request");

        assert_eq!(replay.method(), http::Method::GET);
        assert_eq!(replay.uri(), "http://example.test/resource");
        assert_eq!(
            replay
                .headers()
                .get(&OrdinaryHeaderName::try_from("x-test").unwrap())
                .unwrap()
                .to_str()
                .unwrap(),
            "value"
        );
        assert!(replay.into_head_and_body().1.data().await.is_none());
    }

    #[test]
    fn pre_header_retry_allows_small_declared_body_within_threshold() {
        let req = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::PUT)
                .uri("http://example.test/upload")
                .header(CONTENT_LENGTH, "16")
                .body(Body::from("0123456789abcdef"))
                .expect("request"),
        );
        assert!(request_is_retryable(&req, &http::Method::PUT, 16));
        assert!(!request_is_retryable(&req, &http::Method::PUT, 15));
    }

    #[test]
    fn a_comma_list_of_equal_members_declares_one_length() {
        let req = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::PUT)
                .uri("http://example.test/upload")
                .header(CONTENT_LENGTH, "16, 16")
                .body(Body::from("0123456789abcdef"))
                .expect("request"),
        );
        assert!(request_is_retryable(&req, &http::Method::PUT, 16));
        assert!(!request_is_retryable(&req, &http::Method::PUT, 15));
    }

    #[test]
    fn a_signed_length_is_not_a_declared_length() {
        let req = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::PUT)
                .uri("http://example.test/upload")
                .header(CONTENT_LENGTH, "+16")
                .body(Body::from("0123456789abcdef"))
                .expect("request"),
        );
        assert!(!request_is_retryable(&req, &http::Method::PUT, 16));
        assert!(request_may_have_body(&req));
    }

    #[test]
    fn a_chunked_request_is_not_retried() {
        let req = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::PUT)
                .uri("http://example.test/upload")
                .header(TRANSFER_ENCODING, "chunked")
                .body(Body::from("0123456789abcdef"))
                .expect("request"),
        );
        assert!(!request_is_retryable(&req, &http::Method::PUT, 16));
        assert!(request_may_have_body(&req));
    }

    #[test]
    fn a_live_body_is_retried_within_the_threshold() {
        let (_sender, body) = Body::channel();
        let req = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::PUT)
                .uri("http://example.test/upload")
                .header(CONTENT_LENGTH, "16")
                .body(body)
                .expect("request"),
        );
        assert!(request_is_retryable(&req, &http::Method::PUT, 16));
        assert!(!request_is_retryable(&req, &http::Method::PUT, 15));
    }

    #[test]
    fn a_list_of_zero_members_declares_no_body() {
        let req = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::GET)
                .uri("http://example.test/resource")
                .header(CONTENT_LENGTH, "0, 0")
                .body(Body::empty())
                .expect("request"),
        );
        assert!(!request_may_have_body(&req));
    }

    #[test]
    fn an_unframed_live_body_is_not_treated_as_bodyless() {
        let (_sender, body) = Body::channel();
        let req = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::GET)
                .uri("http://example.test/resource")
                .body(body)
                .expect("request"),
        );

        assert!(request_may_have_body(&req));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn reverse_request_template_spools_large_body_outside_memory() {
        let payload = vec![b'x'; RETRY_TEMPLATE_MEMORY_BYTES + 1];
        let req = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::PUT)
                .uri("http://example.test/upload")
                .header(CONTENT_LENGTH, payload.len().to_string())
                .body(Body::from(payload.clone()))
                .expect("request"),
        );

        let template =
            ReverseRequestTemplate::from_request(req, payload.len(), Duration::from_secs(1))
                .await
                .expect("template");
        let path = match &template.body {
            ReverseRequestTemplateBody::File { file } => file.guard.path().to_path_buf(),
            ReverseRequestTemplateBody::Memory { .. } => panic!("large template should spool"),
        };
        assert!(path.exists());

        for _ in 0..2 {
            let req = template.build().expect("build");
            let body = qpx_http::body::to_bytes(req.into_head_and_body().1)
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
        let req = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::PUT)
                .uri("http://example.test/upload")
                .body(source_body)
                .expect("request"),
        );
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
        let (_, mut replay) = template.build().expect("replay").into_head_and_body();
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

#[cfg(test)]
mod spool_guard_tests {
    use crate::reverse::transport::request_template::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static GUARD_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A plain temp file for guard tests. Secure spool creation is
    /// owner-permission based and unavailable on some platforms; the guard
    /// itself only needs a path and a handle.
    fn plain_guarded_file(tag: &str) -> (std::path::PathBuf, SpoolFile<TokioFile>) {
        let id = GUARD_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "qpx-spool-guard-test-{}-{tag}-{id}",
            std::process::id()
        ));
        std::fs::write(&path, b"guarded").expect("test file");
        let handle = TokioFile::from_std(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open the test file"),
        );
        (
            path.clone(),
            SpoolFile::new(handle, path, "request", "retry_template"),
        )
    }

    #[test]
    fn spool_guard_unlinks_on_drop() {
        let (path, guard) = plain_guarded_file("drop");
        assert!(path.exists());
        drop(guard);
        assert!(!path.exists());
    }

    #[test]
    fn completed_template_keeps_unlink_on_drop() {
        let (path, guard) = plain_guarded_file("transfer");
        let template = SpooledTemplateFile { guard };
        assert!(path.exists());
        drop(template);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    fn retry_template_spool_files() -> std::collections::BTreeSet<std::path::PathBuf> {
        std::fs::read_dir(std::env::temp_dir())
            .expect("temp dir is readable")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("qpx-retry-template-"))
            })
            .collect()
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn failed_recording_leaves_no_spool_file() {
        let before = retry_template_spool_files();
        {
            let mut recorder = TemplateBodyRecorder::new(RETRY_TEMPLATE_MEMORY_BYTES + 1024);
            recorder
                .record_chunk(&Bytes::from(vec![0u8; RETRY_TEMPLATE_MEMORY_BYTES + 1]))
                .await
                .expect("first chunk spools");
            recorder
                .record_chunk(&Bytes::from(vec![0u8; 2048]))
                .await
                .expect_err("second chunk exceeds the limit");
        }
        let leaked: Vec<_> = retry_template_spool_files()
            .difference(&before)
            .cloned()
            .collect();
        assert!(leaked.is_empty(), "spool files left behind: {leaked:?}");
    }
}
