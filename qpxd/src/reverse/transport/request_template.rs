use crate::http::body::Body;
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use hyper::{Request, Uri};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

impl ReverseRequestTemplate {
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

impl ReverseRequestTemplateBody {
    fn build(&self) -> Body {
        match self {
            Self::Memory { chunks } => Body::replay_chunks(chunks.iter().cloned().collect(), None),
            Self::File { file } => file.body(),
        }
    }
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
            let body = crate::http::body::to_bytes(req.into_body())
                .await
                .expect("read body");
            assert_eq!(body.as_ref(), payload.as_slice());
        }

        drop(template);
        assert!(!path.exists());
    }
}
