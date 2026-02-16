use anyhow::{anyhow, Result};
use bytes::BytesMut;
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use hyper::body::HttpBody as _;
use hyper::{Body, Request, Uri};

#[derive(Clone)]
pub(super) struct ReverseRequestTemplate {
    method: http::Method,
    uri: Uri,
    version: http::Version,
    headers: http::HeaderMap,
    body: bytes::Bytes,
}

impl ReverseRequestTemplate {
    pub(super) async fn from_request(req: Request<Body>, max_body_bytes: usize) -> Result<Self> {
        let (parts, body) = req.into_parts();
        let body = collect_body_limited(body, max_body_bytes).await?;
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
            .body(Body::from(self.body.clone()))?;
        *req.headers_mut() = self.headers.clone();
        Ok(req)
    }
}

pub(super) fn request_is_retryable(req: &Request<Body>, method: &http::Method) -> bool {
    req.version() == http::Version::HTTP_11
        && is_retryable_method(method)
        && !request_may_have_body(req)
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

async fn collect_body_limited(mut body: Body, max_body_bytes: usize) -> Result<bytes::Bytes> {
    let mut out = BytesMut::new();
    while let Some(frame) = body.data().await {
        let chunk = frame?;
        let next = out
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("reverse request body length overflow"))?;
        if next > max_body_bytes {
            return Err(anyhow!(
                "reverse retry template body exceeds limit: {} bytes",
                max_body_bytes
            ));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
}
