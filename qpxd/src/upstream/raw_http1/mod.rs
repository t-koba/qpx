use anyhow::{Result, anyhow};
use hyper::header::{CONTENT_LENGTH, HeaderMap};
use hyper::{Request, Response, StatusCode};
use qpx_core::tls::UpstreamCertificateInfo;
use qpx_http::body::Body;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

mod io;
mod request;
mod response;
#[cfg(test)]
mod tests;

const MAX_HEADER_BYTES: usize = 128 * 1024;
const READ_BUF_SIZE: usize = 16 * 1024;
const MAX_CHUNKED_BODY_BYTES: u64 = 1024 * 1024 * 1024;
const RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT: tokio::time::Duration =
    tokio::time::Duration::from_secs(30);
const MAX_RECYCLED_HTTP1_CONNECTIONS_PER_IDLE: usize = 8;

#[derive(Debug, Clone)]
pub(crate) struct InterimResponseHead {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
}

pub(crate) struct Http1ResponseWithInterim {
    pub(crate) interim: Vec<InterimResponseHead>,
    pub(crate) response: Response<Body>,
    pub(crate) upstream_cert: Option<UpstreamCertificateInfo>,
}

type RecycleFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type RecycleFn<S> = dyn Fn(S) -> RecycleFuture + Send + Sync;

#[derive(Clone)]
pub(crate) struct Http1ConnectionRecycler<S> {
    recycle: Arc<RecycleFn<S>>,
}

impl<S> Http1ConnectionRecycler<S> {
    pub(crate) fn new<F, Fut>(recycle: F) -> Self
    where
        F: Fn(S) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self {
            recycle: Arc::new(move |stream| Box::pin(recycle(stream))),
        }
    }

    pub(crate) fn from_idle(idle: Arc<Mutex<Vec<S>>>) -> Self
    where
        S: Send + 'static,
    {
        Self::new(move |stream| {
            let idle = idle.clone();
            async move {
                let mut idle = idle.lock().await;
                if idle.len() < MAX_RECYCLED_HTTP1_CONNECTIONS_PER_IDLE {
                    idle.push(stream);
                }
            }
        })
    }

    async fn recycle(&self, stream: S) {
        (self.recycle)(stream).await;
    }
}

pub(crate) async fn send_http1_request_with_interim<S>(
    stream: S,
    req: Request<Body>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_http1_request_with_interim_inner(stream, req, None).await
}

pub(crate) async fn send_http1_request_with_interim_reusable<S>(
    stream: S,
    req: Request<Body>,
    recycler: Http1ConnectionRecycler<S>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_http1_request_with_interim_inner(stream, req, Some(recycler)).await
}

async fn send_http1_request_with_interim_inner<S>(
    mut stream: S,
    req: Request<Body>,
    recycler: Option<Http1ConnectionRecycler<S>>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request_method = req.method().clone();
    request::write_http1_request(&mut stream, req).await?;
    let (interim, final_head, buffered_body) =
        response::read_response_head_with_interim(&mut stream, &request_method).await?;
    let response = response::build_response(stream, final_head, buffered_body, recycler);
    Ok(Http1ResponseWithInterim {
        interim,
        response,
        upstream_cert: None,
    })
}

fn parse_declared_content_length(headers: &HeaderMap) -> Result<Option<u64>> {
    let mut parsed = None::<u64>;
    for value in headers.get_all(CONTENT_LENGTH).iter() {
        let raw = value
            .to_str()
            .map_err(|_| anyhow!("invalid content-length header"))?;
        for part in raw.split(',') {
            let len = part
                .trim()
                .parse::<u64>()
                .map_err(|_| anyhow!("invalid content-length value: {}", part.trim()))?;
            match parsed {
                Some(existing) if existing != len => {
                    return Err(anyhow!("conflicting content-length values"));
                }
                Some(_) => {}
                None => parsed = Some(len),
            }
        }
    }
    Ok(parsed)
}
