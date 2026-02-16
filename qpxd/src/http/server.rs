use hyper::service::Service;
use hyper::{Body, Request, Response};
use std::error::Error as StdError;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Duration;

pub async fn serve_http1_with_upgrades<I, S>(
    io: I,
    service: S,
    header_read_timeout: Duration,
    http1_only: bool,
) -> Result<(), hyper::Error>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let mut http = hyper::server::conn::Http::new();
    http.http1_keep_alive(true);
    http.http1_header_read_timeout(header_read_timeout);
    http.http1_only(http1_only);
    http.serve_connection(io, service).with_upgrades().await
}
