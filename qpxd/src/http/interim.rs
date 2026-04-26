use crate::http::body::Body;
use crate::http::h2_codec::{h2_request_to_hyper, send_h2_response_with_interim};
use crate::upstream::raw_http1::InterimResponseHead;
use anyhow::Result;
use bytes::Bytes;
use h2::Reason;
use http::{Request, Response};
use qpx_observability::RequestHandler;
use std::convert::Infallible;
use std::future::poll_fn;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration};
use tracing::warn;

pub(crate) const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub(crate) async fn serve_h2_with_interim<I, S>(
    io: I,
    service: S,
    enable_connect_protocol: bool,
    idle_timeout: Duration,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: RequestHandler<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    if enable_connect_protocol {
        builder.enable_connect_protocol();
    }
    let mut conn = timeout(idle_timeout, builder.handshake(io)).await??;
    let active_streams = Arc::new(AtomicUsize::new(0));
    loop {
        let accepted = timeout(idle_timeout, conn.accept()).await;
        let Some(result) = (match accepted {
            Ok(next) => next,
            Err(_) if active_streams.load(Ordering::Acquire) == 0 => return Ok(()),
            Err(_) => continue,
        }) else {
            break;
        };
        let (request, respond) = result?;
        active_streams.fetch_add(1, Ordering::AcqRel);
        let guard = ActiveH2StreamGuard::new(active_streams.clone());
        let service = service.clone();
        tokio::spawn(async move {
            let _guard = guard;
            let request = match h2_request_to_hyper(request) {
                Ok(request) => request,
                Err(err) => {
                    warn!(error = ?err, "invalid HTTP/2 request");
                    let mut respond = respond;
                    respond.send_reset(Reason::PROTOCOL_ERROR);
                    return;
                }
            };
            let request_method = request.method().clone();
            let allow_successful_connect_body =
                request.extensions().get::<h2::ext::Protocol>().is_some();

            let mut response = match service.call(request).await {
                Ok(response) => response,
                Err(impossible) => match impossible {},
            };
            let interim = take_interim_response_heads(&mut response);
            if let Err(err) = send_h2_response_with_interim(
                respond,
                response,
                &interim,
                &request_method,
                allow_successful_connect_body,
                idle_timeout,
            )
            .await
            {
                warn!(error = ?err, "HTTP/2 stream failed");
            }
        });
    }
    poll_fn(|cx| conn.poll_closed(cx)).await?;
    Ok(())
}

struct ActiveH2StreamGuard {
    active_streams: Arc<AtomicUsize>,
}

impl ActiveH2StreamGuard {
    fn new(active_streams: Arc<AtomicUsize>) -> Self {
        Self { active_streams }
    }
}

impl Drop for ActiveH2StreamGuard {
    fn drop(&mut self) {
        self.active_streams.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) async fn sniff_h2_preface<S>(stream: &mut S, timeout_dur: Duration) -> Result<Bytes>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let deadline = tokio::time::Instant::now() + timeout_dur;
    let mut prefix = Vec::new();
    let mut one = [0u8; 1];
    loop {
        if prefix.len() >= H2_PREFACE.len() {
            return Ok(Bytes::from(prefix));
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let n = match timeout(remaining, stream.read(&mut one)).await {
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => return Ok(Bytes::from(prefix)),
        };
        if n == 0 {
            return Ok(Bytes::from(prefix));
        }
        prefix.push(one[0]);
        if !H2_PREFACE.starts_with(prefix.as_slice()) {
            return Ok(Bytes::from(prefix));
        }
    }
}

pub(crate) fn take_interim_response_heads(
    response: &mut Response<Body>,
) -> Vec<InterimResponseHead> {
    response
        .extensions_mut()
        .remove::<Vec<InterimResponseHead>>()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{serve_h2_with_interim, H2_PREFACE};
    use crate::http::body::Body;
    use http::{Request, Response};
    use qpx_observability::handler_fn;
    use std::convert::Infallible;
    use tokio::io::duplex;
    use tokio::io::AsyncWriteExt;
    use tokio::time::{sleep, Duration};

    #[tokio::test(flavor = "current_thread")]
    async fn h2_server_advertises_extended_connect_when_enabled() {
        let (client_io, server_io) = duplex(1024);
        let service = handler_fn(|_req: Request<Body>| async move {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(200)
                    .body(Body::from(""))
                    .expect("static response"),
            )
        });

        tokio::spawn(async move {
            serve_h2_with_interim(server_io, service, true, Duration::from_secs(5))
                .await
                .expect("serve h2");
        });

        let (client, connection) = h2::client::handshake(client_io).await.expect("handshake");
        tokio::spawn(async move {
            connection.await.expect("client connection");
        });
        let _ = client.clone().ready().await.expect("client ready");
        for _ in 0..20 {
            if client.is_extended_connect_protocol_enabled() {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(client.is_extended_connect_protocol_enabled());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_server_omits_extended_connect_when_disabled() {
        let (client_io, server_io) = duplex(1024);
        let service = handler_fn(|_req: Request<Body>| async move {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(200)
                    .body(Body::from(""))
                    .expect("static response"),
            )
        });

        tokio::spawn(async move {
            serve_h2_with_interim(server_io, service, false, Duration::from_secs(5))
                .await
                .expect("serve h2");
        });

        let (client, connection) = h2::client::handshake(client_io).await.expect("handshake");
        tokio::spawn(async move {
            connection.await.expect("client connection");
        });
        let _ = client.clone().ready().await.expect("client ready");
        assert!(!client.is_extended_connect_protocol_enabled());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_preface_only_connection_times_out() {
        let (mut client_io, server_io) = duplex(1024);
        client_io
            .write_all(H2_PREFACE)
            .await
            .expect("write h2 preface");
        let service = handler_fn(|_req: Request<Body>| async move {
            Ok::<_, Infallible>(
                Response::builder()
                    .status(200)
                    .body(Body::from(""))
                    .expect("static response"),
            )
        });

        let result = tokio::time::timeout(
            Duration::from_millis(500),
            serve_h2_with_interim(server_io, service, false, Duration::from_millis(20)),
        )
        .await;
        assert!(result.is_ok(), "preface-only H2 must not stay open");
        drop(client_io);
    }
}
