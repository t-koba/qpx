use crate::http::codec::h2::{H2TransportTuning, send_h2_response_with_interim};
use crate::upstream::raw_http1::InterimResponseHead;
use anyhow::Result;
use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use h2::Reason;
use http::{Request, Response};
use qpx_http::body::Body;
use qpx_observability::RequestHandler;
use std::convert::Infallible;
use std::future::poll_fn;
use tokio::io::AsyncReadExt;
use tokio::time::{Duration, timeout};
use tracing::warn;

pub(crate) const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[cfg(test)]
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
{
    serve_h2_with_interim_and_capacity(io, service, enable_connect_protocol, idle_timeout, 16).await
}

#[cfg(test)]
pub(crate) async fn serve_h2_with_interim_and_capacity<I, S>(
    io: I,
    service: S,
    enable_connect_protocol: bool,
    idle_timeout: Duration,
    body_channel_capacity: usize,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: RequestHandler<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
{
    serve_h2_with_interim_and_capacity_and_tuning(
        io,
        service,
        enable_connect_protocol,
        idle_timeout,
        body_channel_capacity,
        H2TransportTuning::default(),
    )
    .await
}

pub(crate) async fn serve_h2_with_interim_and_capacity_and_tuning<I, S>(
    io: I,
    service: S,
    enable_connect_protocol: bool,
    idle_timeout: Duration,
    body_channel_capacity: usize,
    h2_tuning: H2TransportTuning,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: RequestHandler<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + Sync
        + 'static,
{
    let mut builder = h2::server::Builder::new();
    crate::http::codec::h2::tune_h2_server_builder_with(&mut builder, h2_tuning);
    if enable_connect_protocol {
        builder.enable_connect_protocol();
    }
    let mut conn = timeout(idle_timeout, builder.handshake(io)).await??;
    let mut streams = FuturesUnordered::new();
    let idle_timer = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_timer);
    let mut connection_closed = false;
    loop {
        tokio::select! {
            biased;
            completed = streams.next(), if !streams.is_empty() => {
                debug_assert!(completed.is_some());
                idle_timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + idle_timeout);
            }
            accepted = conn.accept(), if !connection_closed => {
                let Some(result) = accepted else {
                    connection_closed = true;
                    continue;
                };
                let (request, respond) = result?;
                idle_timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + idle_timeout);
                streams.push(serve_h2_stream(
                    request,
                    respond,
                    &service,
                    body_channel_capacity,
                    idle_timeout,
                ));
            }
            () = idle_timer.as_mut() => {
                if streams.is_empty() {
                    return Ok(());
                }
                idle_timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + idle_timeout);
            }
        }
        if connection_closed && streams.is_empty() {
            break;
        }
    }
    poll_fn(|cx| conn.poll_closed(cx)).await?;
    Ok(())
}

async fn serve_h2_stream<S>(
    request: Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    service: &S,
    body_channel_capacity: usize,
    idle_timeout: Duration,
) where
    S: RequestHandler<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Send
        + Sync
        + 'static,
{
    let request = match crate::http::codec::h2::h2_request_to_hyper_with_capacity(
        request,
        body_channel_capacity,
    ) {
        Ok(request) => request,
        Err(err) => {
            warn!(error = ?err, "invalid HTTP/2 request");
            let mut respond = respond;
            respond.send_reset(Reason::PROTOCOL_ERROR);
            return;
        }
    };
    let request_method = request.method().clone();
    let allow_successful_connect_body = request.extensions().get::<h2::ext::Protocol>().is_some();

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
}

pub(crate) async fn sniff_h2_preface<S>(stream: &mut S, timeout_dur: Duration) -> Result<Bytes>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let deadline = crate::runtime::tokio_deadline_after(timeout_dur);
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
    use super::{H2_PREFACE, serve_h2_with_interim};
    use http::{Request, Response};
    use qpx_http::body::Body;
    use qpx_observability::handler_fn;
    use std::convert::Infallible;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::io::duplex;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Notify;
    use tokio::time::{Duration, sleep};

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

    #[tokio::test]
    async fn h2_server_processes_a_second_stream_while_the_first_is_pending() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("listener address");
        let first_started = Arc::new(Notify::new());
        let release_first = Arc::new(Notify::new());
        let server_first_started = first_started.clone();
        let server_release_first = release_first.clone();
        let service = handler_fn(move |req: Request<Body>| {
            let first_started = server_first_started.clone();
            let release_first = server_release_first.clone();
            async move {
                if req.uri().path() == "/first" {
                    first_started.notify_one();
                    release_first.notified().await;
                }
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(200)
                        .body(Body::from(req.uri().path().to_owned()))
                        .expect("response"),
                )
            }
        });
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            serve_h2_with_interim(socket, service, false, Duration::from_secs(5))
                .await
                .expect("serve h2");
        });

        let socket = TcpStream::connect(addr).await.expect("connect");
        let (mut client, connection) = h2::client::handshake(socket).await.expect("handshake");
        tokio::spawn(async move {
            connection.await.expect("client connection");
        });

        client = client.ready().await.expect("first ready");
        let first = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse_edges.test/first")
            .body(())
            .expect("first request");
        let (first_response, _) = client.send_request(first, true).expect("send first");
        first_started.notified().await;

        client = client.ready().await.expect("second ready");
        let second = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse_edges.test/second")
            .body(())
            .expect("second request");
        let (second_response, _) = client.send_request(second, true).expect("send second");
        let second_response = tokio::time::timeout(Duration::from_secs(1), second_response)
            .await
            .expect("second response must not wait for first")
            .expect("second response");
        assert_eq!(second_response.status(), ::http::StatusCode::OK);

        release_first.notify_one();
        let first_response = first_response.await.expect("first response");
        assert_eq!(first_response.status(), ::http::StatusCode::OK);
    }
}
