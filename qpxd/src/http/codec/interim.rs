use crate::http::codec::h2::{
    H2_MAX_CONCURRENT_STREAMS, H2TransportTuning, send_h2_response_with_interim,
};
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
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use tokio::io::AsyncReadExt;
use tokio::time::{Duration, timeout};
use tokio_util::sync::ReusableBoxFuture;
use tracing::{debug, warn};

pub(crate) const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
// Keep request admission aligned with the protocol stream limit. This remains bounded while
// avoiding an artificial half-capacity bottleneck for a single connection's stream fan-out.
const H2_ACCEPT_BACKLOG: usize = H2_MAX_CONCURRENT_STREAMS;
// Release response buffers promptly without letting a continuously ready completion queue
// postpone admission until every previously admitted stream has finished.
const H2_COMPLETION_BURST: usize = 8;

enum H2ConnectionEvent {
    ConcurrentStreamCompleted,
    PrimaryStreamCompleted,
    Accepted,
    IdleTimeout,
}

fn prioritize_h2_admission(completions_since_admission: usize) -> bool {
    completions_since_admission >= H2_COMPLETION_BURST
}

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
    let active_streams = Arc::new(AtomicUsize::new(0));
    let mut reusable_primary_stream: Option<ReusableBoxFuture<'_, ()>> = None;
    let mut primary_stream = None;
    let mut concurrent_streams = FuturesUnordered::new();
    let mut accepting_streams = true;
    let mut completions_since_admission = 0usize;
    let idle_timer = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_timer);
    loop {
        let accept_backlog_available = concurrent_streams.len() < H2_ACCEPT_BACKLOG;
        if accepting_streams && !accept_backlog_available {
            let progress = poll_fn(|cx| {
                Poll::Ready(match conn.poll_closed(cx) {
                    Poll::Ready(result) => Some(result),
                    Poll::Pending => None,
                })
            })
            .await;
            if let Some(result) = progress {
                match result {
                    Ok(()) => {
                        accepting_streams = false;
                        if primary_stream.is_none() && concurrent_streams.is_empty() {
                            break;
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        // Reap completed streams first to release response buffers. After a bounded
        // burst, prefer a ready admission so multiplexed requests cannot starve.
        let mut accepted_stream = None;
        let event = if prioritize_h2_admission(completions_since_admission) {
            tokio::select! {
                biased;
                accepted = conn.accept(), if accepting_streams && accept_backlog_available => {
                    accepted_stream = Some(accepted);
                    H2ConnectionEvent::Accepted
                }
                Some(()) = concurrent_streams.next(), if !concurrent_streams.is_empty() => {
                    H2ConnectionEvent::ConcurrentStreamCompleted
                }
                completed = poll_optional_h2_stream(&mut primary_stream), if primary_stream.is_some() => {
                    let () = completed;
                    H2ConnectionEvent::PrimaryStreamCompleted
                }
                () = idle_timer.as_mut() => H2ConnectionEvent::IdleTimeout,
            }
        } else {
            tokio::select! {
                biased;
                Some(()) = concurrent_streams.next(), if !concurrent_streams.is_empty() => {
                    H2ConnectionEvent::ConcurrentStreamCompleted
                }
                completed = poll_optional_h2_stream(&mut primary_stream), if primary_stream.is_some() => {
                    let () = completed;
                    H2ConnectionEvent::PrimaryStreamCompleted
                }
                accepted = conn.accept(), if accepting_streams && accept_backlog_available => {
                    accepted_stream = Some(accepted);
                    H2ConnectionEvent::Accepted
                }
                () = idle_timer.as_mut() => H2ConnectionEvent::IdleTimeout,
            }
        };
        match event {
            H2ConnectionEvent::ConcurrentStreamCompleted => {
                completions_since_admission = completions_since_admission.saturating_add(1);
                if primary_stream.is_none() && concurrent_streams.is_empty() {
                    if !accepting_streams {
                        break;
                    }
                    idle_timer
                        .as_mut()
                        .reset(tokio::time::Instant::now() + idle_timeout);
                }
            }
            H2ConnectionEvent::PrimaryStreamCompleted => {
                completions_since_admission = completions_since_admission.saturating_add(1);
                reusable_primary_stream = primary_stream.take();
                if !accepting_streams && concurrent_streams.is_empty() {
                    break;
                }
                if concurrent_streams.is_empty() {
                    idle_timer
                        .as_mut()
                        .reset(tokio::time::Instant::now() + idle_timeout);
                }
            }
            H2ConnectionEvent::Accepted => {
                let accepted = accepted_stream.ok_or_else(|| {
                    anyhow::anyhow!("accepted stream event is missing its result")
                })?;
                let Some(result) = accepted else {
                    accepting_streams = false;
                    if primary_stream.is_none() && concurrent_streams.is_empty() {
                        break;
                    }
                    continue;
                };
                completions_since_admission = 0;
                let (request, respond) = result?;
                let active_stream = ActiveH2Stream::new(&active_streams);
                let stream = serve_h2_stream(
                    request,
                    respond,
                    &service,
                    body_channel_capacity,
                    idle_timeout,
                    active_stream,
                );
                if primary_stream.is_none() && concurrent_streams.is_empty() {
                    let reusable = if let Some(mut reusable) = reusable_primary_stream.take() {
                        reusable.set(stream);
                        reusable
                    } else {
                        ReusableBoxFuture::new(stream)
                    };
                    primary_stream = Some(reusable);
                } else {
                    concurrent_streams.push(Box::pin(stream));
                }
            }
            H2ConnectionEvent::IdleTimeout => {
                if primary_stream.is_none() && concurrent_streams.is_empty() {
                    return Ok(());
                }
                idle_timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + idle_timeout);
            }
        }
    }
    drop(reusable_primary_stream);
    drop(primary_stream);
    drop(concurrent_streams);
    poll_fn(|cx| conn.poll_closed(cx)).await?;
    Ok(())
}

async fn poll_optional_h2_stream<T>(stream: &mut Option<ReusableBoxFuture<'_, T>>) -> T {
    poll_fn(|cx| match stream.as_mut() {
        Some(stream) => stream.poll(cx),
        None => std::task::Poll::Pending,
    })
    .await
}

async fn serve_h2_stream<S>(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    service: &S,
    body_channel_capacity: usize,
    idle_timeout: Duration,
    active_stream: ActiveH2Stream,
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
            respond.send_reset(Reason::PROTOCOL_ERROR);
            return;
        }
    };
    let request_method = request.method().clone();
    let allow_successful_connect_body = request.extensions().get::<h2::ext::Protocol>().is_some();

    let mut service_call = Box::pin(service.call(request));
    let mut response = tokio::select! {
        biased;
        response = &mut service_call => match response {
            Ok(response) => response,
            Err(impossible) => match impossible {},
        },
        reset = poll_fn(|cx| respond.poll_reset(cx)) => {
            match reset {
                Ok(reason) => debug!(?reason, "HTTP/2 request cancelled before response headers"),
                Err(err) => {
                    let err = anyhow::Error::from(err);
                    if crate::http::codec::is_expected_peer_disconnect(&err) {
                        debug!(error = ?err, "HTTP/2 response reset watch closed by peer");
                    } else {
                        warn!(error = ?err, "HTTP/2 response reset watch failed");
                    }
                }
            }
            return;
        }
    };
    let interim = take_interim_response_heads(&mut response);
    if let Err(err) = send_h2_response_with_interim(
        respond,
        response,
        &interim,
        &request_method,
        allow_successful_connect_body,
        idle_timeout,
        active_stream.count(),
    )
    .await
    {
        if crate::http::codec::is_expected_peer_disconnect(&err) {
            debug!(error = ?err, "HTTP/2 response stream closed by peer");
        } else {
            warn!(error = ?err, "HTTP/2 stream failed");
        }
    }
}

struct ActiveH2Stream {
    active: Arc<AtomicUsize>,
}

impl ActiveH2Stream {
    fn new(active: &Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::Relaxed);
        Self {
            active: active.clone(),
        }
    }

    fn count(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }
}

impl Drop for ActiveH2Stream {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
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
    use super::{H2_COMPLETION_BURST, H2_PREFACE, prioritize_h2_admission, serve_h2_with_interim};
    use h2::Reason;
    use http::{Request, Response};
    use qpx_http::body::Body;
    use qpx_observability::handler_fn;
    use std::convert::Infallible;
    use std::future::pending;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::io::duplex;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Notify;
    use tokio::time::{Duration, sleep, timeout};

    #[test]
    fn h2_admission_priority_starts_after_a_bounded_completion_burst() {
        assert!(!prioritize_h2_admission(H2_COMPLETION_BURST - 1));
        assert!(prioritize_h2_admission(H2_COMPLETION_BURST));
        assert!(prioritize_h2_admission(H2_COMPLETION_BURST + 1));
    }

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

    #[tokio::test(flavor = "current_thread")]
    async fn h2_idle_timeout_starts_after_stream_completion() {
        let (client_io, server_io) = duplex(4096);
        let service = handler_fn(|_req: Request<Body>| async move {
            sleep(Duration::from_millis(70)).await;
            Ok::<_, Infallible>(
                Response::builder()
                    .status(200)
                    .body(Body::empty())
                    .expect("response"),
            )
        });
        tokio::spawn(async move {
            serve_h2_with_interim(server_io, service, false, Duration::from_millis(100))
                .await
                .expect("serve h2");
        });

        let (mut client, connection) = h2::client::handshake(client_io).await.expect("handshake");
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
        assert_eq!(
            first_response.await.expect("first response").status(),
            ::http::StatusCode::OK
        );

        sleep(Duration::from_millis(60)).await;
        client = client
            .ready()
            .await
            .expect("connection must remain idle after stream completion");
        let second = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse_edges.test/second")
            .body(())
            .expect("second request");
        let (second_response, _) = client.send_request(second, true).expect("send second");
        assert_eq!(
            second_response.await.expect("second response").status(),
            ::http::StatusCode::OK
        );
    }

    #[tokio::test]
    async fn h2_idle_timeout_resets_when_a_worker_stream_finishes_last() {
        let (client_io, server_io) = duplex(4096);
        let primary_started = Arc::new(Notify::new());
        let worker_started = Arc::new(Notify::new());
        let release_primary = Arc::new(Notify::new());
        let release_worker = Arc::new(Notify::new());
        let service = handler_fn({
            let primary_started = Arc::clone(&primary_started);
            let worker_started = Arc::clone(&worker_started);
            let release_primary = Arc::clone(&release_primary);
            let release_worker = Arc::clone(&release_worker);
            move |req: Request<Body>| {
                let primary_started = Arc::clone(&primary_started);
                let worker_started = Arc::clone(&worker_started);
                let release_primary = Arc::clone(&release_primary);
                let release_worker = Arc::clone(&release_worker);
                async move {
                    match req.uri().path() {
                        "/primary" => {
                            primary_started.notify_one();
                            release_primary.notified().await;
                        }
                        "/worker" => {
                            worker_started.notify_one();
                            release_worker.notified().await;
                        }
                        _ => {}
                    }
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                }
            }
        });
        tokio::spawn(async move {
            serve_h2_with_interim(server_io, service, false, Duration::from_millis(500))
                .await
                .expect("serve h2");
        });

        let (mut client, connection) = h2::client::handshake(client_io).await.expect("handshake");
        tokio::spawn(async move {
            connection.await.expect("client connection");
        });
        client = client.ready().await.expect("primary ready");
        let primary = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse_edges.test/primary")
            .body(())
            .expect("primary request");
        let (primary_response, _) = client.send_request(primary, true).expect("send primary");
        primary_started.notified().await;

        client = client.ready().await.expect("worker ready");
        let worker = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse_edges.test/worker")
            .body(())
            .expect("worker request");
        let (worker_response, _) = client.send_request(worker, true).expect("send worker");
        worker_started.notified().await;

        release_primary.notify_one();
        assert_eq!(
            primary_response.await.expect("primary response").status(),
            ::http::StatusCode::OK
        );
        sleep(Duration::from_millis(350)).await;
        release_worker.notify_one();
        assert_eq!(
            worker_response.await.expect("worker response").status(),
            ::http::StatusCode::OK
        );

        sleep(Duration::from_millis(250)).await;
        client = client
            .ready()
            .await
            .expect("connection must remain idle after worker completion");
        let final_request = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse_edges.test/final")
            .body(())
            .expect("final request");
        let (final_response, _) = client
            .send_request(final_request, true)
            .expect("send final request");
        assert_eq!(
            final_response.await.expect("final response").status(),
            ::http::StatusCode::OK
        );
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

    #[tokio::test]
    async fn h2_scheduler_completes_a_multiplexed_request_batch() {
        const REQUESTS: usize = 128;
        let (client_io, server_io) = duplex(1024 * 1024);
        let service = handler_fn(|_req: Request<Body>| async move {
            Ok::<_, Infallible>(Response::new(Body::from("ok")))
        });
        tokio::spawn(async move {
            serve_h2_with_interim(server_io, service, false, Duration::from_secs(5))
                .await
                .expect("serve h2");
        });

        let (mut client, connection) = h2::client::handshake(client_io).await.expect("handshake");
        tokio::spawn(async move {
            connection.await.expect("client connection");
        });
        let mut responses = Vec::with_capacity(REQUESTS);
        for request_id in 0..REQUESTS {
            client = client.ready().await.expect("client ready");
            let request = ::http::Request::builder()
                .method("GET")
                .uri(format!("https://reverse_edges.test/{request_id}"))
                .body(())
                .expect("request");
            let (response, _) = client.send_request(request, true).expect("send request");
            responses.push(response);
        }
        for response in responses {
            let response = timeout(Duration::from_secs(1), response)
                .await
                .expect("multiplexed response timed out")
                .expect("multiplexed response");
            assert_eq!(response.status(), ::http::StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn h2_client_reset_cancels_pending_service_work() {
        struct DropSignal(Arc<Notify>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }

        let (client_io, server_io) = duplex(4096);
        let started = Arc::new(Notify::new());
        let dropped = Arc::new(Notify::new());
        let service_started = started.clone();
        let service_dropped = dropped.clone();
        let service = handler_fn(move |_req: Request<Body>| {
            let started = service_started.clone();
            let dropped = service_dropped.clone();
            async move {
                let _drop_signal = DropSignal(dropped);
                started.notify_one();
                pending::<()>().await;
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        });
        tokio::spawn(async move {
            serve_h2_with_interim(server_io, service, false, Duration::from_secs(5))
                .await
                .expect("serve h2");
        });

        let (mut client, connection) = h2::client::handshake(client_io).await.expect("handshake");
        tokio::spawn(async move {
            connection.await.expect("client connection");
        });
        client = client.ready().await.expect("client ready");
        let request = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse_edges.test/cancel")
            .body(())
            .expect("request");
        let (_response, mut request_stream) =
            client.send_request(request, true).expect("send request");
        started.notified().await;
        request_stream.send_reset(Reason::CANCEL);

        timeout(Duration::from_secs(1), dropped.notified())
            .await
            .expect("service future must be cancelled after reset");
    }

    #[tokio::test]
    async fn h2_client_reset_drops_pending_response_body() {
        let (client_io, server_io) = duplex(4096);
        let body_closed = Arc::new(Notify::new());
        let service_body_closed = body_closed.clone();
        let service = handler_fn(move |_req: Request<Body>| {
            let body_closed = service_body_closed.clone();
            async move {
                let (sender, body) = Body::channel_with_capacity(1);
                tokio::spawn(async move {
                    sender.closed().await;
                    body_closed.notify_one();
                });
                Ok::<_, Infallible>(Response::new(body))
            }
        });
        tokio::spawn(async move {
            serve_h2_with_interim(server_io, service, false, Duration::from_secs(5))
                .await
                .expect("serve h2");
        });

        let (mut client, connection) = h2::client::handshake(client_io).await.expect("handshake");
        tokio::spawn(async move {
            connection.await.expect("client connection");
        });
        client = client.ready().await.expect("client ready");
        let request = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse_edges.test/cancel-response")
            .body(())
            .expect("request");
        let (response, mut request_stream) =
            client.send_request(request, true).expect("send request");
        let response = response.await.expect("response headers");
        assert_eq!(response.status(), ::http::StatusCode::OK);
        request_stream.send_reset(Reason::CANCEL);

        timeout(Duration::from_secs(1), body_closed.notified())
            .await
            .expect("response body must be dropped after reset");
    }

    #[tokio::test]
    async fn h2_connection_close_cancels_pending_service_work() {
        struct DropSignal(Arc<Notify>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }

        let (client_io, server_io) = duplex(4096);
        let started = Arc::new(Notify::new());
        let dropped = Arc::new(Notify::new());
        let service_started = started.clone();
        let service_dropped = dropped.clone();
        let service = handler_fn(move |_req: Request<Body>| {
            let started = service_started.clone();
            let dropped = service_dropped.clone();
            async move {
                let _drop_signal = DropSignal(dropped);
                started.notify_one();
                pending::<()>().await;
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        });
        tokio::spawn(async move {
            let _ = serve_h2_with_interim(server_io, service, false, Duration::from_secs(5)).await;
        });

        let (mut client, connection) = h2::client::handshake(client_io).await.expect("handshake");
        let connection_task = tokio::spawn(connection);
        client = client.ready().await.expect("client ready");
        let request = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse_edges.test/disconnect")
            .body(())
            .expect("request");
        let (response, request_stream) = client.send_request(request, true).expect("send request");
        started.notified().await;
        drop(response);
        drop(request_stream);
        drop(client);
        connection_task.abort();

        timeout(Duration::from_secs(1), dropped.notified())
            .await
            .expect("service future must be cancelled after connection close");
    }
}
