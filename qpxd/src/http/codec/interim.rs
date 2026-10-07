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

enum H2ConnectionEvent<'a> {
    ConcurrentStreamCompleted(ReusableBoxFuture<'a, ()>),
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
    let mut phase = crate::perf_diagnostics::PhaseTimer::begin_native_h2_connection();
    phase
        .observe_future(serve_h2_connection_inner(
            io,
            service,
            enable_connect_protocol,
            idle_timeout,
            body_channel_capacity,
            h2_tuning,
        ))
        .await
}

async fn serve_h2_connection_inner<I, S>(
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
    let active_streams = AtomicUsize::new(0);
    let mut reusable_primary_stream: Option<ReusableBoxFuture<'_, ()>> = None;
    let mut reusable_concurrent_streams: Vec<ReusableBoxFuture<'_, ()>> = Vec::new();
    let mut primary_stream = None;
    let mut concurrent_streams = FuturesUnordered::new();
    let mut accepting_streams = true;
    let mut completions_since_admission = 0usize;
    let mut completions_since_drive = 0usize;
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
            completions_since_drive = 0;
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
        // Reap completed streams first to release response buffers. The reusable primary
        // future sits outside FuturesUnordered, so poll it before the concurrent completion
        // queue to give it the same bounded progress guarantee. After a bounded completion
        // burst, prefer a ready admission so multiplexed requests cannot starve.
        let mut accepted_stream = None;
        let event = if prioritize_h2_admission(completions_since_admission) {
            tokio::select! {
                biased;
                accepted = conn.accept(), if accepting_streams && accept_backlog_available => {
                    accepted_stream = Some(accepted);
                    H2ConnectionEvent::Accepted
                }
                completed = poll_optional_h2_stream(&mut primary_stream), if primary_stream.is_some() => {
                    let () = completed;
                    H2ConnectionEvent::PrimaryStreamCompleted
                }
                Some(stream) = concurrent_streams.next(), if !concurrent_streams.is_empty() => {
                    H2ConnectionEvent::ConcurrentStreamCompleted(stream)
                }
                () = idle_timer.as_mut() => H2ConnectionEvent::IdleTimeout,
            }
        } else {
            tokio::select! {
                biased;
                completed = poll_optional_h2_stream(&mut primary_stream), if primary_stream.is_some() => {
                    let () = completed;
                    H2ConnectionEvent::PrimaryStreamCompleted
                }
                Some(stream) = concurrent_streams.next(), if !concurrent_streams.is_empty() => {
                    H2ConnectionEvent::ConcurrentStreamCompleted(stream)
                }
                accepted = conn.accept(), if accepting_streams && accept_backlog_available => {
                    accepted_stream = Some(accepted);
                    H2ConnectionEvent::Accepted
                }
                () = idle_timer.as_mut() => H2ConnectionEvent::IdleTimeout,
            }
        };
        let stream_completed = matches!(
            event,
            H2ConnectionEvent::ConcurrentStreamCompleted(_)
                | H2ConnectionEvent::PrimaryStreamCompleted
        );
        match event {
            H2ConnectionEvent::ConcurrentStreamCompleted(stream) => {
                // Reuse completed stream storage within this connection, bounded by
                // the existing admission limit. The completion queue holds only
                // pointers instead of copying each large request state into a node.
                if reusable_concurrent_streams.len() < H2_ACCEPT_BACKLOG {
                    reusable_concurrent_streams.push(stream);
                }
            }
            H2ConnectionEvent::PrimaryStreamCompleted => {
                reusable_primary_stream = primary_stream.take();
            }
            H2ConnectionEvent::Accepted => {
                // Admission polls the driver too. Batch ready completions between
                // those polls while always flushing the final outstanding stream.
                completions_since_drive = 0;
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
                let stream = tokio::task::unconstrained(serve_h2_stream(
                    request,
                    respond,
                    &service,
                    body_channel_capacity,
                    idle_timeout,
                    active_stream,
                ));
                if primary_stream.is_none() && concurrent_streams.is_empty() {
                    let reusable = if let Some(mut reusable) = reusable_primary_stream.take() {
                        reusable.set(stream);
                        reusable
                    } else {
                        ReusableBoxFuture::new(stream)
                    };
                    primary_stream = Some(reusable);
                } else {
                    let reusable = if let Some(mut reusable) = reusable_concurrent_streams.pop() {
                        reusable.set(stream);
                        reusable
                    } else {
                        ReusableBoxFuture::new(stream)
                    };
                    concurrent_streams.push(complete_reusable_h2_stream(reusable));
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
        if stream_completed {
            completions_since_admission = completions_since_admission.saturating_add(1);
            completions_since_drive += 1;
            let streams_empty = primary_stream.is_none() && concurrent_streams.is_empty();
            if completions_since_drive >= H2_COMPLETION_BURST || !accepting_streams || streams_empty
            {
                drive_h2_connection_now(&mut conn).await?;
                completions_since_drive = 0;
            }
            if streams_empty {
                if !accepting_streams {
                    break;
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
    drop(reusable_concurrent_streams);
    poll_fn(|cx| conn.poll_closed(cx)).await?;
    Ok(())
}

async fn complete_reusable_h2_stream<'a>(
    mut stream: ReusableBoxFuture<'a, ()>,
) -> ReusableBoxFuture<'a, ()> {
    stream.get_pin().await;
    stream
}

async fn poll_optional_h2_stream<T>(stream: &mut Option<ReusableBoxFuture<'_, T>>) -> T {
    poll_fn(|cx| match stream.as_mut() {
        Some(stream) => stream.poll(cx),
        None => std::task::Poll::Pending,
    })
    .await
}

async fn drive_h2_connection_now<I>(conn: &mut h2::server::Connection<I, Bytes>) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Some(result) = poll_fn(|cx| {
        Poll::Ready(match conn.poll_closed(cx) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => None,
        })
    })
    .await
    {
        result?;
    }
    Ok(())
}

async fn serve_h2_stream<S>(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    service: &S,
    body_channel_capacity: usize,
    idle_timeout: Duration,
    active_stream: ActiveH2Stream<'_>,
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

    let dispatch_phase = crate::perf_diagnostics::phase_timer!("h2_service_dispatch");
    let mut service_call = service.call_pinned(request);
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
    // Release completed dispatch storage before a slow response holds the stream open.
    drop(service_call);
    drop(dispatch_phase);
    let _send_phase = crate::perf_diagnostics::phase_timer!("h2_response_queue");
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

struct ActiveH2Stream<'a> {
    active: &'a AtomicUsize,
}

impl<'a> ActiveH2Stream<'a> {
    fn new(active: &'a AtomicUsize) -> Self {
        active.fetch_add(1, Ordering::Relaxed);
        Self { active }
    }

    fn count(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }
}

impl Drop for ActiveH2Stream<'_> {
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
        const REQUESTS: usize = 2 * super::H2_ACCEPT_BACKLOG;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind actual HTTP/2 server");
        let address = listener.local_addr().expect("HTTP/2 server address");
        let service = handler_fn(|_req: Request<Body>| async move {
            Ok::<_, Infallible>(Response::new(Body::from("ok")))
        });
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept HTTP/2 client");
            serve_h2_with_interim(socket, service, false, Duration::from_secs(5))
                .await
                .expect("serve h2");
        });

        let socket = TcpStream::connect(address)
            .await
            .expect("connect HTTP/2 client");
        // Keep the first stream pending until the peer's SETTINGS arrives. The
        // default unlimited initial allowance could exceed the advertised limit.
        let mut client_builder = h2::client::Builder::new();
        client_builder.initial_max_send_streams(0);
        let (mut client, connection) = client_builder
            .handshake::<_, bytes::Bytes>(socket)
            .await
            .expect("handshake");
        tokio::spawn(async move {
            connection.await.expect("client connection");
        });
        // Send and consume concurrently: responses are polled while the send
        // loop continues, so the upstream small-DATA-frame overhead budget is
        // replenished as frames leave internal buffering instead of piling up.
        let (pending_tx, mut pending_rx) = tokio::sync::mpsc::channel(REQUESTS);
        let send_loop = tokio::spawn(async move {
            for request_id in 0..REQUESTS {
                client = client.ready().await.expect("client ready");
                if request_id == 1 {
                    assert_eq!(
                        client.current_max_send_streams(),
                        super::H2_MAX_CONCURRENT_STREAMS
                    );
                }
                let request = ::http::Request::builder()
                    .method("GET")
                    .uri(format!("https://reverse_edges.test/{request_id}"))
                    .body(())
                    .expect("request");
                let (response, _) = client.send_request(request, true).expect("send request");
                pending_tx
                    .send(response)
                    .await
                    .expect("send response future");
            }
        });
        for _ in 0..REQUESTS {
            let response = pending_rx.recv().await.expect("response future queued");
            let response = timeout(Duration::from_secs(1), response)
                .await
                .expect("multiplexed response timed out")
                .expect("multiplexed response");
            assert_eq!(response.status(), ::http::StatusCode::OK);
            let mut body = response.into_body();
            let mut received = Vec::new();
            timeout(Duration::from_secs(1), async {
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.expect("HTTP/2 response data");
                    received.extend_from_slice(&chunk);
                    body.flow_control()
                        .release_capacity(chunk.len())
                        .expect("release HTTP/2 receive capacity");
                }
            })
            .await
            .expect("multiplexed response body timed out");
            assert_eq!(received, b"ok");
        }
        send_loop.await.expect("send loop completes");
    }

    #[tokio::test]
    async fn h2_completion_batch_preserves_slow_client_flow_control() {
        const REQUESTS: usize = 3;
        const BODY_BYTES: usize = 256 * 1024;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind HTTP/2 server");
        let address = listener.local_addr().expect("HTTP/2 server address");
        let payload = bytes::Bytes::from(vec![b'x'; BODY_BYTES]);
        let service = handler_fn(move |_req: Request<Body>| {
            let payload = payload.clone();
            async move { Ok::<_, Infallible>(Response::new(Body::from(payload))) }
        });
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept slow HTTP/2 client");
            serve_h2_with_interim(socket, service, false, Duration::from_secs(5))
                .await
                .expect("serve flow-controlled HTTP/2 connection");
        });
        let socket = TcpStream::connect(address)
            .await
            .expect("connect slow HTTP/2 client");
        let (mut client, connection) = h2::client::handshake(socket).await.expect("handshake");
        tokio::spawn(async move {
            connection.await.expect("drive slow HTTP/2 client");
        });
        let mut responses = Vec::new();
        for request_id in 0..REQUESTS {
            client = client.ready().await.expect("client ready");
            let request = Request::builder()
                .uri(format!("https://reverse.test/{request_id}"))
                .body(())
                .expect("flow-controlled request");
            responses.push(client.send_request(request, true).expect("send request").0);
        }
        // Drain all streams concurrently so shared connection credit is returned.
        timeout(
            Duration::from_secs(5),
            futures_util::future::join_all(responses.into_iter().map(|response| async move {
                let response = response.await.expect("flow-controlled response");
                assert_eq!(response.status(), ::http::StatusCode::OK);
                let mut body = response.into_body();
                let mut received = 0;
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.expect("flow-controlled response data");
                    assert!(chunk.iter().all(|byte| *byte == b'x'));
                    received += chunk.len();
                    sleep(Duration::from_millis(1)).await;
                    body.flow_control()
                        .release_capacity(chunk.len())
                        .expect("release slow-client capacity");
                }
                assert_eq!(received, BODY_BYTES);
            })),
        )
        .await
        .expect("slow-client flow control stopped making progress");
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
    async fn h2_flushes_response_and_propagates_reset_with_pending_service_work() {
        struct DropSignal(tokio::sync::mpsc::UnboundedSender<()>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.send(()).expect("drop signal receiver remains open");
            }
        }

        for reset in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind server");
            let client_io = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .expect("connect client");
            if reset {
                socket2::SockRef::from(&client_io)
                    .set_linger(Some(Duration::ZERO))
                    .expect("enable TCP reset on close");
            }
            let (server_io, _) = listener.accept().await.expect("accept client");
            let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
            let (dropped, mut drops) = tokio::sync::mpsc::unbounded_channel();
            let service = handler_fn(move |req: Request<Body>| {
                let started = started.clone();
                let dropped = dropped.clone();
                async move {
                    if req.uri().path() == "/ready" {
                        return Ok::<_, Infallible>(Response::new(Body::from("ready")));
                    }
                    let _drop_signal = DropSignal(dropped);
                    started
                        .send(())
                        .expect("start signal receiver remains open");
                    pending::<()>().await;
                    Ok::<_, Infallible>(Response::new(Body::empty()))
                }
            });
            let server_task = tokio::spawn(async move {
                serve_h2_with_interim(server_io, service, false, Duration::from_secs(5)).await
            });

            let (mut client, connection) =
                h2::client::handshake(client_io).await.expect("handshake");
            let connection_task = tokio::spawn(connection);
            let mut requests = Vec::new();
            for _ in 0..2 {
                client = client.ready().await.expect("client ready");
                let request = ::http::Request::builder()
                    .method("GET")
                    .uri("https://reverse_edges.test/disconnect")
                    .body(())
                    .expect("request");
                requests.push(client.send_request(request, true).expect("send request"));
                timeout(Duration::from_secs(1), starts.recv())
                    .await
                    .expect("service must start")
                    .expect("start signal");
            }
            client = client.ready().await.expect("ready response admission");
            let (response, _) = client
                .send_request(
                    Request::builder()
                        .uri("https://reverse_edges.test/ready")
                        .body(())
                        .expect("ready request"),
                    true,
                )
                .expect("send ready request");
            let response = timeout(Duration::from_secs(1), response)
                .await
                .expect("response headers must flush while handlers are pending")
                .expect("ready response");
            let mut body = response.into_body();
            assert_eq!(
                timeout(Duration::from_secs(1), body.data())
                    .await
                    .expect("response body must flush while handlers are pending")
                    .expect("response data")
                    .expect("response body data"),
                bytes::Bytes::from_static(b"ready")
            );
            drop(client);
            connection_task.abort();
            let result = timeout(Duration::from_secs(1), server_task)
                .await
                .expect("TCP reset must terminate the connection")
                .expect("server task");
            if reset {
                assert!(result.is_err(), "TCP reset must remain an error");
            } else {
                result.expect("orderly TCP close");
            }

            for _ in 0..2 {
                timeout(Duration::from_secs(1), drops.recv())
                    .await
                    .expect("every service future must be cancelled after connection close")
                    .expect("drop signal");
            }
            drop(requests);
        }
    }
}
