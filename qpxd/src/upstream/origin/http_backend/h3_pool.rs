use super::OriginEndpoint;
use crate::http::codec::h2::parse_declared_content_length;
use crate::http::protocol::l7::prepare_request_with_headers_in_place;
use crate::http3::codec::{h1_headers_to_http, http_headers_to_h1};
use crate::http3::quic::{
    build_h3_client_config, enforce_h3_connection_trust, extract_h3_connection_certificate_info,
};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use hyper::{Request, StatusCode};
use qpx_core::tls::{CompiledUpstreamTlsTrust, UpstreamCertificateInfo};
use qpx_http::body::Body;
use qpx_http::protocol::semantics::validate_request_trailers;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::lookup_host;
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

mod alt_svc;
mod metrics;
mod pool;
mod response;

pub(super) use self::alt_svc::{
    cached_alt_svc_h3_endpoint, forget_alt_svc_h3_endpoint, record_h3_alt_svc,
    request_can_use_alt_svc_h3,
};
use self::response::{
    InflightStreamGuard, abort_h3_request_relay, h3_response_to_hyper, join_h3_request_relay,
    recv_h3_response_with_interim,
};

const DEFAULT_MAX_CONNECTIONS_PER_ORIGIN: usize = 4;
const DEFAULT_MAX_INFLIGHT_STREAMS_PER_CONNECTION: usize = 128;
const H3_ORIGIN_POOL_SHARDS: usize = 64;
const MAX_H3_ORIGIN_POOL_KEYS: usize = 1024;

type H3SendRequest = ::h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3ClientRequestStream = ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3ClientSendStream = ::h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type H3ClientRecvStream = ::h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
type H3RequestRelayJoin = JoinHandle<Result<()>>;

pub(crate) struct H3OriginPool {
    shards: Vec<H3OriginPoolShard>,
    max_connections_per_origin: AtomicUsize,
    max_inflight_streams_per_connection: AtomicUsize,
}

struct H3OriginPoolShard {
    connections: Mutex<HashMap<OriginKey, H3OriginEntry>>,
    connecting: crate::pool::SingleFlight<OriginKey>,
}

#[derive(Default)]
struct H3OriginEntry {
    connections: Vec<Arc<H3PooledConnection>>,
    cursor: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct OriginKey {
    connect_authority: String,
    server_name: String,
    trust_key: Option<String>,
}

struct H3PooledConnection {
    request_open_tx: mpsc::Sender<H3OpenRequest>,
    open_queue_depth: Arc<AtomicUsize>,
    open_queue_capacity: usize,
    inflight_streams: AtomicUsize,
    inflight_below_threshold: Notify,
    origin_label: String,
    created_at: Instant,
    upstream_cert: UpstreamCertificateInfo,
    _endpoint: quinn::Endpoint,
    driver: JoinHandle<()>,
    open_driver: JoinHandle<()>,
}

struct H3OpenRequest {
    request: ::http::Request<()>,
    cancel_token: CancellationToken,
    deadline: Instant,
    response: oneshot::Sender<Result<H3ClientRequestStream>>,
}

struct H3OpenCancellation {
    token: CancellationToken,
}

struct H3OpenQueueDepthGuard<'a> {
    depth: &'a AtomicUsize,
    origin_label: &'a str,
    active: bool,
}

impl Drop for H3OpenCancellation {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

impl<'a> H3OpenQueueDepthGuard<'a> {
    fn new(depth: &'a AtomicUsize, origin_label: &'a str) -> Self {
        let queued = depth.fetch_add(1, Ordering::Relaxed) + 1;
        metrics::open_queue_depth(origin_label, queued);
        Self {
            depth,
            origin_label,
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for H3OpenQueueDepthGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let remaining = self.depth.fetch_sub(1, Ordering::Relaxed).saturating_sub(1);
        metrics::open_queue_depth(self.origin_label, remaining);
        metrics::open_queue_rejected(self.origin_label);
    }
}

impl H3OriginPool {
    pub(crate) fn set_limits(
        &self,
        max_connections_per_origin: usize,
        max_inflight_streams_per_connection: usize,
    ) {
        self.max_connections_per_origin
            .store(max_connections_per_origin.max(1), Ordering::Relaxed);
        self.max_inflight_streams_per_connection.store(
            max_inflight_streams_per_connection.max(1),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn max_connections_per_origin(&self) -> usize {
        self.max_connections_per_origin.load(Ordering::Relaxed)
    }

    pub(crate) fn max_inflight_streams_per_connection(&self) -> usize {
        self.max_inflight_streams_per_connection
            .load(Ordering::Relaxed)
    }
}

impl H3PooledConnection {
    async fn open_request(
        &self,
        request: ::http::Request<()>,
        timeout_dur: Duration,
    ) -> Result<H3ClientRequestStream> {
        let (response_tx, response_rx) = oneshot::channel();
        let cancel_token = CancellationToken::new();
        let _cancel_on_drop = H3OpenCancellation {
            token: cancel_token.clone(),
        };
        let deadline = Instant::now() + timeout_dur;
        let job = H3OpenRequest {
            request,
            cancel_token,
            deadline,
            response: response_tx,
        };
        send_h3_open_request(
            &self.request_open_tx,
            &self.open_queue_depth,
            self.origin_label.as_str(),
            job,
            deadline,
        )
        .await?;
        timeout_at(deadline, response_rx)
            .await
            .map_err(|_| anyhow!("HTTP/3 upstream request head timed out"))?
            .map_err(|_| anyhow!("HTTP/3 upstream request open actor stopped"))?
    }

    async fn wait_for_inflight_below(&self, threshold: usize, timeout_dur: Duration) -> bool {
        if self.inflight_streams.load(Ordering::Relaxed) < threshold {
            return true;
        }
        timeout(timeout_dur, async {
            loop {
                self.inflight_below_threshold.notified().await;
                if self.inflight_streams.load(Ordering::Relaxed) < threshold {
                    return;
                }
            }
        })
        .await
        .is_ok()
    }
}

async fn send_h3_open_request(
    request_open_tx: &mpsc::Sender<H3OpenRequest>,
    open_queue_depth: &AtomicUsize,
    origin_label: &str,
    job: H3OpenRequest,
    deadline: Instant,
) -> Result<()> {
    let mut depth_guard = H3OpenQueueDepthGuard::new(open_queue_depth, origin_label);
    match timeout_at(deadline, request_open_tx.send(job)).await {
        Ok(Ok(())) => {
            depth_guard.disarm();
            Ok(())
        }
        Ok(Err(err)) => Err(anyhow!("HTTP/3 upstream request open actor stopped: {err}")),
        Err(_) => Err(anyhow!("HTTP/3 upstream request open queue timed out")),
    }
}

pub(super) async fn proxy_h3_origin(
    pool: &H3OriginPool,
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
    timeout_dur: Duration,
) -> Result<crate::upstream::raw_http1::Http1ResponseWithInterim> {
    let request_method = req.method().clone();
    let default_port = origin.default_port_hint();
    let connect_authority = origin.connect_authority(default_port)?;
    let host_authority = origin.host_header_authority(default_port)?;
    let server_name = origin.tls_server_name()?;
    let key = OriginKey {
        connect_authority,
        server_name,
        trust_key: trust.map(CompiledUpstreamTlsTrust::pool_key),
    };
    let pooled = pool.acquire(key, trust, timeout_dur).await?;
    let inflight_guard = InflightStreamGuard::new(pooled.clone());

    let (request, body, declared_request_length) =
        prepare_h3_origin_request(req, host_authority.as_str(), proxy_name)?;
    let req_stream = pooled.open_request(request, timeout_dur).await?;
    let (mut req_send, mut req_recv) = req_stream.split();
    let mut request_relay = Some(tokio::spawn(async move {
        stream_h3_request_body(&mut req_send, body, declared_request_length, timeout_dur).await
    }));
    let (interim, response) = match recv_h3_response_with_interim(&mut req_recv, timeout_dur).await
    {
        Ok(response) => response,
        Err(err) => {
            abort_h3_request_relay(request_relay.take());
            return Err(err);
        }
    };
    if request_relay
        .as_ref()
        .is_some_and(tokio::task::JoinHandle::is_finished)
        && let Some(relay) = request_relay.take()
    {
        join_h3_request_relay(relay).await?;
    }
    let response = h3_response_to_hyper(
        response,
        &request_method,
        req_recv,
        inflight_guard,
        timeout_dur,
        request_relay,
    )?;
    Ok(crate::upstream::raw_http1::Http1ResponseWithInterim {
        interim: interim
            .into_iter()
            .map(|head| crate::upstream::raw_http1::InterimResponseHead {
                status: qpx_http::protocol::semantics::validate_http_status_class(
                    head.status(),
                    "HTTP/3 interim response",
                )
                .unwrap_or(StatusCode::OK),
                headers: h1_headers_to_http(head.headers()).unwrap_or_default(),
            })
            .collect(),
        response,
        upstream_cert: Some(pooled.upstream_cert.clone()),
    })
}

pub(super) fn clone_empty_body_request(req: &Request<Body>) -> Result<Request<Body>> {
    let mut out = Request::builder()
        .method(req.method().clone())
        .uri(req.uri().clone())
        .version(req.version())
        .body(Body::empty())?;
    *out.headers_mut() = req.headers().clone();
    Ok(out)
}

fn content_length_is_zero_or_absent(headers: &HeaderMap) -> bool {
    matches!(parse_declared_content_length(headers), Ok(None | Some(0)))
}

async fn connect_h3_origin(
    key: &OriginKey,
    trust: Option<&CompiledUpstreamTlsTrust>,
    timeout_dur: Duration,
    open_queue_capacity: usize,
) -> Result<H3PooledConnection> {
    let upstream_addr = timeout(timeout_dur, lookup_host(key.connect_authority.as_str()))
        .await
        .map_err(|_| anyhow!("HTTP/3 upstream DNS resolution timed out"))??
        .next()
        .ok_or_else(|| anyhow!("HTTP/3 upstream resolved no addresses"))?;
    let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(build_h3_client_config(true, trust)?);
    let connection = timeout(
        timeout_dur,
        endpoint.connect(upstream_addr, key.server_name.as_str())?,
    )
    .await
    .map_err(|_| anyhow!("HTTP/3 upstream connect timed out"))??;
    let upstream_cert = extract_h3_connection_certificate_info(&connection);
    enforce_h3_connection_trust(&connection, key.server_name.as_str(), trust)?;
    let quic_conn = h3_quinn::Connection::new(connection);
    let mut builder = ::h3::client::builder();
    let h3_build = builder.build::<_, _, Bytes>(quic_conn);
    let (mut h3_conn, sender) = timeout(timeout_dur, h3_build)
        .await
        .map_err(|_| anyhow!("HTTP/3 upstream setup timed out"))??;
    let open_queue_depth = Arc::new(AtomicUsize::new(0));
    let (request_open_tx, open_driver) = spawn_h3_request_open_actor(
        sender,
        key.server_name.clone(),
        open_queue_depth.clone(),
        open_queue_capacity,
    );
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });
    Ok(H3PooledConnection {
        request_open_tx,
        open_queue_depth,
        open_queue_capacity,
        inflight_streams: AtomicUsize::new(0),
        inflight_below_threshold: Notify::new(),
        origin_label: key.server_name.clone(),
        created_at: Instant::now(),
        upstream_cert,
        _endpoint: endpoint,
        driver,
        open_driver,
    })
}

fn spawn_h3_request_open_actor(
    mut sender: H3SendRequest,
    origin_label: String,
    queue_depth: Arc<AtomicUsize>,
    queue_capacity: usize,
) -> (mpsc::Sender<H3OpenRequest>, JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<H3OpenRequest>(queue_capacity.max(1));
    let driver = tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            if job.cancel_token.is_cancelled() || job.response.is_closed() {
                let remaining = queue_depth
                    .fetch_sub(1, Ordering::Relaxed)
                    .saturating_sub(1);
                metrics::open_queue_depth(origin_label.as_str(), remaining);
                metrics::open_queue_rejected(origin_label.as_str());
                continue;
            }
            let H3OpenRequest {
                request,
                cancel_token,
                deadline,
                response,
            } = job;
            let started = Instant::now();
            let result = tokio::select! {
                biased;
                _ = cancel_token.cancelled() => {
                    Err(anyhow!("HTTP/3 upstream request open cancelled"))
                }
                result = timeout_at(deadline, sender.send_request(request)) => {
                    match result {
                        Ok(Ok(stream)) => Ok(stream),
                        Ok(Err(err)) => Err(anyhow!("failed to open HTTP/3 upstream request stream: {err}")),
                        Err(_) => Err(anyhow!("HTTP/3 upstream request head timed out")),
                    }
                }
            };
            let elapsed = started.elapsed();
            let remaining = queue_depth
                .fetch_sub(1, Ordering::Relaxed)
                .saturating_sub(1);
            metrics::open_queue_depth(origin_label.as_str(), remaining);
            metrics::request_open(origin_label.as_str(), elapsed);
            if cancel_token.is_cancelled() && result.is_ok() {
                metrics::open_queue_rejected(origin_label.as_str());
            }
            let _ = response.send(result);
        }
    });
    (tx, driver)
}

fn prepare_h3_origin_request(
    mut req: Request<Body>,
    authority: &str,
    proxy_name: &str,
) -> Result<(::http::Request<()>, Body, Option<u64>)> {
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    prepare_request_with_headers_in_place(&mut req, proxy_name, None, false);
    req.headers_mut().remove(http::header::HOST);
    *req.version_mut() = http::Version::HTTP_3;
    *req.uri_mut() = http::Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path.as_str())
        .build()?;
    let (parts, body) = req.into_parts();
    let declared_length = parse_declared_content_length(&parts.headers)?;
    let mut out = ::http::Request::builder()
        .method(parts.method.as_str())
        .uri(parts.uri.to_string())
        .body(())?;
    *out.headers_mut() = http_headers_to_h1(&parts.headers)?;
    Ok((out, body, declared_length))
}

async fn stream_h3_request_body(
    req_stream: &mut H3ClientSendStream,
    mut body: Body,
    declared_length: Option<u64>,
    timeout_dur: Duration,
) -> Result<()> {
    let mut sent_len = 0u64;
    while let Some(chunk) = timeout(timeout_dur, body.data())
        .await
        .map_err(|_| anyhow!("HTTP/3 upstream request body read timed out"))?
    {
        let chunk = chunk?;
        sent_len = sent_len
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| anyhow!("HTTP/3 upstream request body length overflow"))?;
        if let Some(expected) = declared_length
            && sent_len > expected
        {
            return Err(anyhow!(
                "HTTP/3 upstream request body exceeded declared content-length"
            ));
        }
        if !chunk.is_empty() {
            timeout(timeout_dur, req_stream.send_data(chunk))
                .await
                .map_err(|_| anyhow!("HTTP/3 upstream request body send timed out"))??;
        }
    }
    let trailers = timeout(timeout_dur, body.trailers())
        .await
        .map_err(|_| anyhow!("HTTP/3 upstream request trailers read timed out"))??;
    if let Some(expected) = declared_length
        && sent_len != expected
    {
        return Err(anyhow!(
            "HTTP/3 upstream request body ended before declared content-length was satisfied"
        ));
    }
    if let Some(trailers) = trailers {
        validate_request_trailers(&trailers)
            .map_err(|err| anyhow!("invalid HTTP/3 request trailers: {err:?}"))?;
        timeout(
            timeout_dur,
            req_stream.send_trailers(http_headers_to_h1(&trailers)?),
        )
        .await
        .map_err(|_| anyhow!("HTTP/3 upstream request trailers send timed out"))??;
    }
    timeout(timeout_dur, req_stream.finish())
        .await
        .map_err(|_| anyhow!("HTTP/3 upstream request finish timed out"))??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::upstream::origin::http_backend::h3_pool::alt_svc::{
        MAX_H3_ALT_SVC_MAX_AGE, alt_svc_endpoint_matches_same_origin_host, parse_h3_alt_svc,
    };
    use crate::upstream::origin::http_backend::h3_pool::response::{
        declared_h3_response_body_length, enforce_h3_body_content_length_complete,
        record_h3_body_content_length,
    };
    use crate::upstream::origin::http_backend::h3_pool::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::Duration;

    #[test]
    fn h3_upstream_origin_key_keeps_authority_and_tls_name_distinct() {
        let a = OriginKey {
            connect_authority: "127.0.0.1:443".to_string(),
            server_name: "a.example".to_string(),
            trust_key: None,
        };
        let b = OriginKey {
            connect_authority: "127.0.0.1:443".to_string(),
            server_name: "b.example".to_string(),
            trust_key: None,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn h3_upstream_origin_key_keeps_trust_policy_distinct() {
        let a = OriginKey {
            connect_authority: "127.0.0.1:443".to_string(),
            server_name: "a.example".to_string(),
            trust_key: Some("pin=a".to_string()),
        };
        let b = OriginKey {
            connect_authority: "127.0.0.1:443".to_string(),
            server_name: "a.example".to_string(),
            trust_key: Some("pin=b".to_string()),
        };
        assert_ne!(a, b);
    }

    fn test_open_request() -> H3OpenRequest {
        let (response, _rx) = oneshot::channel();
        H3OpenRequest {
            request: ::http::Request::builder()
                .uri("https://example.test/")
                .body(())
                .expect("test request"),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            deadline: Instant::now() + Duration::from_secs(1),
            response,
        }
    }

    #[tokio::test]
    async fn h3_open_request_enqueue_uses_bounded_send() {
        let (tx, mut rx) = mpsc::channel(1);
        let depth = AtomicUsize::new(0);

        send_h3_open_request(
            &tx,
            &depth,
            "example.test",
            test_open_request(),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect("enqueue succeeds");

        assert_eq!(depth.load(Ordering::Relaxed), 1);
        assert!(rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn h3_open_request_enqueue_timeout_releases_depth() {
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(test_open_request()).expect("pre-fill queue");
        let depth = AtomicUsize::new(0);

        let err = send_h3_open_request(
            &tx,
            &depth,
            "example.test",
            test_open_request(),
            Instant::now() + Duration::from_millis(1),
        )
        .await
        .expect_err("full queue times out");

        assert!(
            err.to_string()
                .contains("HTTP/3 upstream request open queue timed out")
        );
        assert_eq!(depth.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn h3_open_request_enqueue_closed_actor_releases_depth() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let depth = AtomicUsize::new(0);

        let err = send_h3_open_request(
            &tx,
            &depth,
            "example.test",
            test_open_request(),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("closed actor rejects enqueue");

        assert!(
            err.to_string()
                .contains("HTTP/3 upstream request open actor stopped")
        );
        assert_eq!(depth.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn parses_h3_alt_svc_authority_and_max_age() {
        let parsed =
            parse_h3_alt_svc(r#"h2=":443", h3="alt.example:8443"; ma=60"#).expect("h3 alt-svc");

        assert_eq!(parsed.connect_host.as_deref(), Some("alt.example"));
        assert_eq!(parsed.connect_port, 8443);
        assert!(parsed.expires_at > Instant::now());
    }

    #[test]
    fn parses_origin_host_h3_alt_svc_authority() {
        let parsed = parse_h3_alt_svc(r#"h3=":443"; ma=60"#).expect("h3 alt-svc");

        assert_eq!(parsed.connect_host, None);
        assert_eq!(parsed.connect_port, 443);
    }

    #[test]
    fn alt_svc_endpoint_is_intentionally_limited_to_same_origin_host() {
        let same =
            parse_h3_alt_svc(r#"h3="Example.Test.:8443"; ma=60"#).expect("same origin alt-svc");
        assert!(alt_svc_endpoint_matches_same_origin_host(
            &same,
            "example.test"
        ));

        let origin_host = parse_h3_alt_svc(r#"h3=":443"; ma=60"#).expect("origin-host alt-svc");
        assert!(alt_svc_endpoint_matches_same_origin_host(
            &origin_host,
            "example.test"
        ));

        let cross = parse_h3_alt_svc(r#"h3="10.0.0.5:443"; ma=60"#).expect("cross origin alt-svc");
        assert!(!alt_svc_endpoint_matches_same_origin_host(
            &cross,
            "example.test"
        ));
    }

    #[test]
    fn alt_svc_max_age_is_clamped_before_instant_addition() {
        let parsed = parse_h3_alt_svc(r#"h3=":443"; ma=18446744073709551615"#).expect("h3 alt-svc");
        assert!(parsed.expires_at > Instant::now());
        assert!(parsed.expires_at <= Instant::now() + MAX_H3_ALT_SVC_MAX_AGE);
    }

    #[test]
    fn alt_svc_h3_auto_upgrade_only_uses_definitely_empty_safe_requests() {
        let get = Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/")
            .body(Body::empty())
            .expect("request");
        assert!(request_can_use_alt_svc_h3(&get));

        let get_zero_cl = Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/")
            .header(http::header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .expect("request");
        assert!(request_can_use_alt_svc_h3(&get_zero_cl));

        let get_zero_cl_list = Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/")
            .header(http::header::CONTENT_LENGTH, "0, 0")
            .body(Body::empty())
            .expect("request");
        assert!(request_can_use_alt_svc_h3(&get_zero_cl_list));

        let get_nonzero_cl = Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/")
            .header(http::header::CONTENT_LENGTH, "1")
            .body(Body::empty())
            .expect("request");
        assert!(!request_can_use_alt_svc_h3(&get_nonzero_cl));

        let (_sender, streaming_body) = Body::channel();
        let get_unknown_stream = Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/")
            .body(streaming_body)
            .expect("request");
        assert!(!request_can_use_alt_svc_h3(&get_unknown_stream));

        let post = Request::builder()
            .method(http::Method::POST)
            .uri("https://example.test/")
            .header(http::header::CONTENT_LENGTH, "1")
            .body(Body::empty())
            .expect("request");
        assert!(!request_can_use_alt_svc_h3(&post));
    }

    #[test]
    fn h3_upstream_body_content_length_rejects_overflow_before_exposure() {
        let mut received = 0;
        record_h3_body_content_length(Some(5), &mut received, 5, "response")
            .expect("exact first frame");
        let err = record_h3_body_content_length(Some(5), &mut received, 1, "response")
            .expect_err("extra response body bytes must be rejected");
        assert!(err.to_string().contains("exceeds Content-Length"));
    }

    #[test]
    fn h3_upstream_body_content_length_rejects_underflow_on_completion() {
        enforce_h3_body_content_length_complete(Some(5), 5, "response").expect("complete body");
        let err = enforce_h3_body_content_length_complete(Some(5), 4, "response")
            .expect_err("short response body must be rejected");
        assert!(err.to_string().contains("length mismatch"));
    }

    #[test]
    fn h3_upstream_response_head_and_no_body_statuses_expect_zero_data() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, "10".parse().unwrap());

        assert_eq!(
            declared_h3_response_body_length(&http::Method::HEAD, StatusCode::OK, &headers)
                .expect("declared"),
            Some(0)
        );
        assert_eq!(
            declared_h3_response_body_length(
                &http::Method::GET,
                StatusCode::NOT_MODIFIED,
                &headers,
            )
            .expect("declared"),
            Some(0)
        );
        assert_eq!(
            declared_h3_response_body_length(
                &http::Method::GET,
                StatusCode::RESET_CONTENT,
                &headers,
            )
            .expect("declared"),
            Some(0)
        );
        assert_eq!(
            declared_h3_response_body_length(&http::Method::GET, StatusCode::OK, &headers)
                .expect("declared"),
            Some(10)
        );
    }
}
