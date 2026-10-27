use super::OriginEndpoint;
use crate::http::codec::h2::parse_declared_content_length;
use crate::http::protocol::l7::prepare_request_with_headers_in_place;
use crate::http3::codec::http_headers_to_h1;
use crate::http3::listener::H3_MAX_FIELD_SECTION_SIZE;
use crate::http3::quic::{
    build_h3_client_config, enforce_h3_connection_trust, extract_h3_connection_certificate_info,
};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use qpx_core::http_message::{OrdinaryHeaderName, Request as OwnerRequest};
use qpx_core::tls::{CompiledUpstreamTlsTrust, UpstreamCertificateInfo};
use qpx_http::body::Body;
use qpx_http::protocol::semantics::validate_request_trailers;
use std::collections::HashMap;
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
    req: OwnerRequest<Body>,
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
        interim,
        response,
        upstream_cert: Some(pooled.upstream_cert.clone()),
        response_finalized: false,
    })
}

pub(super) fn clone_empty_body_request(req: &OwnerRequest<Body>) -> Result<OwnerRequest<Body>> {
    let mut out = OwnerRequest::new(Body::empty());
    *out.method_mut() = req.method().clone();
    *out.uri_mut() = req.uri().clone();
    *out.version_mut() = req.version();
    *out.headers_mut() = req.headers().clone();
    *out.extensions_mut() = req.extensions().clone();
    Ok(out)
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
    let bind_addr = crate::http3::quic::upstream_client_bind_addr(upstream_addr);
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
    builder.max_field_section_size(H3_MAX_FIELD_SECTION_SIZE);
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
    mut req: OwnerRequest<Body>,
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
    req.headers_mut().remove(
        &OrdinaryHeaderName::try_from(http::header::HOST).expect("host is an ordinary field"),
    );
    *req.version_mut() = http::Version::HTTP_3;
    *req.uri_mut() = http::Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path.as_str())
        .build()?;
    let hyper_req = req.into_http_for_codec().map_err(|err| anyhow!("{err}"))?;
    let (parts, body) = hyper_req.into_parts();
    let declared_length = parse_declared_content_length(&parts.headers)?;
    let mut out = ::http::Request::builder()
        .method(parts.method.as_str())
        .uri(parts.uri.to_string())
        .body(())?;
    *out.headers_mut() = http_headers_to_h1(&parts.headers)?;
    // RFC 9110 section 8.6: the value a sender writes is one decimal, so
    // the declaration leaves in the field's canonical form. RFC 9114
    // section 4.1.2 makes a comma list of lengths malformed in HTTP/3, so
    // the field the origin receives is the one the section allows.
    if let Some(length) = declared_length {
        out.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            qpx_core::http_content_length::canonical_content_length_value(length),
        );
    }
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
    use crate::upstream::origin::OriginEndpoint;
    use crate::upstream::origin::http_backend::h3_pool::alt_svc::{
        MAX_H3_ALT_SVC_MAX_AGE, alt_svc_effective_remaining,
        alt_svc_endpoint_matches_same_origin_host, alt_svc_response_age,
        alt_svc_value_is_valid_advertisement, cached_alt_svc_h3_endpoint,
        forget_alt_svc_h3_endpoint, parse_h3_alt_svc, record_h3_alt_svc,
    };
    use crate::upstream::origin::http_backend::h3_pool::response::{
        declared_h3_response_body_length, enforce_h3_body_content_length_complete,
        record_h3_body_content_length,
    };
    use crate::upstream::origin::http_backend::h3_pool::*;
    use hyper::StatusCode;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::Duration;

    #[test]
    fn h3_origin_request_export_preserves_cookie_occurrences_and_sensitivity() {
        let mut request = ::http::Request::builder()
            .method("GET")
            .uri("https://origin.example.test/resource")
            .body(Body::empty())
            .expect("request");
        *request.version_mut() = http::Version::HTTP_3;
        request
            .headers_mut()
            .append("cookie", ::http::HeaderValue::from_static("a=1"));
        let mut second = ::http::HeaderValue::from_static("b=2");
        second.set_sensitive(true);
        request.headers_mut().append("cookie", second);
        let request = OwnerRequest::from_http(request);

        let (prepared, _body, _declared_length) =
            prepare_h3_origin_request(request, "origin.example.test:443", "qpx")
                .expect("prepare H3 origin request");
        let cookies: Vec<_> = prepared.headers().get_all("cookie").iter().collect();
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].as_bytes(), b"a=1");
        assert!(!cookies[0].is_sensitive());
        assert_eq!(cookies[1].as_bytes(), b"b=2");
        assert!(cookies[1].is_sensitive());
    }

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
        let get = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::GET)
                .uri("https://example.test/")
                .body(Body::empty())
                .expect("request"),
        );
        assert!(request_can_use_alt_svc_h3(&get));

        let get_zero_cl = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::GET)
                .uri("https://example.test/")
                .header(http::header::CONTENT_LENGTH, "0")
                .body(Body::empty())
                .expect("request"),
        );
        assert!(request_can_use_alt_svc_h3(&get_zero_cl));

        let get_zero_cl_list = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::GET)
                .uri("https://example.test/")
                .header(http::header::CONTENT_LENGTH, "0, 0")
                .body(Body::empty())
                .expect("request"),
        );
        assert!(request_can_use_alt_svc_h3(&get_zero_cl_list));

        let get_nonzero_cl = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::GET)
                .uri("https://example.test/")
                .header(http::header::CONTENT_LENGTH, "1")
                .body(Body::empty())
                .expect("request"),
        );
        assert!(!request_can_use_alt_svc_h3(&get_nonzero_cl));

        let (_sender, streaming_body) = Body::channel();
        let get_unknown_stream = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::GET)
                .uri("https://example.test/")
                .body(streaming_body)
                .expect("request"),
        );
        assert!(!request_can_use_alt_svc_h3(&get_unknown_stream));

        let post = OwnerRequest::from_http(
            http::Request::builder()
                .method(http::Method::POST)
                .uri("https://example.test/")
                .header(http::header::CONTENT_LENGTH, "1")
                .body(Body::empty())
                .expect("request"),
        );
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

    #[test]
    fn alt_svc_parser_skips_expired_entry_for_later_usable_h3() {
        let parsed = parse_h3_alt_svc(r#"h3=":443"; ma=0, h3=":8443"; ma=60"#)
            .expect("later h3 survives ma=0");
        assert_eq!(parsed.connect_port, 8443);
    }

    #[test]
    fn alt_svc_parser_skips_malformed_entry_for_later_usable_h3() {
        let parsed = parse_h3_alt_svc(r#"not-a-field, h3=":8443"; ma=60"#)
            .expect("later h3 survives garbage");
        assert_eq!(parsed.connect_port, 8443);
    }

    #[test]
    fn alt_svc_single_expired_h3_has_no_usable_endpoint() {
        assert!(parse_h3_alt_svc(r#"h3=":8443"; ma=0"#).is_none());
        assert!(alt_svc_value_is_valid_advertisement(r#"h3=":8443"; ma=0"#));
        assert!(alt_svc_value_is_valid_advertisement(r#"h2=":443""#));
        assert!(!alt_svc_value_is_valid_advertisement("not-a-field"));
        assert!(!alt_svc_value_is_valid_advertisement(""));
    }

    fn alt_svc_test_origin(suffix: &str) -> OriginEndpoint {
        OriginEndpoint::direct(format!("https://alt-svc-{suffix}.example:443"))
    }

    fn alt_svc_headers(values: &[&str]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for value in values {
            headers.append(
                http::header::HeaderName::from_static("alt-svc"),
                value.parse().expect("alt-svc value"),
            );
        }
        headers
    }

    #[tokio::test]
    async fn alt_svc_withdrawn_h3_replaces_seeded_route() {
        let origin = alt_svc_test_origin("withdrawn-replaces");
        forget_alt_svc_h3_endpoint(&origin).await;

        record_h3_alt_svc(&origin, &alt_svc_headers(&[r#"h3=":8443"; ma=600"#])).await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("seeded")
                .is_some()
        );

        // Absent header preserves the seeded route.
        record_h3_alt_svc(&origin, &http::HeaderMap::new()).await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("absent keeps")
                .is_some()
        );

        // Expired ma=0 withdraws the route.
        record_h3_alt_svc(&origin, &alt_svc_headers(&[r#"h3=":8443"; ma=0"#])).await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("ma=0 clears")
                .is_none()
        );

        // h2-only advertisement withdraws the route.
        record_h3_alt_svc(&origin, &alt_svc_headers(&[r#"h3=":8443"; ma=600"#])).await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("reseed")
                .is_some()
        );
        record_h3_alt_svc(&origin, &alt_svc_headers(&[r#"h2=":443""#])).await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("h2-only clears")
                .is_none()
        );

        // Malformed field preserves the route.
        record_h3_alt_svc(&origin, &alt_svc_headers(&[r#"h3=":8443"; ma=600"#])).await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("reseed")
                .is_some()
        );
        record_h3_alt_svc(&origin, &alt_svc_headers(&["not-a-field"])).await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("malformed keeps")
                .is_some()
        );

        // Explicit clear removes the route.
        record_h3_alt_svc(&origin, &alt_svc_headers(&["clear"])).await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("clear clears")
                .is_none()
        );

        forget_alt_svc_h3_endpoint(&origin).await;
    }

    #[tokio::test]
    async fn alt_svc_usable_h3_wins_within_mixed_field() {
        let origin = alt_svc_test_origin("mixed-field-wins");
        forget_alt_svc_h3_endpoint(&origin).await;

        // Leading cross-host entry must not hide a later same-host entry.
        record_h3_alt_svc(
            &origin,
            &alt_svc_headers(&[r#"h3="other.example:443"; ma=60, h3=":8443"; ma=60"#]),
        )
        .await;
        let cached = cached_alt_svc_h3_endpoint(&origin)
            .await
            .expect("mixed")
            .expect("kept");
        assert_eq!(
            cached.connect_authority(443).expect("authority"),
            "alt-svc-mixed-field-wins.example:8443"
        );

        // Leading expired entry must not hide a later usable entry.
        forget_alt_svc_h3_endpoint(&origin).await;
        record_h3_alt_svc(
            &origin,
            &alt_svc_headers(&[r#"h3=":443"; ma=0, h3=":8443"; ma=60"#]),
        )
        .await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("expired-first")
                .is_some()
        );

        forget_alt_svc_h3_endpoint(&origin).await;
    }

    #[test]
    fn alt_svc_age_accounting_declines_expired_advertisements() {
        use std::time::Duration;
        // ma=60 Age=30 leaves at most 30 seconds.
        let remaining =
            alt_svc_effective_remaining(Duration::from_secs(60), Duration::from_secs(30))
                .expect("30s remain");
        assert!(remaining <= Duration::from_secs(30));
        assert!(!remaining.is_zero());
        // Age covering the whole lifetime declines the endpoint.
        assert!(
            alt_svc_effective_remaining(Duration::from_secs(60), Duration::from_secs(60)).is_none()
        );
        assert!(
            alt_svc_effective_remaining(Duration::from_secs(60), Duration::from_secs(120))
                .is_none()
        );
        // No age preserves the advertised lifetime.
        assert_eq!(
            alt_svc_effective_remaining(Duration::from_secs(60), Duration::ZERO),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn alt_svc_response_age_prefers_age_header_then_date() {
        use std::time::{Duration, SystemTime};
        let mut headers = http::HeaderMap::new();
        assert_eq!(alt_svc_response_age(&headers), Duration::ZERO);

        headers.insert(http::header::AGE, "30".parse().expect("age"));
        assert_eq!(alt_svc_response_age(&headers), Duration::from_secs(30));

        // Malformed Age is ignored.
        let mut bad = http::HeaderMap::new();
        bad.insert(http::header::AGE, "not-a-number".parse().expect("bad age"));
        assert_eq!(alt_svc_response_age(&bad), Duration::ZERO);

        // Fresh Date carries only resident-time noise.
        let mut fresh = http::HeaderMap::new();
        fresh.insert(
            http::header::DATE,
            httpdate::fmt_http_date(SystemTime::now())
                .parse()
                .expect("date"),
        );
        assert!(alt_svc_response_age(&fresh) < Duration::from_secs(5));

        // Old Date without Age still ages the response.
        let mut old = http::HeaderMap::new();
        old.insert(
            http::header::DATE,
            httpdate::fmt_http_date(SystemTime::now() - Duration::from_secs(120))
                .parse()
                .expect("old date"),
        );
        assert!(alt_svc_response_age(&old) >= Duration::from_secs(119));

        // Age wins when both are present and larger.
        let mut both = http::HeaderMap::new();
        both.insert(http::header::AGE, "90".parse().expect("age"));
        both.insert(
            http::header::DATE,
            httpdate::fmt_http_date(SystemTime::now())
                .parse()
                .expect("date"),
        );
        assert_eq!(alt_svc_response_age(&both), Duration::from_secs(90));
    }

    fn alt_svc_headers_with_age(
        alt_svc: &str,
        age: Option<&str>,
        date: Option<String>,
    ) -> http::HeaderMap {
        let mut headers = alt_svc_headers(&[alt_svc]);
        if let Some(age) = age {
            headers.insert(http::header::AGE, age.parse().expect("age"));
        }
        if let Some(date) = date {
            headers.insert(http::header::DATE, date.parse().expect("date"));
        }
        headers
    }

    #[tokio::test]
    async fn alt_svc_aged_response_declines_expired_h3() {
        use std::time::SystemTime;
        let origin = alt_svc_test_origin("aged-declines");
        forget_alt_svc_h3_endpoint(&origin).await;

        // Seed a usable route first.
        record_h3_alt_svc(&origin, &alt_svc_headers(&[r#"h3=":8443"; ma=600"#])).await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("seeded")
                .is_some()
        );

        // Age covering ma declines and withdraws the seeded route.
        record_h3_alt_svc(
            &origin,
            &alt_svc_headers_with_age(r#"h3=":8443"; ma=60"#, Some("120"), None),
        )
        .await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("aged-out clears")
                .is_none()
        );

        // Age within ma keeps a usable route.
        record_h3_alt_svc(&origin, &alt_svc_headers(&[r#"h3=":8443"; ma=600"#])).await;
        record_h3_alt_svc(
            &origin,
            &alt_svc_headers_with_age(r#"h3=":8443"; ma=60"#, Some("30"), None),
        )
        .await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("within-age keeps")
                .is_some()
        );

        // Fresh Date without Age preserves the route.
        record_h3_alt_svc(
            &origin,
            &alt_svc_headers_with_age(
                r#"h3=":8443"; ma=60"#,
                None,
                Some(httpdate::fmt_http_date(SystemTime::now())),
            ),
        )
        .await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("fresh-date keeps")
                .is_some()
        );

        // Old Date without Age declines like an aged response.
        record_h3_alt_svc(
            &origin,
            &alt_svc_headers_with_age(
                r#"h3=":8443"; ma=60"#,
                None,
                Some(httpdate::fmt_http_date(
                    SystemTime::now() - std::time::Duration::from_secs(120),
                )),
            ),
        )
        .await;
        assert!(
            cached_alt_svc_h3_endpoint(&origin)
                .await
                .expect("old-date clears")
                .is_none()
        );

        forget_alt_svc_h3_endpoint(&origin).await;
    }
}
