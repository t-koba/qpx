use crate::http::mitm::proxy_mitm_request;
use crate::runtime::Runtime;
use crate::test_util::{decode_gzip, spawn_http1_send_request};
use hyper::Request;
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config, IdentityConfig,
    IngressEdgeConfig, IngressEdgeMode, MessagesConfig, RuntimeConfig, SystemLogConfig,
};
use qpx_http::body::{Body, to_bytes};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn mitm_runtime(http_modules: Vec<qpx_core::config::HttpModuleConfig>) -> Runtime {
    Runtime::new(Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        telemetry: qpx_core::config::TelemetryConfig {
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            exporter: None,
        },
        security: qpx_core::config::SecurityConfig {
            auth: AuthConfig::default(),
            identity_sources: Vec::new(),
            decisions: qpx_core::config::DecisionConfig {
                services: Vec::new(),
            },
            destination: Default::default(),
            named_sets: Vec::new(),
            upstream_trust_profiles: Vec::new(),
        },
        http: qpx_core::config::HttpGlobalConfig::default(),
        traffic: qpx_core::config::TrafficConfig::default(),
        acme: None,
        edges: vec![qpx_core::config::EdgeConfig::Forward(IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Direct,
                upstream: None,
                local_response: None,
            },
            original_dst: None,
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: None,
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            capture: None,
            rate_limit: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            http_modules,
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime")
}

#[tokio::test]
async fn mitm_http_modules_can_compress_responses() {
    let http_modules = vec![
        serde_yaml::from_str(
            r#"type: response_compression
settings:
  min_body_bytes: 1
  max_body_bytes: 65536
  content_types:
    - text/plain
  gzip: true
  brotli: false
  zstd: false
  gzip_level: 6
  brotli_level: 5
  zstd_level: 3"#,
        )
        .expect("http module config"),
    ];
    let runtime = mitm_runtime(http_modules);
    let sender = spawn_http1_send_request("mitm compression").await;
    let request = Request::builder()
        .method(http::Method::GET)
        .uri("/asset")
        .header("host", "secure.example")
        .header("accept-encoding", "gzip")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let response = proxy_mitm_request(
        request,
        runtime,
        sender,
        crate::http::mitm::MitmRouteContext {
            listener_name: "forward",
            src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            dst_port: 443,
            host: "secure.example",
            sni: "secure.example",
            upstream_cert: None,
        },
    )
    .await
    .expect("response");

    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok()),
        Some("gzip")
    );
    let body = to_bytes(response.into_body()).await.expect("body");
    assert_eq!(decode_gzip(body.as_ref()), "mitm compression");
}

// Exercise the whole MITM request direction, including the real Hyper client
// handoff, rather than exporting a head just to inspect it inside the pipeline.
#[tokio::test]
async fn mitm_forwards_owned_request_bytes_and_body() {
    use http_body_util::BodyExt as _;
    use hyper_util::rt::TokioIo;
    use std::sync::Arc;
    use tokio::sync::{Mutex, oneshot};
    use tokio::time::{Duration, timeout};

    timeout(Duration::from_secs(5), async {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (observed_tx, observed_rx) = oneshot::channel();
        let observed_tx = Arc::new(Mutex::new(Some(observed_tx)));
        let server = tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(server_io),
                    hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        let observed_tx = observed_tx.clone();
                        async move {
                            let (head, body) = req.into_parts();
                            let body = body.collect().await.expect("upstream body");
                            observed_tx
                                .lock()
                                .await
                                .take()
                                .expect("one request")
                                .send((head, body.to_bytes()))
                                .expect("observed request");
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Body::from(
                                "ok",
                            )))
                        }
                    }),
                )
                .await
                .expect("upstream server");
        });
        let (sender, connection) = qpx_http::protocol::common::handshake_http1(client_io)
            .await
            .expect("handshake");
        let connection = tokio::spawn(connection);
        let sender = Arc::new(Mutex::new(sender));
        let (mut body_tx, body) = Body::channel();
        let producer = tokio::spawn(async move {
            body_tx
                .send_data(bytes::Bytes::from_static(b"payload"))
                .await
                .expect("data");
        });
        let mut request = Request::builder()
            .method(http::Method::POST)
            .uri("/upload?part=1")
            .header("host", "secure.example")
            .header("x-order", "first")
            .header("x-order", "second")
            .header("connection", "x-remove")
            .header("x-remove", "hop only")
            .body(body)
            .expect("request");
        request
            .headers_mut()
            .insert("x-bytes", http::HeaderValue::from_bytes(b"a\x80z").unwrap());
        let response = proxy_mitm_request(
            request,
            mitm_runtime(Vec::new()),
            sender,
            crate::http::mitm::MitmRouteContext {
                listener_name: "forward",
                src_addr: "127.0.0.1:12345".parse().unwrap(),
                dst_port: 443,
                host: "secure.example",
                sni: "secure.example",
                upstream_cert: None,
            },
        )
        .await
        .expect("MITM response");
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap().as_ref(),
            b"ok"
        );
        let (head, body) = observed_rx.await.expect("observed request");
        assert_eq!(head.method, http::Method::POST);
        assert_eq!(head.uri, "/upload?part=1");
        assert_eq!(head.version, http::Version::HTTP_11);
        assert_eq!(head.headers["host"], "secure.example");
        assert_eq!(
            head.headers
                .get_all("x-order")
                .iter()
                .map(|v| v.as_bytes())
                .collect::<Vec<_>>(),
            vec![b"first".as_slice(), b"second".as_slice()]
        );
        assert_eq!(head.headers["x-bytes"].as_bytes(), b"a\x80z");
        assert!(!head.headers.contains_key("x-remove"));
        assert_eq!(body.as_ref(), b"payload");
        producer.await.expect("body producer");
        connection.abort();
        server.abort();
    })
    .await
    .expect("bounded MITM round trip");
}

#[tokio::test]
async fn mitm_owned_ingress_retains_upgrade_cancellation_and_trailer_frames() {
    use crate::http::protocol::{l7, upgrade, websocket};
    use qpx_core::http_message::Request as OwnerRequest;

    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-check", http::HeaderValue::from_static("done"));
    let mut decoded = Request::builder()
        .uri("/socket")
        .header("host", "secure.example")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("trailer", "x-check")
        .body(Body::replay(
            bytes::Bytes::from_static(b"payload"),
            Some(trailers),
        ))
        .unwrap();
    let commit = upgrade::install(&mut decoded);
    let mut req = OwnerRequest::from_http(decoded);
    assert!(websocket::is_websocket_upgrade(req.method(), req.headers()).unwrap());
    let pending = upgrade::on(req.extensions_mut());
    l7::prepare_request_with_headers_in_place(&mut req, "qpx", None, true);
    assert_eq!(
        req.body_mut().data().await.unwrap().unwrap().as_ref(),
        b"payload"
    );
    assert!(req.body_mut().data().await.is_none());
    assert_eq!(
        req.body_mut().trailers().await.unwrap().unwrap()["x-check"],
        "done"
    );
    drop(commit);
    assert_eq!(
        pending.await.err().unwrap().to_string(),
        "downstream upgrade canceled"
    );
}
