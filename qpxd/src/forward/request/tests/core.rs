use super::*;

#[tokio::test]
async fn request_size_rule_uses_actual_chunked_body_size() {
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig {
            unknown_length_exact_size: UnknownLengthExactSizePolicy::Buffer,
            ..RuntimeConfig::default()
        },
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
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            },
            original_dst: None,
            tls_inspection: None,
            rules: vec![RuleConfig {
                name: "size".to_string(),
                r#match: Some(MatchConfig {
                    request_size: vec!["4".to_string()],
                    ..Default::default()
                }),
                auth: None,
                action: Some(ActionConfig {
                    kind: ActionKind::Respond,
                    upstream: None,
                    local_response: Some(LocalResponseConfig {
                        status: 204,
                        body: String::new(),
                        content_type: None,
                        headers: HashMap::new(),
                        rpc: None,
                    }),
                }),
                headers: None,
                rate_limit: None,
            }],
            connection_filter: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: Some(StreamingRequirement::Preferred),
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
            http_modules: Vec::new(),
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let (mut sender, body) = Body::channel();
    tokio::spawn(async move {
        sender
            .send_data(bytes::Bytes::from_static(b"ab"))
            .await
            .expect("send first chunk");
        sender
            .send_data(bytes::Bytes::from_static(b"cd"))
            .await
            .expect("send second chunk");
    });
    let request = http::Request::builder()
        .method(Method::POST)
        .uri("http://example.com/upload")
        .header("host", "example.com")
        .version(http::Version::HTTP_11)
        .body(body)
        .expect("request");

    let response = handle_request_inner(
        OwnerRequest::from_http(request),
        runtime,
        "forward",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
    )
    .await
    .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn forward_request_preserves_upstream_early_hints() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("accept upstream");
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        crate::test_util::read_request_head(&mut stream, &mut raw, &mut buf).await;
        stream
            .write_all(
                b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
            )
            .await
            .expect("write response");
    });

    let runtime = Runtime::new(Config {
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
            streaming_requirement: Some(StreamingRequirement::Preferred),
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
            http_modules: Vec::new(),
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime");

    let request = http::Request::builder()
        .method(Method::GET)
        .uri(format!("http://{upstream_addr}/asset"))
        .header("host", upstream_addr.to_string())
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let mut response = handle_request_inner(
        OwnerRequest::from_http(request),
        runtime,
        "forward",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
    )
    .await
    .expect("response");

    let interim = response
        .extensions_mut()
        .remove::<Vec<crate::upstream::raw_http1::InterimResponseHead>>()
        .expect("interim responses");
    assert_eq!(interim.len(), 1);
    assert_eq!(
        interim[0].status,
        StatusCode::from_u16(103).expect("early hints")
    );
    assert_eq!(
        interim[0]
            .headers_for_egress()
            .get(http::header::LINK)
            .and_then(|value| value.to_str().ok()),
        Some("</style.css>; rel=preload; as=style")
    );
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn forward_consumes_client_nominations_before_trusted_headers() {
    let addr = crate::test_util::spawn_request_head_echo_server().await;
    let config: Config = serde_yaml::from_str(
        r#"
edges:
  - kind: forward
    name: forward
    listen: 127.0.0.1:0
    default_action: { type: direct }
    http:
      forwarded: { trusted_peers: [10.0.0.0/8], by: qpx-test }
    rules:
      - name: headers
        headers:
          request_set: { x-qpx-trusted: proxy-value, keep-alive: timeout=5 }
"#,
    )
    .expect("config");
    let runtime = Runtime::new(config).expect("runtime");
    let request = http::Request::builder()
        .uri(format!("http://{addr}/"))
        .header("host", addr.to_string())
        .header("connection", "X-QpX-TrUsTeD, forwarded")
        .header("connection", "x-ClIeNt-OnLy, Keep-Alive")
        .header("x-qpx-trusted", "client-value")
        .header("x-client-only", "must-not-leak")
        .body(Body::empty())
        .expect("request");
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        handle_request_inner(
            OwnerRequest::from_http(request),
            runtime,
            "forward",
            "192.0.2.1:12345".parse().expect("peer"),
        ),
    )
    .await
    .expect("dispatch timeout")
    .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_head_and_body().1)
        .await
        .expect("echo");
    let head = std::str::from_utf8(&body)
        .expect("UTF-8")
        .to_ascii_lowercase();
    assert!(
        head.contains("\r\nx-qpx-trusted: proxy-value\r\n"),
        "{head}"
    );
    assert!(
        head.contains("\r\nforwarded: for=192.0.2.1;by=qpx-test;proto=http;"),
        "{head}"
    );
    assert!(!head.contains("\r\nx-client-only:"), "{head}");
    assert!(!head.contains("\r\nkeep-alive:"), "{head}");
    assert!(!head.contains("\r\nconnection:"), "{head}");
}

#[tokio::test]
async fn forward_success_keeps_owner_through_finalization_observation_and_codec() {
    use qpx_core::http_message::{OrdinaryHeaderName, Response as OwnerResponse};
    use qpx_observability::access_log::RequestLogContext;
    use std::time::Duration;

    tokio::time::timeout(Duration::from_secs(5), async {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut raw = Vec::new();
            crate::test_util::read_request_head(&mut stream, &mut raw, &mut [0; 1024]).await;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: x-upstream-hop, close\r\nX-Upstream-Hop: drop\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nVia: 1.0 upstream\r\nProxy-Status: upstream\r\n\r\nabc").await.unwrap();
        });
        let config: Config = serde_yaml::from_str(r#"
telemetry:
  access_log: { enabled: true }
edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:0
  default_action: { type: direct }
  rules:
  - name: suffix
    headers:
      response_set:
        content-length: '3, 3'
        connection: x-configured-hop
        x-configured-hop: drop
        x-finalized: yes
      response_add:
        set-cookie: c=3
"#).unwrap();
        let runtime = Runtime::new(config).unwrap();
        let request = http::Request::builder()
            .uri(format!("http://{upstream_addr}/asset"))
            .header("host", upstream_addr.to_string())
            .body(Body::empty()).unwrap();
        // The actual successful dispatch runs cache write/module preparation,
        // owner finalization, optional export limiting, logging and annotation.
        let response: OwnerResponse<Body> = handle_request_inner(
            OwnerRequest::from_http(request), runtime, "forward",
            "127.0.0.1:12345".parse().unwrap(),
        ).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().declared_content_length(), Ok(Some(3)));
        let name = |n| OrdinaryHeaderName::try_from(n).unwrap();
        assert_eq!(response.headers().get(&name("x-finalized")).unwrap(), "yes");
        assert!(response.headers().get(&name("x-configured-hop")).is_none());
        assert!(response.headers().get(&name("connection")).is_none());
        assert_eq!(response.headers().get_all(&name("set-cookie")).map(|v| v.to_str().unwrap()).collect::<Vec<_>>(), ["a=1", "b=2", "c=3"]);
        assert_eq!(response.headers().get(&name("proxy-status")).unwrap(), "upstream, qpx");
        let log = response.extensions().get::<RequestLogContext>().expect("suffix audit annotation");
        assert_eq!(log.matched_rule.as_deref(), Some("suffix"));

        // Genuine downstream codec egress: the owner reaches serialization,
        // where the duplicate declaration is canonicalized, not unwrapped by
        // any intervening policy/finalization/observation facade.
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        crate::http::codec::h1::send_http1_response_with_interim(
            &mut writer, http::Version::HTTP_11, &Method::GET, response, &[],
            false, Duration::from_secs(2), &mut bytes::BytesMut::new(),
        ).await.unwrap();
        drop(writer);
        let mut wire = String::new();
        reader.read_to_string(&mut wire).await.unwrap();
        let wire = wire.to_ascii_lowercase();
        assert!(wire.contains("\r\ncontent-length: 3\r\n"), "{wire}");
        assert!(!wire.contains("content-length: 3, 3"), "{wire}");
        assert!(wire.contains("\r\nx-finalized: yes\r\n"), "{wire}");
        assert!(wire.contains("\r\nvia: 1.1 qpx\r\n"), "{wire}");
        assert!(wire.contains("\r\ndate: "), "{wire}");
        assert!(wire.ends_with("\r\n\r\nabc"), "{wire}");
        server.await.unwrap();
    }).await.expect("bounded forward success suffix");
}

#[tokio::test]
async fn ftp_module_response_is_finalized_and_audited_as_owner() {
    use qpx_core::http_message::OrdinaryHeaderName;
    use qpx_observability::access_log::RequestLogContext;

    let config = serde_yaml::from_str(
        r#"
telemetry:
  access_log: { enabled: true }
messages:
  unsupported_ftp_method: "ftp method is not supported"
edges:
- kind: forward
  name: ftp-test
  listen: 127.0.0.1:0
  default_action: { type: direct }
  ftp: { enabled: true }
  rules:
  - name: ftp-response
    headers:
      response_set:
        x-ftp-policy: applied
"#,
    )
    .expect("FTP forward config");
    let runtime = Runtime::new(config).expect("FTP forward runtime");
    let request = http::Request::builder()
        .method(Method::PATCH)
        .uri("ftp://example.com/file.txt")
        .header("host", "example.com")
        .body(Body::empty())
        .expect("unsupported FTP request");

    let response = handle_request_inner(
        OwnerRequest::from_http(request),
        runtime,
        "ftp-test",
        "127.0.0.1:12345".parse().unwrap(),
    )
    .await
    .expect("FTP response");

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let name = OrdinaryHeaderName::try_from("x-ftp-policy").expect("ordinary header");
    assert_eq!(response.headers().get(&name).unwrap(), "applied");
    assert!(!response.headers().contains_content_length());
    let log = response
        .extensions()
        .get::<RequestLogContext>()
        .expect("FTP dispatch audit annotation");
    assert_eq!(log.matched_rule.as_deref(), Some("ftp-response"));
    let body = to_bytes(response.into_head_and_body().1)
        .await
        .expect("FTP response body");
    assert_eq!(body.as_ref(), b"ftp method is not supported");
}
