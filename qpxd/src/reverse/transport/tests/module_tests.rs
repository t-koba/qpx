use super::*;

#[tokio::test]
async fn reverse_route_http_module_compresses_responses() {
    let upstream_addr = spawn_static_http_server(
        "200 OK",
        vec![("Content-Type", "text/plain".to_string())],
        "reverse compression".to_string(),
        1,
    )
    .await;
    let reverse_cfg = ReverseEdgeConfig {
        name: "test".to_string(),
        listen: "127.0.0.1:0".to_string(),
        tls: None,
        http3: None,
        xdp: None,
        enforce_sni_host_match: false,
        sni_host_exceptions: Vec::new(),
        policy_context: None,
        destination_resolution: None,
        connection_filter: Vec::new(),
        streaming: None,
        grpc: None,
        sse: None,
        routes: vec![ReverseRouteConfig {
            name: Some("route".to_string()),
            r#match: MatchConfig::default(),
            target: qpx_core::config::ReverseRouteTargetConfig::Upstream {
                upstreams: vec!["upstream".to_string()],
                lb: "round_robin".to_string(),
            },
            mirrors: Vec::new(),
            headers: None,
            timeout_ms: None,
            health_check: None,
            cache: None,
            capture: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            affinity: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: vec![
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
            ],
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: Some(StreamingRequirement::Preferred),
        }],
        tls_passthrough_routes: Vec::new(),
    };
    let config = Config {
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
        edges: vec![qpx_core::config::EdgeConfig::Reverse(reverse_cfg.clone())],
        upstreams: vec![UpstreamConfig {
            name: "upstream".to_string(),
            url: format!("http://{upstream_addr}"),
            tls_trust_profile: None,
            tls_trust: None,
            discovery: None,
            resilience: None,
        }],
        caches: Vec::new(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = crate::reverse::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_http_modules_compression"),
    )
    .expect("reloadable reverse");
    let request = Request::from_http(
        http::Request::builder()
            .method(Method::GET)
            .uri("/asset")
            .header("host", "reverse.test")
            .header("accept-encoding", "gzip")
            .version(http::Version::HTTP_11)
            .body(Body::empty())
            .expect("request"),
    );

    let (_, response) = handle_request_with_interim(
        request,
        reverse,
        ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 80),
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
    assert_eq!(decode_gzip(body.as_ref()), "reverse compression");
}

#[tokio::test]
async fn reverse_route_http_module_can_inject_subrequest_headers() {
    let upstream_addr = spawn_static_http_server(
        "200 OK",
        vec![("Content-Type", "text/plain".to_string())],
        "origin".to_string(),
        1,
    )
    .await;
    let subrequest_addr = spawn_static_http_server(
        "200 OK",
        vec![("X-Decision", "allow".to_string())],
        String::new(),
        1,
    )
    .await;
    let reverse_cfg = ReverseEdgeConfig {
        name: "test".to_string(),
        listen: "127.0.0.1:0".to_string(),
        tls: None,
        http3: None,
        xdp: None,
        enforce_sni_host_match: false,
        sni_host_exceptions: Vec::new(),
        policy_context: None,
        destination_resolution: None,
        connection_filter: Vec::new(),
        streaming: None,
        grpc: None,
        sse: None,
        routes: vec![ReverseRouteConfig {
            name: Some("route".to_string()),
            r#match: MatchConfig::default(),
            target: qpx_core::config::ReverseRouteTargetConfig::Upstream {
                upstreams: vec!["upstream".to_string()],
                lb: "round_robin".to_string(),
            },
            mirrors: Vec::new(),
            headers: None,
            timeout_ms: None,
            health_check: None,
            cache: None,
            capture: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            affinity: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: vec![
                serde_yaml::from_str(&format!(
                    r#"type: subrequest
settings:
  name: header-inject
  phase: response_headers
  url: http://{subrequest_addr}/headers
  timeout_ms: 1000
  max_response_bytes: 65536
  allowed_schemes: [http]
  allowed_hosts: [127.0.0.1]
  deny_private_ip_redirects: false
  copy_response_headers_to_response:
    - from: x-decision
      to: x-module-decision"#
                ))
                .expect("http module config"),
            ],
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: Some(StreamingRequirement::Preferred),
        }],
        tls_passthrough_routes: Vec::new(),
    };
    let config = Config {
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
        edges: vec![qpx_core::config::EdgeConfig::Reverse(reverse_cfg.clone())],
        upstreams: vec![UpstreamConfig {
            name: "upstream".to_string(),
            url: format!("http://{upstream_addr}"),
            tls_trust_profile: None,
            tls_trust: None,
            discovery: None,
            resilience: None,
        }],
        caches: Vec::new(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = crate::reverse::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_http_modules_subrequest"),
    )
    .expect("reloadable reverse");
    let request = Request::from_http(
        http::Request::builder()
            .method(Method::GET)
            .uri("/asset")
            .header("host", "reverse.test")
            .version(http::Version::HTTP_11)
            .body(Body::empty())
            .expect("request"),
    );

    let (_, response) = handle_request_with_interim(
        request,
        reverse,
        ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 80),
    )
    .await
    .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-module-decision")
            .and_then(|value| value.to_str().ok()),
        Some("allow")
    );
    assert_eq!(
        to_bytes(response.into_body()).await.expect("body"),
        bytes::Bytes::from_static(b"origin")
    );
}

#[tokio::test]
async fn reverse_consumes_client_nominations_before_trusted_headers() {
    let addr = crate::test_util::spawn_request_head_echo_server().await;
    let config: Config = serde_yaml::from_str(&format!(
        r#"
upstreams:
  - name: origin
    url: http://{addr}
edges:
  - kind: reverse
    name: reverse
    listen: 127.0.0.1:0
    routes:
      - name: headers
        match: {{}}
        target: {{ type: upstream, upstreams: [origin] }}
        http:
          forwarded: {{ trusted_peers: [10.0.0.0/8], by: qpx-test }}
        headers:
          request_set: {{ x-qpx-trusted: proxy-value, keep-alive: timeout=5 }}
"#
    ))
    .expect("config");
    let reverse_config = config.reverse_edges().next().expect("reverse edge").clone();
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = crate::reverse::ReloadableReverse::new(
        reverse_config,
        runtime,
        StdArc::<str>::from("header-ordering-test"),
    )
    .expect("reverse");
    let request = Request::from_http(
        http::Request::builder()
            .uri("/")
            .header("host", "reverse.test")
            .header("connection", "X-QpX-TrUsTeD, forwarded")
            .header("connection", "x-ClIeNt-OnLy, Keep-Alive")
            .header("x-qpx-trusted", "client-value")
            .header("x-client-only", "must-not-leak")
            .body(Body::empty())
            .expect("request"),
    );
    let (_, response) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        handle_request_with_interim(
            request,
            reverse,
            ReverseConnInfo::plain("192.0.2.1:12345".parse().expect("peer"), 80),
        ),
    )
    .await
    .expect("dispatch timeout")
    .expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let body = to_bytes(response.into_body()).await.expect("echo");
    let head = std::str::from_utf8(&body)
        .expect("UTF-8")
        .to_ascii_lowercase();
    assert!(
        head.contains("\r\nx-qpx-trusted: proxy-value\r\n"),
        "{head}"
    );
    assert!(
        head.contains("\r\nforwarded: for=192.0.2.1;by=qpx-test;proto=http;host=reverse.test\r\n"),
        "{head}"
    );
    assert!(!head.contains("\r\nx-client-only:"), "{head}");
    assert!(!head.contains("\r\nkeep-alive:"), "{head}");
    assert!(!head.contains("\r\nconnection:"), "{head}");
}
