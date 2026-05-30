use super::*;

#[tokio::test]
async fn forward_http_module_compresses_responses() {
    let upstream_addr = spawn_static_http_server(
        "200 OK",
        vec![("Content-Type", "text/plain".to_string())],
        "compress me please".to_string(),
        1,
    )
    .await;
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
                ext_authz: Vec::new(),
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
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime");
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{upstream_addr}/asset"))
        .header("host", upstream_addr.to_string())
        .header("accept-encoding", "gzip")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let response = handle_request_inner(
        request,
        runtime,
        "forward",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
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
    assert_eq!(decode_gzip(body.as_ref()), "compress me please");
}

#[tokio::test]
async fn forward_http_module_subrequest_can_short_circuit() {
    let subrequest_addr = spawn_static_http_server(
        "503 Service Unavailable",
        vec![("Content-Type", "text/plain".to_string())],
        "blocked by subrequest".to_string(),
        1,
    )
    .await;
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
                ext_authz: Vec::new(),
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
            http_modules: vec![
                serde_yaml::from_str(&format!(
                    r#"type: subrequest
settings:
  name: authz
  phase: request_headers
  url: http://{subrequest_addr}/check?path={{request.path:urlquery}}
  timeout_ms: 1000
  max_response_bytes: 65536
  allowed_schemes: [http]
  allowed_hosts: [127.0.0.1]
  deny_private_ip_redirects: false
  pass_headers:
    - x-test
  response_mode: return_on_error"#
                ))
                .expect("http module config"),
            ],
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime");
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://127.0.0.1:9/asset")
        .header("host", "127.0.0.1:9")
        .header("x-test", "present")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let response = handle_request_inner(
        request,
        runtime,
        "forward",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
    )
    .await
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body()).await.expect("body");
    assert_eq!(body.as_ref(), b"blocked by subrequest");
}

#[derive(serde::Deserialize)]
struct TestResponseHeaderModuleConfig {
    header_name: String,
    header_value: String,
}

struct TestResponseHeaderModuleFactory;

struct TestResponseHeaderModule {
    header_name: http::HeaderName,
    header_value: http::HeaderValue,
}

impl crate::module_api::HttpModuleFactory for TestResponseHeaderModuleFactory {
    fn build(
        &self,
        spec: &HttpModuleConfig,
    ) -> anyhow::Result<std::sync::Arc<dyn crate::module_api::HttpModule>> {
        let config: TestResponseHeaderModuleConfig = spec.parse_settings()?;
        Ok(std::sync::Arc::new(TestResponseHeaderModule {
            header_name: http::HeaderName::from_bytes(config.header_name.as_bytes())?,
            header_value: http::HeaderValue::from_str(config.header_value.as_str())?,
        }))
    }
}

#[async_trait::async_trait]
impl crate::module_api::HttpModule for TestResponseHeaderModule {
    fn capabilities(&self) -> crate::module_api::HttpModuleCapabilities {
        crate::module_api::HttpModuleCapabilities::headers_only(
            crate::module_api::ModuleStages::DOWNSTREAM_RESPONSE,
        )
    }

    async fn call<'a>(
        &self,
        stage: crate::module_api::HttpModuleStage,
        _ctx: &mut crate::module_api::HttpModuleContext,
        event: crate::module_api::HttpModuleEvent<'a>,
    ) -> anyhow::Result<crate::module_api::HttpModuleEvent<'a>> {
        let crate::module_api::HttpModuleStage::DownstreamResponse = stage else {
            return Ok(event);
        };
        let crate::module_api::HttpModuleEvent::DownstreamResponse(mut response) = event else {
            anyhow::bail!("invalid downstream response event");
        };
        response
            .headers_mut()
            .insert(self.header_name.clone(), self.header_value.clone());
        Ok(crate::module_api::HttpModuleEvent::DownstreamResponse(
            response,
        ))
    }
}

#[tokio::test]
async fn forward_custom_http_module_registry_adds_response_header() {
    let upstream_addr = spawn_static_http_server(
        "200 OK",
        vec![("Content-Type", "text/plain".to_string())],
        "custom module".to_string(),
        1,
    )
    .await;
    let daemon = crate::Daemon::builder()
        .register_http_module("test_response_header", TestResponseHeaderModuleFactory)
        .expect("register module")
        .build();
    let runtime = daemon
        .build_runtime(Config {
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
                    ext_authz: Vec::new(),
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
                http_modules: vec![
                    serde_yaml::from_str(
                        r#"type: test_response_header
settings:
  header_name: x-in-process-module
  header_value: active"#,
                    )
                    .expect("http module config"),
                ],
            })],
            upstreams: Vec::new(),
            caches: Vec::new(),
        })
        .expect("runtime");
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{upstream_addr}/asset"))
        .header("host", upstream_addr.to_string())
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let response = handle_request_inner(
        request,
        runtime,
        "forward",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
    )
    .await
    .expect("response");

    assert_eq!(
        response
            .headers()
            .get("x-in-process-module")
            .and_then(|value| value.to_str().ok()),
        Some("active")
    );
}
