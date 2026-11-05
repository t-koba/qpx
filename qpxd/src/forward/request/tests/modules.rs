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
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(format!("http://{upstream_addr}/asset"))
        .header("host", upstream_addr.to_string())
        .header("accept-encoding", "gzip")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let response = handle_request_inner(
        OwnerRequest::from_http(request),
        runtime,
        "forward",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
    )
    .await
    .expect("response");

    assert_eq!(
        response
            .headers()
            .get(&qpx_core::http_message::OrdinaryHeaderName::try_from("content-encoding").unwrap())
            .and_then(|value| value.to_str().ok()),
        Some("gzip")
    );
    let body = to_bytes(response.into_head_and_body().1)
        .await
        .expect("body");
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
    let request = http::Request::builder()
        .method(Method::GET)
        .uri("http://127.0.0.1:9/asset")
        .header("host", "127.0.0.1:9")
        .header("x-test", "present")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let response = handle_request_inner(
        OwnerRequest::from_http(request),
        runtime,
        "forward",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
    )
    .await
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_head_and_body().1)
        .await
        .expect("body");
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
        let mut capabilities = crate::module_api::HttpModuleCapabilities::headers_only(
            crate::module_api::ModuleStages::DOWNSTREAM_RESPONSE,
        );
        capabilities.mutates_response_headers = true;
        capabilities
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
        response.set_header(self.header_name.clone(), self.header_value.clone());
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
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(format!("http://{upstream_addr}/asset"))
        .header("host", upstream_addr.to_string())
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let response = handle_request_inner(
        OwnerRequest::from_http(request),
        runtime,
        "forward",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
    )
    .await
    .expect("response");

    assert_eq!(
        response
            .headers()
            .get(
                &qpx_core::http_message::OrdinaryHeaderName::try_from("x-in-process-module")
                    .unwrap()
            )
            .and_then(|value| value.to_str().ok()),
        Some("active")
    );
}

#[derive(Clone)]
struct UriRewriteModule {
    stage: crate::module_api::HttpModuleStage,
    uri: http::Uri,
}

impl crate::module_api::HttpModuleFactory for UriRewriteModule {
    fn build(
        &self,
        _: &HttpModuleConfig,
    ) -> anyhow::Result<std::sync::Arc<dyn crate::module_api::HttpModule>> {
        Ok(std::sync::Arc::new(self.clone()))
    }
}

#[async_trait::async_trait]
impl crate::module_api::HttpModule for UriRewriteModule {
    fn capabilities(&self) -> crate::module_api::HttpModuleCapabilities {
        use crate::module_api::{HttpModuleCapabilities, HttpModuleStage, ModuleStages};
        HttpModuleCapabilities::headers_only(match self.stage {
            HttpModuleStage::RequestHeaders => ModuleStages::REQUEST_HEADERS,
            HttpModuleStage::UpstreamRequest => ModuleStages::UPSTREAM_REQUEST,
            _ => unreachable!(),
        })
    }

    async fn call<'a>(
        &self,
        stage: crate::module_api::HttpModuleStage,
        _: &mut crate::module_api::HttpModuleContext,
        event: crate::module_api::HttpModuleEvent<'a>,
    ) -> anyhow::Result<crate::module_api::HttpModuleEvent<'a>> {
        use crate::module_api::HttpModuleEvent;
        assert_eq!(stage, self.stage);
        let (HttpModuleEvent::RequestHeaders(mut request)
        | HttpModuleEvent::UpstreamRequest(mut request)) = event
        else {
            unreachable!()
        };
        if self.uri.authority().map(|value| value.as_str()) == Some("different.invalid")
            && request.authority().is_none()
        {
            assert_eq!(
                request.host(),
                Some("different.invalid"),
                "Host policy must have run before this hook"
            );
        }
        request.set_uri(self.uri.clone());
        Ok(HttpModuleEvent::Complete)
    }
}

#[tokio::test]
async fn forward_module_uri_authority_policy() {
    use crate::module_api::HttpModuleStage;
    use futures_util::FutureExt as _;
    use std::time::Duration;
    // Exercise the real preflight, cache-key preparation, hooks and wire send.
    // Rejected cases must not reach either an origin or a configured proxy.
    for stage in [
        HttpModuleStage::RequestHeaders,
        HttpModuleStage::UpstreamRequest,
    ] {
        for via_proxy in [false, true] {
            for origin_form in [false, true] {
                for rewrite in [
                    "origin",
                    "absolute",
                    "host",
                    "port",
                    "prepared_host",
                    "scheme_port",
                ] {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = listener.local_addr().unwrap();
                    let authority = if via_proxy {
                        "example.test:8080".to_owned()
                    } else {
                        addr.to_string()
                    };
                    let original = if origin_form {
                        "/old?before=1".to_owned()
                    } else {
                        format!("http://{authority}/old?before=1")
                    };
                    let uri = match rewrite {
                        "origin" => "/new?after=2".to_owned(),
                        "absolute" => format!("http://{authority}/new?after=2"),
                        "prepared_host" => "http://different.invalid/new?after=2".to_owned(),
                        "host" => format!("http://different.invalid:{}/new?after=2", addr.port()),
                        "port" => format!(
                            "http://{}:{}/new?after=2",
                            if via_proxy {
                                "example.test"
                            } else {
                                "127.0.0.1"
                            },
                            if addr.port() == 80 { 81 } else { 80 }
                        ),
                        "scheme_port" => format!(
                            "https://{}/new?after=2",
                            if via_proxy {
                                "example.test"
                            } else {
                                "127.0.0.1"
                            }
                        ),
                        _ => unreachable!(),
                    };
                    let accepted = matches!(rewrite, "origin" | "absolute");
                    let mut config: Config = serde_yaml::from_str("edges:\n  - kind: forward\n    name: forward\n    listen: 127.0.0.1:0\n    default_action: { type: direct }\n    http_modules: [{ type: rewrite_uri }]\n").unwrap();
                    if via_proxy {
                        config.upstreams =
                            serde_yaml::from_str(&format!("- name: next\n  url: http://{addr}\n"))
                                .unwrap();
                        let qpx_core::config::EdgeConfig::Forward(edge) = &mut config.edges[0]
                        else {
                            unreachable!()
                        };
                        edge.upstream_proxy = Some("next".to_owned());
                        edge.default_action.kind = ActionKind::Proxy;
                    }
                    if rewrite == "prepared_host" {
                        // A configured Host mutation must not become permission
                        // for a URI rewrite away from the preflight-selected target.
                        let qpx_core::config::EdgeConfig::Forward(edge) = &mut config.edges[0]
                        else {
                            unreachable!()
                        };
                        let action = if via_proxy { "proxy" } else { "direct" };
                        edge.rules = serde_yaml::from_str(&format!("- name: prepared-host\n  match: {{ host: ['*'] }}\n  action: {{ type: {action} }}\n  headers: {{ request_set: {{ Host: different.invalid }} }}\n")).unwrap();
                    }
                    let runtime = crate::Daemon::builder()
                        .register_http_module(
                            "rewrite_uri",
                            UriRewriteModule {
                                stage,
                                uri: uri.parse().unwrap(),
                            },
                        )
                        .unwrap()
                        .build()
                        .build_runtime(config)
                        .unwrap();
                    let request = http::Request::builder()
                        .uri(original)
                        .header("host", &authority)
                        .body(Body::empty())
                        .unwrap();
                    let mut listener = Some(listener);
                    let server = if accepted {
                        let listener = listener.take().unwrap();
                        Some(tokio::spawn(async move {
                            let (mut socket, _) = listener.accept().await.unwrap();
                            let mut head = Vec::new();
                            while !head.ends_with(b"\r\n\r\n") {
                                let mut byte = [0];
                                assert_eq!(socket.read(&mut byte).await.unwrap(), 1);
                                head.push(byte[0]);
                            }
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
                            String::from_utf8(head).unwrap()
                        }))
                    } else {
                        None
                    };
                    let result = tokio::time::timeout(
                        Duration::from_secs(3),
                        handle_request_inner(
                            OwnerRequest::from_http(request),
                            runtime,
                            "forward",
                            "127.0.0.1:12345".parse().unwrap(),
                        ),
                    )
                    .await
                    .expect("bounded dispatch");
                    if let Some(server) = server {
                        let response = result.unwrap();
                        assert_eq!(response.status(), StatusCode::OK);
                        assert_eq!(
                            to_bytes(response.into_head_and_body().1).await.unwrap(),
                            "ok"
                        );
                        let head = tokio::time::timeout(Duration::from_secs(3), server)
                            .await
                            .unwrap()
                            .unwrap();
                        let target = if via_proxy {
                            format!("http://{authority}/new?after=2")
                        } else {
                            "/new?after=2".to_owned()
                        };
                        assert!(
                            head.starts_with(&format!("GET {target} HTTP/1.1\r\n")),
                            "{stage:?} {head}"
                        );
                        assert!(
                            head.to_ascii_lowercase()
                                .contains(&format!("\r\nhost: {authority}\r\n")),
                            "{head}"
                        );
                    } else {
                        assert!(listener.as_ref().unwrap().accept().now_or_never().is_none());
                        let error = result.unwrap_err().to_string();
                        let stage_name = if stage == HttpModuleStage::RequestHeaders {
                            "request_headers"
                        } else {
                            "upstream_request"
                        };
                        assert_eq!(
                            error,
                            format!(
                                "http module rewrite_uri {stage_name} failed: request URI authority changed"
                            )
                        );
                    }
                }
            }
        }
    }
}
