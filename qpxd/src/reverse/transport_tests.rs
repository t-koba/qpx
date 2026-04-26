use super::super::router::{CompiledPathRewrite, CompiledRegexPathRewrite, ReverseRouter};
use super::*;
use crate::destination::DestinationMetadata;
use crate::http::base_fields::BaseRequestFields;
use crate::http::body::to_bytes;
use crate::runtime::Runtime;
use crate::tls::UpstreamCertificateInfo;
use http::header::CONTENT_LENGTH;
use qpx_core::config::{
    AccessLogConfig, AuditLogConfig, AuthConfig, CacheConfig, CertificateMatchConfig, Config,
    DestinationDimensionMatchConfig, DestinationMatchConfig, ExtAuthzConfig, ExtAuthzSendConfig,
    HeaderControl, HttpPolicyConfig, HttpResponseCacheEffectsConfig, HttpResponseEffectsConfig,
    HttpResponseRuleConfig, IdentityConfig, LocalResponseConfig, MatchConfig, MessagesConfig,
    NamedSetConfig, NamedSetKind, PolicyContextConfig, RateLimitConfig, RateLimitProfileConfig,
    ReverseConfig, ReverseRouteConfig, RpcMatchConfig, RuntimeConfig, SystemLogConfig,
    UpstreamConfig,
};
use rcgen::generate_simple_self_signed;
use regex::Regex;
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc as StdArc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn make_req(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn compile_headers(name: &str, value: &str) -> Arc<CompiledHeaderControl> {
    let mut response_set = HashMap::new();
    response_set.insert(name.to_string(), value.to_string());
    Arc::new(
        CompiledHeaderControl::compile(&HeaderControl {
            request_set: HashMap::new(),
            request_add: HashMap::new(),
            request_remove: Vec::new(),
            request_regex_replace: Vec::new(),
            response_set,
            response_add: HashMap::new(),
            response_remove: Vec::new(),
            response_regex_replace: Vec::new(),
        })
        .expect("compile headers"),
    )
}

fn make_base_request_fields(
    method: &str,
    authority: &str,
    path: &str,
    query: Option<&str>,
) -> BaseRequestFields {
    let request_uri = match query {
        Some(query) => format!("https://{authority}{path}?{query}"),
        None => format!("https://{authority}{path}"),
    };
    BaseRequestFields {
        peer_ip: None,
        dst_port: None,
        host: Some(authority.to_string()),
        sni: None,
        method: method.parse().expect("method"),
        path: Some(path.to_string()),
        query: query.map(str::to_string),
        authority: Some(authority.to_string()),
        scheme: Some("https".to_string()),
        request_uri,
        http_version: crate::http::common::http_version_label(http::Version::HTTP_11),
    }
}

async fn spawn_ext_authz_server(response_body: String, accepts: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind authz");
    let addr = listener.local_addr().expect("authz addr");
    tokio::spawn(async move {
        for _ in 0..accepts {
            let (mut stream, _) = listener.accept().await.expect("authz accept");
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.expect("authz read");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("authz write");
        }
    });
    addr
}

async fn spawn_static_http_server(
    status_line: &'static str,
    headers: Vec<(&'static str, String)>,
    body: String,
    accepts: usize,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        for _ in 0..accepts {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.expect("read request");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let mut response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (name, value) in &headers {
                response.push_str(name);
                response.push_str(": ");
                response.push_str(value);
                response.push_str("\r\n");
            }
            response.push_str("\r\n");
            response.push_str(body.as_str());
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        }
    });
    addr
}

fn decode_gzip(bytes: &[u8]) -> String {
    let mut decoder = flate2::read::GzDecoder::new(bytes);
    let mut out = String::new();
    decoder.read_to_string(&mut out).expect("decode gzip");
    out
}

fn build_router(response_rules: Vec<HttpResponseRuleConfig>) -> ReverseRouter {
    let registry = crate::http::modules::default_http_module_registry();
    ReverseRouter::new(
        ReverseConfig {
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
            routes: vec![ReverseRouteConfig {
                name: Some("test".to_string()),
                r#match: MatchConfig::default(),
                upstreams: vec!["upstream".to_string()],
                backends: Vec::new(),
                mirrors: Vec::new(),
                local_response: None,
                headers: None,
                lb: "round_robin".to_string(),
                timeout_ms: None,
                health_check: None,
                cache: None,
                rate_limit: None,
                path_rewrite: None,
                upstream_trust_profile: None,
                upstream_trust: None,
                lifecycle: None,
                ipc: None,
                affinity: None,
                policy_context: None,
                http: Some(HttpPolicyConfig { response_rules }),
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
            }],
            tls_passthrough_routes: Vec::new(),
        },
        &[UpstreamConfig {
            name: "upstream".to_string(),
            url: "http://127.0.0.1:8080".to_string(),
            tls_trust_profile: None,
            tls_trust: None,
            discovery: None,
            resilience: None,
        }],
        registry.as_ref(),
    )
    .expect("router")
}

#[test]
fn path_rewrite_strip_prefix() {
    let mut req = make_req("/api/v1/users");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: Some("/api/v1".into()),
            add_prefix: None,
            regex: None,
        },
    );
    assert_eq!(req.uri().path(), "/users");
}

#[test]
fn path_rewrite_add_prefix() {
    let mut req = make_req("/users");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: None,
            add_prefix: Some("/v2".into()),
            regex: None,
        },
    );
    assert_eq!(req.uri().path(), "/v2/users");
}

#[test]
fn path_rewrite_strip_and_add() {
    let mut req = make_req("/api/v1/users");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: Some("/api/v1".into()),
            add_prefix: Some("/v2".into()),
            regex: None,
        },
    );
    assert_eq!(req.uri().path(), "/v2/users");
}

#[test]
fn path_rewrite_preserves_query() {
    let mut req = make_req("/api/v1/users?q=foo&limit=10");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: Some("/api/v1".into()),
            add_prefix: None,
            regex: None,
        },
    );
    assert_eq!(
        req.uri().path_and_query().unwrap().as_str(),
        "/users?q=foo&limit=10"
    );
}

#[test]
fn path_rewrite_root_only() {
    let mut req = make_req("/api/v1");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: Some("/api/v1".into()),
            add_prefix: None,
            regex: None,
        },
    );
    assert_eq!(req.uri().path(), "/");
}

#[test]
fn path_rewrite_no_match_passthrough() {
    let mut req = make_req("/other/path");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: Some("/api/v1".into()),
            add_prefix: None,
            regex: None,
        },
    );
    assert_eq!(req.uri().path(), "/other/path");
}

#[test]
fn path_rewrite_regex_replace() {
    let mut req = make_req("/api/v1/users");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: None,
            add_prefix: None,
            regex: Some(CompiledRegexPathRewrite {
                pattern: Regex::new(r"^/api/v1/(.*)$").unwrap(),
                replace: "/v2/$1".to_string(),
            }),
        },
    );
    assert_eq!(req.uri().path(), "/v2/users");
}

#[test]
fn path_rewrite_regex_ensures_leading_slash() {
    let mut req = make_req("/api/v1/users");
    apply_path_rewrite(
        &mut req,
        &CompiledPathRewrite {
            strip_prefix: None,
            add_prefix: None,
            regex: Some(CompiledRegexPathRewrite {
                pattern: Regex::new(r"^/api/v1/(.*)$").unwrap(),
                replace: "$1".to_string(),
            }),
        },
    );
    assert_eq!(req.uri().path(), "/users");
}

#[tokio::test]
async fn response_rule_can_force_local_response_and_merge_headers() {
    let router = build_router(vec![HttpResponseRuleConfig {
        name: "resp-local".to_string(),
        r#match: Some(MatchConfig {
            response_status: vec!["500-599".to_string()],
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig {
            local_response: Some(LocalResponseConfig {
                status: 418,
                body: "blocked upstream".to_string(),
                content_type: Some("text/plain".to_string()),
                headers: HashMap::new(),
                rpc: None,
            }),
            headers: Some(HeaderControl {
                request_set: HashMap::new(),
                request_add: HashMap::new(),
                request_remove: Vec::new(),
                request_regex_replace: Vec::new(),
                response_set: HashMap::from([("x-rule".to_string(), "local".to_string())]),
                response_add: HashMap::new(),
                response_remove: Vec::new(),
                response_regex_replace: Vec::new(),
            }),
            ..Default::default()
        },
    }]);
    let route = router.route_at(0).expect("route");
    let conn = ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 443);
    let identity = crate::policy_context::ResolvedIdentity::default();
    let destination = DestinationMetadata::default();
    let response = Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::empty())
        .unwrap();
    let request_rpc = crate::http::rpc::RpcMatchContext::default();
    let base = make_base_request_fields("GET", "example.com", "/", None);

    let decision = apply_response_rules(ResponseRuleInput {
        route,
        base: &base,
        conn: &conn,
        destination: &destination,
        upstream_cert: None,
        identity: &identity,
        request_rpc: Some(&request_rpc),
        route_headers: Some(compile_headers("x-base", "route")),
        response,
        max_observed_response_body_bytes: usize::MAX,
        response_body_read_timeout: std::time::Duration::from_secs(1),
    })
    .await
    .expect("apply");

    match decision {
        ResponseRuleDecision::LocalResponse {
            response,
            route_headers,
            ..
        } => {
            assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
            let headers = route_headers.expect("merged headers");
            assert!(headers
                .response_set()
                .iter()
                .any(|(name, value)| name == "x-base" && value == "route"));
            assert!(headers
                .response_set()
                .iter()
                .any(|(name, value)| name == "x-rule" && value == "local"));
        }
        ResponseRuleDecision::Continue { .. } => panic!("expected local response"),
    }
}

#[tokio::test]
async fn response_rule_matches_request_derived_rpc_fields() {
    let router = build_router(vec![HttpResponseRuleConfig {
        name: "resp-rpc".to_string(),
        r#match: Some(MatchConfig {
            rpc: Some(RpcMatchConfig {
                protocol: vec!["grpc".to_string()],
                service: vec!["demo.Echo".to_string()],
                method: vec!["Say".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig {
            local_response: Some(LocalResponseConfig {
                status: 204,
                body: String::new(),
                content_type: None,
                headers: HashMap::new(),
                rpc: None,
            }),
            ..Default::default()
        },
    }]);
    let route = router.route_at(0).expect("route");
    assert!(route.response_rules_require_request_rpc_context());
    let conn = ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 443);
    let identity = crate::policy_context::ResolvedIdentity::default();
    let destination = DestinationMetadata::default();
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap();
    let request_rpc = crate::http::rpc::RpcMatchContext {
        protocol: Some("grpc".to_string()),
        service: Some("demo.Echo".to_string()),
        method: Some("Say".to_string()),
        ..Default::default()
    };
    let base = make_base_request_fields("POST", "example.com", "/demo.Echo/Say", None);

    let decision = apply_response_rules(ResponseRuleInput {
        route,
        base: &base,
        conn: &conn,
        destination: &destination,
        upstream_cert: None,
        identity: &identity,
        request_rpc: Some(&request_rpc),
        route_headers: None,
        response,
        max_observed_response_body_bytes: usize::MAX,
        response_body_read_timeout: std::time::Duration::from_secs(1),
    })
    .await
    .expect("apply");

    match decision {
        ResponseRuleDecision::LocalResponse { response, .. } => {
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }
        ResponseRuleDecision::Continue { .. } => panic!("expected local response"),
    }
}

#[tokio::test]
async fn reverse_response_rule_matches_client_streaming_rpc() {
    let mut request_body = grpc_test_frame(b"one");
    request_body.extend_from_slice(&grpc_test_frame(b"two"));
    assert_reverse_response_rule_matches_streaming("client", 210, Vec::new(), request_body).await;
}

#[tokio::test]
async fn reverse_response_rule_matches_bidi_streaming_rpc() {
    let mut request_body = grpc_test_frame(b"one");
    request_body.extend_from_slice(&grpc_test_frame(b"two"));
    let mut response_body = grpc_test_frame(b"alpha");
    response_body.extend_from_slice(&grpc_test_frame(b"beta"));
    assert_reverse_response_rule_matches_streaming("bidi", 211, response_body, request_body).await;
}

async fn assert_reverse_response_rule_matches_streaming(
    streaming: &str,
    status: u16,
    upstream_body: Vec<u8>,
    request_body: Vec<u8>,
) {
    let upstream_addr = spawn_static_http_server(
        "200 OK",
        vec![("Content-Type", "application/grpc".to_string())],
        String::from_utf8(upstream_body).expect("test gRPC frame bytes are UTF-8 control bytes"),
        1,
    )
    .await;
    let reverse_cfg = ReverseConfig {
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
        routes: vec![ReverseRouteConfig {
            name: Some("grpc".to_string()),
            r#match: MatchConfig::default(),
            upstreams: vec!["upstream".to_string()],
            backends: Vec::new(),
            mirrors: Vec::new(),
            local_response: None,
            headers: None,
            lb: "round_robin".to_string(),
            timeout_ms: None,
            health_check: None,
            cache: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            ipc: None,
            affinity: None,
            policy_context: None,
            http: Some(HttpPolicyConfig {
                response_rules: vec![HttpResponseRuleConfig {
                    name: "rpc-streaming".to_string(),
                    r#match: Some(MatchConfig {
                        rpc: Some(RpcMatchConfig {
                            streaming: vec![streaming.to_string()],
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    effects: HttpResponseEffectsConfig {
                        local_response: Some(LocalResponseConfig {
                            status,
                            body: "reverse streaming matched".to_string(),
                            content_type: Some("text/plain".to_string()),
                            headers: HashMap::new(),
                            rpc: None,
                        }),
                        ..Default::default()
                    },
                }],
            }),
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: Vec::new(),
        }],
        tls_passthrough_routes: Vec::new(),
    };
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        system_log: SystemLogConfig::default(),
        access_log: AccessLogConfig::default(),
        audit_log: AuditLogConfig::default(),
        metrics: None,
        otel: None,
        acme: None,
        exporter: None,
        auth: AuthConfig::default(),
        identity_sources: Vec::new(),
        ext_authz: Vec::new(),
        destination_resolution: Default::default(),
        listeners: Vec::new(),
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: vec![reverse_cfg.clone()],
        upstreams: vec![UpstreamConfig {
            name: "upstream".to_string(),
            url: format!("http://{upstream_addr}"),
            tls_trust_profile: None,
            tls_trust: None,
            discovery: None,
            resilience: None,
        }],
        cache: CacheConfig::default(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = super::super::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_upstreams_unhealthy"),
    )
    .expect("reloadable reverse");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/demo.Echo/Say")
        .header("host", "reverse.test")
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::CONTENT_LENGTH, request_body.len().to_string())
        .version(http::Version::HTTP_11)
        .body(Body::from(request_body))
        .expect("request");

    let (_, response) = handle_request_with_interim(
        request,
        reverse,
        ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 80),
    )
    .await
    .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::from_u16(status).expect("custom status")
    );
    let body = to_bytes(response.into_body()).await.expect("body");
    assert_eq!(body.as_ref(), b"reverse streaming matched");
}

fn grpc_test_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[tokio::test]
async fn response_rule_can_bypass_cache_without_replacing_response() {
    let router = build_router(vec![HttpResponseRuleConfig {
        name: "resp-cache-bypass".to_string(),
        r#match: Some(MatchConfig {
            response_status: vec!["200".to_string()],
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig {
            cache: Some(HttpResponseCacheEffectsConfig { bypass: true }),
            ..Default::default()
        },
    }]);
    let route = router.route_at(0).expect("route");
    let conn = ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999), 80);
    let identity = crate::policy_context::ResolvedIdentity::default();
    let destination = DestinationMetadata::default();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_LENGTH, "12")
        .body(Body::empty())
        .unwrap();
    let request_rpc = crate::http::rpc::RpcMatchContext::default();
    let base = make_base_request_fields("GET", "cache.example", "/asset", None);

    let decision = apply_response_rules(ResponseRuleInput {
        route,
        base: &base,
        conn: &conn,
        destination: &destination,
        upstream_cert: None,
        request_rpc: Some(&request_rpc),
        identity: &identity,
        route_headers: None,
        response,
        max_observed_response_body_bytes: usize::MAX,
        response_body_read_timeout: std::time::Duration::from_secs(1),
    })
    .await
    .expect("apply");

    match decision {
        ResponseRuleDecision::Continue {
            response,
            route_headers,
            cache_bypass,
            ..
        } => {
            assert_eq!(response.status(), StatusCode::OK);
            assert!(route_headers.is_none());
            assert!(cache_bypass);
        }
        ResponseRuleDecision::LocalResponse { .. } => panic!("expected continued response"),
    }
}

#[tokio::test]
async fn response_rule_matches_actual_chunked_response_size() {
    let router = build_router(vec![HttpResponseRuleConfig {
        name: "resp-sized".to_string(),
        r#match: Some(MatchConfig {
            response_size: vec!["12".to_string()],
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig {
            local_response: Some(LocalResponseConfig {
                status: 418,
                body: "sized".to_string(),
                content_type: Some("text/plain".to_string()),
                headers: HashMap::new(),
                rpc: None,
            }),
            ..Default::default()
        },
    }]);
    let route = router.route_at(0).expect("route");
    let conn = ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999), 80);
    let identity = crate::policy_context::ResolvedIdentity::default();
    let destination = DestinationMetadata::default();
    let (mut sender, body) = Body::channel();
    tokio::spawn(async move {
        sender
            .send_data(bytes::Bytes::from_static(b"hello "))
            .await
            .expect("send first chunk");
        sender
            .send_data(bytes::Bytes::from_static(b"world!"))
            .await
            .expect("send second chunk");
    });
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(body)
        .unwrap();
    let request_rpc = crate::http::rpc::RpcMatchContext::default();
    let base = make_base_request_fields("GET", "chunked.example", "/asset", None);

    let decision = apply_response_rules(ResponseRuleInput {
        route,
        base: &base,
        conn: &conn,
        destination: &destination,
        upstream_cert: None,
        request_rpc: Some(&request_rpc),
        identity: &identity,
        route_headers: None,
        response,
        max_observed_response_body_bytes: usize::MAX,
        response_body_read_timeout: std::time::Duration::from_secs(1),
    })
    .await
    .expect("apply");

    match decision {
        ResponseRuleDecision::LocalResponse { response, .. } => {
            assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        }
        ResponseRuleDecision::Continue { .. } => panic!("expected local response"),
    }
}

#[tokio::test]
async fn response_rule_matches_destination_and_upstream_cert_context() {
    let router = build_router(vec![HttpResponseRuleConfig {
        name: "resp-destination-cert".to_string(),
        r#match: Some(MatchConfig {
            destination: Some(DestinationMatchConfig {
                category: Some(DestinationDimensionMatchConfig {
                    value: vec!["corp".to_string()],
                    source: Vec::new(),
                    confidence: Vec::new(),
                }),
                reputation: None,
                application: None,
            }),
            upstream_cert: Some(CertificateMatchConfig {
                issuer: vec!["Corp Issuer".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig {
            local_response: Some(LocalResponseConfig {
                status: 451,
                body: "policy".to_string(),
                content_type: Some("text/plain".to_string()),
                headers: HashMap::new(),
                rpc: None,
            }),
            ..Default::default()
        },
    }]);
    let route = router.route_at(0).expect("route");
    let conn = ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999), 443);
    let identity = crate::policy_context::ResolvedIdentity::default();
    let destination = DestinationMetadata {
        category: Some("corp".to_string()),
        ..Default::default()
    };
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap();

    let upstream_cert = UpstreamCertificateInfo {
        present: true,
        issuer: Some("Corp Issuer".to_string()),
        ..Default::default()
    };
    let request_rpc = crate::http::rpc::RpcMatchContext::default();
    let base = make_base_request_fields("GET", "app.internal.example.com", "/", None);
    let decision = apply_response_rules(ResponseRuleInput {
        route,
        base: &base,
        conn: &conn,
        destination: &destination,
        upstream_cert: Some(&upstream_cert),
        request_rpc: Some(&request_rpc),
        identity: &identity,
        route_headers: None,
        response,
        max_observed_response_body_bytes: usize::MAX,
        response_body_read_timeout: std::time::Duration::from_secs(1),
    })
    .await
    .expect("apply");

    match decision {
        ResponseRuleDecision::LocalResponse { response, .. } => {
            assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        }
        ResponseRuleDecision::Continue { .. } => panic!("expected local response"),
    }
}

#[tokio::test]
async fn response_rule_matches_client_cert_context() {
    let router = build_router(vec![HttpResponseRuleConfig {
        name: "resp-client-cert".to_string(),
        r#match: Some(MatchConfig {
            client_cert: Some(CertificateMatchConfig {
                present: Some(true),
                san_dns: vec!["example.com".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig {
            local_response: Some(LocalResponseConfig {
                status: 451,
                body: "client-cert-policy".to_string(),
                content_type: Some("text/plain".to_string()),
                headers: HashMap::new(),
                rpc: None,
            }),
            ..Default::default()
        },
    }]);
    let route = router.route_at(0).expect("route");
    let certified =
        generate_simple_self_signed(vec!["example.com".to_string()]).expect("self-signed cert");
    let conn = ReverseConnInfo::terminated(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999),
        443,
        Some(StdArc::<str>::from("example.com")),
        Some(StdArc::new(vec![certified.cert.der().as_ref().to_vec()])),
    );
    let identity = crate::policy_context::ResolvedIdentity::default();
    let destination = DestinationMetadata::default();
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap();
    let request_rpc = crate::http::rpc::RpcMatchContext::default();
    let base = make_base_request_fields("GET", "example.com", "/", None);

    let decision = apply_response_rules(ResponseRuleInput {
        route,
        base: &base,
        conn: &conn,
        destination: &destination,
        upstream_cert: None,
        request_rpc: Some(&request_rpc),
        identity: &identity,
        route_headers: None,
        response,
        max_observed_response_body_bytes: usize::MAX,
        response_body_read_timeout: std::time::Duration::from_secs(1),
    })
    .await
    .expect("apply");

    match decision {
        ResponseRuleDecision::LocalResponse { response, .. } => {
            assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        }
        ResponseRuleDecision::Continue { .. } => panic!("expected local response"),
    }
}

#[tokio::test]
async fn route_match_uses_actual_chunked_request_size() {
    let reverse_cfg = ReverseConfig {
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
        routes: vec![
            ReverseRouteConfig {
                name: Some("sized".to_string()),
                r#match: MatchConfig {
                    request_size: vec!["4".to_string()],
                    ..Default::default()
                },
                upstreams: vec!["upstream".to_string()],
                backends: Vec::new(),
                mirrors: Vec::new(),
                local_response: Some(LocalResponseConfig {
                    status: 204,
                    body: String::new(),
                    content_type: None,
                    headers: HashMap::new(),
                    rpc: None,
                }),
                headers: None,
                lb: "round_robin".to_string(),
                timeout_ms: None,
                health_check: None,
                cache: None,
                rate_limit: None,
                path_rewrite: None,
                upstream_trust_profile: None,
                upstream_trust: None,
                lifecycle: None,
                ipc: None,
                affinity: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
            },
            ReverseRouteConfig {
                name: Some("fallback".to_string()),
                r#match: MatchConfig::default(),
                upstreams: vec!["upstream".to_string()],
                backends: Vec::new(),
                mirrors: Vec::new(),
                local_response: Some(LocalResponseConfig {
                    status: 409,
                    body: "fallback".to_string(),
                    content_type: Some("text/plain".to_string()),
                    headers: HashMap::new(),
                    rpc: None,
                }),
                headers: None,
                lb: "round_robin".to_string(),
                timeout_ms: None,
                health_check: None,
                cache: None,
                rate_limit: None,
                path_rewrite: None,
                upstream_trust_profile: None,
                upstream_trust: None,
                lifecycle: None,
                ipc: None,
                affinity: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
            },
        ],
        tls_passthrough_routes: Vec::new(),
    };
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        system_log: SystemLogConfig::default(),
        access_log: AccessLogConfig::default(),
        audit_log: AuditLogConfig::default(),
        metrics: None,
        otel: None,
        acme: None,
        exporter: None,
        auth: AuthConfig::default(),
        identity_sources: Vec::new(),
        ext_authz: Vec::new(),
        destination_resolution: Default::default(),
        listeners: Vec::new(),
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: vec![reverse_cfg.clone()],
        upstreams: vec![UpstreamConfig {
            name: "upstream".to_string(),
            url: "http://127.0.0.1:8080".to_string(),
            tls_trust_profile: None,
            tls_trust: None,
            discovery: None,
            resilience: None,
        }],
        cache: CacheConfig::default(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = super::super::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_upstreams_unhealthy"),
    )
    .expect("reloadable reverse");
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
    let request = Request::builder()
        .method(Method::POST)
        .uri("/upload")
        .header("host", "reverse.test")
        .version(http::Version::HTTP_11)
        .body(body)
        .expect("request");

    let (_, response) = handle_request_with_interim(
        request,
        reverse,
        ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 80),
    )
    .await
    .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn route_match_uses_destination_category() {
    let reverse_cfg = ReverseConfig {
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
        routes: vec![
            ReverseRouteConfig {
                name: Some("ai".to_string()),
                r#match: MatchConfig {
                    destination: Some(DestinationMatchConfig {
                        category: Some(DestinationDimensionMatchConfig {
                            value: vec!["ai".to_string()],
                            source: Vec::new(),
                            confidence: Vec::new(),
                        }),
                        reputation: None,
                        application: None,
                    }),
                    ..Default::default()
                },
                upstreams: Vec::new(),
                backends: Vec::new(),
                mirrors: Vec::new(),
                local_response: Some(LocalResponseConfig {
                    status: 204,
                    body: String::new(),
                    content_type: None,
                    headers: HashMap::new(),
                    rpc: None,
                }),
                headers: None,
                lb: "round_robin".to_string(),
                timeout_ms: None,
                health_check: None,
                cache: None,
                rate_limit: None,
                path_rewrite: None,
                upstream_trust_profile: None,
                upstream_trust: None,
                lifecycle: None,
                ipc: None,
                affinity: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
            },
            ReverseRouteConfig {
                name: Some("fallback".to_string()),
                r#match: MatchConfig::default(),
                upstreams: Vec::new(),
                backends: Vec::new(),
                mirrors: Vec::new(),
                local_response: Some(LocalResponseConfig {
                    status: 409,
                    body: "fallback".to_string(),
                    content_type: Some("text/plain".to_string()),
                    headers: HashMap::new(),
                    rpc: None,
                }),
                headers: None,
                lb: "round_robin".to_string(),
                timeout_ms: None,
                health_check: None,
                rate_limit: None,
                cache: None,
                path_rewrite: None,
                upstream_trust_profile: None,
                upstream_trust: None,
                lifecycle: None,
                ipc: None,
                affinity: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
            },
        ],
        tls_passthrough_routes: Vec::new(),
    };
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        system_log: SystemLogConfig::default(),
        access_log: AccessLogConfig::default(),
        audit_log: AuditLogConfig::default(),
        metrics: None,
        otel: None,
        acme: None,
        exporter: None,
        auth: AuthConfig::default(),
        identity_sources: Vec::new(),
        ext_authz: Vec::new(),
        destination_resolution: Default::default(),
        listeners: Vec::new(),
        named_sets: vec![NamedSetConfig {
            name: "category:ai".to_string(),
            kind: NamedSetKind::Domain,
            values: vec!["*.openai.com".to_string()],
            file: None,
        }],
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: vec![reverse_cfg.clone()],
        upstreams: Vec::new(),
        cache: CacheConfig::default(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = super::super::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_destination_category"),
    )
    .expect("reloadable reverse");
    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("host", "api.openai.com")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let (_, response) = handle_request_with_interim(
        request,
        reverse,
        ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 443),
    )
    .await
    .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn reverse_ext_authz_rate_limit_profile_is_enforced() {
    let authz_addr = spawn_ext_authz_server(
        r#"{"decision":"allow","rate_limit_profile":"reverse-profile"}"#.to_string(),
        2,
    )
    .await;
    let reverse_cfg = ReverseConfig {
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
        routes: vec![ReverseRouteConfig {
            name: Some("route".to_string()),
            r#match: MatchConfig::default(),
            upstreams: Vec::new(),
            backends: Vec::new(),
            mirrors: Vec::new(),
            local_response: Some(LocalResponseConfig {
                status: 204,
                body: String::new(),
                content_type: None,
                headers: HashMap::new(),
                rpc: None,
            }),
            headers: None,
            lb: "round_robin".to_string(),
            timeout_ms: None,
            health_check: None,
            cache: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            ipc: None,
            affinity: None,
            policy_context: Some(PolicyContextConfig {
                identity_sources: Vec::new(),
                ext_authz: Some("authz".to_string()),
            }),
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: Vec::new(),
        }],
        tls_passthrough_routes: Vec::new(),
    };
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        system_log: SystemLogConfig::default(),
        access_log: AccessLogConfig::default(),
        audit_log: AuditLogConfig::default(),
        metrics: None,
        otel: None,
        acme: None,
        exporter: None,
        auth: AuthConfig::default(),
        identity_sources: Vec::new(),
        ext_authz: vec![ExtAuthzConfig {
            name: "authz".to_string(),
            kind: Default::default(),
            endpoint: format!("http://{}", authz_addr),
            timeout_ms: 1_000,
            max_response_bytes: 1024 * 1024,
            send: ExtAuthzSendConfig::default(),
            on_error: Default::default(),
        }],
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: vec![RateLimitProfileConfig {
            name: "reverse-profile".to_string(),
            limit: RateLimitConfig {
                enabled: true,
                apply_to: vec![qpx_core::config::RateLimitApplyTo::Request],
                key: "global".to_string(),
                requests: Some(qpx_core::config::RateLimitRequestsConfig {
                    rps: Some(1),
                    burst: Some(1),
                    quota: None,
                }),
                traffic: None,
                sessions: None,
            },
        }],
        upstream_trust_profiles: Vec::new(),
        destination_resolution: Default::default(),
        listeners: Vec::new(),
        reverse: vec![reverse_cfg.clone()],
        upstreams: Vec::new(),
        cache: CacheConfig::default(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = super::super::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_upstreams_unhealthy"),
    )
    .expect("reloadable reverse");

    let request = || {
        Request::builder()
            .method(Method::GET)
            .uri("/asset")
            .header("host", "reverse.test")
            .version(http::Version::HTTP_11)
            .body(Body::empty())
            .expect("request")
    };
    let conn = ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 80);

    let (_, first) = handle_request_with_interim(request(), reverse.clone(), conn.clone())
        .await
        .expect("first response");
    assert_eq!(first.status(), StatusCode::NO_CONTENT);

    let (_, second) = handle_request_with_interim(request(), reverse, conn)
        .await
        .expect("second response");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn handle_request_with_interim_returns_early_hints_for_h3_downstream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let upstream_addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.expect("read request");
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(
                b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            )
            .await
            .expect("write response");
    });

    let reverse_cfg = ReverseConfig {
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
        routes: vec![ReverseRouteConfig {
            name: Some("route".to_string()),
            r#match: MatchConfig::default(),
            upstreams: vec!["upstream".to_string()],
            backends: Vec::new(),
            mirrors: Vec::new(),
            local_response: None,
            headers: None,
            lb: "round_robin".to_string(),
            timeout_ms: None,
            health_check: None,
            cache: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            ipc: None,
            affinity: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: Vec::new(),
        }],
        tls_passthrough_routes: Vec::new(),
    };
    let upstream_cfg = UpstreamConfig {
        name: "upstream".to_string(),
        url: format!("http://{}", upstream_addr),
        tls_trust_profile: None,
        tls_trust: None,
        discovery: None,
        resilience: None,
    };
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        system_log: SystemLogConfig::default(),
        access_log: AccessLogConfig::default(),
        audit_log: AuditLogConfig::default(),
        metrics: None,
        otel: None,
        acme: None,
        exporter: None,
        auth: AuthConfig::default(),
        identity_sources: Vec::new(),
        ext_authz: Vec::new(),
        destination_resolution: Default::default(),
        listeners: Vec::new(),
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: vec![reverse_cfg.clone()],
        upstreams: vec![upstream_cfg],
        cache: CacheConfig::default(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = super::super::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_upstreams_unhealthy"),
    )
    .expect("reloadable reverse");
    let request = Request::builder()
        .method(Method::GET)
        .uri("/asset")
        .header("host", "reverse.test")
        .version(http::Version::HTTP_3)
        .body(Body::empty())
        .expect("request");

    let (interim, response) = handle_request_with_interim(
        request,
        reverse,
        ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 443),
    )
    .await
    .expect("response");

    assert_eq!(interim.len(), 1);
    assert_eq!(interim[0].status, StatusCode::from_u16(103).unwrap());
    assert_eq!(
        interim[0]
            .headers
            .get("link")
            .and_then(|value| value.to_str().ok()),
        Some("</style.css>; rel=preload; as=style")
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body()).await.expect("body bytes"),
        bytes::Bytes::from_static(b"OK")
    );
}

#[tokio::test]
async fn reverse_route_http_module_compresses_responses() {
    let upstream_addr = spawn_static_http_server(
        "200 OK",
        vec![("Content-Type", "text/plain".to_string())],
        "reverse compression".to_string(),
        1,
    )
    .await;
    let reverse_cfg = ReverseConfig {
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
        routes: vec![ReverseRouteConfig {
            name: Some("route".to_string()),
            r#match: MatchConfig::default(),
            upstreams: vec!["upstream".to_string()],
            backends: Vec::new(),
            mirrors: Vec::new(),
            local_response: None,
            headers: None,
            lb: "round_robin".to_string(),
            timeout_ms: None,
            health_check: None,
            cache: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            ipc: None,
            affinity: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: vec![serde_yaml::from_str(
                r#"type: response_compression
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
            .expect("http module config")],
        }],
        tls_passthrough_routes: Vec::new(),
    };
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        system_log: SystemLogConfig::default(),
        access_log: AccessLogConfig::default(),
        audit_log: AuditLogConfig::default(),
        metrics: None,
        otel: None,
        acme: None,
        exporter: None,
        auth: AuthConfig::default(),
        identity_sources: Vec::new(),
        ext_authz: Vec::new(),
        destination_resolution: Default::default(),
        listeners: Vec::new(),
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: vec![reverse_cfg.clone()],
        upstreams: vec![UpstreamConfig {
            name: "upstream".to_string(),
            url: format!("http://{upstream_addr}"),
            tls_trust_profile: None,
            tls_trust: None,
            discovery: None,
            resilience: None,
        }],
        cache: CacheConfig::default(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = super::super::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_http_modules_compression"),
    )
    .expect("reloadable reverse");
    let request = Request::builder()
        .method(Method::GET)
        .uri("/asset")
        .header("host", "reverse.test")
        .header("accept-encoding", "gzip")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

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
    let reverse_cfg = ReverseConfig {
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
        routes: vec![ReverseRouteConfig {
            name: Some("route".to_string()),
            r#match: MatchConfig::default(),
            upstreams: vec!["upstream".to_string()],
            backends: Vec::new(),
            mirrors: Vec::new(),
            local_response: None,
            headers: None,
            lb: "round_robin".to_string(),
            timeout_ms: None,
            health_check: None,
            cache: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            ipc: None,
            affinity: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: vec![serde_yaml::from_str(&format!(
                r#"type: subrequest
name: header-inject
phase: response_headers
url: http://{subrequest_addr}/headers
timeout_ms: 1000
copy_response_headers_to_response:
  - from: x-decision
    to: x-module-decision"#
            ))
            .expect("http module config")],
        }],
        tls_passthrough_routes: Vec::new(),
    };
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        system_log: SystemLogConfig::default(),
        access_log: AccessLogConfig::default(),
        audit_log: AuditLogConfig::default(),
        metrics: None,
        otel: None,
        acme: None,
        exporter: None,
        auth: AuthConfig::default(),
        identity_sources: Vec::new(),
        ext_authz: Vec::new(),
        destination_resolution: Default::default(),
        listeners: Vec::new(),
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: vec![reverse_cfg.clone()],
        upstreams: vec![UpstreamConfig {
            name: "upstream".to_string(),
            url: format!("http://{upstream_addr}"),
            tls_trust_profile: None,
            tls_trust: None,
            discovery: None,
            resilience: None,
        }],
        cache: CacheConfig::default(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = super::super::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_http_modules_subrequest"),
    )
    .expect("reloadable reverse");
    let request = Request::builder()
        .method(Method::GET)
        .uri("/asset")
        .header("host", "reverse.test")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

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
async fn handle_request_with_interim_returns_early_hints_for_h2_downstream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let upstream_addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.expect("read request");
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(
                b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            )
            .await
            .expect("write response");
    });

    let reverse_cfg = ReverseConfig {
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
        routes: vec![ReverseRouteConfig {
            name: Some("route".to_string()),
            r#match: MatchConfig::default(),
            upstreams: vec!["upstream".to_string()],
            backends: Vec::new(),
            mirrors: Vec::new(),
            local_response: None,
            headers: None,
            lb: "round_robin".to_string(),
            timeout_ms: None,
            health_check: None,
            cache: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            ipc: None,
            affinity: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: Vec::new(),
        }],
        tls_passthrough_routes: Vec::new(),
    };
    let upstream_cfg = UpstreamConfig {
        name: "upstream".to_string(),
        url: format!("http://{}", upstream_addr),
        tls_trust_profile: None,
        tls_trust: None,
        discovery: None,
        resilience: None,
    };
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        system_log: SystemLogConfig::default(),
        access_log: AccessLogConfig::default(),
        audit_log: AuditLogConfig::default(),
        metrics: None,
        otel: None,
        acme: None,
        exporter: None,
        auth: AuthConfig::default(),
        identity_sources: Vec::new(),
        ext_authz: Vec::new(),
        destination_resolution: Default::default(),
        listeners: Vec::new(),
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: vec![reverse_cfg.clone()],
        upstreams: vec![upstream_cfg],
        cache: CacheConfig::default(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = super::super::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_upstreams_unhealthy"),
    )
    .expect("reloadable reverse");
    let request = Request::builder()
        .method(Method::GET)
        .uri("/asset")
        .header("host", "reverse.test")
        .version(http::Version::HTTP_2)
        .body(Body::empty())
        .expect("request");

    let (interim, response) = handle_request_with_interim(
        request,
        reverse,
        ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 443),
    )
    .await
    .expect("response");

    assert_eq!(interim.len(), 1);
    assert_eq!(interim[0].status, StatusCode::from_u16(103).unwrap());
    assert_eq!(
        interim[0]
            .headers
            .get("link")
            .and_then(|value| value.to_str().ok()),
        Some("</style.css>; rel=preload; as=style")
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body()).await.expect("body bytes"),
        bytes::Bytes::from_static(b"OK")
    );
}

#[tokio::test]
async fn handle_request_with_interim_returns_early_hints_for_h1_downstream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let upstream_addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.expect("read request");
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(
                b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            )
            .await
            .expect("write response");
    });

    let reverse_cfg = ReverseConfig {
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
        routes: vec![ReverseRouteConfig {
            name: Some("route".to_string()),
            r#match: MatchConfig::default(),
            upstreams: vec!["upstream".to_string()],
            backends: Vec::new(),
            mirrors: Vec::new(),
            local_response: None,
            headers: None,
            lb: "round_robin".to_string(),
            timeout_ms: None,
            health_check: None,
            cache: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            ipc: None,
            affinity: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: Vec::new(),
        }],
        tls_passthrough_routes: Vec::new(),
    };
    let upstream_cfg = UpstreamConfig {
        name: "upstream".to_string(),
        url: format!("http://{}", upstream_addr),
        tls_trust_profile: None,
        tls_trust: None,
        discovery: None,
        resilience: None,
    };
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        system_log: SystemLogConfig::default(),
        access_log: AccessLogConfig::default(),
        audit_log: AuditLogConfig::default(),
        metrics: None,
        otel: None,
        acme: None,
        exporter: None,
        auth: AuthConfig::default(),
        identity_sources: Vec::new(),
        ext_authz: Vec::new(),
        destination_resolution: Default::default(),
        listeners: Vec::new(),
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: vec![reverse_cfg.clone()],
        upstreams: vec![upstream_cfg],
        cache: CacheConfig::default(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = super::super::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_upstreams_unhealthy"),
    )
    .expect("reloadable reverse");
    let request = Request::builder()
        .method(Method::GET)
        .uri("/asset")
        .header("host", "reverse.test")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let (interim, response) = handle_request_with_interim(
        request,
        reverse,
        ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 80),
    )
    .await
    .expect("response");

    assert_eq!(interim.len(), 1);
    assert_eq!(interim[0].status, StatusCode::from_u16(103).unwrap());
    assert_eq!(
        interim[0]
            .headers
            .get("link")
            .and_then(|value| value.to_str().ok()),
        Some("</style.css>; rel=preload; as=style")
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body()).await.expect("body bytes"),
        bytes::Bytes::from_static(b"OK")
    );
}
