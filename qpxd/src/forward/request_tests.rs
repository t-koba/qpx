use super::*;
use crate::http::body::to_bytes;
use crate::runtime::Runtime;
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CacheConfig, Config,
    ExtAuthzConfig, ExtAuthzSendConfig, HttpModuleConfig, HttpPolicyConfig,
    HttpResponseEffectsConfig, HttpResponseRuleConfig, IdentityConfig, ListenerConfig,
    ListenerMode, LocalResponseConfig, MatchConfig, MessagesConfig, PolicyContextConfig,
    RpcMatchConfig, RuleConfig, RuntimeConfig, SystemLogConfig,
};
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn request_size_rule_uses_actual_chunked_body_size() {
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
        listeners: vec![ListenerConfig {
            name: "forward".to_string(),
            mode: ListenerMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            },
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
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            rate_limit: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            http_modules: Vec::new(),
        }],
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: Vec::new(),
        upstreams: Vec::new(),
        cache: CacheConfig::default(),
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
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://example.com/upload")
        .header("host", "example.com")
        .version(http::Version::HTTP_11)
        .body(body)
        .expect("request");

    let response = handle_request_inner(
        request,
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
        listeners: vec![ListenerConfig {
            name: "forward".to_string(),
            mode: ListenerMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Direct,
                upstream: None,
                local_response: None,
            },
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            rate_limit: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            http_modules: Vec::new(),
        }],
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: Vec::new(),
        upstreams: Vec::new(),
        cache: CacheConfig::default(),
    })
    .expect("runtime");

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{upstream_addr}/asset"))
        .header("host", upstream_addr.to_string())
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let mut response = handle_request_inner(
        request,
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
            .headers
            .get(http::header::LINK)
            .and_then(|value| value.to_str().ok()),
        Some("</style.css>; rel=preload; as=style")
    );
    assert_eq!(response.status(), StatusCode::OK);
}

async fn spawn_ext_authz_server(response_body: &str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind authz");
    let addr = listener.local_addr().expect("authz addr");
    let response_body = response_body.to_string();
    tokio::spawn(async move {
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
    });
    addr
}

async fn spawn_static_http_server(
    status_line: &'static str,
    headers: Vec<(&'static str, String)>,
    body: String,
    accepts: usize,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind static http server");
    let addr = listener.local_addr().expect("server addr");
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
            if let Some(header_end) = raw
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|idx| idx + 4)
            {
                let headers = String::from_utf8_lossy(&raw[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap_or(0);
                let mut received_body = raw.len().saturating_sub(header_end);
                while received_body < content_length {
                    let n = stream.read(&mut buf).await.expect("read request body");
                    if n == 0 {
                        break;
                    }
                    received_body = received_body.saturating_add(n);
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

#[tokio::test]
async fn forward_response_rule_matches_request_derived_rpc_fields() {
    let upstream_addr = spawn_static_http_server(
        "200 OK",
        vec![("Content-Type", "application/grpc".to_string())],
        String::new(),
        1,
    )
    .await;
    let runtime = Runtime::new(Config {
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
        listeners: vec![ListenerConfig {
            name: "forward".to_string(),
            mode: ListenerMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Direct,
                upstream: None,
                local_response: None,
            },
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            rate_limit: None,
            policy_context: None,
            http: Some(HttpPolicyConfig {
                response_rules: vec![HttpResponseRuleConfig {
                    name: "rpc-response".to_string(),
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
                            status: 209,
                            body: "rpc matched".to_string(),
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
            http_modules: Vec::new(),
        }],
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: Vec::new(),
        upstreams: Vec::new(),
        cache: CacheConfig::default(),
    })
    .expect("runtime");

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{upstream_addr}/demo.Echo/Say"))
        .header("host", upstream_addr.to_string())
        .header(http::header::CONTENT_TYPE, "application/grpc")
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
        response.status(),
        StatusCode::from_u16(209).expect("custom status")
    );
    let body = to_bytes(response.into_body()).await.expect("body");
    assert_eq!(body.as_ref(), b"rpc matched");
}

#[tokio::test]
async fn forward_response_rule_matches_client_streaming_rpc() {
    let mut request_body = grpc_test_frame(b"one");
    request_body.extend_from_slice(&grpc_test_frame(b"two"));
    assert_forward_response_rule_matches_streaming("client", 210, Vec::new(), request_body).await;
}

#[tokio::test]
async fn forward_response_rule_matches_bidi_streaming_rpc() {
    let mut request_body = grpc_test_frame(b"one");
    request_body.extend_from_slice(&grpc_test_frame(b"two"));
    let mut response_body = grpc_test_frame(b"alpha");
    response_body.extend_from_slice(&grpc_test_frame(b"beta"));
    assert_forward_response_rule_matches_streaming("bidi", 211, response_body, request_body).await;
}

async fn assert_forward_response_rule_matches_streaming(
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
    let runtime = Runtime::new(Config {
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
        listeners: vec![ListenerConfig {
            name: "forward".to_string(),
            mode: ListenerMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Direct,
                upstream: None,
                local_response: None,
            },
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            rate_limit: None,
            policy_context: None,
            http: Some(HttpPolicyConfig {
                response_rules: vec![HttpResponseRuleConfig {
                    name: "rpc-client-streaming".to_string(),
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
                            body: "streaming matched".to_string(),
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
            http_modules: Vec::new(),
        }],
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: Vec::new(),
        upstreams: Vec::new(),
        cache: CacheConfig::default(),
    })
    .expect("runtime");

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{upstream_addr}/demo.Echo/Say"))
        .header("host", upstream_addr.to_string())
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::CONTENT_LENGTH, request_body.len().to_string())
        .version(http::Version::HTTP_11)
        .body(Body::from(request_body))
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
        response.status(),
        StatusCode::from_u16(status).expect("custom status")
    );
    let body = to_bytes(response.into_body()).await.expect("body");
    assert_eq!(body.as_ref(), b"streaming matched");
}

fn grpc_test_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn decode_gzip(bytes: &[u8]) -> String {
    let mut decoder = flate2::read::GzDecoder::new(bytes);
    let mut out = String::new();
    decoder.read_to_string(&mut out).expect("decode gzip");
    out
}

#[tokio::test]
async fn ext_authz_unknown_rate_limit_profile_fails_closed() {
    let authz_addr =
        spawn_ext_authz_server(r#"{"decision":"allow","rate_limit_profile":"missing"}"#).await;
    let runtime = Runtime::new(Config {
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
            endpoint: format!("http://{authz_addr}"),
            timeout_ms: 1_000,
            max_response_bytes: 1024 * 1024,
            send: ExtAuthzSendConfig::default(),
            on_error: Default::default(),
        }],
        destination_resolution: Default::default(),
        listeners: vec![ListenerConfig {
            name: "forward".to_string(),
            mode: ListenerMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Direct,
                upstream: None,
                local_response: None,
            },
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            rate_limit: None,
            policy_context: Some(PolicyContextConfig {
                identity_sources: Vec::new(),
                ext_authz: Some("authz".to_string()),
            }),
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            http_modules: Vec::new(),
        }],
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: Vec::new(),
        upstreams: Vec::new(),
        cache: CacheConfig::default(),
    })
    .expect("runtime");
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://example.com/")
        .header("host", "example.com")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let err = handle_request_inner(
        request,
        runtime,
        "forward",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
    )
    .await
    .expect_err("unknown ext_authz profile should fail closed");
    assert!(err.to_string().contains("unknown rate limit profile"));
}

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
        listeners: vec![ListenerConfig {
            name: "forward".to_string(),
            mode: ListenerMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Direct,
                upstream: None,
                local_response: None,
            },
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            rate_limit: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
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
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: Vec::new(),
        upstreams: Vec::new(),
        cache: CacheConfig::default(),
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
        listeners: vec![ListenerConfig {
            name: "forward".to_string(),
            mode: ListenerMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Direct,
                upstream: None,
                local_response: None,
            },
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            rate_limit: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            http_modules: vec![serde_yaml::from_str(&format!(
                r#"type: subrequest
name: authz
phase: request_headers
url: http://{subrequest_addr}/check?path={{request.path}}
timeout_ms: 1000
pass_headers:
  - x-test
response_mode: return_on_error"#
            ))
            .expect("http module config")],
        }],
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: Vec::new(),
        upstreams: Vec::new(),
        cache: CacheConfig::default(),
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
    async fn on_downstream_response(
        &self,
        _ctx: &mut crate::module_api::HttpModuleContext,
        mut response: hyper::Response<crate::module_api::Body>,
    ) -> anyhow::Result<hyper::Response<crate::module_api::Body>> {
        response
            .headers_mut()
            .insert(self.header_name.clone(), self.header_value.clone());
        Ok(response)
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
            listeners: vec![ListenerConfig {
                name: "forward".to_string(),
                mode: ListenerMode::Forward,
                listen: "127.0.0.1:0".to_string(),
                default_action: ActionConfig {
                    kind: ActionKind::Direct,
                    upstream: None,
                    local_response: None,
                },
                tls_inspection: None,
                rules: Vec::new(),
                connection_filter: Vec::new(),
                upstream_proxy: None,
                http3: None,
                ftp: Default::default(),
                xdp: None,
                cache: None,
                rate_limit: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                http_modules: vec![serde_yaml::from_str(
                    r#"type: test_response_header
header_name: x-in-process-module
header_value: active"#,
                )
                .expect("http module config")],
            }],
            named_sets: Vec::new(),
            http_guard_profiles: Vec::new(),
            rate_limit_profiles: Vec::new(),
            upstream_trust_profiles: Vec::new(),
            reverse: Vec::new(),
            upstreams: Vec::new(),
            cache: CacheConfig::default(),
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
