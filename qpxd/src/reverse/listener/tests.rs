use super::*;
use crate::http::codec::interim::{
    H2_PREFACE, serve_h2_with_interim_and_capacity, sniff_h2_preface,
};
use crate::runtime::Runtime;
use crate::tls::TlsClientHelloInfo;
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config, IdentityConfig,
    MatchConfig, MessagesConfig, ReverseEdgeConfig, ReverseRouteConfig, RuleConfig, RuntimeConfig,
    SystemLogConfig, TlsFingerprintMatchConfig, UpstreamConfig,
};
use qpx_observability::access_log::{AccessLogContext, AccessLogService};
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::Duration;

fn build_reloadable_reverse(upstream_addr: SocketAddr) -> ReloadableReverse {
    build_reloadable_reverse_with_filter(upstream_addr, Vec::new())
}

fn build_reloadable_reverse_with_filter(
    upstream_addr: SocketAddr,
    connection_filter: Vec<RuleConfig>,
) -> ReloadableReverse {
    let reverse_cfg = ReverseEdgeConfig {
        name: "test".to_string(),
        listen: "127.0.0.1:0".to_string(),
        tls: None,
        http3: None,
        xdp: None,
        enforce_sni_host_match: false,
        sni_host_exceptions: Vec::new(),
        policy_context: None,
        connection_filter,
        destination_resolution: None,
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
            http_modules: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: None,
        }],
        tls_passthrough_routes: Vec::new(),
    };
    let upstream_cfg = UpstreamConfig {
        name: "upstream".to_string(),
        url: format!("http://{upstream_addr}"),
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
        edges: vec![qpx_core::config::EdgeConfig::Reverse(reverse_cfg.clone())],
        upstreams: vec![upstream_cfg],
        caches: Vec::new(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    ReloadableReverse::new(
        reverse_cfg,
        runtime,
        Arc::<str>::from("reverse_upstreams_unhealthy"),
    )
    .expect("reloadable reverse")
}

#[tokio::test]
async fn reverse_connection_filter_blocks_accept_stage_before_upstream() {
    let _upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = _upstream_listener.local_addr().expect("upstream addr");
    let reverse = build_reloadable_reverse_with_filter(
        upstream_addr,
        vec![RuleConfig {
            name: "block-local".to_string(),
            r#match: Some(MatchConfig::default()),
            auth: None,
            action: Some(ActionConfig {
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            }),
            headers: None,
            rate_limit: None,
        }],
    );
    let reverse_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reverse");
    let reverse_addr = reverse_listener.local_addr().expect("reverse addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let acceptor = tokio::spawn(async move {
        run_reverse_http_acceptor(reverse_listener, None, reverse, shutdown_rx)
            .await
            .expect("acceptor");
    });

    let mut client = TcpStream::connect(reverse_addr)
        .await
        .expect("connect reverse");
    client
        .write_all(b"GET /asset HTTP/1.1\r\nHost: reverse.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf))
        .await
        .expect("read timeout");
    match read {
        Ok(0) => {}
        Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(n) => panic!("blocked connection returned unexpected {n} bytes"),
        Err(err) => panic!("unexpected read error: {err}"),
    }
    let _ = shutdown_tx.send(true);
    acceptor.await.expect("join");
}

#[tokio::test]
async fn reverse_connection_filter_matches_client_hello_metadata() {
    let reverse = build_reloadable_reverse_with_filter(
        SocketAddr::from(([127, 0, 0, 1], 8080)),
        vec![RuleConfig {
            name: "block-client-hello".to_string(),
            r#match: Some(MatchConfig {
                sni: vec!["blocked.example".to_string()],
                alpn: vec!["h2".to_string()],
                tls_version: vec!["tls1.3".to_string()],
                tls_fingerprint: Some(TlsFingerprintMatchConfig {
                    ja3: vec!["ja3-hash".to_string()],
                    ja4: vec!["ja4-hash".to_string()],
                }),
                ..Default::default()
            }),
            auth: None,
            action: Some(ActionConfig {
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            }),
            headers: None,
            rate_limit: None,
        }],
    );

    let matched = reverse_connection_filter_match(
        &reverse,
        SocketAddr::from(([127, 0, 0, 1], 12345)),
        443,
        Some(&TlsClientHelloInfo {
            sni: Some("blocked.example".to_string()),
            alpn: Some("h2".to_string()),
            tls_version: Some("tls1.3".to_string()),
            ja3: Some("ja3-hash".to_string()),
            ja4: Some("ja4-hash".to_string()),
        }),
    );

    assert_eq!(matched.as_deref(), Some("block-client-hello"));
}

#[tokio::test]
async fn reverse_h2_service_emits_early_hints() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = upstream_listener.accept().await.expect("accept upstream");
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
            if !raw.windows(4).any(|window| window == b"\r\n\r\n") {
                continue;
            }
            stream
                    .write_all(
                        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
                    )
                    .await
                    .expect("write response");
            tokio::time::sleep(Duration::from_millis(50)).await;
            stream.shutdown().await.expect("shutdown");
            break;
        }
    });

    let reverse = build_reloadable_reverse(upstream_addr);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reverse");
    let addr = listener.local_addr().expect("reverse addr");
    let access_cfg = reverse.runtime.state().resources.access_log.clone();
    let service = AccessLogService::new(
        ReverseInterimService {
            reverse,
            conn: ReverseConnInfo::plain(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
                80,
            ),
        },
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
        AccessLogContext {
            kind: crate::http::dispatch::ProxyKind::Reverse.as_str(),
            name: Arc::<str>::from("test"),
        },
        &access_cfg,
    );
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept reverse");
        serve_h2_with_interim_and_capacity(socket, service, false, Duration::from_secs(5), 16)
            .await
            .expect("serve h2");
    });

    let socket = TcpStream::connect(addr).await.expect("connect reverse");
    let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
    tokio::spawn(async move {
        connection.await.expect("client connection");
    });

    let mut client = client.ready().await.expect("ready");
    let request = ::http::Request::builder()
        .method("GET")
        .uri("/asset")
        .header("host", "reverse.test")
        .body(())
        .expect("request");
    let (mut response_future, _) = client.send_request(request, true).expect("send");

    let interim = poll_fn(|cx| response_future.poll_informational(cx)).await;
    let response = response_future.await;
    assert!(
        interim.is_some(),
        "missing interim: response={:?}",
        response.as_ref().map(|resp| resp.status())
    );
    let interim = interim
        .expect("informational state")
        .expect("informational ok");
    assert_eq!(interim.status(), ::http::StatusCode::EARLY_HINTS);
    assert_eq!(
        interim
            .headers()
            .get(::http::header::LINK)
            .and_then(|value| value.to_str().ok()),
        Some("</style.css>; rel=preload; as=style")
    );

    let response = response.expect("final response");
    assert_eq!(response.status(), ::http::StatusCode::OK);
    let mut body = response.into_body();
    assert_eq!(
        body.data().await.expect("body frame").expect("body bytes"),
        bytes::Bytes::from_static(b"OK")
    );

    drop(client);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn reverse_h1_listener_emits_early_hints() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = upstream_listener.accept().await.expect("accept upstream");
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
            if !raw.windows(4).any(|window| window == b"\r\n\r\n") {
                continue;
            }
            stream
                    .write_all(
                        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
                    )
                    .await
                    .expect("write response");
            tokio::time::sleep(Duration::from_millis(50)).await;
            stream.shutdown().await.expect("shutdown");
            break;
        }
    });

    let reverse = build_reloadable_reverse(upstream_addr);
    let reverse_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind reverse");
    let reverse_addr = reverse_listener.local_addr().expect("reverse addr");
    let acceptor = tokio::spawn(async move {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        run_reverse_http_acceptor(reverse_listener, None, reverse, shutdown_rx)
            .await
            .expect("acceptor");
    });

    let mut client = TcpStream::connect(reverse_addr)
        .await
        .expect("connect reverse");
    client
        .write_all(b"GET /asset HTTP/1.1\r\nHost: reverse.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    let mut raw = Vec::new();
    client.read_to_end(&mut raw).await.expect("read response");
    let text = String::from_utf8(raw).expect("utf8");
    assert!(text.contains("HTTP/1.1 103"), "response: {text}");
    assert!(text.contains("</style.css>; rel=preload; as=style"));
    assert!(text.contains("HTTP/1.1 200"));
    assert!(text.ends_with("OK"));

    acceptor.abort();
    let _ = acceptor.await;
}

#[tokio::test]
async fn sniff_h2_preface_reads_full_client_preface() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let extra = b"extra";
    tokio::spawn(async move {
        client.write_all(H2_PREFACE).await.expect("write preface");
        client.write_all(extra).await.expect("write extra");
    });

    let preface = sniff_h2_preface(&mut server, Duration::from_secs(1))
        .await
        .expect("sniff preface");
    assert_eq!(preface.as_ref(), H2_PREFACE);

    let mut rest = [0u8; 5];
    server.read_exact(&mut rest).await.expect("read rest");
    assert_eq!(&rest, extra);
}
