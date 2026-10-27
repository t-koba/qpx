use super::extended::prepare_h2_upstream_connect_request;
use super::*;
use crate::tls::TlsClientHelloInfo;
use http::Uri;
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CertificateMatchConfig,
    Config, IdentityConfig, IngressEdgeConfig, IngressEdgeMode, MatchConfig, MessagesConfig,
    RuleConfig, RuntimeConfig, SystemLogConfig, TlsFingerprintMatchConfig,
};
use qpx_core::http_message::Headers;
use qpx_core::tls::UpstreamCertificateInfo;

fn connect_config() -> Config {
    Config {
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
                kind: ActionKind::Tunnel,
                upstream: None,
                local_response: None,
            },
            original_dst: None,
            tls_inspection: None,
            rules: if cfg!(feature = "mitm") {
                vec![RuleConfig {
                    name: "inspect-ja4".to_string(),
                    r#match: Some(MatchConfig {
                        tls_fingerprint: Some(TlsFingerprintMatchConfig {
                            ja3: Vec::new(),
                            ja4: vec!["t13dh2_03_05_02".to_string()],
                        }),
                        ..Default::default()
                    }),
                    auth: None,
                    action: Some(ActionConfig {
                        kind: ActionKind::Inspect,
                        upstream: None,
                        local_response: None,
                    }),
                    headers: None,
                    rate_limit: None,
                }]
            } else {
                Vec::new()
            },
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
            http_modules: Vec::new(),
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    }
}

fn connect_runtime() -> Runtime {
    Runtime::new(connect_config()).expect("runtime")
}

#[test]
fn connect_tls_fingerprint_requirement_uses_the_compiled_forward_plan() {
    let runtime = connect_runtime();
    assert_eq!(
        super::tunnel::connect_tls_fingerprints_required(&runtime, "forward"),
        cfg!(feature = "mitm"),
    );
    assert!(!super::tunnel::connect_tls_fingerprints_required(
        &runtime, "missing"
    ));
}

#[cfg(feature = "mitm")]
#[tokio::test]
async fn connect_client_hello_policy_can_upgrade_tunnel_to_inspect() {
    let runtime = connect_runtime();
    let sanitized_headers = Headers::new();
    let identity = crate::policy_context::ResolvedIdentity::default();
    let client_hello = TlsClientHelloInfo {
        sni: Some("example.com".to_string()),
        alpn: Some("h2".to_string()),
        tls_version: Some("tls1.3".to_string()),
        ja3: Some("771,4865-4866-4867,0-10-16-43-45,29-23,0".to_string()),
        ja4: Some("t13dh2_03_05_02".to_string()),
    };
    let action = decide_connect_action_from_client_hello(ConnectPolicyInput {
        runtime: &runtime,
        listener_name: "forward",
        remote_addr: SocketAddr::from(([127, 0, 0, 1], 12345)),
        host: "example.com",
        port: 443,
        authority: "example.com:443",
        request_version: http::Version::HTTP_11,
        sanitized_headers: &sanitized_headers,
        identity: &identity,
        client_hello: &client_hello,
        upstream_cert: None,
    })
    .await
    .expect("action");
    assert!(matches!(action.kind, ActionKind::Inspect));
}

#[tokio::test]
async fn connect_client_hello_policy_uses_protocol_cookie_view() {
    use http::{HeaderValue, Version, header::COOKIE};
    use qpx_core::config::HeaderMatch;
    use qpx_core::http_message::OrdinaryHeaderName;

    let cookie_rule = |name: &str, value: &str, kind| RuleConfig {
        name: name.into(),
        r#match: Some(MatchConfig {
            headers: vec![HeaderMatch {
                name: "cookie".into(),
                value: Some(value.into()),
                regex: None,
            }],
            ..Default::default()
        }),
        auth: None,
        action: Some(ActionConfig {
            kind,
            upstream: None,
            local_response: None,
        }),
        headers: None,
        rate_limit: None,
    };
    let mut config = connect_config();
    let qpx_core::config::EdgeConfig::Forward(edge) = &mut config.edges[0] else {
        panic!("forward edge");
    };
    // Put the fragment first so an incorrect per-field H3 match wins instead.
    edge.rules = vec![
        cookie_rule("fragment", "a=1", ActionKind::Block),
        cookie_rule("joined", "a=1; b=2", ActionKind::Direct),
    ];
    let runtime = Runtime::new(config).expect("runtime");
    let name = OrdinaryHeaderName::try_from(COOKIE).unwrap();
    let mut headers = Headers::new();
    let mut first = HeaderValue::from_static("a=1");
    first.set_sensitive(true);
    headers.append(name.clone(), first);
    headers.append(name.clone(), HeaderValue::from_static("b=2"));
    let before = headers.clone();
    let identity = crate::policy_context::ResolvedIdentity::default();
    let client_hello = TlsClientHelloInfo {
        sni: Some("example.com".into()),
        alpn: Some("h2".into()),
        tls_version: Some("tls1.3".into()),
        ja3: None,
        ja4: None,
    };
    for (version, expected) in [
        (Version::HTTP_3, ActionKind::Direct),
        (Version::HTTP_11, ActionKind::Block),
    ] {
        let action = decide_connect_action_from_client_hello(ConnectPolicyInput {
            runtime: &runtime,
            listener_name: "forward",
            remote_addr: SocketAddr::from(([127, 0, 0, 1], 12345)),
            host: "example.com",
            port: 443,
            authority: "example.com:443",
            request_version: version,
            sanitized_headers: &headers,
            identity: &identity,
            client_hello: &client_hello,
            upstream_cert: None,
        })
        .await
        .expect("action");
        assert_eq!(action.kind, expected, "{version:?}");
        assert_eq!(headers, before);
        assert_eq!(
            headers
                .get_all(&name)
                .map(|v| (v.as_bytes().to_vec(), v.is_sensitive()))
                .collect::<Vec<_>>(),
            vec![(b"a=1".to_vec(), true), (b"b=2".to_vec(), false)]
        );
    }
}

#[tokio::test]
async fn connect_upstream_cert_policy_can_block_after_client_hello() {
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
                kind: ActionKind::Tunnel,
                upstream: None,
                local_response: None,
            },
            original_dst: None,
            tls_inspection: None,
            rules: vec![RuleConfig {
                name: "block-present-upstream-cert".to_string(),
                r#match: Some(MatchConfig {
                    upstream_cert: Some(CertificateMatchConfig {
                        present: Some(true),
                        ..Default::default()
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
            http_modules: Vec::new(),
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime");
    let sanitized_headers = Headers::new();
    let identity = crate::policy_context::ResolvedIdentity::default();
    let client_hello = TlsClientHelloInfo {
        sni: Some("example.com".to_string()),
        alpn: Some("h2".to_string()),
        tls_version: Some("tls1.3".to_string()),
        ja3: Some("771,4865-4866-4867,0-10-16-43-45,29-23,0".to_string()),
        ja4: Some("t13dh2_03_05_02".to_string()),
    };
    let upstream_cert = UpstreamCertificateInfo {
        present: true,
        ..Default::default()
    };

    let action = decide_connect_action_from_tls_metadata(ConnectPolicyInput {
        runtime: &runtime,
        listener_name: "forward",
        remote_addr: SocketAddr::from(([127, 0, 0, 1], 12345)),
        host: "example.com",
        port: 443,
        authority: "example.com:443",
        request_version: http::Version::HTTP_11,
        sanitized_headers: &sanitized_headers,
        identity: &identity,
        client_hello: &client_hello,
        upstream_cert: Some(&upstream_cert),
    })
    .await
    .expect("action");
    assert!(matches!(action.kind, ActionKind::Block));
}

#[test]
fn prepare_h2_upstream_connect_request_strips_proxy_auth_and_adds_via() {
    use qpx_core::http_message::{Headers, OrdinaryHeaderName};

    let uri: Uri = "https://example.com:443/chat".parse().expect("uri");
    let mut headers = Headers::new();
    headers.insert(
        OrdinaryHeaderName::try_from(http::header::PROXY_AUTHORIZATION).expect("ordinary"),
        http::HeaderValue::from_static("Basic abc"),
    );
    headers.insert(
        OrdinaryHeaderName::try_from(http::header::CONNECTION).expect("ordinary"),
        http::HeaderValue::from_static("keep-alive"),
    );

    let normalized = prepare_h2_upstream_connect_request(&uri, &headers, "qpx")
        .expect("prepared CONNECT request");
    assert_eq!(normalized.method(), http::Method::CONNECT);
    assert_eq!(normalized.version(), http::Version::HTTP_2);
    let normalized = normalized.headers();
    assert!(
        normalized
            .get(
                &OrdinaryHeaderName::try_from(http::header::PROXY_AUTHORIZATION).expect("ordinary")
            )
            .is_none()
    );
    assert!(
        normalized
            .get(&OrdinaryHeaderName::try_from(http::header::CONNECTION).expect("ordinary"))
            .is_none()
    );
    assert_eq!(
        normalized
            .get(&OrdinaryHeaderName::try_from(http::header::VIA).expect("ordinary"))
            .and_then(|value| value.to_str().ok()),
        Some("2 qpx")
    );
    assert_eq!(
        normalized
            .get(&OrdinaryHeaderName::try_from(http::header::HOST).expect("ordinary"))
            .and_then(|value| value.to_str().ok()),
        Some("example.com:443")
    );
}

#[tokio::test]
async fn h2_extended_connect_upload_stalls_without_upstream_window() {
    use super::extended::spawn_h2_extended_connect_relay;
    use bytes::Bytes;
    use qpx_http::body::Body;
    use std::time::Duration;

    // Peer withholds WINDOW_UPDATE: zero stream window, and the request body
    // is never read, so no window is ever granted back.
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let mut server_builder = h2::server::Builder::new();
    server_builder.initial_window_size(0);
    // Drive the server connection for the whole test; forward the first
    // accepted stream. The handshake must run concurrently with the client's.
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let mut server_conn = server_builder
            .handshake::<_, Bytes>(server_io)
            .await
            .expect("server handshake");
        let mut accepted_tx = Some(accepted_tx);
        while let Some(accepted) = server_conn.accept().await {
            let stream = accepted.expect("stream");
            if let Some(tx) = accepted_tx.take() {
                let _ = tx.send(stream);
            }
        }
    });
    let (mut send_req, client_conn) = h2::client::handshake(client_io)
        .await
        .expect("client handshake");
    tokio::spawn(async move {
        let _ = client_conn.await;
    });

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://example.test/upload")
        .body(())
        .expect("request");
    let (response_future, upstream_send) =
        send_req.send_request(request, false).expect("send request");
    let (req, mut respond) = accepted_rx.await.expect("accepted");
    assert_eq!(req.method(), http::Method::POST);
    let mut req_body = req.into_body();
    let mut peer_send = respond
        .send_response(http::Response::new(()), false)
        .expect("respond");
    // Download direction stays live while the upload is stalled. The request
    // body is never read, so no WINDOW_UPDATE is ever granted back.
    peer_send
        .send_data(Bytes::from(vec![7u8; 1024]), false)
        .expect("peer download");

    let response = response_future.await.expect("response headers");
    assert_eq!(response.status(), http::StatusCode::OK);
    let upstream_body = response.into_body();

    let (mut downstream_tx, downstream_body) = Body::channel_with_capacity(1);
    let mut out_body = spawn_h2_extended_connect_relay(
        downstream_body,
        None,
        upstream_send,
        upstream_body,
        Duration::from_millis(300),
    );

    let chunk = || Bytes::from(vec![0xABu8; 16384]);
    // The relay must consume these promptly; generous bounds fail loudly
    // instead of hanging the suite.
    tokio::time::timeout(Duration::from_secs(5), downstream_tx.send_data(chunk()))
        .await
        .expect("chunk 1 accepted")
        .expect("chunk 1 sent");
    tokio::time::timeout(Duration::from_secs(5), downstream_tx.send_data(chunk()))
        .await
        .expect("chunk 2 accepted")
        .expect("chunk 2 sent");
    // The relay parks at most one chunk and stops reading downstream, so the
    // third send must stall instead of queueing unboundedly inside h2.
    let stalled =
        tokio::time::timeout(Duration::from_millis(200), downstream_tx.send_data(chunk())).await;
    assert!(
        stalled.is_err(),
        "producer must stall without upstream window"
    );

    // Reverse traffic still progresses while the upload waits for capacity.
    let received = tokio::time::timeout(Duration::from_secs(5), out_body.data())
        .await
        .expect("download arrives")
        .expect("body item")
        .expect("download chunk");
    assert_eq!(received.len(), 1024);

    // The idle timer tears the tunnel down: no upload progress, no download end.
    // The abort surfaces downstream as a body error, which is what resets the
    // downstream stream; hanging or a clean end would both be wrong here.
    let end = tokio::time::timeout(Duration::from_secs(5), out_body.data())
        .await
        .expect("teardown arrives");
    assert!(
        matches!(end, Some(Err(_))),
        "downstream body must abort, got {end:?}"
    );
    // The relay's idle teardown resets the upstream stream: the peer must
    // observe termination instead of hanging on unread upload bytes.
    let peer_end = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match req_body.data().await {
                None | Some(Err(_)) => break,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(
        peer_end.is_ok(),
        "peer request stream must terminate when the relay tears down"
    );
    server_task.abort();
}

#[test]
fn shared_connect_decision_service_preserves_allow_and_deny_behavior() {
    let runtime = connect_runtime();
    let state = runtime.state();
    let identity = crate::policy_context::ResolvedIdentity::default();
    let remote_ip = SocketAddr::from(([127, 0, 0, 1], 12345)).ip();
    let request_limit_ctx = RateLimitContext::from_identity(remote_ip, &identity, None, None);
    let mut request_limits = crate::rate_limit::AppliedRateLimits::default();
    let mut action = ActionConfig {
        kind: ActionKind::Tunnel,
        upstream: None,
        local_response: None,
    };

    let allow = apply_connect_decision_service(
        crate::policy_context::DecisionServiceEnforcement::Continue(
            crate::policy_context::DecisionServiceAllow {
                force_inspect: true,
                ..Default::default()
            },
        ),
        http::Version::HTTP_11,
        "qpx",
        state.messages.forbidden.as_str(),
        &state.policy.rate_limiters,
        &mut request_limits,
        &request_limit_ctx,
        &mut action,
    )
    .expect("allow result");
    assert!(matches!(
        allow,
        std::ops::ControlFlow::Continue(allow)
            if allow.headers.is_none() && allow.timeout_override.is_none()
    ));
    assert!(matches!(action.kind, ActionKind::Inspect));

    let deny = apply_connect_decision_service(
        crate::policy_context::DecisionServiceEnforcement::Deny(
            crate::policy_context::DecisionServiceDeny::default(),
        ),
        http::Version::HTTP_11,
        "qpx",
        state.messages.forbidden.as_str(),
        &state.policy.rate_limiters,
        &mut request_limits,
        &request_limit_ctx,
        &mut action,
    )
    .expect("deny result");
    match deny {
        std::ops::ControlFlow::Break((response, outcome)) => {
            assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
            assert!(matches!(
                outcome,
                crate::http::dispatch::DispatchOutcome::DecisionServiceDeny
            ));
        }
        std::ops::ControlFlow::Continue(_) => {
            panic!("deny enforcement must return a response")
        }
    }

    let deny_local = apply_connect_decision_service(
        crate::policy_context::DecisionServiceEnforcement::Deny(
            crate::policy_context::DecisionServiceDeny {
                local_response: Some(qpx_core::config::LocalResponseConfig {
                    status: 418,
                    body: String::new(),
                    content_type: None,
                    headers: std::collections::HashMap::new(),
                    rpc: None,
                }),
                ..Default::default()
            },
        ),
        http::Version::HTTP_11,
        "qpx",
        state.messages.forbidden.as_str(),
        &state.policy.rate_limiters,
        &mut request_limits,
        &request_limit_ctx,
        &mut action,
    )
    .expect("deny local result");
    match deny_local {
        std::ops::ControlFlow::Break((response, outcome)) => {
            assert_eq!(response.status().as_u16(), 418);
            assert!(matches!(
                outcome,
                crate::http::dispatch::DispatchOutcome::DecisionServiceLocalResponse
            ));
        }
        std::ops::ControlFlow::Continue(_) => {
            panic!("deny with local response must return a response")
        }
    }
}
