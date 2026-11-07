use super::extended::prepare_h2_upstream_connect_request;
use super::*;
use crate::tls::TlsClientHelloInfo;
use http::{Response, Uri};
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
    let out_body = spawn_h2_extended_connect_relay(
        downstream_body,
        None,
        upstream_send,
        upstream_body,
        Duration::from_millis(300),
    );
    let response = crate::http::protocol::l7::finalize_extended_connect_response_with_headers(
        http::Version::HTTP_2,
        "qpx",
        OwnerResponse::new(out_body),
        None,
        false,
    );
    let (_, mut out_body) = response.into_head_and_body();

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

#[tokio::test]
async fn shared_connect_decision_service_preserves_allow_and_deny_behavior() {
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
                    body: "denied".to_string(),
                    content_type: None,
                    headers: std::collections::HashMap::new(),
                    rpc: None,
                }),
                headers: Some(std::sync::Arc::new(
                    qpx_core::rules::CompiledHeaderControl::compile(
                        &serde_yaml::from_str(
                            "response_set: { x-policy: denied, connection: x-hop, x-hop: removed }",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                )),
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
            let response: OwnerResponse<Body> = response;
            assert_eq!(response.status().as_u16(), 418);
            assert_eq!(
                response
                    .headers()
                    .get(&qpx_core::http_message::OrdinaryHeaderName::try_from("x-policy").unwrap())
                    .unwrap(),
                "denied"
            );
            assert!(!response.headers().contains_key(
                &qpx_core::http_message::OrdinaryHeaderName::try_from("x-hop").unwrap()
            ));
            assert_eq!(
                qpx_http::body::to_bytes(response.into_head_and_body().1)
                    .await
                    .unwrap(),
                "denied"
            );
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

fn direct_connect_runtime() -> Runtime {
    let mut config = connect_config();
    let qpx_core::config::EdgeConfig::Forward(edge) = &mut config.edges[0] else {
        unreachable!()
    };
    edge.rules.clear();
    edge.default_action.kind = ActionKind::Direct;
    Runtime::new(config).unwrap()
}

#[tokio::test]
async fn connect_owned_finalization_preserves_control_order_headers_and_bodies() {
    use crate::http::protocol::l7::finalize_response_with_headers;
    use qpx_core::rules::CompiledHeaderControl;

    let control = CompiledHeaderControl::compile(
        &serde_yaml::from_str(
            "response_set: { connection: x-hop, x-hop: removed, content-length: '3' }
\
             response_add: { x-duplicate: third }
\
             response_remove: [x-remove]",
        )
        .unwrap(),
    )
    .unwrap();
    for version in [http::Version::HTTP_11, http::Version::HTTP_2] {
        for status in [
            StatusCode::OK,
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
        ] {
            let base = || {
                let mut response = Response::builder()
                    .status(status)
                    .header("date", "Thu, 01 Jan 1970 00:00:00 GMT")
                    .header("x-duplicate", "first")
                    .header("x-duplicate", "second")
                    .header("x-remove", "gone")
                    .header("retry-after", "7")
                    .body(Body::from("err"))
                    .unwrap();
                response.headers_mut().insert(
                    "x-opaque",
                    http::HeaderValue::from_bytes(b"\x80\xff").unwrap(),
                );
                response.extensions_mut().insert(42u32);
                response
            };
            let expected = finalize_response_with_headers(
                &Method::CONNECT,
                version,
                "qpx",
                base(),
                Some(&control),
                false,
            );
            let mut owned = OwnerResponse::from_http(base());
            finalize_response_with_headers_in_place(
                &Method::CONNECT,
                version,
                "qpx",
                &mut owned,
                Some(&control),
                false,
            );
            // Inspect the exact serialized head at codec egress, not an internal
            // map projection. CONNECT success loses framing and its local body;
            // errors retain both. Ordinary duplicate/opaque bytes stay intact.
            let actual = owned.into_http_for_codec().unwrap();
            assert_eq!(actual.status(), expected.status());
            assert_eq!(actual.version(), expected.version());
            assert_eq!(actual.headers(), expected.headers());
            assert_eq!(actual.extensions().get::<u32>(), Some(&42));
            assert!(!actual.headers().contains_key("x-hop"));
            assert!(!actual.headers().contains_key("x-remove"));
            assert_eq!(
                actual
                    .headers()
                    .get_all("x-duplicate")
                    .iter()
                    .collect::<Vec<_>>(),
                ["first", "second", "third"]
            );
            let expected_body = if status.is_success() { "" } else { "err" };
            assert_eq!(
                qpx_http::body::to_bytes(actual.into_body()).await.unwrap(),
                expected_body
            );
            assert_eq!(
                qpx_http::body::to_bytes(expected.into_body())
                    .await
                    .unwrap(),
                expected_body
            );
        }
    }
}

#[tokio::test]
async fn connect_owned_generated_responses_keep_status_and_tunnel_semantics() {
    for (kind, status) in [
        (ActionKind::Block, StatusCode::FORBIDDEN),
        (ActionKind::Direct, StatusCode::BAD_GATEWAY),
    ] {
        for (version, extended) in [
            (http::Version::HTTP_11, false),
            (http::Version::HTTP_2, false),
            (http::Version::HTTP_2, true),
        ] {
            let mut config = connect_config();
            config.messages.proxy_error = "configured CONNECT failure".to_string();
            let expected_body = if status == StatusCode::BAD_GATEWAY {
                config.messages.proxy_error.clone()
            } else {
                config.messages.blocked.clone()
            };
            let qpx_core::config::EdgeConfig::Forward(edge) = &mut config.edges[0] else {
                unreachable!()
            };
            edge.rules.clear();
            edge.default_action.kind = kind.clone();
            let runtime = Runtime::new(config).unwrap();
            // Port zero cannot be an upstream listener; failure is deterministic.
            let mut request = http::Request::builder()
                .method(Method::CONNECT)
                .version(version)
                .uri(if extended {
                    "http://127.0.0.1:0/"
                } else {
                    "127.0.0.1:0"
                })
                .body(Body::empty())
                .unwrap();
            if extended {
                request
                    .extensions_mut()
                    .insert(H2Protocol::from_static("test"));
            }
            let response: OwnerResponse<Body> = handle_connect(
                OwnerRequest::from_http(request),
                runtime,
                "forward",
                SocketAddr::from(([127, 0, 0, 1], 12345)),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), status);
            assert!(
                response
                    .extensions()
                    .get::<crate::http::codec::h2::ClassicConnectTunnel>()
                    .is_none()
            );
            let response = response.into_http_for_codec().unwrap();
            assert!(response.headers().contains_key("via"));
            // Local builders retain their default head version; the request
            // version selects finalization policy and the Via protocol label.
            assert_eq!(response.version(), http::Version::HTTP_11);
            assert_eq!(
                response.headers()["via"],
                if version == http::Version::HTTP_2 {
                    "2 qpx"
                } else {
                    "1.1 qpx"
                }
            );
            assert_eq!(
                qpx_http::body::to_bytes(response.into_body())
                    .await
                    .unwrap(),
                expected_body
            );
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let request = http::Request::builder()
        .method(Method::CONNECT)
        .uri(listener.local_addr().unwrap().to_string())
        .body(Body::empty())
        .unwrap();
    let response: OwnerResponse<Body> = handle_connect(
        OwnerRequest::from_http(request),
        direct_connect_runtime(),
        "forward",
        SocketAddr::from(([127, 0, 0, 1], 12345)),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = response.into_http_for_codec().unwrap();
    assert!(!response.headers().contains_key("content-length"));
    assert!(
        qpx_http::body::to_bytes(response.into_body())
            .await
            .unwrap()
            .is_empty()
    );
    // The upstream socket was established before returning the owned response.
    tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn h2_extended_connect_owned_finalization_keeps_stream_body_and_header_controls() {
    use crate::http::protocol::l7::finalize_extended_connect_response_with_headers;
    use qpx_core::rules::CompiledHeaderControl;

    let control = CompiledHeaderControl::compile(
        &serde_yaml::from_str(
            "response_set: { connection: x-hop, x-hop: removed, content-length: '5' }\n\
             response_add: { x-duplicate: third }",
        )
        .unwrap(),
    )
    .unwrap();
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .version(http::Version::HTTP_2)
        .header("date", "Thu, 01 Jan 1970 00:00:00 GMT")
        .header("x-duplicate", "first")
        .header("x-duplicate", "second")
        .header("upgrade", "websocket")
        .body(Body::from("reply"))
        .unwrap();
    response.extensions_mut().insert(42u32);
    let response: OwnerResponse<Body> = finalize_extended_connect_response_with_headers(
        http::Version::HTTP_2,
        "qpx",
        OwnerResponse::from_http(response),
        Some(&control),
        false,
    );
    let response = response.into_http_for_codec().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), http::Version::HTTP_2);
    assert_eq!(response.extensions().get::<u32>(), Some(&42));
    assert_eq!(response.headers()["content-length"], "5");
    assert_eq!(response.headers()["via"], "2 qpx");
    assert_eq!(response.headers()["proxy-status"], "qpx");
    assert!(!response.headers().contains_key("x-hop"));
    assert!(!response.headers().contains_key("connection"));
    assert!(!response.headers().contains_key("upgrade"));
    assert_eq!(
        response
            .headers()
            .get_all("x-duplicate")
            .iter()
            .collect::<Vec<_>>(),
        ["first", "second", "third"]
    );
    // Unlike an ordinary successful CONNECT response, extended CONNECT must
    // retain the tunnel stream and must not run bodyless normalization.
    assert_eq!(
        qpx_http::body::to_bytes(response.into_body())
            .await
            .unwrap(),
        "reply"
    );
}

// Exercise the real custom H2 codec and CONNECT handler, not Hyper's upgrade API.
async fn classic_h2_client(
    tunnel_idle_timeout_ms: u64,
) -> (
    h2::client::SendRequest<bytes::Bytes>,
    [task::JoinHandle<()>; 2],
) {
    let mut config = connect_config();
    config.runtime.tunnel_idle_timeout_ms = tunnel_idle_timeout_ms;
    let qpx_core::config::EdgeConfig::Forward(edge) = &mut config.edges[0] else {
        unreachable!()
    };
    edge.rules.clear();
    edge.default_action.kind = ActionKind::Direct;
    let runtime = Runtime::new(config).unwrap();
    let service = qpx_observability::handler_fn(move |req| {
        let runtime = runtime.clone();
        async move {
            Ok::<_, std::convert::Infallible>(
                handle_connect(
                    OwnerRequest::from_http(req),
                    runtime,
                    "forward",
                    SocketAddr::from(([127, 0, 0, 1], 12345)),
                )
                .await
                .unwrap(),
            )
        }
    });
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = task::spawn(async move {
        crate::http::codec::interim::serve_h2_with_interim(
            server_io,
            service,
            false,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    });
    let (client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = task::spawn(async move {
        let _ = connection.await;
    });
    (client, [server, driver])
}

#[tokio::test]
async fn classic_h2_connect_relays_data_and_preserves_both_half_closes() {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for upstream_closes_first in [false, true] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = listener.local_addr().unwrap();
            let payload = vec![b'x'; 32 * 1024];
            let expected = payload.clone();
            let upstream = task::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut received = vec![0; expected.len()];
                socket.read_exact(&mut received).await.unwrap();
                assert_eq!(received, expected);
                socket.write_all(&received).await.unwrap();
                if upstream_closes_first {
                    socket.shutdown().await.unwrap();
                }
                // The client can continue uploading after response END_STREAM.
                let mut tail = Vec::new();
                socket.read_to_end(&mut tail).await.unwrap();
                assert_eq!(tail, b"after-half-close");
                if !upstream_closes_first {
                    // A client END_STREAM only closes the upstream write half.
                    socket.write_all(b"after-client-eof").await.unwrap();
                    socket.shutdown().await.unwrap();
                }
            });
            let (mut client, drivers) = classic_h2_client(5_000).await;
            let request = http::Request::builder()
                .method("CONNECT")
                .uri(target.to_string())
                .body(())
                .unwrap();
            let (response, mut upload) = client.send_request(request, false).unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            for name in ["content-length", "transfer-encoding", "trailer"] {
                assert!(!response.headers().contains_key(name));
            }
            let mut download = response.into_body();
            assert!(!download.is_end_stream());
            upload
                .send_data(Bytes::from(payload.clone()), false)
                .unwrap();
            let mut echoed = Vec::new();
            while echoed.len() < payload.len() {
                let chunk = download.data().await.unwrap().unwrap();
                download
                    .flow_control()
                    .release_capacity(chunk.len())
                    .unwrap();
                echoed.extend_from_slice(&chunk);
            }
            assert_eq!(echoed, payload);
            if upstream_closes_first {
                while let Some(chunk) = download.data().await {
                    assert!(chunk.unwrap().is_empty());
                }
            }
            upload
                .send_data(Bytes::from_static(b"after-half-close"), true)
                .unwrap();
            if !upstream_closes_first {
                let mut tail = Vec::new();
                while let Some(chunk) = download.data().await {
                    let chunk = chunk.unwrap();
                    download
                        .flow_control()
                        .release_capacity(chunk.len())
                        .unwrap();
                    tail.extend_from_slice(&chunk);
                }
                assert_eq!(tail, b"after-client-eof");
            }
            assert!(download.trailers().await.unwrap().is_none());
            upstream.await.unwrap();
            for driver in drivers {
                driver.abort();
            }
        })
        .await
        .expect("classic CONNECT must close normally");
    }
}

#[tokio::test]
async fn classic_h2_connect_reset_and_idle_timeout_release_upstream() {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for reset in [true, false] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = listener.local_addr().unwrap();
            let upstream = task::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut start = [0; 5];
                socket.read_exact(&mut start).await.unwrap();
                assert_eq!(&start, b"hello");
                socket.write_all(b"ready").await.unwrap();
                let mut rest = Vec::new();
                socket.read_to_end(&mut rest).await.unwrap();
                assert!(rest.is_empty());
            });
            let (mut client, drivers) = classic_h2_client(if reset { 5_000 } else { 100 }).await;
            let request = http::Request::builder()
                .method("CONNECT")
                .uri(target.to_string())
                .body(())
                .unwrap();
            let (response, mut upload) = client.send_request(request, false).unwrap();
            let mut download = response.await.unwrap().into_body();
            upload
                .send_data(Bytes::from_static(b"hello"), false)
                .unwrap();
            assert_eq!(download.data().await.unwrap().unwrap(), "ready");
            if reset {
                upload.send_reset(h2::Reason::CANCEL);
            } else {
                while let Some(chunk) = download.data().await {
                    assert!(chunk.unwrap().is_empty());
                }
            }
            upstream.await.unwrap();
            for driver in drivers {
                driver.abort();
            }
        })
        .await
        .expect("reset or tunnel idle timeout must release the TCP tunnel");
    }
}
