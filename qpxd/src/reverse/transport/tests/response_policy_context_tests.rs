use super::*;

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
        force_response_body_observation: false,
    })
    .await
    .expect("apply");

    match decision {
        ListenerResponsePolicyDecision::Continue {
            response,
            headers,
            cache_bypass,
            ..
        } => {
            assert_eq!(response.status(), StatusCode::OK);
            assert!(headers.is_none());
            assert!(cache_bypass);
        }
        ListenerResponsePolicyDecision::LocalResponse { .. } => {
            panic!("expected continued response")
        }
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
        force_response_body_observation: false,
    })
    .await
    .expect("apply");

    match decision {
        ListenerResponsePolicyDecision::LocalResponse { response, .. } => {
            assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        }
        ListenerResponsePolicyDecision::Continue { .. } => panic!("expected local response"),
    }
}

#[test]
fn response_rule_request_body_observation_uses_prefiltered_candidates() {
    let router = build_router(vec![HttpResponseRuleConfig {
        name: "post-only-client-streaming".to_string(),
        r#match: Some(MatchConfig {
            method: vec!["POST".to_string()],
            rpc: Some(RpcMatchConfig {
                streaming: vec!["client".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig::default(),
    }]);
    let route = router.route_at(0).expect("route");

    let get_candidates = route.response_rule_candidate_profile(MatchPrefilterContext {
        method: Some("GET"),
        dst_port: Some(443),
        src_ip: None,
        host: Some("example.com"),
        sni: None,
        path: Some("/demo.Echo/Say"),
    });
    assert!(!get_candidates.requires_request_body_observation);
    assert!(!get_candidates.requires_request_rpc_context);

    let post_candidates = route.response_rule_candidate_profile(MatchPrefilterContext {
        method: Some("POST"),
        dst_port: Some(443),
        src_ip: None,
        host: Some("example.com"),
        sni: None,
        path: Some("/demo.Echo/Say"),
    });
    assert!(post_candidates.requires_request_body_observation);
    assert!(post_candidates.requires_request_rpc_context);
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
        force_response_body_observation: false,
    })
    .await
    .expect("apply");

    match decision {
        ListenerResponsePolicyDecision::LocalResponse { response, .. } => {
            assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        }
        ListenerResponsePolicyDecision::Continue { .. } => panic!("expected local response"),
    }
}

#[tokio::test]
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
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
        force_response_body_observation: false,
    })
    .await
    .expect("apply");

    match decision {
        ListenerResponsePolicyDecision::LocalResponse { response, .. } => {
            assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        }
        ListenerResponsePolicyDecision::Continue { .. } => panic!("expected local response"),
    }
}
