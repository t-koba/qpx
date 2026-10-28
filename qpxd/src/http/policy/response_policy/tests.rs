use crate::http::policy::response_policy::*;
use qpx_core::config::{
    HeaderControl, HttpResponseCacheEffectsConfig, HttpResponseEffectsConfig,
    HttpResponseRetryEffectsConfig, MatchConfig, RpcMatchConfig,
};

#[tokio::test]
async fn response_policy_surfaces_tags_and_retry_controls() {
    let rules = vec![HttpResponseRuleConfig {
        name: "response-policy".to_string(),
        r#match: Some(MatchConfig {
            response_status: vec!["200".to_string()],
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig {
            headers: Some(HeaderControl {
                response_set: std::collections::HashMap::from([(
                    "x-response-policy".to_string(),
                    "applied".to_string(),
                )]),
                ..Default::default()
            }),
            cache: Some(HttpResponseCacheEffectsConfig { bypass: true }),
            retry: Some(HttpResponseRetryEffectsConfig { suppress: true }),
            mirror: Some(qpx_core::config::HttpResponseMirrorEffectsConfig {
                enabled: Some(false),
                upstreams: Vec::new(),
            }),
            tags: vec!["resp-tag".to_string()],
            ..Default::default()
        },
    }];
    let engine = HttpResponseRuleEngine::new(rules.as_slice())
        .expect("engine")
        .expect("some");
    let response = Response::builder()
        .status(200)
        .body(Body::from("ok"))
        .expect("response");
    let candidates = engine.candidate_profile(MatchPrefilterContext {
        method: Some("GET"),
        dst_port: Some(443),
        src_ip: None,
        host: Some("example.com"),
        sni: None,
        path: Some("/"),
    });
    let decision = apply_listener_response_policy(
        Some(&engine),
        candidates,
        RuleMatchContext {
            method: Some("GET"),
            host: Some("example.com"),
            path: Some("/"),
            ..Default::default()
        },
        qpx_core::http_message::Response::from_http(response),
        None,
        None,
        ResponseBodyObservationLimits {
            max_body_bytes: usize::MAX,
            read_timeout: Duration::from_secs(1),
            force_body: false,
        },
    )
    .await
    .expect("decision");

    match decision {
        ListenerResponsePolicyDecision::Continue {
            cache_bypass,
            suppress_retry,
            mirror,
            policy_tags,
            headers,
            ..
        } => {
            assert!(cache_bypass);
            assert!(suppress_retry);
            assert_eq!(mirror, Some(false));
            assert_eq!(policy_tags, vec!["resp-tag".to_string()]);
            let headers = headers.expect("headers");
            assert!(headers.has_response_mutations());
        }
        ListenerResponsePolicyDecision::LocalResponse { .. } => {
            panic!("expected continued response")
        }
    }
}

#[tokio::test]
async fn response_policy_does_not_buffer_for_later_body_rule_after_header_match() {
    let rules = vec![
        HttpResponseRuleConfig {
            name: "body-dependent-nonmatch".to_string(),
            r#match: Some(MatchConfig {
                response_status: vec!["404".to_string()],
                response_size: vec![">=1".to_string()],
                ..Default::default()
            }),
            effects: HttpResponseEffectsConfig {
                tags: vec!["body-dependent-nonmatch".to_string()],
                ..Default::default()
            },
        },
        HttpResponseRuleConfig {
            name: "status-first".to_string(),
            r#match: Some(MatchConfig {
                response_status: vec!["200".to_string()],
                ..Default::default()
            }),
            effects: HttpResponseEffectsConfig {
                tags: vec!["status-first".to_string()],
                ..Default::default()
            },
        },
        HttpResponseRuleConfig {
            name: "size-later".to_string(),
            r#match: Some(MatchConfig {
                response_size: vec![">=1".to_string()],
                ..Default::default()
            }),
            effects: HttpResponseEffectsConfig {
                tags: vec!["size-later".to_string()],
                ..Default::default()
            },
        },
    ];
    let engine = HttpResponseRuleEngine::new(rules.as_slice())
        .expect("engine")
        .expect("some");
    let (_sender, body) = Body::channel_with_capacity(1);
    let response = Response::builder()
        .status(200)
        .body(body)
        .expect("response");
    let candidates = engine.candidate_profile(MatchPrefilterContext {
        method: Some("GET"),
        dst_port: Some(443),
        src_ip: None,
        host: Some("example.com"),
        sni: None,
        path: Some("/"),
    });
    assert!(candidates.requires_response_size);

    let decision = apply_listener_response_policy(
        Some(&engine),
        candidates,
        RuleMatchContext {
            method: Some("GET"),
            host: Some("example.com"),
            path: Some("/"),
            ..Default::default()
        },
        qpx_core::http_message::Response::from_http(response),
        None,
        None,
        ResponseBodyObservationLimits {
            max_body_bytes: usize::MAX,
            read_timeout: Duration::from_millis(1),
            force_body: false,
        },
    )
    .await
    .expect("decision");

    match decision {
        ListenerResponsePolicyDecision::Continue { policy_tags, .. } => {
            assert_eq!(policy_tags, vec!["status-first".to_string()]);
        }
        ListenerResponsePolicyDecision::LocalResponse { .. } => {
            panic!("expected continued response")
        }
    }
}

#[tokio::test]
async fn forced_body_observation_buffers_response_without_rules() {
    let response = Response::builder()
        .status(200)
        .body(Body::from("captured"))
        .expect("response");
    let decision = apply_listener_response_policy(
        None,
        ResponseRuleCandidates::default(),
        RuleMatchContext::default(),
        qpx_core::http_message::Response::from_http(response),
        None,
        None,
        ResponseBodyObservationLimits {
            max_body_bytes: 16,
            read_timeout: Duration::from_secs(1),
            force_body: true,
        },
    )
    .await
    .expect("decision");

    match decision {
        ListenerResponsePolicyDecision::Continue { response, .. } => {
            let observed = crate::http::body::size::observed_response_bytes(&response)
                .expect("response body should be buffered for capture");
            assert_eq!(observed.as_ref(), b"captured");
        }
        ListenerResponsePolicyDecision::LocalResponse { .. } => {
            panic!("expected continued response")
        }
    }
}

#[tokio::test]
async fn grpc_status_rule_matches_trailers() {
    let rules = vec![HttpResponseRuleConfig {
        name: "grpc-status".to_string(),
        r#match: Some(MatchConfig {
            rpc: Some(RpcMatchConfig {
                protocol: vec!["grpc".to_string()],
                status: vec!["14".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig {
            local_response: Some(qpx_core::config::LocalResponseConfig {
                status: 204,
                body: String::new(),
                content_type: None,
                headers: Default::default(),
                rpc: None,
            }),
            tags: vec!["grpc".to_string()],
            ..Default::default()
        },
    }];
    let engine = HttpResponseRuleEngine::new(rules.as_slice())
        .expect("engine")
        .expect("some");
    let (mut sender, body) = Body::channel_with_capacity(16);
    tokio::spawn(async move {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("14"));
        let _ = sender.send_trailers(trailers).await;
    });
    let response = Response::builder()
        .status(200)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(body)
        .expect("response");
    let response = crate::http::body::size::buffer_response_body(
        qpx_core::http_message::Response::from_http(response),
        usize::MAX,
        Duration::from_secs(1),
    )
    .await
    .expect("buffer");
    let request_rpc = crate::http::rpc::RpcMatchContext {
        protocol: Some("grpc".to_string()),
        service: Some("demo.Echo".to_string()),
        method: Some("Say".to_string()),
        ..Default::default()
    };
    let candidates = engine.candidate_profile(MatchPrefilterContext {
        method: Some("POST"),
        dst_port: Some(443),
        src_ip: None,
        host: Some("rpc.example.com"),
        sni: None,
        path: Some("/demo.Echo/Say"),
    });
    let decision = apply_listener_response_policy(
        Some(&engine),
        candidates,
        RuleMatchContext {
            method: Some("POST"),
            host: Some("rpc.example.com"),
            path: Some("/demo.Echo/Say"),
            ..Default::default()
        },
        response,
        None,
        Some(&request_rpc),
        ResponseBodyObservationLimits {
            max_body_bytes: usize::MAX,
            read_timeout: Duration::from_secs(1),
            force_body: false,
        },
    )
    .await
    .expect("decision");

    match decision {
        ListenerResponsePolicyDecision::LocalResponse { policy_tags, .. } => {
            assert_eq!(policy_tags, vec!["grpc".to_string()]);
        }
        ListenerResponsePolicyDecision::Continue { .. } => {
            panic!("expected grpc local response")
        }
    }
}

#[tokio::test]
async fn rpc_protocol_service_method_rule_uses_request_rpc_without_response_inspection() {
    let rules = vec![HttpResponseRuleConfig {
        name: "grpc-method".to_string(),
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
            local_response: Some(qpx_core::config::LocalResponseConfig {
                status: 204,
                body: String::new(),
                content_type: None,
                headers: Default::default(),
                rpc: None,
            }),
            tags: vec!["grpc-method".to_string()],
            ..Default::default()
        },
    }];
    let engine = HttpResponseRuleEngine::new(rules.as_slice())
        .expect("engine")
        .expect("some");
    let candidates = engine.candidate_profile(MatchPrefilterContext {
        method: Some("POST"),
        dst_port: Some(443),
        src_ip: None,
        host: Some("rpc.example.com"),
        sni: None,
        path: Some("/demo.Echo/Say"),
    });
    assert!(candidates.requires_request_rpc_context);
    assert!(!candidates.requires_request_body_observation);
    assert!(candidates.requires_response_rpc_context);
    assert!(!candidates.requires_response_rpc_observation);
    let response = Response::builder()
        .status(200)
        .body(Body::from("ok"))
        .expect("response");
    let request_rpc = crate::http::rpc::RpcMatchContext {
        protocol: Some("grpc".to_string()),
        service: Some("demo.Echo".to_string()),
        method: Some("Say".to_string()),
        ..Default::default()
    };
    let decision = apply_listener_response_policy(
        Some(&engine),
        candidates,
        RuleMatchContext {
            method: Some("POST"),
            host: Some("rpc.example.com"),
            path: Some("/demo.Echo/Say"),
            ..Default::default()
        },
        qpx_core::http_message::Response::from_http(response),
        None,
        Some(&request_rpc),
        ResponseBodyObservationLimits {
            max_body_bytes: usize::MAX,
            read_timeout: Duration::from_secs(1),
            force_body: false,
        },
    )
    .await
    .expect("decision");

    match decision {
        ListenerResponsePolicyDecision::LocalResponse { policy_tags, .. } => {
            assert_eq!(policy_tags, vec!["grpc-method".to_string()]);
        }
        ListenerResponsePolicyDecision::Continue { .. } => {
            panic!("expected grpc method local response")
        }
    }
}

#[test]
fn response_rpc_streaming_requires_request_body_observation() {
    let rules = vec![HttpResponseRuleConfig {
        name: "grpc-client-streaming".to_string(),
        r#match: Some(qpx_core::config::MatchConfig {
            rpc: Some(qpx_core::config::RpcMatchConfig {
                streaming: vec!["client".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig::default(),
    }];
    let engine = HttpResponseRuleEngine::new(rules.as_slice())
        .expect("engine")
        .expect("some");
    let candidates = engine.candidate_profile(MatchPrefilterContext {
        method: Some("POST"),
        dst_port: Some(443),
        src_ip: None,
        host: Some("rpc.example.com"),
        sni: None,
        path: Some("/demo.Echo/Say"),
    });
    assert!(candidates.requires_request_rpc_context);
    assert!(candidates.requires_request_body_observation);
    assert!(candidates.requires_response_rpc_context);
    assert!(candidates.requires_response_rpc_observation);
}

#[test]
fn response_request_observation_ignores_request_mismatched_candidates() {
    let rules = vec![
        HttpResponseRuleConfig {
            name: "slow-query-streaming".to_string(),
            r#match: Some(qpx_core::config::MatchConfig {
                method: vec!["GET".to_string()],
                query: vec!["mode=slow".to_string()],
                rpc: Some(qpx_core::config::RpcMatchConfig {
                    streaming: vec!["client".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            effects: HttpResponseEffectsConfig::default(),
        },
        HttpResponseRuleConfig {
            name: "get-header-only".to_string(),
            r#match: Some(qpx_core::config::MatchConfig {
                method: vec!["GET".to_string()],
                ..Default::default()
            }),
            effects: HttpResponseEffectsConfig::default(),
        },
    ];
    let engine = HttpResponseRuleEngine::new(rules.as_slice())
        .expect("engine")
        .expect("some");
    let candidates = engine.candidate_profile(MatchPrefilterContext {
        method: Some("GET"),
        dst_port: Some(443),
        src_ip: None,
        host: Some("rpc.example.com"),
        sni: None,
        path: Some("/demo.Echo/Say"),
    });
    let requirements = engine.request_observation_requirements_for_candidates(
        &candidates,
        &RuleMatchContext {
            method: Some("GET"),
            host: Some("rpc.example.com"),
            path: Some("/demo.Echo/Say"),
            query: Some("mode=fast"),
            ..Default::default()
        },
    );
    assert!(requirements.is_empty());
}

#[test]
fn response_request_observation_does_not_evaluate_response_headers_against_request_headers() {
    let rules = vec![HttpResponseRuleConfig {
        name: "grpc-client-streaming-response-header".to_string(),
        r#match: Some(qpx_core::config::MatchConfig {
            headers: vec![qpx_core::config::HeaderMatch {
                name: "x-response-mode".to_string(),
                value: Some("slow".to_string()),
                regex: None,
            }],
            rpc: Some(qpx_core::config::RpcMatchConfig {
                streaming: vec!["client".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig::default(),
    }];
    let engine = HttpResponseRuleEngine::new(rules.as_slice())
        .expect("engine")
        .expect("some");
    let candidates = engine.candidate_profile(MatchPrefilterContext {
        method: Some("POST"),
        dst_port: Some(443),
        src_ip: None,
        host: Some("rpc.example.com"),
        sni: None,
        path: Some("/demo.Echo/Say"),
    });
    let mut request_headers = http::HeaderMap::new();
    request_headers.insert("x-response-mode", http::HeaderValue::from_static("fast"));
    let requirements = engine.request_observation_requirements_for_candidates(
        &candidates,
        &RuleMatchContext {
            method: Some("POST"),
            host: Some("rpc.example.com"),
            path: Some("/demo.Echo/Say"),
            headers: Some(qpx_core::http_content_length::HeaderView::new(
                &request_headers,
            )),
            ..Default::default()
        },
    );
    assert!(requirements.needs_rpc);
    assert!(requirements.needs_body);
}

#[tokio::test]
async fn owned_policy_observation_preserves_head_framing_extensions_and_trailers() {
    use http::HeaderValue;
    use qpx_core::config::HeaderMatch;
    use qpx_core::http_message::{OrdinaryHeaderName, Response as OwnedResponse};
    let engine = HttpResponseRuleEngine::new(&[HttpResponseRuleConfig {
        name: "owner-continuation".into(),
        r#match: Some(MatchConfig {
            response_status: vec!["201".into()],
            headers: vec![HeaderMatch {
                name: "x-match".into(),
                value: Some("yes".into()),
                regex: None,
            }],
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig {
            tags: vec!["observed".into()],
            ..Default::default()
        },
    }])
    .unwrap()
    .unwrap();
    for lengths in [
        vec![],
        vec!["0"],
        vec!["2, 02", " 2 "],
        vec!["invalid"],
        vec!["2", "3"],
    ] {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-trailer", HeaderValue::from_static("kept"));
        let mut raw = http::Response::builder()
            .status(201)
            .version(http::Version::HTTP_2)
            .header("x-match", "yes")
            .body(Body::replay(
                bytes::Bytes::from_static(b"ok"),
                Some(trailers.clone()),
            ))
            .unwrap();
        for value in lengths {
            raw.headers_mut()
                .append(http::header::CONTENT_LENGTH, value.parse().unwrap());
        }
        let mut sensitive = HeaderValue::from_bytes(b"\xff").unwrap();
        sensitive.set_sensitive(true);
        raw.headers_mut().append("x-repeat", sensitive);
        raw.headers_mut()
            .append("x-repeat", HeaderValue::from_static("second"));
        raw.extensions_mut().insert(42usize);
        let response = OwnedResponse::from_http(raw);
        let original = response.headers().clone();
        let candidates = engine.candidate_profile(MatchPrefilterContext {
            method: Some("GET"),
            dst_port: None,
            src_ip: None,
            host: None,
            sni: None,
            path: Some("/"),
        });
        let decision = apply_listener_response_policy(
            Some(&engine),
            candidates,
            RuleMatchContext::default(),
            response,
            None,
            None,
            ResponseBodyObservationLimits {
                max_body_bytes: 32,
                read_timeout: Duration::from_secs(1),
                force_body: true,
            },
        )
        .await
        .unwrap();
        let ListenerResponsePolicyDecision::Continue {
            mut response,
            policy_tags,
            ..
        } = decision
        else {
            panic!("continuation");
        };
        assert_eq!(policy_tags, vec!["observed"]);
        assert_eq!(response.status(), http::StatusCode::CREATED);
        assert_eq!(response.version(), http::Version::HTTP_2);
        assert_eq!(response.extensions().get::<usize>(), Some(&42));
        assert_eq!(response.headers(), &original);
        let repeated = response
            .headers()
            .get_all(&OrdinaryHeaderName::try_from("x-repeat").unwrap())
            .map(|v| (v.as_bytes(), v.is_sensitive()))
            .collect::<Vec<_>>();
        assert_eq!(
            repeated,
            vec![(b"\xff".as_slice(), true), (b"second".as_slice(), false)]
        );
        assert_eq!(response.body_mut().data().await.unwrap().unwrap(), "ok");
        assert!(response.body_mut().data().await.is_none());
        assert_eq!(
            response.body_mut().trailers().await.unwrap(),
            Some(trailers)
        );
    }
}
