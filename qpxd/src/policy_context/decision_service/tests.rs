use crate::http::dispatch::ProxyKind;
use crate::policy_context::decision_service::*;
use crate::policy_context::identity::ResolvedIdentity;
use hyper::HeaderMap;
use qpx_core::config::{
    ActionConfig, ActionKind, DecisionServiceAuthorityConfig, DecisionServiceConstraintsConfig,
    DecisionServiceMappingTargetDocument, HeaderControl,
};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::time::Duration;
use url::Url;

fn test_cfg() -> CompiledDecisionService {
    CompiledDecisionService {
        name: "test".to_string(),
        driver: qpx_core::config::DecisionServiceDriver::SchemaMappedHttp,
        endpoint: Url::parse("http://127.0.0.1/check").expect("url"),
        timeout: Duration::from_millis(100),
        max_response_bytes: 1024,
        profile_id: "test".to_string(),
        contract_id: None,
        selected_headers: Vec::new(),
        sensitive_headers: HashSet::new(),
        signal_extensions: json!({}),
        expected_auth_context: json!({}),
        request_mapping: Vec::new(),
        response_mapping: compile_mapping_rules(&[
            qpx_core::config::DecisionServiceMappingRuleConfig {
                target_document: DecisionServiceMappingTargetDocument::EnforceableEffect,
                target: "/decision".to_string(),
                source: Some("$.decision_response.decision".to_string()),
                literal: None,
                value_map: Default::default(),
                optional: false,
            },
            qpx_core::config::DecisionServiceMappingRuleConfig {
                target_document: DecisionServiceMappingTargetDocument::EnforceableEffect,
                target: "/cache_bypass".to_string(),
                source: Some("$.decision_response.cache_bypass".to_string()),
                literal: None,
                value_map: Default::default(),
                optional: true,
            },
            qpx_core::config::DecisionServiceMappingRuleConfig {
                target_document: DecisionServiceMappingTargetDocument::EnforceableEffect,
                target: "/policy_tags".to_string(),
                source: Some("$.decision_response.policy_tags".to_string()),
                literal: None,
                value_map: Default::default(),
                optional: true,
            },
        ])
        .expect("mapping"),
        remote_request_schema: None,
        remote_response_schema: None,
        remote_auth_context_schema: None,
        qpx_enforceable_effect_schema: compile_schema(
            qpx_enforceable_effect_schema(),
            "enforceable_effect",
        )
        .expect("schema"),
        authority: DecisionServiceAuthorityConfig {
            can_allow: true,
            can_deny: true,
            can_override_route: false,
            can_weaken_local_policy: false,
        },
        constraints: DecisionServiceConstraintsConfig::default(),
        allowed_modes: HashSet::new(),
        allowed_effects: HashSet::from(["allow".to_string(), "cache_bypass".to_string()]),
        upstream_trust: None,
        bearer_token: None,
        oauth2_client_credentials: None,
        signature: None,
        cache: None,
    }
}

#[test]
fn decision_service_mode_validation_rejects_unsupported_fields() {
    let allow = DecisionServiceAllow {
        force_inspect: true,
        ..Default::default()
    };
    let err = validate_decision_service_allow_mode(&allow, DecisionServiceMode::ReverseHttp)
        .expect_err("reverse_edges should reject force_inspect");
    assert!(err.to_string().contains("force_inspect"));

    let allow = DecisionServiceAllow {
        headers: Some(Arc::new(
            CompiledHeaderControl::compile(&HeaderControl::default()).expect("headers"),
        )),
        ..Default::default()
    };
    let err = validate_decision_service_allow_mode(&allow, DecisionServiceMode::TransparentTls)
        .expect_err("transparent tls should reject header injection");
    assert!(err.to_string().contains("inject_headers"));
}

#[test]
fn decision_service_response_mapping_builds_enforceable_effect() {
    let enforcement = map_remote_decision_response(
        &test_cfg(),
        json!({
            "decision": "allow",
            "cache_bypass": true,
            "policy_tags": ["audit"]
        }),
    )
    .expect("mapped response");
    let DecisionServiceEnforcement::Continue(allow) = enforcement else {
        panic!("expected allow");
    };
    assert!(allow.cache_bypass);
    assert_eq!(allow.policy_tags, vec!["audit"]);
}

#[test]
fn decision_service_value_map_translates_external_enum_and_fails_closed() {
    let mut cfg = test_cfg();
    cfg.response_mapping =
        compile_mapping_rules(&[qpx_core::config::DecisionServiceMappingRuleConfig {
            target_document: DecisionServiceMappingTargetDocument::EnforceableEffect,
            target: "/decision".to_string(),
            source: Some("$.decision_response.results[0].effect".to_string()),
            literal: None,
            value_map: [
                ("EFFECT_ALLOW".to_string(), json!("allow")),
                ("EFFECT_DENY".to_string(), json!("deny")),
            ]
            .into_iter()
            .collect(),
            optional: false,
        }])
        .expect("mapping");

    let allow =
        map_remote_decision_response(&cfg, json!({"results": [{"effect": "EFFECT_ALLOW"}]}))
            .expect("mapped allow");
    assert!(matches!(allow, DecisionServiceEnforcement::Continue(_)));

    let err =
        map_remote_decision_response(&cfg, json!({"results": [{"effect": "EFFECT_UNKNOWN"}]}))
            .expect_err("unknown external enum must fail closed");
    assert!(err.to_string().contains("unmapped value EFFECT_UNKNOWN"));
}

#[test]
fn authzen_request_uses_native_subject_resource_action_context_shape() {
    let mut cfg = test_cfg();
    cfg.driver = qpx_core::config::DecisionServiceDriver::Authzen;
    cfg.request_mapping.clear();
    let identity = ResolvedIdentity {
        user: Some("alice".to_string()),
        tenant: Some("tenant-a".to_string()),
        groups: vec!["finance".to_string()],
        roles: vec!["reviewer".to_string()],
        idp: Some("https://issuer.example".to_string()),
        identity_source: Some("bearer".to_string()),
        ..Default::default()
    };
    let input = DecisionServiceInput {
        mode: DecisionServiceMode::ReverseHttp,
        proxy_kind: ProxyKind::Reverse,
        proxy_name: "edge",
        scope_name: "default",
        remote_ip: "192.0.2.10".parse().unwrap(),
        dst_port: Some(443),
        host: Some("api.example"),
        sni: Some("api.example"),
        method: Some("GET"),
        path: Some("/reports"),
        uri: Some("https://api.example/reports"),
        matched_rule: Some("api"),
        matched_route: Some("reports"),
        action: None,
        headers: None,
        identity: &identity,
    };

    let request = build_remote_decision_request(&cfg, &input).unwrap();
    assert_eq!(request["subject"]["id"], "alice");
    assert_eq!(request["subject"]["properties"]["groups"][0], "finance");
    assert_eq!(request["resource"]["id"], "https://api.example/reports");
    assert_eq!(request["action"]["name"], "GET");
    assert_eq!(request["context"]["remote_ip"], "192.0.2.10");
    assert!(request.get("pep_signal").is_none());
}

#[test]
fn authzen_boolean_decision_and_mapped_context_build_enforceable_effect() {
    let mut cfg = test_cfg();
    cfg.driver = qpx_core::config::DecisionServiceDriver::Authzen;
    cfg.response_mapping = compile_mapping_rules(&[
        qpx_core::config::DecisionServiceMappingRuleConfig {
            target_document: DecisionServiceMappingTargetDocument::EnforceableEffect,
            target: "/external_decision_id".to_string(),
            source: Some("$.decision_response.context.decision_id".to_string()),
            literal: None,
            value_map: Default::default(),
            optional: false,
        },
        qpx_core::config::DecisionServiceMappingRuleConfig {
            target_document: DecisionServiceMappingTargetDocument::EnforceableEffect,
            target: "/policy_id".to_string(),
            source: Some("$.decision_response.context.policy_id".to_string()),
            literal: None,
            value_map: Default::default(),
            optional: false,
        },
    ])
    .unwrap();
    let enforcement = map_remote_decision_response(
        &cfg,
        json!({
            "decision": true,
            "context": {"decision_id": "d-1", "policy_id": "p-1"}
        }),
    )
    .unwrap();
    let DecisionServiceEnforcement::Continue(allow) = enforcement else {
        panic!("expected allow");
    };
    assert_eq!(allow.external_decision_id.as_deref(), Some("d-1"));
    assert_eq!(allow.policy_id.as_deref(), Some("p-1"));
}

#[test]
fn decision_service_empty_effects_allow_only() {
    let mut cfg = test_cfg();
    cfg.allowed_effects.clear();

    let err = map_remote_decision_response(
        &cfg,
        json!({
            "decision": "allow",
            "cache_bypass": true
        }),
    )
    .expect_err("cache_bypass must require explicit effect capability");
    assert!(err.to_string().contains("cache_bypass"));
}

#[test]
fn decision_service_response_mapping_keeps_complex_jsonpath() {
    let mut cfg = test_cfg();
    cfg.response_mapping =
        compile_mapping_rules(&[qpx_core::config::DecisionServiceMappingRuleConfig {
            target_document: DecisionServiceMappingTargetDocument::EnforceableEffect,
            target: "/decision".to_string(),
            source: Some("$.decision_response.items[0].decision".to_string()),
            literal: None,
            value_map: Default::default(),
            optional: false,
        }])
        .expect("mapping");
    assert!(mapping_rules_need_json_source(&cfg.response_mapping));

    let enforcement = map_remote_decision_response(
        &cfg,
        json!({
            "items": [
                {
                    "decision": "allow"
                }
            ]
        }),
    )
    .expect("mapped response");
    let DecisionServiceEnforcement::Continue(_) = enforcement else {
        panic!("expected allow");
    };
}

#[test]
fn decision_service_request_mapping_uses_builtin_sources() {
    let mut cfg = test_cfg();
    cfg.request_mapping = compile_mapping_rules(&[
        qpx_core::config::DecisionServiceMappingRuleConfig {
            target_document: DecisionServiceMappingTargetDocument::DecisionRequest,
            target: "/subject/id".to_string(),
            source: Some("$.pep_signal.identity.user".to_string()),
            literal: None,
            value_map: Default::default(),
            optional: false,
        },
        qpx_core::config::DecisionServiceMappingRuleConfig {
            target_document: DecisionServiceMappingTargetDocument::DecisionRequest,
            target: "/subject/groups".to_string(),
            source: Some("$.pep_signal.identity.groups".to_string()),
            literal: None,
            value_map: Default::default(),
            optional: false,
        },
        qpx_core::config::DecisionServiceMappingRuleConfig {
            target_document: DecisionServiceMappingTargetDocument::DecisionRequest,
            target: "/action/name".to_string(),
            source: Some("$.pep_signal.request.method".to_string()),
            literal: None,
            value_map: Default::default(),
            optional: false,
        },
        qpx_core::config::DecisionServiceMappingRuleConfig {
            target_document: DecisionServiceMappingTargetDocument::DecisionRequest,
            target: "/resource/path".to_string(),
            source: Some("$.pep_signal.request.path".to_string()),
            literal: None,
            value_map: Default::default(),
            optional: false,
        },
    ])
    .expect("mapping");
    assert!(!mapping_rules_need_json_source(&cfg.request_mapping));

    let identity = ResolvedIdentity {
        user: Some("alice".to_string()),
        groups: vec!["engineering".to_string()],
        ..Default::default()
    };
    let input = DecisionServiceInput {
        mode: DecisionServiceMode::ForwardHttp,
        proxy_kind: ProxyKind::Forward,
        proxy_name: "egress",
        scope_name: "default",
        remote_ip: "127.0.0.1".parse().expect("ip"),
        dst_port: Some(443),
        host: Some("example.com"),
        sni: None,
        method: Some("GET"),
        path: Some("/admin"),
        uri: Some("https://example.com/admin"),
        matched_rule: None,
        matched_route: None,
        action: None,
        headers: None,
        identity: &identity,
    };

    let request = build_remote_decision_request(&cfg, &input).expect("request");
    assert_eq!(
        request,
        json!({
            "subject": {
                "id": "alice",
                "groups": ["engineering"]
            },
            "action": {
                "name": "GET"
            },
            "resource": {
                "path": "/admin"
            }
        })
    );
}

#[test]
fn decision_service_never_exports_credentials_or_sensitive_headers() {
    let mut cfg = test_cfg();
    cfg.selected_headers = vec![
        http::header::AUTHORIZATION,
        http::header::PROXY_AUTHORIZATION,
        http::header::COOKIE,
        http::HeaderName::from_static("x-private-assertion"),
        http::HeaderName::from_static("x-request-class"),
    ];
    cfg.sensitive_headers = HashSet::from([http::HeaderName::from_static("x-private-assertion")]);
    let mut headers = qpx_core::http_message::Headers::new();
    headers.insert(
        qpx_core::http_message::OrdinaryHeaderName::try_from(http::header::AUTHORIZATION.clone())
            .expect("ordinary field"),
        "Bearer secret".parse().unwrap(),
    );
    headers.insert(
        qpx_core::http_message::OrdinaryHeaderName::try_from(
            http::header::PROXY_AUTHORIZATION.clone(),
        )
        .expect("ordinary field"),
        "Basic secret".parse().unwrap(),
    );
    headers.insert(
        qpx_core::http_message::OrdinaryHeaderName::try_from(http::header::COOKIE.clone())
            .expect("ordinary field"),
        "sid=secret".parse().unwrap(),
    );
    headers.insert(
        qpx_core::http_message::OrdinaryHeaderName::try_from("x-private-assertion")
            .expect("ordinary field"),
        "secret".parse().unwrap(),
    );
    headers.insert(
        qpx_core::http_message::OrdinaryHeaderName::try_from("x-request-class")
            .expect("ordinary field"),
        "interactive".parse().unwrap(),
    );
    let exported = build_selected_headers(&cfg, Some(&headers));
    assert_eq!(exported.len(), 1);
    assert_eq!(exported["x-request-class"], json!(["interactive"]));
}

#[test]
fn decision_service_content_length_is_rejected_before_body_read() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, "65".parse().expect("header"));

    let err = validate_decision_service_content_length(&headers, 64)
        .expect_err("content-length above cap should fail");
    assert!(err.to_string().contains("exceeds hard cap"));
}

#[test]
fn decision_service_reads_the_declared_length_through_the_owner() {
    // A comma list of equal members is one length, so a response that
    // declares a length over the cap is refused before its body is read.
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_LENGTH,
        "65, 65".parse().expect("header"),
    );

    let err = validate_decision_service_content_length(&headers, 64)
        .expect_err("content-length above cap should fail");
    assert!(err.to_string().contains("exceeds hard cap"));

    // A declaration the owner refuses names no length, so the body is read
    // under the cap instead; the cap holds either way.
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, "+65".parse().expect("header"));

    validate_decision_service_content_length(&headers, 64)
        .expect("a declaration that names no length is not over the cap");
}

#[tokio::test]
async fn decision_service_response_bounded_collect_enforces_cap() {
    let err = parse_decision_service_response_body(Body::from(r#"{"decision":"allow"}"#), 8)
        .await
        .expect_err("bounded response collect should enforce response cap");
    assert!(err.to_string().contains("exceeds hard cap"));
}

#[test]
fn decision_service_mode_validation_accepts_supported_fields() {
    let connect_allow = DecisionServiceAllow {
        headers: Some(Arc::new(
            CompiledHeaderControl::compile(&HeaderControl::default()).expect("headers"),
        )),
        override_upstream: Some("http://upstream.internal:8080".to_string()),
        timeout_override: Some(Duration::from_millis(250)),
        rate_limit_profile: Some("subject-egress".to_string()),
        force_inspect: true,
        force_tunnel: false,
        ..Default::default()
    };

    validate_decision_service_allow_mode(&connect_allow, DecisionServiceMode::ForwardConnect)
        .expect("forward connect should accept force_inspect");

    let transparent_tls_allow = DecisionServiceAllow {
        override_upstream: connect_allow.override_upstream.clone(),
        timeout_override: connect_allow.timeout_override,
        rate_limit_profile: connect_allow.rate_limit_profile.clone(),
        force_inspect: true,
        ..Default::default()
    };
    validate_decision_service_allow_mode(
        &transparent_tls_allow,
        DecisionServiceMode::TransparentTls,
    )
    .expect("transparent tls should accept force_inspect");

    let http_allow = DecisionServiceAllow {
        headers: connect_allow.headers.clone(),
        override_upstream: connect_allow.override_upstream.clone(),
        timeout_override: connect_allow.timeout_override,
        cache_bypass: true,
        rate_limit_profile: connect_allow.rate_limit_profile.clone(),
        ..Default::default()
    };
    validate_decision_service_allow_mode(&http_allow, DecisionServiceMode::ForwardHttp)
        .expect("forward http should accept cache_bypass");
    validate_decision_service_allow_mode(&http_allow, DecisionServiceMode::ReverseHttp)
        .expect("reverse_edges http should accept cache_bypass");
}

#[test]
fn decision_service_action_overrides_apply_force_modes() {
    let mut action = ActionConfig {
        kind: ActionKind::Tunnel,
        upstream: Some("baseline".to_string()),
        local_response: None,
    };
    DecisionServiceAllow {
        override_upstream: Some("http://override.internal:8080".to_string()),
        force_inspect: true,
        ..Default::default()
    }
    .apply_action_overrides(&mut action);
    assert!(matches!(action.kind, ActionKind::Inspect));
    assert_eq!(
        action.upstream.as_deref(),
        Some("http://override.internal:8080")
    );

    let mut action = ActionConfig {
        kind: ActionKind::Inspect,
        upstream: None,
        local_response: None,
    };
    DecisionServiceAllow {
        force_tunnel: true,
        ..Default::default()
    }
    .apply_action_overrides(&mut action);
    assert!(matches!(action.kind, ActionKind::Tunnel));
}

#[test]
fn decision_service_allow_validation_rejects_ipc_override_and_mirror() {
    let mut cfg = test_cfg();
    cfg.allowed_effects.extend([
        "override_upstream".to_string(),
        "mirror_upstreams".to_string(),
    ]);
    let err = EnforceableEffect {
        decision: "allow".to_string(),
        override_upstream: Some("ipc://qpxf.sock".to_string()),
        ..Default::default()
    }
    .into_enforcement(&cfg)
    .expect_err("ipc override should fail");
    assert!(err.to_string().contains("unsupported upstream scheme"));

    let err = EnforceableEffect {
        decision: "allow".to_string(),
        mirror_upstreams: vec!["ipc+unix://qpxf.sock".to_string()],
        ..Default::default()
    }
    .into_enforcement(&cfg)
    .expect_err("ipc mirror should fail");
    assert!(err.to_string().contains("unsupported upstream scheme"));
}

#[tokio::test]
async fn oauth_token_request_sends_form_encoded_client_secret_basic() {
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use zeroize::Zeroizing;

    let client_id = "edge:id with+chars%";
    let client_secret = "s:e c+r%t/u?e@f";
    let expected_userinfo = format!(
        "{}:{}",
        url::form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>(),
        url::form_urlencoded::byte_serialize(client_secret.as_bytes()).collect::<String>(),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock token endpoint");
    let addr = listener.local_addr().expect("mock token addr");
    let (captured_tx, captured_rx) = tokio::sync::oneshot::channel::<(Option<String>, String)>();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept mock token");
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        crate::test_util::read_request_head(&mut stream, &mut raw, &mut buf).await;
        let head_end = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
            .unwrap_or(raw.len());
        let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
        let content_length = crate::test_util::declared_content_length(&head);
        while raw.len() < head_end + content_length {
            let read = stream.read(&mut buf).await.expect("read mock token body");
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..read]);
        }
        let authorization = head
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.trim().to_string());
        let body = String::from_utf8_lossy(&raw[head_end..head_end + content_length]).into_owned();
        let _ = captured_tx.send((authorization, body));
        let response_body =
            r#"{"access_token":"mock-token","token_type":"Bearer","expires_in":3600}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
            response_body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write mock token response");
    });

    let mut cfg = test_cfg();
    cfg.timeout = Duration::from_secs(5);
    let pools = crate::pool::PoolRegistry::new();
    let provider = OAuth2ClientCredentialsProvider {
        endpoint: Url::parse(&format!("http://{addr}/token")).expect("mock token url"),
        client_id: client_id.to_string(),
        client_secret: Some(Zeroizing::new(client_secret.to_string())),
        private_key: None,
        key_id: None,
        scope: None,
        resource: None,
        client_auth_method: qpx_core::config::OAuth2ClientAuthMethod::ClientSecretBasic,
        token: tokio::sync::Mutex::new(None),
    };
    let token = fetch_oauth2_client_credentials_token(&pools, &cfg, &provider)
        .await
        .expect("mock token fetch succeeds");
    assert_eq!(&*token, "mock-token");

    let (authorization, body) = tokio::time::timeout(Duration::from_secs(5), captured_rx)
        .await
        .expect("mock token capture arrives")
        .expect("mock token sender");
    let encoded = authorization
        .as_deref()
        .and_then(|value| value.strip_prefix("Basic "))
        .expect("token request uses Basic auth");
    let decoded = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("Basic body is base64"),
    )
    .expect("Basic body is UTF-8");
    assert_eq!(decoded, expected_userinfo);
    assert_ne!(decoded, format!("{client_id}:{client_secret}"));
    let pairs: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
    assert_eq!(
        pairs.get("grant_type").map(String::as_str),
        Some("client_credentials")
    );
    assert!(!pairs.contains_key("client_secret"));
}
