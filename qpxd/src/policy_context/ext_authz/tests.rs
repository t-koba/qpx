use crate::policy_context::ext_authz::*;
use qpx_core::config::HeaderControl;
use std::sync::Arc;
use tokio::time::Duration;

#[test]
fn ext_authz_mode_validation_rejects_unsupported_fields() {
    let allow = ExtAuthzAllow {
        force_inspect: true,
        ..Default::default()
    };
    let err = validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ReverseHttp)
        .expect_err("reverse_edges should reject force_inspect");
    assert!(err.to_string().contains("force_inspect"));

    let allow = ExtAuthzAllow {
        headers: Some(Arc::new(
            CompiledHeaderControl::compile(&HeaderControl::default()).expect("headers"),
        )),
        ..Default::default()
    };
    let err = validate_ext_authz_allow_mode(&allow, ExtAuthzMode::TransparentTls)
        .expect_err("transparent tls should reject header injection");
    assert!(err.to_string().contains("inject_headers"));
}

#[test]
fn ext_authz_mode_validation_accepts_supported_fields() {
    let connect_allow = ExtAuthzAllow {
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

    validate_ext_authz_allow_mode(&connect_allow, ExtAuthzMode::ForwardConnect)
        .expect("forward connect should accept force_inspect");

    let transparent_tls_allow = ExtAuthzAllow {
        override_upstream: connect_allow.override_upstream.clone(),
        timeout_override: connect_allow.timeout_override,
        rate_limit_profile: connect_allow.rate_limit_profile.clone(),
        force_inspect: true,
        ..Default::default()
    };
    validate_ext_authz_allow_mode(&transparent_tls_allow, ExtAuthzMode::TransparentTls)
        .expect("transparent tls should accept force_inspect");

    let http_allow = ExtAuthzAllow {
        headers: connect_allow.headers.clone(),
        override_upstream: connect_allow.override_upstream.clone(),
        timeout_override: connect_allow.timeout_override,
        cache_bypass: true,
        rate_limit_profile: connect_allow.rate_limit_profile.clone(),
        ..Default::default()
    };
    validate_ext_authz_allow_mode(&http_allow, ExtAuthzMode::ForwardHttp)
        .expect("forward http should accept cache_bypass");
    validate_ext_authz_allow_mode(&http_allow, ExtAuthzMode::ReverseHttp)
        .expect("reverse_edges http should accept cache_bypass");

    let reverse_allow = ExtAuthzAllow {
        headers: connect_allow.headers.clone(),
        override_upstream: connect_allow.override_upstream.clone(),
        timeout_override: connect_allow.timeout_override,
        mirror_upstreams: vec!["http://mirror.internal:8080".to_string()],
        rate_limit_profile: connect_allow.rate_limit_profile.clone(),
        ..Default::default()
    };
    validate_ext_authz_allow_mode(&reverse_allow, ExtAuthzMode::ReverseHttp)
        .expect("reverse_edges http should accept mirror_upstreams");
}

#[test]
fn ext_authz_action_overrides_apply_force_modes() {
    let mut action = ActionConfig {
        kind: ActionKind::Tunnel,
        upstream: Some("baseline".to_string()),
        local_response: None,
    };
    apply_ext_authz_action_overrides(
        &mut action,
        &ExtAuthzAllow {
            override_upstream: Some("http://override.internal:8080".to_string()),
            force_inspect: true,
            ..Default::default()
        },
    );
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
    apply_ext_authz_action_overrides(
        &mut action,
        &ExtAuthzAllow {
            force_tunnel: true,
            ..Default::default()
        },
    );
    assert!(matches!(action.kind, ActionKind::Tunnel));
}

#[test]
fn ext_authz_local_response_validation_rejects_invalid_status() {
    let response: ExtAuthzResponse = serde_json::from_str(
        r#"{
                "decision": "local_response",
                "local_response": {
                    "status": 700,
                    "body": "bad"
                }
            }"#,
    )
    .expect("response json");

    let err = response
        .into_enforcement()
        .expect_err("invalid local response status should fail");
    assert!(err.to_string().contains("status must be in 200..=599"));
}

#[test]
fn ext_authz_local_response_validation_rejects_invalid_rpc_trailer() {
    let response: ExtAuthzResponse = serde_json::from_str(
        r#"{
                "decision": "local_response",
                "local_response": {
                    "status": 403,
                    "rpc": {
                        "protocol": "grpc_web",
                        "status": "7",
                        "trailers": {
                            "grpc-message": "bad\ninjected: yes"
                        }
                    }
                }
            }"#,
    )
    .expect("response json");

    let err = response
        .into_enforcement()
        .expect_err("invalid grpc-web trailer should fail");
    assert!(err.to_string().contains("trailers has invalid value"));
}

#[test]
fn ext_authz_allow_validation_rejects_ipc_override_and_mirror() {
    let response: ExtAuthzResponse = serde_json::from_str(
        r#"{
                "decision": "allow",
                "override_upstream": "ipc://qpxf.sock"
            }"#,
    )
    .expect("response json");
    let err = response
        .into_enforcement()
        .expect_err("ipc override should fail");
    assert!(err.to_string().contains("unsupported upstream scheme"));

    let response: ExtAuthzResponse = serde_json::from_str(
        r#"{
                "decision": "allow",
                "mirror_upstreams": ["ipc+unix://qpxf.sock"]
            }"#,
    )
    .expect("response json");
    let err = response
        .into_enforcement()
        .expect_err("ipc mirror should fail");
    assert!(err.to_string().contains("unsupported upstream scheme"));
}
