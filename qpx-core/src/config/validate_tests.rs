use super::*;
use crate::config::{
    AssertionClaimsMapConfig, IdentitySourceConfig, IdentitySourceKind, SignedAssertionConfig,
    UpstreamTlsTrustConfig, UpstreamTlsTrustProfileConfig,
};

#[test]
fn upstream_tls_trust_rejects_unpaired_client_key() {
    let err = validate_upstream_tls_trust_config(
        Some(&UpstreamTlsTrustConfig {
            pin_sha256: Vec::new(),
            issuer: Vec::new(),
            san_dns: Vec::new(),
            san_uri: Vec::new(),
            client_cert: Some("/tmp/client.crt".into()),
            client_key: None,
        }),
        "listener test",
    )
    .expect_err("validation should fail");
    assert!(err
        .to_string()
        .contains("client_cert and client_key must be set together"));
}

#[test]
fn upstream_tls_trust_rejects_invalid_pin() {
    let err = validate_upstream_tls_trust_config(
        Some(&UpstreamTlsTrustConfig {
            pin_sha256: vec!["xyz".into()],
            issuer: Vec::new(),
            san_dns: Vec::new(),
            san_uri: Vec::new(),
            client_cert: None,
            client_key: None,
        }),
        "reverse route",
    )
    .expect_err("validation should fail");
    assert!(err
        .to_string()
        .contains("pin_sha256 entries must be 64 hex characters"));
}

#[test]
fn upstream_trust_profiles_collect_valid_names() {
    let names = validate_upstream_trust_profiles(&[UpstreamTlsTrustProfileConfig {
        name: "corp".to_string(),
        trust: UpstreamTlsTrustConfig {
            pin_sha256: vec!["aa".repeat(32)],
            issuer: Vec::new(),
            san_dns: Vec::new(),
            san_uri: Vec::new(),
            client_cert: None,
            client_key: None,
        },
    }])
    .expect("valid profiles");
    assert!(names.contains("corp"));
}

#[test]
fn upstream_trust_profile_ref_rejects_unknown_name() {
    let err = validate_upstream_trust_profile_ref(
        Some("missing"),
        &HashSet::new(),
        "listener test tls_inspection",
    )
    .expect_err("unknown profile should fail");
    assert!(err
        .to_string()
        .contains("listener test tls_inspection references unknown upstream_trust_profile"));
}

#[test]
fn signed_assertion_public_key_without_algorithms_is_valid() {
    validate_identity_sources(&[IdentitySourceConfig {
        name: "jwt".to_string(),
        kind: IdentitySourceKind::SignedAssertion,
        from: Default::default(),
        headers: None,
        map: None,
        assertion: Some(SignedAssertionConfig {
            header: "x-assertion".to_string(),
            prefix: None,
            algorithms: Vec::new(),
            issuer: None,
            audience: None,
            secret_env: None,
            public_key_env: Some("JWT_PUBLIC_KEY".to_string()),
            claims: AssertionClaimsMapConfig {
                user_from_sub: true,
                ..Default::default()
            },
        }),
        strip_from_untrusted: false,
    }])
    .expect("public-key signed assertion should validate");
}
