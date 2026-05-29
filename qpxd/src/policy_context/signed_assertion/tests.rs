use super::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::HeaderValue;
use qpx_core::config::{AssertionClaimsMapConfig, SignedAssertionConfig};
use ring::{rand::SystemRandom, signature};
use serde_json::json;

fn test_env_name(label: &str) -> String {
    format!(
        "QPX_TEST_{}_{}_{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

fn set_test_env(key: &str, value: impl AsRef<std::ffi::OsStr>) {
    // SAFETY: these tests hold crate::test_env_lock(), use process-unique keys,
    // and remove the variable before releasing the lock.
    unsafe {
        std::env::set_var(key, value);
    }
}

fn remove_test_env(key: impl AsRef<std::ffi::OsStr>) {
    // SAFETY: these tests hold crate::test_env_lock() and use process-unique keys.
    unsafe {
        std::env::remove_var(key);
    }
}

fn encode_segment(value: &JsonValue) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("segment json"))
}

fn sign_es256_jwt(private_key_der: &[u8], payload: JsonValue) -> String {
    let header = json!({
        "alg": "ES256",
        "typ": "JWT"
    });
    let header_segment = encode_segment(&header);
    let payload_segment = encode_segment(&payload);
    let signing_input = format!("{header_segment}.{payload_segment}");
    let rng = SystemRandom::new();
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        private_key_der,
        &rng,
    )
    .expect("ecdsa keypair");
    let signature = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("ecdsa sign");
    format!(
        "{}.{}",
        signing_input,
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    )
}

fn compiled_hs256() -> CompiledSignedAssertion {
    CompiledSignedAssertion {
        name: "signed-jwt".to_string(),
        header: HeaderName::from_static("x-assertion"),
        prefix: None,
        algorithms: vec![JwtAlgorithm::Hs256],
        issuer: None,
        audience: None,
        hmac_secret: Some(Arc::from(&b"secret"[..])),
        public_key: None,
        claims: CompiledAssertionClaims::from_config(&AssertionClaimsMapConfig {
            user_from_sub: true,
            ..Default::default()
        }),
    }
}

fn sign_hs256_jwt(payload: JsonValue) -> String {
    let header = json!({"alg": "HS256", "typ": "JWT"});
    let header_segment = encode_segment(&header);
    let payload_segment = encode_segment(&payload);
    let signing_input = format!("{header_segment}.{payload_segment}");
    let signature = crate::policy_context::util::hmac_digest::<sha2::Sha256>(
        b"secret",
        signing_input.as_bytes(),
        64,
    );
    format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature))
}

#[test]
fn jwt_missing_header_segment() {
    assert!(compiled_hs256().verify_and_extract("payload.sig").is_err());
}

#[test]
fn jwt_empty_segments() {
    assert!(compiled_hs256().verify_and_extract("..sig").is_err());
}

#[test]
fn jwt_invalid_base64_header() {
    assert!(
        compiled_hs256()
            .verify_and_extract("%%% .payload.sig")
            .is_err()
    );
}

#[test]
fn jwt_unsupported_algorithm() {
    let header = encode_segment(&json!({"alg": "none"}));
    let payload = encode_segment(&json!({"sub": "alice"}));
    assert!(
        compiled_hs256()
            .verify_and_extract(format!("{header}.{payload}.sig").as_str())
            .is_err()
    );
}

#[test]
fn jwt_expired_claim() {
    let token = sign_hs256_jwt(json!({"sub": "alice", "exp": 1}));
    assert!(compiled_hs256().verify_and_extract(token.as_str()).is_err());
}

#[test]
fn jwt_missing_exp_claim() {
    let token = sign_hs256_jwt(json!({"sub": "alice"}));
    let err = compiled_hs256()
        .verify_and_extract(token.as_str())
        .expect_err("signed assertion identity token must carry exp");
    assert!(err.to_string().contains("exp claim is missing"));
}

#[test]
fn signed_assertion_accepts_es256_public_key_tokens() {
    let _guard = crate::test_env_lock().lock().expect("env lock");
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
    let private_key_der = key_pair.serialize_der();
    let public_key_pem = key_pair.public_key_pem();
    let env_name = test_env_name("ASSERTION_PUBLIC_KEY");
    set_test_env(&env_name, public_key_pem);

    let config = SignedAssertionConfig {
        header: "x-assertion".to_string(),
        algorithms: vec!["ES256".to_string()],
        public_key_env: Some(env_name.clone()),
        claims: AssertionClaimsMapConfig {
            user_from_sub: true,
            groups: Some("groups".to_string()),
            groups_separator: Some(",".to_string()),
            tenant: Some("tenant".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let compiled = CompiledSignedAssertion::from_config("signed-jwt", &config).expect("compile");
    let token = sign_es256_jwt(
        private_key_der.as_slice(),
        json!({
            "sub": "alice",
            "groups": ["eng", "ops"],
            "tenant": "acme",
            "exp": i64::MAX,
        }),
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        "x-assertion",
        HeaderValue::from_str(token.as_str()).expect("header value"),
    );
    let identity = compiled.extract(&headers).expect("valid assertion");

    assert_eq!(identity.user.as_deref(), Some("alice"));
    assert_eq!(identity.groups, vec!["eng".to_string(), "ops".to_string()]);
    assert_eq!(identity.tenant.as_deref(), Some("acme"));
    assert_eq!(identity.identity_source.as_deref(), Some("signed-jwt"));

    remove_test_env(env_name);
}

#[test]
fn signed_assertion_defaults_to_public_key_algorithms() {
    let _guard = crate::test_env_lock().lock().expect("env lock");
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
    let private_key_der = key_pair.serialize_der();
    let public_key_pem = key_pair.public_key_pem();
    let env_name = test_env_name("ASSERTION_PUBLIC_KEY_DEFAULT");
    set_test_env(&env_name, public_key_pem);

    let config = SignedAssertionConfig {
        header: "x-assertion".to_string(),
        algorithms: Vec::new(),
        public_key_env: Some(env_name.clone()),
        claims: AssertionClaimsMapConfig {
            user_from_sub: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let compiled = CompiledSignedAssertion::from_config("signed-jwt", &config).expect("compile");
    let token = sign_es256_jwt(
        private_key_der.as_slice(),
        json!({
            "sub": "alice",
            "exp": i64::MAX,
        }),
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        "x-assertion",
        HeaderValue::from_str(token.as_str()).expect("header value"),
    );
    let identity = compiled.extract(&headers).expect("valid assertion");

    assert_eq!(identity.user.as_deref(), Some("alice"));

    remove_test_env(env_name);
}

#[test]
fn signed_assertion_rejects_invalid_present_token() {
    let mut headers = HeaderMap::new();
    headers.insert("x-assertion", HeaderValue::from_static("not-a-jwt"));

    assert!(compiled_hs256().extract(&headers).is_err());
}
