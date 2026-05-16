use super::crypto::JwtAlgorithm;
use super::identity::ResolvedIdentity;
use super::util::{
    decode_jwt_segment, extract_assertion_token, json_list_claim, json_string_claim,
    load_hmac_secret_from_env, load_public_key_from_env, validate_registered_claims,
};
use anyhow::{Result, anyhow};
use http::header::HeaderName;
use hyper::HeaderMap;
use metrics::counter;
use qpx_core::config::{AssertionClaimsMapConfig, SignedAssertionConfig};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::sync::Arc;
use tracing::warn;

#[derive(Debug, Clone)]
pub(super) struct CompiledSignedAssertion {
    name: String,
    pub(super) header: HeaderName,
    prefix: Option<String>,
    algorithms: Vec<JwtAlgorithm>,
    issuer: Option<String>,
    audience: Option<String>,
    hmac_secret: Option<Arc<[u8]>>,
    public_key: Option<Arc<[u8]>>,
    claims: CompiledAssertionClaims,
}

#[derive(Debug, Clone)]
struct CompiledAssertionClaims {
    user: Option<String>,
    groups: Option<String>,
    device_id: Option<String>,
    posture: Option<String>,
    tenant: Option<String>,
    auth_strength: Option<String>,
    idp: Option<String>,
    user_from_sub: bool,
    groups_separator: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
}
impl CompiledSignedAssertion {
    pub(super) fn from_config(name: &str, config: &SignedAssertionConfig) -> Result<Self> {
        let header = HeaderName::from_bytes(config.header.as_bytes())?;
        let hmac_secret = config
            .secret_env
            .as_deref()
            .filter(|env| !env.trim().is_empty())
            .map(load_hmac_secret_from_env)
            .transpose()?;
        let public_key = config
            .public_key_env
            .as_deref()
            .filter(|env| !env.trim().is_empty())
            .map(load_public_key_from_env)
            .transpose()?;
        let algorithms = default_signed_assertion_algorithms(
            config,
            hmac_secret.is_some(),
            public_key.is_some(),
        )?;
        Ok(Self {
            name: name.to_string(),
            header,
            prefix: config.prefix.clone(),
            algorithms,
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            hmac_secret,
            public_key,
            claims: CompiledAssertionClaims::from_config(&config.claims),
        })
    }

    pub(super) fn extract(&self, headers: &HeaderMap) -> Result<ResolvedIdentity> {
        let Some(token) = extract_assertion_token(headers, &self.header, self.prefix.as_deref())
        else {
            return Ok(ResolvedIdentity::default());
        };
        match self.verify_and_extract(token) {
            Ok(identity) => Ok(identity),
            Err(err) => {
                warn!(
                    source = %self.name,
                    header = %self.header,
                    error = ?err,
                    "signed assertion verification failed"
                );
                counter!(
                    "qpx_signed_assertion_verification_failed_total",
                    "source" => self.name.clone(),
                )
                .increment(1);
                Err(anyhow!("invalid signed assertion {}: {err}", self.name))
            }
        }
    }

    fn verify_and_extract(&self, token: &str) -> Result<ResolvedIdentity> {
        let mut parts = token.split('.');
        let header_segment = parts.next().ok_or_else(|| anyhow!("missing JWT header"))?;
        let payload_segment = parts.next().ok_or_else(|| anyhow!("missing JWT payload"))?;
        let signature_segment = parts
            .next()
            .ok_or_else(|| anyhow!("missing JWT signature"))?;
        if parts.next().is_some() {
            return Err(anyhow!("JWT must contain exactly 3 segments"));
        }

        let header: JwtHeader = serde_json::from_slice(&decode_jwt_segment(header_segment)?)?;
        let algorithm = self
            .algorithms
            .iter()
            .copied()
            .find(|alg| alg.header_name() == header.alg.trim().to_ascii_uppercase())
            .ok_or_else(|| anyhow!("JWT algorithm {} is not allowed", header.alg))?;
        let signed = format!("{header_segment}.{payload_segment}");
        let signature = decode_jwt_segment(signature_segment)?;
        algorithm.verify(
            self.hmac_secret.as_deref(),
            self.public_key.as_deref(),
            signed.as_bytes(),
            signature.as_slice(),
        )?;

        let payload: JsonValue = serde_json::from_slice(&decode_jwt_segment(payload_segment)?)?;
        validate_registered_claims(&payload, self.issuer.as_deref(), self.audience.as_deref())?;
        self.claims.extract(self.name.as_str(), &payload)
    }
}

fn default_signed_assertion_algorithms(
    config: &SignedAssertionConfig,
    has_hmac_secret: bool,
    has_public_key: bool,
) -> Result<Vec<JwtAlgorithm>> {
    if !config.algorithms.is_empty() {
        return config
            .algorithms
            .iter()
            .map(|alg| JwtAlgorithm::parse(alg))
            .collect::<Result<Vec<_>>>();
    }

    let mut algorithms = Vec::new();
    if has_hmac_secret {
        algorithms.push(JwtAlgorithm::Hs256);
    }
    if has_public_key {
        algorithms.extend([
            JwtAlgorithm::Rs256,
            JwtAlgorithm::Rs384,
            JwtAlgorithm::Rs512,
            JwtAlgorithm::Es256,
            JwtAlgorithm::Es384,
        ]);
    }
    if algorithms.is_empty() {
        algorithms.push(JwtAlgorithm::Hs256);
    }
    Ok(algorithms)
}

impl CompiledAssertionClaims {
    fn from_config(config: &AssertionClaimsMapConfig) -> Self {
        Self {
            user: config.user.clone(),
            groups: config.groups.clone(),
            device_id: config.device_id.clone(),
            posture: config.posture.clone(),
            tenant: config.tenant.clone(),
            auth_strength: config.auth_strength.clone(),
            idp: config.idp.clone(),
            user_from_sub: config.user_from_sub,
            groups_separator: config.groups_separator.clone(),
        }
    }

    fn extract(&self, source_name: &str, payload: &JsonValue) -> Result<ResolvedIdentity> {
        let mut identity = ResolvedIdentity::default();
        if self.user_from_sub {
            identity.user = json_string_claim(payload, "sub");
        }
        if identity.user.is_none() {
            identity.user = self
                .user
                .as_deref()
                .and_then(|claim| json_string_claim(payload, claim));
        }
        identity.groups = self
            .groups
            .as_deref()
            .map(|claim| json_list_claim(payload, claim, self.groups_separator.as_deref()))
            .unwrap_or_default();
        identity.device_id = self
            .device_id
            .as_deref()
            .and_then(|claim| json_string_claim(payload, claim));
        identity.posture = self
            .posture
            .as_deref()
            .map(|claim| json_list_claim(payload, claim, None))
            .unwrap_or_default();
        identity.tenant = self
            .tenant
            .as_deref()
            .and_then(|claim| json_string_claim(payload, claim));
        identity.auth_strength = self
            .auth_strength
            .as_deref()
            .and_then(|claim| json_string_claim(payload, claim));
        identity.idp = self
            .idp
            .as_deref()
            .and_then(|claim| json_string_claim(payload, claim));
        if identity.user.is_some()
            || !identity.groups.is_empty()
            || identity.device_id.is_some()
            || !identity.posture.is_empty()
            || identity.tenant.is_some()
            || identity.auth_strength.is_some()
            || identity.idp.is_some()
        {
            identity.identity_source = Some(source_name.to_string());
        }
        Ok(identity)
    }
}
#[cfg(test)]
mod tests {
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
    fn signed_assertion_accepts_es256_public_key_tokens() {
        let _guard = crate::test_env_lock().lock().expect("env lock");
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
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
        let compiled =
            CompiledSignedAssertion::from_config("signed-jwt", &config).expect("compile");
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
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
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
        let compiled =
            CompiledSignedAssertion::from_config("signed-jwt", &config).expect("compile");
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
}
