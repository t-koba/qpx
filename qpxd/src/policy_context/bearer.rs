use super::crypto::JwtAlgorithm;
use super::identity::IdentityRequestContext;
use super::identity::ResolvedIdentity;
use super::signed_assertion::CompiledAssertionClaims;
use super::util::{decode_jwt_segment, json_i64_claim, load_public_key_from_env};
use crate::runtime::RuntimeState;
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::HeaderName;
use http_body_util::BodyExt as _;
use hyper::{HeaderMap, Request};
use qpx_core::config::{BearerIdentityConfig, BearerIdentitySourceConfig, DpopConfig};
use qpx_core::dpop::{
    DpopAlgorithm, DpopError, DpopJwk, DpopPolicy, DpopReplayError, DpopReplayKey, DpopReplayStore,
    DpopSignatureError, DpopSignatureVerifier, DpopValidationContext, access_token_jkt,
    validate_dpop,
};
use qpx_http::body::Body;
use qpx_http::problem::{PROBLEM_JSON, ProblemDetails};
use ring::signature;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant, timeout};
use url::Url;
use zeroize::Zeroizing;

const MAX_AUTHORITY_RESPONSE_BYTES: usize = 1024 * 1024;
const AUTHORITY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(super) struct CompiledBearerIdentity {
    name: String,
    header: HeaderName,
    claims: CompiledAssertionClaims,
    source: BearerSource,
    dpop: Option<DpopRuntime>,
}

#[derive(Debug)]
struct DpopRuntime {
    required: bool,
    policy: DpopPolicy,
    algorithms: Vec<DpopAlgorithm>,
    nonce: Option<String>,
    replay: StdMutex<DpopReplayCache>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DpopAuthErrorCode {
    InvalidProof,
    UseNonce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticationErrorCode {
    Dpop(DpopAuthErrorCode),
    DpopInvalidToken,
    BearerInvalidToken,
}

#[derive(Debug, Error)]
#[error("{detail}")]
pub(crate) struct BearerAuthenticationError {
    detail: String,
    nonce: Option<String>,
    code: AuthenticationErrorCode,
}

impl BearerAuthenticationError {
    fn new(detail: impl Into<String>, nonce: Option<&str>) -> Self {
        Self {
            detail: detail.into(),
            nonce: nonce.map(str::to_string),
            code: AuthenticationErrorCode::Dpop(DpopAuthErrorCode::InvalidProof),
        }
    }

    fn with_nonce_challenge(detail: impl Into<String>, nonce: Option<&str>) -> Self {
        Self {
            detail: detail.into(),
            nonce: nonce.map(str::to_string),
            code: AuthenticationErrorCode::Dpop(DpopAuthErrorCode::UseNonce),
        }
    }

    fn dpop_invalid_token(detail: impl Into<String>, nonce: Option<&str>) -> Self {
        Self {
            detail: detail.into(),
            nonce: nonce.map(str::to_string),
            code: AuthenticationErrorCode::DpopInvalidToken,
        }
    }

    fn bearer_invalid_token(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            nonce: None,
            code: AuthenticationErrorCode::BearerInvalidToken,
        }
    }

    pub(crate) fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    fn challenge(&self) -> String {
        match self.code {
            AuthenticationErrorCode::Dpop(DpopAuthErrorCode::InvalidProof) => {
                "DPoP error=\"invalid_dpop_proof\"".to_string()
            }
            AuthenticationErrorCode::Dpop(DpopAuthErrorCode::UseNonce) => {
                "DPoP error=\"use_dpop_nonce\"".to_string()
            }
            AuthenticationErrorCode::DpopInvalidToken => "DPoP error=\"invalid_token\"".to_string(),
            AuthenticationErrorCode::BearerInvalidToken => {
                "Bearer error=\"invalid_token\"".to_string()
            }
        }
    }

    fn error_code(&self) -> &'static str {
        match self.code {
            AuthenticationErrorCode::Dpop(DpopAuthErrorCode::InvalidProof) => "invalid_dpop_proof",
            AuthenticationErrorCode::Dpop(DpopAuthErrorCode::UseNonce) => "use_dpop_nonce",
            AuthenticationErrorCode::DpopInvalidToken => "invalid_token",
            AuthenticationErrorCode::BearerInvalidToken => "invalid_token",
        }
    }

    fn is_dpop(&self) -> bool {
        matches!(
            self.code,
            AuthenticationErrorCode::Dpop(_) | AuthenticationErrorCode::DpopInvalidToken
        )
    }
}

pub(crate) fn authentication_response(
    method: &http::Method,
    version: http::Version,
    proxy_name: &str,
    error: &BearerAuthenticationError,
) -> Result<hyper::Response<Body>> {
    let challenge = error.challenge();
    let title = if error.is_dpop() {
        "DPoP authentication required"
    } else {
        "Bearer authentication required"
    };
    let body = ProblemDetails::new(http::StatusCode::UNAUTHORIZED, title)
        .with_detail(error.to_string())
        .with_extension(
            "error",
            serde_json::Value::String(error.error_code().to_string()),
        )?
        .to_json()?;
    let mut builder = hyper::Response::builder()
        .status(http::StatusCode::UNAUTHORIZED)
        .header(http::header::WWW_AUTHENTICATE, challenge)
        .header(http::header::CONTENT_TYPE, PROBLEM_JSON);
    if error.is_dpop()
        && let Some(nonce) = error.nonce()
    {
        builder = builder.header("DPoP-Nonce", nonce);
    }
    let mut response = builder.body(Body::from(body))?;
    response = crate::http::protocol::l7::finalize_response_for_request(
        method, version, proxy_name, response, false,
    );
    Ok(response)
}

pub(crate) fn authentication_response_for_error(
    method: &http::Method,
    version: http::Version,
    proxy_name: &str,
    error: &anyhow::Error,
) -> Option<Result<hyper::Response<Body>>> {
    error
        .downcast_ref::<BearerAuthenticationError>()
        .map(|error| authentication_response(method, version, proxy_name, error))
}

#[derive(Debug)]
struct DpopReplayCache {
    entries: HashMap<(String, String), i64>,
    capacity: usize,
    lifetime_seconds: u64,
}

impl DpopRuntime {
    fn from_config(config: &DpopConfig) -> Result<Self> {
        let policy = DpopPolicy::new(config.max_age_seconds, config.clock_skew_seconds)
            .map_err(|error| anyhow!("invalid DPoP policy: {error}"))?;
        let algorithms = config
            .algorithms
            .iter()
            .map(|algorithm| {
                let algorithm = DpopAlgorithm::parse(algorithm.trim())
                    .map_err(|error| anyhow!("invalid DPoP algorithm: {error}"))?;
                if !matches!(
                    algorithm,
                    DpopAlgorithm::Es256
                        | DpopAlgorithm::Es384
                        | DpopAlgorithm::Rs256
                        | DpopAlgorithm::Rs384
                        | DpopAlgorithm::Rs512
                        | DpopAlgorithm::Ed25519
                ) {
                    return Err(anyhow!(
                        "DPoP algorithm {} is unavailable in the ring backend",
                        algorithm.as_str()
                    ));
                }
                Ok(algorithm)
            })
            .collect::<Result<Vec<_>>>()?;
        if algorithms.is_empty() {
            return Err(anyhow!("DPoP algorithm allow-list must not be empty"));
        }
        let lifetime_seconds = config
            .max_age_seconds
            .saturating_add(config.clock_skew_seconds);
        Ok(Self {
            required: config.required,
            policy,
            algorithms,
            nonce: config.nonce.clone(),
            replay: StdMutex::new(DpopReplayCache {
                entries: HashMap::new(),
                capacity: config.replay_cache_capacity,
                lifetime_seconds,
            }),
        })
    }

    fn validate(
        &self,
        headers: &HeaderMap,
        access_token: &str,
        payload: &Value,
        request: &IdentityRequestContext,
    ) -> Result<()> {
        let expected_jkt = access_token_jkt(payload).map_err(|error| {
            BearerAuthenticationError::new(
                format!("DPoP access token binding is invalid: {error}"),
                self.nonce.as_deref(),
            )
        })?;
        let context = DpopValidationContext {
            method: request.method.as_str(),
            request_uri: request.request_uri.as_str(),
            access_token: Some(access_token),
            expected_jkt: Some(expected_jkt.as_str()),
            expected_nonce: self.nonce.as_deref(),
            now: unix_seconds(),
        };
        let verifier = RingDpopSignatureVerifier {
            algorithms: &self.algorithms,
        };
        let mut replay = self
            .replay
            .lock()
            .map_err(|_| anyhow!("DPoP replay store lock is poisoned"))?;
        validate_dpop(headers, &context, self.policy, &verifier, &mut *replay).map_err(
            |error| {
                let detail = format!("DPoP validation failed: {error}");
                if matches!(error, DpopError::InvalidNonce) {
                    BearerAuthenticationError::with_nonce_challenge(detail, self.nonce.as_deref())
                } else {
                    BearerAuthenticationError::new(detail, self.nonce.as_deref())
                }
            },
        )?;
        Ok(())
    }
}

impl DpopReplayStore for DpopReplayCache {
    fn check_and_store(&mut self, key: &DpopReplayKey) -> std::result::Result<(), DpopReplayError> {
        let now = unix_seconds();
        self.entries.retain(|_, expires_at| *expires_at > now);
        let replay_key = (key.jkt.clone(), key.jti.clone());
        if self.entries.contains_key(&replay_key) {
            return Err(DpopReplayError::Replay);
        }
        if self.entries.len() >= self.capacity {
            return Err(DpopReplayError::Unavailable);
        }
        let lifetime = i64::try_from(self.lifetime_seconds).unwrap_or(i64::MAX);
        let expires_at = key.iat.saturating_add(lifetime).max(now.saturating_add(1));
        self.entries.insert(replay_key, expires_at);
        Ok(())
    }
}

struct RingDpopSignatureVerifier<'a> {
    algorithms: &'a [DpopAlgorithm],
}

impl DpopSignatureVerifier for RingDpopSignatureVerifier<'_> {
    fn verify(
        &self,
        algorithm: DpopAlgorithm,
        key: &DpopJwk,
        signing_input: &[u8],
        signature_bytes: &[u8],
    ) -> std::result::Result<(), DpopSignatureError> {
        if !self.algorithms.contains(&algorithm) {
            return Err(DpopSignatureError::Unavailable);
        }
        let (verification_algorithm, public_key): (
            &'static dyn signature::VerificationAlgorithm,
            Vec<u8>,
        ) = match algorithm {
            DpopAlgorithm::Es256 => (
                &signature::ECDSA_P256_SHA256_FIXED,
                key.ec_uncompressed_point()
                    .ok_or(DpopSignatureError::Invalid)?,
            ),
            DpopAlgorithm::Es384 => (
                &signature::ECDSA_P384_SHA384_FIXED,
                key.ec_uncompressed_point()
                    .ok_or(DpopSignatureError::Invalid)?,
            ),
            DpopAlgorithm::Rs256 => (
                &signature::RSA_PKCS1_2048_8192_SHA256,
                der_rsa_public_key(
                    key.n_bytes().ok_or(DpopSignatureError::Invalid)?,
                    key.e_bytes().ok_or(DpopSignatureError::Invalid)?,
                ),
            ),
            DpopAlgorithm::Rs384 => (
                &signature::RSA_PKCS1_2048_8192_SHA384,
                der_rsa_public_key(
                    key.n_bytes().ok_or(DpopSignatureError::Invalid)?,
                    key.e_bytes().ok_or(DpopSignatureError::Invalid)?,
                ),
            ),
            DpopAlgorithm::Rs512 => (
                &signature::RSA_PKCS1_2048_8192_SHA512,
                der_rsa_public_key(
                    key.n_bytes().ok_or(DpopSignatureError::Invalid)?,
                    key.e_bytes().ok_or(DpopSignatureError::Invalid)?,
                ),
            ),
            DpopAlgorithm::Ed25519 => (
                &signature::ED25519,
                key.x_bytes().ok_or(DpopSignatureError::Invalid)?.to_vec(),
            ),
            DpopAlgorithm::Es512
            | DpopAlgorithm::Ps256
            | DpopAlgorithm::Ps384
            | DpopAlgorithm::Ps512 => return Err(DpopSignatureError::Unavailable),
        };
        signature::UnparsedPublicKey::new(verification_algorithm, public_key)
            .verify(signing_input, signature_bytes)
            .map_err(|_| DpopSignatureError::Invalid)
    }
}

#[derive(Debug)]
enum BearerSource {
    Jwt(JwtSource),
    Introspection(IntrospectionSource),
}

#[derive(Debug)]
struct JwtSource {
    issuer: String,
    audience: String,
    algorithms: Vec<JwtAlgorithm>,
    static_key: Option<Arc<[u8]>>,
    jwks: Option<JwksSource>,
    clock_skew_seconds: u64,
}

#[derive(Debug)]
struct JwksSource {
    url: Url,
    cache: Mutex<Option<CachedJwks>>,
}

#[derive(Debug)]
struct CachedJwks {
    keys: Vec<JwkVerificationKey>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct JwkVerificationKey {
    kid: Option<String>,
    algorithm: JwtAlgorithm,
    key: Arc<[u8]>,
}

#[derive(Debug)]
struct IntrospectionSource {
    endpoint: Url,
    client_id: String,
    client_secret: Zeroizing<String>,
    positive_cache_seconds: u64,
    negative_cache_seconds: u64,
    cache: Mutex<HashMap<[u8; 32], CachedIntrospection>>,
}

#[derive(Debug, Clone)]
struct CachedIntrospection {
    payload: Option<Value>,
    expires_at: Instant,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

impl CompiledBearerIdentity {
    pub(super) fn from_config(name: &str, config: &BearerIdentityConfig) -> Result<Self> {
        let header = HeaderName::from_bytes(
            config
                .header
                .as_deref()
                .unwrap_or("authorization")
                .as_bytes(),
        )?;
        let source = match &config.source {
            BearerIdentitySourceConfig::Jwt {
                issuer,
                audience,
                algorithms,
                jwks_url,
                public_key_env,
                clock_skew_seconds,
            } => {
                let algorithms = if algorithms.is_empty() {
                    vec![JwtAlgorithm::Rs256, JwtAlgorithm::Es256]
                } else {
                    algorithms
                        .iter()
                        .map(|value| JwtAlgorithm::parse(value))
                        .collect::<Result<Vec<_>>>()?
                };
                let static_key = public_key_env
                    .as_deref()
                    .map(load_public_key_from_env)
                    .transpose()?;
                let jwks = jwks_url
                    .as_deref()
                    .map(Url::parse)
                    .transpose()?
                    .map(|url| JwksSource {
                        url,
                        cache: Mutex::new(None),
                    });
                BearerSource::Jwt(JwtSource {
                    issuer: issuer.clone(),
                    audience: audience.clone(),
                    algorithms,
                    static_key,
                    jwks,
                    clock_skew_seconds: *clock_skew_seconds,
                })
            }
            BearerIdentitySourceConfig::Introspection {
                endpoint,
                client_id,
                client_secret_env,
                positive_cache_seconds,
                negative_cache_seconds,
            } => BearerSource::Introspection(IntrospectionSource {
                endpoint: Url::parse(endpoint)?,
                client_id: client_id.clone(),
                client_secret: Zeroizing::new(std::env::var(client_secret_env).with_context(
                    || format!("failed to read introspection secret env {client_secret_env}"),
                )?),
                positive_cache_seconds: *positive_cache_seconds,
                negative_cache_seconds: *negative_cache_seconds,
                cache: Mutex::new(HashMap::new()),
            }),
        };
        let dpop = config
            .dpop
            .as_ref()
            .map(DpopRuntime::from_config)
            .transpose()?;
        Ok(Self {
            name: name.to_string(),
            header,
            claims: CompiledAssertionClaims::from_config(&config.claims),
            source,
            dpop,
        })
    }

    pub(super) async fn extract(
        &self,
        state: &RuntimeState,
        headers: &HeaderMap,
        request: Option<&IdentityRequestContext>,
    ) -> Result<ResolvedIdentity> {
        let authorization = match authorization_token(headers, &self.header, self.dpop.is_some()) {
            Ok(authorization) => authorization,
            Err(error) => {
                if let Some(dpop) = self.dpop.as_ref() {
                    return Err(BearerAuthenticationError::new(
                        format!("bearer authorization rejected: {error}"),
                        dpop.nonce.as_deref(),
                    )
                    .into());
                }
                return Err(BearerAuthenticationError::bearer_invalid_token(format!(
                    "bearer authorization rejected: {error}"
                ))
                .into());
            }
        };
        let Some((token, dpop_scheme)) = authorization else {
            if let Some(dpop) = self.dpop.as_ref()
                && (dpop.required || headers.contains_key("dpop"))
            {
                return Err(BearerAuthenticationError::dpop_invalid_token(
                    "DPoP authorization is required",
                    dpop.nonce.as_deref(),
                )
                .into());
            }
            return Ok(ResolvedIdentity::default());
        };
        let payload = match &self.source {
            BearerSource::Jwt(source) => source.verify(state, token).await,
            BearerSource::Introspection(source) => match source.introspect(state, token).await {
                Ok(Some(payload)) => Ok(payload),
                Ok(None) => Err(anyhow!("bearer token is inactive")),
                Err(error) => Err(error),
            },
        };
        let payload = match payload {
            Ok(payload) => payload,
            Err(error) => {
                if let Some(dpop) = self.dpop.as_ref() {
                    let error = if dpop_scheme {
                        BearerAuthenticationError::dpop_invalid_token(
                            format!("bearer token rejected: {error}"),
                            dpop.nonce.as_deref(),
                        )
                    } else {
                        BearerAuthenticationError::bearer_invalid_token(format!(
                            "bearer token rejected: {error}"
                        ))
                    };
                    return Err(error.into());
                }
                return Err(BearerAuthenticationError::bearer_invalid_token(format!(
                    "bearer token rejected: {error}"
                ))
                .into());
            }
        };
        if let Some(dpop) = self.dpop.as_ref() {
            if dpop_scheme {
                let request = request.ok_or_else(|| {
                    BearerAuthenticationError::new(
                        "DPoP validation requires an HTTP request context",
                        dpop.nonce.as_deref(),
                    )
                })?;
                let already_validated = headers
                    .get("dpop")
                    .map(|proof| request.dpop_was_validated(&self.name, proof.as_bytes()))
                    .transpose()?
                    .unwrap_or(false);
                if !already_validated {
                    dpop.validate(headers, token, &payload, request)?;
                    if let Some(proof) = headers.get("dpop") {
                        request.mark_dpop_validated(&self.name, proof.as_bytes())?;
                    }
                }
            } else if dpop.required {
                return Err(BearerAuthenticationError::new(
                    "DPoP authorization scheme is required",
                    dpop.nonce.as_deref(),
                )
                .into());
            } else if headers.contains_key("dpop") {
                return Err(BearerAuthenticationError::new(
                    "DPoP proof requires the DPoP authorization scheme",
                    dpop.nonce.as_deref(),
                )
                .into());
            }
        }
        match self.claims.extract(&self.name, &payload) {
            Ok(identity) => Ok(identity),
            Err(error) => {
                if let Some(dpop) = self.dpop.as_ref() {
                    let error = if dpop_scheme {
                        BearerAuthenticationError::dpop_invalid_token(
                            format!("bearer identity claims rejected: {error}"),
                            dpop.nonce.as_deref(),
                        )
                    } else {
                        BearerAuthenticationError::bearer_invalid_token(format!(
                            "bearer identity claims rejected: {error}"
                        ))
                    };
                    return Err(error.into());
                }
                Err(BearerAuthenticationError::bearer_invalid_token(format!(
                    "bearer identity claims rejected: {error}"
                ))
                .into())
            }
        }
    }
}

impl JwtSource {
    async fn verify(&self, state: &RuntimeState, token: &str) -> Result<Value> {
        let mut segments = token.split('.');
        let header_segment = segments
            .next()
            .ok_or_else(|| anyhow!("missing JWT header"))?;
        let payload_segment = segments
            .next()
            .ok_or_else(|| anyhow!("missing JWT payload"))?;
        let signature_segment = segments
            .next()
            .ok_or_else(|| anyhow!("missing JWT signature"))?;
        if segments.next().is_some() {
            return Err(anyhow!("JWT must contain exactly three segments"));
        }
        let header: JwtHeader = serde_json::from_slice(&decode_jwt_segment(header_segment)?)?;
        let algorithm = JwtAlgorithm::parse(&header.alg)?;
        if !self.algorithms.contains(&algorithm) {
            return Err(anyhow!("JWT algorithm is not allowed"));
        }
        let key = if let Some(key) = self.static_key.as_ref() {
            key.clone()
        } else {
            self.jwks
                .as_ref()
                .ok_or_else(|| anyhow!("JWKS source is unavailable"))?
                .verification_key(state, header.kid.as_deref(), algorithm)
                .await?
        };
        let signed = format!("{header_segment}.{payload_segment}");
        let signature = decode_jwt_segment(signature_segment)?;
        algorithm.verify(None, Some(&key), signed.as_bytes(), &signature)?;
        let payload: Value = serde_json::from_slice(&decode_jwt_segment(payload_segment)?)?;
        validate_claims_with_skew(
            &payload,
            &self.issuer,
            &self.audience,
            self.clock_skew_seconds,
        )?;
        Ok(payload)
    }
}

impl JwksSource {
    async fn verification_key(
        &self,
        state: &RuntimeState,
        kid: Option<&str>,
        algorithm: JwtAlgorithm,
    ) -> Result<Arc<[u8]>> {
        let mut cache = self.cache.lock().await;
        if cache
            .as_ref()
            .is_none_or(|cached| Instant::now() >= cached.expires_at)
        {
            *cache = Some(fetch_jwks(state, &self.url).await?);
        }
        if select_jwks_key(cache.as_ref(), kid, algorithm)?.is_none() {
            *cache = Some(fetch_jwks(state, &self.url).await?);
        }
        select_jwks_key(cache.as_ref(), kid, algorithm)?
            .ok_or_else(|| anyhow!("JWT signing key was not found after JWKS refresh"))
    }
}

fn select_jwks_key(
    cached: Option<&CachedJwks>,
    kid: Option<&str>,
    algorithm: JwtAlgorithm,
) -> Result<Option<Arc<[u8]>>> {
    let Some(cached) = cached else {
        return Ok(None);
    };
    let mut matching = cached.keys.iter().filter(|key| {
        key.algorithm == algorithm && kid.is_none_or(|kid| key.kid.as_deref() == Some(kid))
    });
    let Some(key) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() && kid.is_none() {
        return Err(anyhow!("JWT kid is required when multiple keys match"));
    }
    Ok(Some(key.key.clone()))
}

impl IntrospectionSource {
    async fn introspect(&self, state: &RuntimeState, token: &str) -> Result<Option<Value>> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut cache = self.cache.lock().await;
        cache.retain(|_, entry| Instant::now() < entry.expires_at);
        if let Some(entry) = cache.get(&digest) {
            return Ok(entry.payload.clone());
        }
        let payload = fetch_introspection(state, self, token).await?;
        let now_unix = unix_seconds();
        let ttl = if payload.as_ref().is_some_and(is_active) {
            let exp_ttl = payload
                .as_ref()
                .and_then(|value| json_i64_claim(value, "exp"))
                .map(|exp| exp.saturating_sub(now_unix).max(0) as u64)
                .unwrap_or(self.positive_cache_seconds);
            exp_ttl.min(self.positive_cache_seconds)
        } else {
            self.negative_cache_seconds
        };
        cache.insert(
            digest,
            CachedIntrospection {
                payload: payload.clone(),
                expires_at: Instant::now() + Duration::from_secs(ttl.max(1)),
            },
        );
        Ok(payload)
    }
}

fn authorization_token<'a>(
    headers: &'a HeaderMap,
    header: &HeaderName,
    dpop_enabled: bool,
) -> Result<Option<(&'a str, bool)>> {
    let mut values = headers.get_all(header).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(anyhow!("authorization field must occur exactly once"));
    }
    let value = value
        .to_str()
        .map_err(|_| anyhow!("bearer field is not ASCII"))?;
    let Some((scheme, token)) = value.trim().split_once(' ') else {
        return Err(anyhow!("bearer field is malformed"));
    };
    let dpop_scheme = if scheme.eq_ignore_ascii_case("dpop") {
        if !dpop_enabled {
            return Err(anyhow!("DPoP authorization scheme is not enabled"));
        }
        true
    } else if scheme.eq_ignore_ascii_case("bearer") {
        false
    } else {
        return Err(anyhow!("authorization field is malformed"));
    };
    if token.is_empty() || token.contains(char::is_whitespace) {
        return Err(anyhow!("bearer field is malformed"));
    }
    Ok(Some((token, dpop_scheme)))
}

async fn fetch_jwks(state: &RuntimeState, url: &Url) -> Result<CachedJwks> {
    let request = Request::builder()
        .method(http::Method::GET)
        .uri(url.as_str())
        .body(Body::empty())?;
    let response = authority_request(state, url, request).await?;
    if !response.status().is_success() {
        return Err(anyhow!("JWKS endpoint returned {}", response.status()));
    }
    let max_age = cache_max_age(response.headers()).min(3600);
    let body = response
        .into_body()
        .limit_bytes(MAX_AUTHORITY_RESPONSE_BYTES)
        .collect()
        .await?
        .to_bytes();
    let document: JwksDocument = serde_json::from_slice(&body)?;
    let keys = verification_keys(document)?;
    if keys.is_empty() {
        return Err(anyhow!("JWKS contains no supported verification keys"));
    }
    Ok(CachedJwks {
        keys,
        expires_at: Instant::now() + Duration::from_secs(max_age.max(1)),
    })
}

async fn fetch_introspection(
    state: &RuntimeState,
    source: &IntrospectionSource,
    token: &str,
) -> Result<Option<Value>> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("token", token)
        .finish();
    let credentials = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        source.client_id,
        source.client_secret.as_str()
    ));
    let mut authorization = http::HeaderValue::from_str(&format!("Basic {credentials}"))?;
    authorization.set_sensitive(true);
    let request = Request::builder()
        .method(http::Method::POST)
        .uri(source.endpoint.as_str())
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(http::header::AUTHORIZATION, authorization)
        .body(Body::from(body))?;
    let response = authority_request(state, &source.endpoint, request).await?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "introspection endpoint returned {}",
            response.status()
        ));
    }
    let body = response
        .into_body()
        .limit_bytes(MAX_AUTHORITY_RESPONSE_BYTES)
        .collect()
        .await?
        .to_bytes();
    let payload: Value = serde_json::from_slice(&body)?;
    Ok(is_active(&payload).then_some(payload))
}

async fn authority_request(
    state: &RuntimeState,
    url: &Url,
    request: Request<Body>,
) -> Result<hyper::Response<Body>> {
    timeout(AUTHORITY_TIMEOUT, async {
        match url.scheme() {
            "http" => crate::http::protocol::common::request_with_shared_client(request)
                .await
                .map_err(Into::into),
            "https" => {
                crate::upstream::origin::shared_reverse_https_request_with_trust(
                    &state.pools,
                    request,
                    None,
                )
                .await
            }
            scheme => Err(anyhow!("unsupported authority URL scheme: {scheme}")),
        }
    })
    .await?
}

fn validate_claims_with_skew(
    payload: &Value,
    issuer: &str,
    audience: &str,
    skew: u64,
) -> Result<()> {
    if payload.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(anyhow!("JWT issuer mismatch"));
    }
    let audience_matches = match payload.get("aud") {
        Some(Value::String(value)) => value == audience,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(audience)),
        _ => false,
    };
    if !audience_matches {
        return Err(anyhow!("JWT audience mismatch"));
    }
    let now = unix_seconds();
    let skew = i64::try_from(skew).unwrap_or(i64::MAX);
    let exp = json_i64_claim(payload, "exp").ok_or_else(|| anyhow!("JWT exp is missing"))?;
    if now.saturating_sub(skew) >= exp {
        return Err(anyhow!("JWT is expired"));
    }
    if let Some(nbf) = json_i64_claim(payload, "nbf")
        && now.saturating_add(skew) < nbf
    {
        return Err(anyhow!("JWT is not yet valid"));
    }
    Ok(())
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn is_active(payload: &Value) -> bool {
    payload.get("active").and_then(Value::as_bool) == Some(true)
}

fn cache_max_age(headers: &HeaderMap) -> u64 {
    headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .find_map(|directive| {
            directive
                .trim()
                .strip_prefix("max-age=")
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or(300)
}

#[derive(Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    key_use: Option<String>,
    #[serde(default)]
    key_ops: Option<Vec<String>>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

fn verification_keys(document: JwksDocument) -> Result<Vec<JwkVerificationKey>> {
    document
        .keys
        .into_iter()
        .filter_map(|jwk| match JwkVerificationKey::try_from(jwk) {
            Ok(Some(key)) => Some(Ok(key)),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        })
        .collect()
}

impl JwkVerificationKey {
    fn try_from(jwk: Jwk) -> Result<Option<Self>> {
        if jwk.key_use.as_deref().is_some_and(|value| value != "sig")
            || jwk
                .key_ops
                .as_ref()
                .is_some_and(|operations| !operations.iter().any(|operation| operation == "verify"))
        {
            return Ok(None);
        }
        match jwk.kty.as_str() {
            "EC" if jwk.crv.as_deref() == Some("P-256")
                && jwk
                    .alg
                    .as_deref()
                    .is_none_or(|algorithm| algorithm == "ES256") =>
            {
                let mut key = vec![4];
                key.extend(
                    URL_SAFE_NO_PAD.decode(jwk.x.ok_or_else(|| anyhow!("JWK x is missing"))?)?,
                );
                key.extend(
                    URL_SAFE_NO_PAD.decode(jwk.y.ok_or_else(|| anyhow!("JWK y is missing"))?)?,
                );
                if key.len() != 65 {
                    return Err(anyhow!("P-256 JWK coordinates have invalid length"));
                }
                Ok(Some(Self {
                    kid: jwk.kid,
                    algorithm: JwtAlgorithm::Es256,
                    key: Arc::from(key),
                }))
            }
            "RSA"
                if jwk
                    .alg
                    .as_deref()
                    .is_none_or(|algorithm| matches!(algorithm, "RS256" | "RS384" | "RS512")) =>
            {
                let n =
                    URL_SAFE_NO_PAD.decode(jwk.n.ok_or_else(|| anyhow!("JWK n is missing"))?)?;
                let e =
                    URL_SAFE_NO_PAD.decode(jwk.e.ok_or_else(|| anyhow!("JWK e is missing"))?)?;
                let algorithm = JwtAlgorithm::parse(jwk.alg.as_deref().unwrap_or("RS256"))?;
                Ok(Some(Self {
                    kid: jwk.kid,
                    algorithm,
                    key: Arc::from(der_rsa_public_key(&n, &e)),
                }))
            }
            _ => Ok(None),
        }
    }
}

fn der_rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut body = der_integer(modulus);
    body.extend(der_integer(exponent));
    der_tlv(0x30, &body)
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    let value = value
        .iter()
        .skip_while(|byte| **byte == 0)
        .copied()
        .collect::<Vec<_>>();
    let mut body = if value.first().is_some_and(|byte| byte & 0x80 != 0) {
        let mut prefixed = vec![0];
        prefixed.extend(value);
        prefixed
    } else {
        value
    };
    if body.is_empty() {
        body.push(0);
    }
    der_tlv(0x02, &body)
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if body.len() < 128 {
        output.push(body.len() as u8);
    } else {
        let bytes = body.len().to_be_bytes();
        let significant = bytes
            .iter()
            .skip_while(|byte| **byte == 0)
            .copied()
            .collect::<Vec<_>>();
        output.push(0x80 | significant.len() as u8);
        output.extend(significant);
    }
    output.extend(body);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    fn parse_jwks(json: &str) -> JwksDocument {
        serde_json::from_str(json).expect("JWKS should parse")
    }

    #[test]
    fn ignores_encryption_keys_and_accepts_signature_keys() {
        let document = parse_jwks(
            r#"{"keys":[
                {"kty":"RSA","kid":"enc","use":"enc","alg":"RSA-OAEP","n":"AQ","e":"AQAB"},
                {"kty":"RSA","kid":"sig","use":"sig","key_ops":["verify"],"alg":"RS256","n":"AQ","e":"AQAB"}
            ]}"#,
        );

        let keys = verification_keys(document).expect("verification keys should convert");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid.as_deref(), Some("sig"));
        assert_eq!(keys[0].algorithm, JwtAlgorithm::Rs256);
    }

    #[test]
    fn ignores_keys_without_verify_operation() {
        let document = parse_jwks(
            r#"{"keys":[{"kty":"RSA","kid":"sign-only","use":"sig","key_ops":["sign"],"alg":"RS256","n":"AQ","e":"AQAB"}]}"#,
        );

        let keys = verification_keys(document).expect("non-verification keys should be ignored");

        assert!(keys.is_empty());
    }

    #[test]
    fn rejects_malformed_supported_signature_key() {
        let document = parse_jwks(
            r#"{"keys":[{"kty":"RSA","kid":"broken","use":"sig","alg":"RS256","e":"AQAB"}]}"#,
        );

        let err = verification_keys(document).expect_err("missing modulus must fail");

        assert!(err.to_string().contains("JWK n is missing"));
    }

    #[test]
    fn ring_verifier_accepts_ed25519_proof_signature() {
        let key_pair = signature::Ed25519KeyPair::from_seed_unchecked(&[7u8; 32])
            .expect("test key should be valid");
        let public_key = key_pair.public_key().as_ref();
        let key = DpopJwk::Okp {
            crv: "Ed25519".to_string(),
            x: URL_SAFE_NO_PAD.encode(public_key),
            x_bytes: public_key.to_vec(),
        };
        let input = b"dpop-signing-input";
        let signature = key_pair.sign(input);
        let allowed = [DpopAlgorithm::Ed25519];
        let verifier = RingDpopSignatureVerifier {
            algorithms: &allowed,
        };
        verifier
            .verify(DpopAlgorithm::Ed25519, &key, input, signature.as_ref())
            .expect("ring must verify Ed25519 signatures");
    }

    #[test]
    fn replay_cache_rejects_same_jti_for_same_key() {
        let now = unix_seconds();
        let mut cache = DpopReplayCache {
            entries: HashMap::new(),
            capacity: 2,
            lifetime_seconds: 300,
        };
        let key = DpopReplayKey {
            jkt: "key".to_string(),
            jti: "proof".to_string(),
            iat: now,
        };
        cache
            .check_and_store(&key)
            .expect("first proof should store");
        assert_eq!(cache.check_and_store(&key), Err(DpopReplayError::Replay));
        let same_jti_different_iat = DpopReplayKey {
            iat: now + 1,
            ..key
        };
        assert_eq!(
            cache.check_and_store(&same_jti_different_iat),
            Err(DpopReplayError::Replay)
        );
    }

    #[test]
    fn dpop_authentication_failure_is_structured_401_with_nonce_header() {
        let error = BearerAuthenticationError::new("proof was replayed", Some("server-nonce"));
        let response =
            authentication_response(&http::Method::GET, http::Version::HTTP_11, "qpx", &error)
                .expect("DPoP authentication response should be constructible");

        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some(r#"DPoP error="invalid_dpop_proof""#)
        );
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(PROBLEM_JSON)
        );
        assert_eq!(
            response
                .headers()
                .get("DPoP-Nonce")
                .and_then(|value| value.to_str().ok()),
            Some("server-nonce")
        );
    }

    #[test]
    fn dpop_nonce_failure_uses_nonce_challenge_and_header() {
        let error =
            BearerAuthenticationError::with_nonce_challenge("nonce is missing", Some("nonce-1"));
        let response =
            authentication_response(&http::Method::GET, http::Version::HTTP_2, "qpx", &error)
                .expect("DPoP nonce response should be constructible");

        assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some(r#"DPoP error="use_dpop_nonce""#)
        );
        assert_eq!(
            response
                .headers()
                .get("DPoP-Nonce")
                .and_then(|value| value.to_str().ok()),
            Some("nonce-1")
        );
    }

    #[test]
    fn dpop_missing_credential_uses_invalid_token_challenge() {
        let error = BearerAuthenticationError::dpop_invalid_token(
            "DPoP authorization is required",
            Some("nonce-2"),
        );
        let response =
            authentication_response(&http::Method::GET, http::Version::HTTP_11, "qpx", &error)
                .expect("missing DPoP credential response should be constructible");

        assert_eq!(
            response
                .headers()
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some(r#"DPoP error="invalid_token""#)
        );
        assert_eq!(
            response
                .headers()
                .get("DPoP-Nonce")
                .and_then(|value| value.to_str().ok()),
            Some("nonce-2")
        );
    }

    #[test]
    fn bearer_invalid_token_uses_bearer_challenge_without_dpop_nonce() {
        let error = BearerAuthenticationError::bearer_invalid_token("token is invalid");
        let response =
            authentication_response(&http::Method::GET, http::Version::HTTP_2, "qpx", &error)
                .expect("Bearer authentication response should be constructible");

        assert_eq!(
            response
                .headers()
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some(r#"Bearer error="invalid_token""#)
        );
        assert!(!response.headers().contains_key("DPoP-Nonce"));
    }
}
