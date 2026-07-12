use super::crypto::JwtAlgorithm;
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
use qpx_core::config::{BearerIdentityConfig, BearerIdentitySourceConfig};
use qpx_http::body::Body;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
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
        Ok(Self {
            name: name.to_string(),
            header,
            claims: CompiledAssertionClaims::from_config(&config.claims),
            source,
        })
    }

    pub(super) async fn extract(
        &self,
        state: &RuntimeState,
        headers: &HeaderMap,
    ) -> Result<ResolvedIdentity> {
        let Some(token) = bearer_token(headers, &self.header)? else {
            return Ok(ResolvedIdentity::default());
        };
        let payload = match &self.source {
            BearerSource::Jwt(source) => source.verify(state, token).await?,
            BearerSource::Introspection(source) => {
                let Some(payload) = source.introspect(state, token).await? else {
                    return Err(anyhow!("bearer token is inactive"));
                };
                payload
            }
        };
        self.claims.extract(&self.name, &payload)
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

fn bearer_token<'a>(headers: &'a HeaderMap, header: &HeaderName) -> Result<Option<&'a str>> {
    let Some(value) = headers.get(header) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| anyhow!("bearer field is not ASCII"))?;
    let Some((scheme, token)) = value.trim().split_once(' ') else {
        return Err(anyhow!("bearer field is malformed"));
    };
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.contains(char::is_whitespace)
    {
        return Err(anyhow!("bearer field is malformed"));
    }
    Ok(Some(token))
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
}
