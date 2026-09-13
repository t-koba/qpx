//! DPoP (Demonstrating Proof of Possession) validation primitives.
//!
//! This module deliberately owns protocol validation only. Signature
//! verification and replay persistence are supplied by the caller through
//! [`crate::dpop::DpopSignatureVerifier`] and [`crate::dpop::DpopReplayStore`]. Keeping those operations
//! behind explicit interfaces prevents an unavailable security dependency or
//! replay database from becoming an accidental allow path.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::HeaderMap;
use serde::de::{DeserializeSeed, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use url::Url;

const DPOP_HEADER: &str = "dpop";
const MAX_PROOF_BYTES: usize = 64 * 1024;
const MAX_ACCESS_TOKEN_BYTES: usize = 64 * 1024;
const MAX_JTI_BYTES: usize = 512;
const MAX_NONCE_BYTES: usize = 512;
const DEFAULT_MAX_AGE_SECONDS: u64 = 300;
const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 5;

/// A DPoP signature algorithm accepted by the protocol validator.
///
/// Symmetric JWS algorithms are intentionally absent. DPoP proofs are bound
/// to a public key carried by the proof and therefore must use an asymmetric
/// signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DpopAlgorithm {
    /// ECDSA using P-256 and SHA-256.
    Es256,
    /// ECDSA using P-384 and SHA-384.
    Es384,
    /// ECDSA using P-521 and SHA-512.
    Es512,
    /// RSA PKCS#1 v1.5 using SHA-256.
    Rs256,
    /// RSA PKCS#1 v1.5 using SHA-384.
    Rs384,
    /// RSA PKCS#1 v1.5 using SHA-512.
    Rs512,
    /// RSA-PSS using SHA-256.
    Ps256,
    /// RSA-PSS using SHA-384.
    Ps384,
    /// RSA-PSS using SHA-512.
    Ps512,
    /// EdDSA using an Ed25519 public key.
    Ed25519,
}

impl DpopAlgorithm {
    /// Parses a JOSE `alg` value.
    pub fn parse(value: &str) -> Result<Self, DpopError> {
        match value {
            "ES256" => Ok(Self::Es256),
            "ES384" => Ok(Self::Es384),
            "ES512" => Ok(Self::Es512),
            "RS256" => Ok(Self::Rs256),
            "RS384" => Ok(Self::Rs384),
            "RS512" => Ok(Self::Rs512),
            "PS256" => Ok(Self::Ps256),
            "PS384" => Ok(Self::Ps384),
            "PS512" => Ok(Self::Ps512),
            "EdDSA" => Ok(Self::Ed25519),
            _ => Err(DpopError::UnsupportedAlgorithm(value.to_string())),
        }
    }

    /// Returns the JOSE `alg` spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Ed25519 => "EdDSA",
        }
    }

    fn matches_key(self, key: &DpopJwk) -> bool {
        match (self, key) {
            (Self::Es256, DpopJwk::Ec { crv, .. }) => crv == "P-256",
            (Self::Es384, DpopJwk::Ec { crv, .. }) => crv == "P-384",
            (Self::Es512, DpopJwk::Ec { crv, .. }) => crv == "P-521",
            (
                Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512,
                DpopJwk::Rsa { .. },
            ) => true,
            (Self::Ed25519, DpopJwk::Okp { crv, .. }) => crv == "Ed25519",
            _ => false,
        }
    }

    fn expected_signature_length(self) -> Option<usize> {
        match self {
            Self::Es256 => Some(64),
            Self::Es384 => Some(96),
            Self::Es512 => Some(132),
            Self::Ed25519 => Some(64),
            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                None
            }
        }
    }
}

/// A validated public JWK embedded in a DPoP proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpopJwk {
    /// An EC public key.
    Ec {
        /// The named curve (`P-256`, `P-384`, or `P-521`).
        crv: String,
        /// Base64url-encoded affine X coordinate.
        x: String,
        /// Base64url-encoded affine Y coordinate.
        y: String,
        /// Decoded affine X coordinate.
        x_bytes: Vec<u8>,
        /// Decoded affine Y coordinate.
        y_bytes: Vec<u8>,
    },
    /// An RSA public key.
    Rsa {
        /// Base64url-encoded modulus.
        n: String,
        /// Base64url-encoded public exponent.
        e: String,
        /// Decoded modulus.
        n_bytes: Vec<u8>,
        /// Decoded public exponent.
        e_bytes: Vec<u8>,
    },
    /// An OKP public key. DPoP currently accepts Ed25519 here.
    Okp {
        /// The named curve (`Ed25519`).
        crv: String,
        /// Base64url-encoded public key bytes.
        x: String,
        /// Decoded public key bytes.
        x_bytes: Vec<u8>,
    },
}

impl DpopJwk {
    /// Returns the JWK key type.
    pub const fn kty(&self) -> &'static str {
        match self {
            Self::Ec { .. } => "EC",
            Self::Rsa { .. } => "RSA",
            Self::Okp { .. } => "OKP",
        }
    }

    /// Returns the EC or OKP curve name, if applicable.
    pub fn crv(&self) -> Option<&str> {
        match self {
            Self::Ec { crv, .. } | Self::Okp { crv, .. } => Some(crv),
            Self::Rsa { .. } => None,
        }
    }

    /// Returns EC or OKP X/public-key bytes, if applicable.
    pub fn x_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Ec { x_bytes, .. } | Self::Okp { x_bytes, .. } => Some(x_bytes),
            Self::Rsa { .. } => None,
        }
    }

    /// Returns EC Y-coordinate bytes, if applicable.
    pub fn y_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Ec { y_bytes, .. } => Some(y_bytes),
            Self::Rsa { .. } | Self::Okp { .. } => None,
        }
    }

    /// Returns the RSA modulus bytes, if applicable.
    pub fn n_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Rsa { n_bytes, .. } => Some(n_bytes),
            Self::Ec { .. } | Self::Okp { .. } => None,
        }
    }

    /// Returns the RSA public exponent bytes, if applicable.
    pub fn e_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Rsa { e_bytes, .. } => Some(e_bytes),
            Self::Ec { .. } | Self::Okp { .. } => None,
        }
    }

    /// Returns an uncompressed SEC1 point for an EC key.
    pub fn ec_uncompressed_point(&self) -> Option<Vec<u8>> {
        let Self::Ec {
            x_bytes, y_bytes, ..
        } = self
        else {
            return None;
        };
        let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
        point.push(4);
        point.extend_from_slice(x_bytes);
        point.extend_from_slice(y_bytes);
        Some(point)
    }

    /// Computes the RFC 7638 JWK thumbprint.
    pub fn thumbprint(&self) -> String {
        let canonical = match self {
            Self::Ec { crv, x, y, .. } => {
                format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
            Self::Rsa { n, e, .. } => {
                format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
            }
            Self::Okp { crv, x, .. } => {
                format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
            }
        };
        encode_base64url(&sha256(canonical.as_bytes()))
    }
}

/// A parsed and semantically validated DPoP proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopProof {
    /// The selected JWS algorithm.
    pub algorithm: DpopAlgorithm,
    /// The proof's embedded public key.
    pub jwk: DpopJwk,
    /// The HTTP method claim.
    pub htm: String,
    /// The normalized target URI claim.
    pub htu: String,
    /// The issued-at NumericDate claim.
    pub iat: i64,
    /// The unique proof identifier.
    pub jti: String,
    /// The access-token hash claim, if present.
    pub ath: Option<String>,
    /// The server nonce claim, if present.
    pub nonce: Option<String>,
    /// The RFC 7638 thumbprint of [`Self::jwk`].
    pub jkt: String,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
}

impl DpopProof {
    /// Returns the exact JWS signing input (`header.payload`).
    pub fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }

    /// Returns the decoded JWS signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// Input facts supplied by the HTTP runtime for one DPoP validation.
#[derive(Debug, Clone, Copy)]
pub struct DpopValidationContext<'a> {
    /// The exact request method.
    pub method: &'a str,
    /// The absolute HTTP(S) request URI. Its query is ignored for matching,
    /// while a query in the DPoP `htu` claim is rejected.
    pub request_uri: &'a str,
    /// The access token carried by the request, when one exists.
    pub access_token: Option<&'a str>,
    /// The `cnf.jkt` value obtained from the already-verified access token.
    pub expected_jkt: Option<&'a str>,
    /// The nonce required by the resource server, if any.
    pub expected_nonce: Option<&'a str>,
    /// The trusted current Unix time in seconds.
    pub now: i64,
}

/// DPoP proof lifetime and clock-skew policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DpopPolicy {
    /// Maximum age of a proof in seconds.
    pub max_age_seconds: u64,
    /// Permitted clock skew in seconds.
    pub clock_skew_seconds: u64,
}

impl Default for DpopPolicy {
    fn default() -> Self {
        Self {
            max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
        }
    }
}

impl DpopPolicy {
    /// Creates a policy after validating non-zero lifetime bounds.
    pub fn new(max_age_seconds: u64, clock_skew_seconds: u64) -> Result<Self, DpopError> {
        if max_age_seconds == 0 {
            return Err(DpopError::InvalidPolicy(
                "max_age_seconds must be greater than zero",
            ));
        }
        Ok(Self {
            max_age_seconds,
            clock_skew_seconds,
        })
    }
}

/// A replay key that must be inserted atomically before accepting a proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DpopReplayKey {
    /// The public-key thumbprint that scopes `jti` uniqueness.
    pub jkt: String,
    /// The proof's unique identifier.
    pub jti: String,
    /// The proof's issued-at timestamp, useful for expiry-aware stores.
    pub iat: i64,
}

/// Signature verification supplied by the runtime's real crypto backend.
pub trait DpopSignatureVerifier {
    /// Verifies the exact JWS signing input and signature under the embedded
    /// public key. Implementations must fail closed for unsupported algorithms.
    fn verify(
        &self,
        algorithm: DpopAlgorithm,
        key: &DpopJwk,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), DpopSignatureError>;
}

/// Atomic replay persistence supplied by the runtime.
pub trait DpopReplayStore {
    /// Stores a replay key if unseen, or returns [`DpopReplayError::Replay`]
    /// when it has already been consumed. Any backend failure must return
    /// [`DpopReplayError::Unavailable`] or [`DpopReplayError::Failure`]; the
    /// validator never treats such failures as an allow.
    fn check_and_store(&mut self, key: &DpopReplayKey) -> Result<(), DpopReplayError>;
}

/// Signature verification failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DpopSignatureError {
    /// The signature is invalid.
    #[error("DPoP signature verification failed")]
    Invalid,
    /// The configured crypto backend cannot verify this algorithm.
    #[error("DPoP signature algorithm is unavailable")]
    Unavailable,
    /// The crypto backend failed closed for an internal reason.
    #[error("DPoP signature backend failed")]
    Failure,
}

/// Replay persistence failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DpopReplayError {
    /// The proof `jti` was already consumed for this key.
    #[error("DPoP proof was replayed")]
    Replay,
    /// The replay store is unavailable.
    #[error("DPoP replay store is unavailable")]
    Unavailable,
    /// The replay store failed closed.
    #[error("DPoP replay store failed")]
    Failure,
}

/// A DPoP proof validation failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DpopError {
    /// The request did not contain exactly one DPoP field.
    #[error("DPoP header is missing")]
    MissingHeader,
    /// Multiple DPoP field lines were supplied.
    #[error("DPoP header must occur exactly once")]
    DuplicateHeader,
    /// The compact proof token is malformed.
    #[error("malformed DPoP proof: {0}")]
    MalformedProof(&'static str),
    /// A proof segment exceeded the bounded parser input.
    #[error("DPoP proof exceeds the maximum size")]
    ProofTooLarge,
    /// A base64url segment is malformed.
    #[error("invalid DPoP base64url encoding")]
    InvalidBase64,
    /// The protected header is not a DPoP JOSE header.
    #[error("DPoP typ must be dpop+jwt")]
    InvalidType,
    /// The algorithm is not allowed for DPoP.
    #[error("unsupported DPoP algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The key type and algorithm do not agree.
    #[error("DPoP algorithm and JWK key type do not match")]
    AlgorithmKeyMismatch,
    /// The embedded key is malformed or private.
    #[error("invalid DPoP JWK: {0}")]
    InvalidJwk(&'static str),
    /// A required claim is absent or has the wrong JSON type.
    #[error("invalid DPoP claim: {0}")]
    InvalidClaim(&'static str),
    /// The proof method does not match the request.
    #[error("DPoP htm does not match the request method")]
    MethodMismatch,
    /// The proof URI does not match the request target.
    #[error("DPoP htu does not match the request target")]
    TargetMismatch,
    /// The proof timestamp is outside the configured acceptance window.
    #[error("DPoP iat is outside the acceptance window")]
    InvalidIssuedAt,
    /// The supplied access token is too large to hash safely.
    #[error("access token exceeds the maximum DPoP binding size")]
    AccessTokenTooLarge,
    /// The proof's `ath` does not bind the supplied access token.
    #[error("DPoP access-token hash does not match")]
    AccessTokenMismatch,
    /// An `ath` was supplied without a token to bind it to.
    #[error("DPoP ath requires an access token")]
    UnexpectedAccessTokenHash,
    /// The proof key does not bind to the access token's `cnf.jkt`.
    #[error("DPoP key thumbprint does not match cnf.jkt")]
    KeyBindingMismatch,
    /// A required server nonce is missing or wrong.
    #[error("DPoP nonce is missing or invalid")]
    InvalidNonce,
    /// The configured policy is invalid.
    #[error("invalid DPoP policy: {0}")]
    InvalidPolicy(&'static str),
    /// The signature backend rejected the proof.
    #[error(transparent)]
    Signature(#[from] DpopSignatureError),
    /// The replay store rejected the proof.
    #[error(transparent)]
    Replay(#[from] DpopReplayError),
}

/// Validates a request's DPoP proof, including signature and replay checks.
///
/// The replay store is called only after all proof claims and the signature
/// have passed. A store error is returned directly and is never converted to
/// success. The caller must obtain `expected_jkt` from a separately verified
/// access token `cnf.jkt` claim; this function does not trust an unverified JWT.
pub fn validate_dpop(
    headers: &HeaderMap,
    context: &DpopValidationContext<'_>,
    policy: DpopPolicy,
    verifier: &dyn DpopSignatureVerifier,
    replay_store: &mut dyn DpopReplayStore,
) -> Result<DpopProof, DpopError> {
    let token = extract_dpop_header(headers)?;
    let parsed = parse_proof(token, context, policy)?;
    verifier.verify(
        parsed.algorithm,
        &parsed.jwk,
        parsed.signing_input(),
        parsed.signature(),
    )?;
    let replay_key = DpopReplayKey {
        jkt: parsed.jkt.clone(),
        jti: parsed.jti.clone(),
        iat: parsed.iat,
    };
    replay_store.check_and_store(&replay_key)?;
    Ok(parsed)
}

/// Extracts the `cnf.jkt` binding from already-verified access-token claims.
pub fn access_token_jkt(claims: &Value) -> Result<String, DpopError> {
    let jkt = claims
        .get("cnf")
        .and_then(Value::as_object)
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(Value::as_str)
        .ok_or(DpopError::InvalidClaim("cnf.jkt"))?;
    validate_thumbprint(jkt)?;
    Ok(jkt.to_string())
}

/// Computes the RFC 9449 `ath` value for an access token.
pub fn access_token_hash(access_token: &str) -> Result<String, DpopError> {
    if access_token.is_empty() {
        return Err(DpopError::InvalidClaim("access token"));
    }
    if access_token.len() > MAX_ACCESS_TOKEN_BYTES {
        return Err(DpopError::AccessTokenTooLarge);
    }
    Ok(encode_base64url(&sha256(access_token.as_bytes())))
}

fn extract_dpop_header(headers: &HeaderMap) -> Result<&str, DpopError> {
    let mut values = headers.get_all(DPOP_HEADER).iter();
    let Some(value) = values.next() else {
        return Err(DpopError::MissingHeader);
    };
    if values.next().is_some() {
        return Err(DpopError::DuplicateHeader);
    }
    let value = value
        .to_str()
        .map_err(|_| DpopError::MalformedProof("header is not ASCII"))?;
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(DpopError::MalformedProof("header contains whitespace"));
    }
    Ok(value)
}

fn parse_proof(
    token: &str,
    context: &DpopValidationContext<'_>,
    policy: DpopPolicy,
) -> Result<DpopProof, DpopError> {
    if token.len() > MAX_PROOF_BYTES {
        return Err(DpopError::ProofTooLarge);
    }
    let mut segments = token.split('.');
    let header_segment = segments
        .next()
        .ok_or(DpopError::MalformedProof("missing header"))?;
    let payload_segment = segments
        .next()
        .ok_or(DpopError::MalformedProof("missing payload"))?;
    let signature_segment = segments
        .next()
        .ok_or(DpopError::MalformedProof("missing signature"))?;
    if segments.next().is_some()
        || header_segment.is_empty()
        || payload_segment.is_empty()
        || signature_segment.is_empty()
    {
        return Err(DpopError::MalformedProof(
            "proof must contain exactly three segments",
        ));
    }

    let header_bytes = decode_base64url(header_segment)?;
    let payload_bytes = decode_base64url(payload_segment)?;
    let signature = decode_base64url(signature_segment)?;
    let header = parse_json_object(header_bytes.as_slice())?;
    let payload = parse_json_object(payload_bytes.as_slice())?;

    if header.contains_key("crit") {
        return Err(DpopError::MalformedProof(
            "unsupported JOSE critical header",
        ));
    }
    if header.contains_key("b64") {
        return Err(DpopError::MalformedProof(
            "JWS b64 extension is not supported",
        ));
    }

    let typ = header
        .get("typ")
        .and_then(Value::as_str)
        .ok_or(DpopError::InvalidType)?;
    if typ != "dpop+jwt" {
        return Err(DpopError::InvalidType);
    }
    let alg_value = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(DpopError::InvalidClaim("alg"))?;
    let algorithm = DpopAlgorithm::parse(alg_value)?;
    let jwk_value = header.get("jwk").ok_or(DpopError::InvalidClaim("jwk"))?;
    let jwk = parse_jwk(jwk_value)?;
    if !algorithm.matches_key(&jwk) {
        return Err(DpopError::AlgorithmKeyMismatch);
    }
    if let Some(jwk_alg) = jwk_value.get("alg")
        && jwk_alg.as_str() != Some(algorithm.as_str())
    {
        return Err(DpopError::AlgorithmKeyMismatch);
    }
    if let Some(expected) = algorithm.expected_signature_length()
        && signature.len() != expected
    {
        return Err(DpopError::MalformedProof("signature has an invalid length"));
    }
    if signature.is_empty() || signature.len() > 16 * 1024 {
        return Err(DpopError::MalformedProof("signature has an invalid length"));
    }

    let method = payload
        .get("htm")
        .and_then(Value::as_str)
        .ok_or(DpopError::InvalidClaim("htm"))?;
    if !is_http_token(method) {
        return Err(DpopError::InvalidClaim("htm"));
    }
    if method != context.method {
        return Err(DpopError::MethodMismatch);
    }

    let claim_target = payload
        .get("htu")
        .and_then(Value::as_str)
        .ok_or(DpopError::InvalidClaim("htu"))?;
    let normalized_claim_target = normalize_htu(claim_target, false)?;
    let normalized_request_target = normalize_htu(context.request_uri, true)?;
    if normalized_claim_target != normalized_request_target {
        return Err(DpopError::TargetMismatch);
    }

    let iat = payload
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(DpopError::InvalidClaim("iat"))?;
    validate_iat(iat, context.now, policy)?;

    let jti = bounded_string_claim(&payload, "jti", MAX_JTI_BYTES)?;
    let nonce = optional_bounded_string_claim(&payload, "nonce", MAX_NONCE_BYTES)?;
    match context.expected_nonce {
        Some(expected)
            if expected.is_empty()
                || expected.len() > MAX_NONCE_BYTES
                || expected.chars().any(char::is_control)
                || nonce.as_deref() != Some(expected) =>
        {
            return Err(DpopError::InvalidNonce);
        }
        _ => {}
    }

    let ath = optional_string_claim(&payload, "ath")?;
    if context.access_token.is_some() && context.expected_jkt.is_none() {
        return Err(DpopError::KeyBindingMismatch);
    }
    match (context.access_token, ath.as_deref()) {
        (Some(token), Some(actual)) => {
            let expected = access_token_hash(token)?;
            if !constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
                return Err(DpopError::AccessTokenMismatch);
            }
        }
        (Some(_), None) => return Err(DpopError::InvalidClaim("ath")),
        (None, Some(_)) => return Err(DpopError::UnexpectedAccessTokenHash),
        (None, None) => {}
    }

    let jkt = jwk.thumbprint();
    if let Some(expected) = context.expected_jkt {
        validate_thumbprint(expected)?;
        if !constant_time_eq(jkt.as_bytes(), expected.as_bytes()) {
            return Err(DpopError::KeyBindingMismatch);
        }
    }

    Ok(DpopProof {
        algorithm,
        jwk,
        htm: method.to_string(),
        htu: normalized_claim_target,
        iat,
        jti,
        ath,
        nonce,
        jkt,
        signing_input: format!("{header_segment}.{payload_segment}").into_bytes(),
        signature,
    })
}

fn parse_jwk(value: &Value) -> Result<DpopJwk, DpopError> {
    let object = value
        .as_object()
        .ok_or(DpopError::InvalidJwk("must be an object"))?;
    let kty = object
        .get("kty")
        .and_then(Value::as_str)
        .ok_or(DpopError::InvalidJwk("kty is missing"))?;
    if object
        .get("use")
        .is_some_and(|value| value.as_str() != Some("sig"))
    {
        return Err(DpopError::InvalidJwk("use must be sig"));
    }
    if object.get("key_ops").is_some_and(|value| {
        value
            .as_array()
            .is_none_or(|ops| ops.is_empty() || ops.iter().any(|op| op.as_str() != Some("verify")))
    }) {
        return Err(DpopError::InvalidJwk("key_ops must contain only verify"));
    }
    if object
        .get("alg")
        .is_some_and(|value| value.as_str().is_none())
    {
        return Err(DpopError::InvalidJwk("alg must be a string"));
    }

    match kty {
        "EC" => {
            reject_private_jwk_members(object, &["d"])?;
            let crv = required_string(object, "crv", "EC crv")?;
            let width = match crv.as_str() {
                "P-256" => 32,
                "P-384" => 48,
                "P-521" => 66,
                _ => return Err(DpopError::InvalidJwk("unsupported EC curve")),
            };
            let x = required_b64_string(object, "x", "EC x")?;
            let y = required_b64_string(object, "y", "EC y")?;
            let x_bytes = decode_base64url(x.as_str())?;
            let y_bytes = decode_base64url(y.as_str())?;
            if x_bytes.len() != width || y_bytes.len() != width {
                return Err(DpopError::InvalidJwk("EC coordinate length is invalid"));
            }
            Ok(DpopJwk::Ec {
                crv: crv.to_string(),
                x,
                y,
                x_bytes,
                y_bytes,
            })
        }
        "RSA" => {
            reject_private_jwk_members(object, &["d", "p", "q", "dp", "dq", "qi", "oth"])?;
            let n = required_b64_string(object, "n", "RSA n")?;
            let e = required_b64_string(object, "e", "RSA e")?;
            let n_bytes = decode_base64url(n.as_str())?;
            let e_bytes = decode_base64url(e.as_str())?;
            if n_bytes.len() < 256
                || n_bytes.len() > 1024
                || n_bytes.first() == Some(&0)
                || e_bytes.is_empty()
                || e_bytes[0] & 1 == 0
            {
                return Err(DpopError::InvalidJwk("RSA modulus or exponent is invalid"));
            }
            if e_bytes.len() == 1 && e_bytes[0] < 3 {
                return Err(DpopError::InvalidJwk("RSA exponent is invalid"));
            }
            Ok(DpopJwk::Rsa {
                n,
                e,
                n_bytes,
                e_bytes,
            })
        }
        "OKP" => {
            reject_private_jwk_members(object, &["d"])?;
            let crv = required_string(object, "crv", "OKP crv")?;
            if crv != "Ed25519" {
                return Err(DpopError::InvalidJwk("unsupported OKP curve"));
            }
            let x = required_b64_string(object, "x", "OKP x")?;
            let x_bytes = decode_base64url(x.as_str())?;
            if x_bytes.len() != 32 {
                return Err(DpopError::InvalidJwk(
                    "Ed25519 public key length is invalid",
                ));
            }
            Ok(DpopJwk::Okp {
                crv: crv.to_string(),
                x,
                x_bytes,
            })
        }
        _ => Err(DpopError::InvalidJwk("unsupported kty")),
    }
}

fn reject_private_jwk_members(
    object: &Map<String, Value>,
    private_members: &[&str],
) -> Result<(), DpopError> {
    if private_members
        .iter()
        .any(|member| object.contains_key(*member))
    {
        return Err(DpopError::InvalidJwk("private key material is forbidden"));
    }
    Ok(())
}

fn required_string(
    object: &Map<String, Value>,
    name: &'static str,
    label: &'static str,
) -> Result<String, DpopError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or(DpopError::InvalidJwk(label))
}

fn required_b64_string(
    object: &Map<String, Value>,
    name: &'static str,
    label: &'static str,
) -> Result<String, DpopError> {
    let value = required_string(object, name, label)?;
    decode_base64url(value.as_str())?;
    Ok(value)
}

fn optional_string_claim(
    payload: &Map<String, Value>,
    name: &'static str,
) -> Result<Option<String>, DpopError> {
    let Some(value) = payload.get(name) else {
        return Ok(None);
    };
    let value = value.as_str().ok_or(DpopError::InvalidClaim(name))?;
    if value.is_empty() || value.len() > MAX_NONCE_BYTES || value.chars().any(char::is_control) {
        return Err(DpopError::InvalidClaim(name));
    }
    Ok(Some(value.to_string()))
}

fn bounded_string_claim(
    payload: &Map<String, Value>,
    name: &'static str,
    max_bytes: usize,
) -> Result<String, DpopError> {
    let value = payload
        .get(name)
        .and_then(Value::as_str)
        .ok_or(DpopError::InvalidClaim(name))?;
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(DpopError::InvalidClaim(name));
    }
    Ok(value.to_string())
}

fn optional_bounded_string_claim(
    payload: &Map<String, Value>,
    name: &'static str,
    max_bytes: usize,
) -> Result<Option<String>, DpopError> {
    let Some(value) = payload.get(name) else {
        return Ok(None);
    };
    let value = value.as_str().ok_or(DpopError::InvalidClaim(name))?;
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(DpopError::InvalidClaim(name));
    }
    Ok(Some(value.to_string()))
}

fn validate_iat(iat: i64, now: i64, policy: DpopPolicy) -> Result<(), DpopError> {
    if policy.max_age_seconds == 0 {
        return Err(DpopError::InvalidPolicy(
            "max_age_seconds must be greater than zero",
        ));
    }
    let skew = i64::try_from(policy.clock_skew_seconds).unwrap_or(i64::MAX);
    let age = i64::try_from(policy.max_age_seconds).unwrap_or(i64::MAX);
    let earliest = now.saturating_sub(age).saturating_sub(skew);
    let latest = now.saturating_add(skew);
    if iat < earliest || iat > latest {
        return Err(DpopError::InvalidIssuedAt);
    }
    Ok(())
}

fn normalize_htu(raw: &str, allow_query: bool) -> Result<String, DpopError> {
    let mut url = Url::parse(raw).map_err(|_| DpopError::TargetMismatch)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(DpopError::TargetMismatch);
    }
    if !allow_query && url.query().is_some() {
        return Err(DpopError::TargetMismatch);
    }
    url.set_query(None);
    url.set_fragment(None);
    if (url.scheme() == "http" && url.port() == Some(80))
        || (url.scheme() == "https" && url.port() == Some(443))
    {
        url.set_port(None).map_err(|_| DpopError::TargetMismatch)?;
    }
    if url.path().is_empty() {
        url.set_path("/");
    }
    Ok(url.to_string())
}

fn validate_thumbprint(value: &str) -> Result<(), DpopError> {
    let decoded = decode_base64url(value)?;
    if decoded.len() != 32 {
        return Err(DpopError::InvalidClaim("cnf.jkt"));
    }
    Ok(())
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'..=b'\''
                    | b'*'
                    | b'+'..=b'9'
                    | b'A'..=b'Z'
                    | b'^'..=b'~'
            )
        })
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn decode_base64url(value: &str) -> Result<Vec<u8>, DpopError> {
    if value.is_empty() || value.contains('=') || value.len() % 4 == 1 {
        return Err(DpopError::InvalidBase64);
    }
    URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| DpopError::InvalidBase64)
}

fn encode_base64url(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn parse_json_object(bytes: &[u8]) -> Result<Map<String, Value>, DpopError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValueSeed
        .deserialize(&mut deserializer)
        .map_err(|_| DpopError::MalformedProof("invalid JSON"))?;
    deserializer
        .end()
        .map_err(|_| DpopError::MalformedProof("trailing JSON data"))?;
    value
        .as_object()
        .cloned()
        .ok_or(DpopError::MalformedProof("JSON value must be an object"))
}

struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValueSeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(A::Error::custom("duplicate JSON object member"));
            }
            let value = map.next_value_seed(StrictValueSeed)?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_jwk() -> Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode([1u8; 32]),
            "y": URL_SAFE_NO_PAD.encode([2u8; 32]),
        })
    }

    fn compact_segment(value: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("JSON segment"))
    }

    fn valid_proof(payload: Value) -> String {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": valid_jwk(),
        });
        format!(
            "{}.{}.{}",
            compact_segment(&header),
            compact_segment(&payload),
            URL_SAFE_NO_PAD.encode([0u8; 64])
        )
    }

    fn valid_context() -> DpopValidationContext<'static> {
        DpopValidationContext {
            method: "GET",
            request_uri: "https://example.test/resource?cache=1",
            access_token: None,
            expected_jkt: None,
            expected_nonce: None,
            now: 1_700_000_000,
        }
    }

    fn valid_payload() -> Value {
        serde_json::json!({
            "htm": "GET",
            "htu": "https://example.test/resource",
            "iat": 1_700_000_000,
            "jti": "proof-1",
        })
    }

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            encode_base64url(&sha256(b"abc")),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }

    #[test]
    fn base64url_rejects_non_canonical_tail_bits() {
        assert!(decode_base64url("Zg").is_ok());
        assert!(decode_base64url("Zh").is_err());
        assert!(decode_base64url("Zg=").is_err());
        assert!(decode_base64url("a").is_err());
    }

    #[test]
    fn strict_json_rejects_duplicate_members() {
        assert!(parse_json_object(br#"{"typ":"dpop+jwt","typ":"JWT"}"#).is_err());
    }

    #[test]
    fn proof_claims_are_parsed_and_normalized() {
        let proof = parse_proof(
            valid_proof(valid_payload()).as_str(),
            &valid_context(),
            DpopPolicy::default(),
        )
        .expect("proof should parse");
        assert_eq!(proof.algorithm, DpopAlgorithm::Es256);
        assert_eq!(proof.htm, "GET");
        assert_eq!(proof.htu, "https://example.test/resource");
        assert_eq!(proof.jti, "proof-1");
        assert_eq!(proof.signature().len(), 64);
        assert_eq!(proof.signing_input().split(|byte| *byte == b'.').count(), 2);
    }

    #[test]
    fn duplicate_dpop_headers_are_rejected_before_parsing() {
        let mut headers = HeaderMap::new();
        headers.append("dpop", http::HeaderValue::from_static("a.b.c"));
        headers.append("dpop", http::HeaderValue::from_static("d.e.f"));
        assert_eq!(
            extract_dpop_header(&headers),
            Err(DpopError::DuplicateHeader)
        );
    }

    #[test]
    fn proof_rejects_query_in_htu_claim() {
        let mut payload = valid_payload();
        payload["htu"] = Value::String("https://example.test/resource?cache=1".to_string());
        assert_eq!(
            parse_proof(
                valid_proof(payload).as_str(),
                &valid_context(),
                DpopPolicy::default()
            ),
            Err(DpopError::TargetMismatch)
        );
    }

    #[test]
    fn access_token_requires_both_ath_and_cnf_jkt() {
        let jwk = valid_jwk();
        let jkt = DpopJwk::Ec {
            crv: "P-256".to_string(),
            x: jwk["x"].as_str().expect("x").to_string(),
            y: jwk["y"].as_str().expect("y").to_string(),
            x_bytes: vec![1; 32],
            y_bytes: vec![2; 32],
        }
        .thumbprint();
        let context = DpopValidationContext {
            method: "GET",
            request_uri: "https://example.test/resource?cache=1",
            access_token: Some("access-token"),
            expected_jkt: Some(jkt.as_str()),
            expected_nonce: None,
            now: 1_700_000_000,
        };
        assert_eq!(
            parse_proof(
                valid_proof(valid_payload()).as_str(),
                &context,
                DpopPolicy::default()
            ),
            Err(DpopError::InvalidClaim("ath"))
        );
    }

    #[test]
    fn dpop_jwk_thumbprint_is_stable_and_canonical() {
        let key = DpopJwk::Ec {
            crv: "P-256".to_string(),
            x: "f83OJ3D2xF4mY8N3r4p8hJpR9e7q0K3YcCjK8h6sE3I".to_string(),
            y: "x_FEzRu9uK4V7H2C9qY0h0L3K5j4P3Q6xJ2mP3sK7qU".to_string(),
            x_bytes: vec![1; 32],
            y_bytes: vec![2; 32],
        };
        assert_eq!(key.thumbprint().len(), 43);
        assert!(
            key.thumbprint().bytes().all(|byte| {
                matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
            })
        );
    }

    #[test]
    fn jwk_rejects_private_material_and_wrong_curve() {
        let private = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": "AQ", "y": "Ag", "d": "Aw"
        });
        assert!(matches!(parse_jwk(&private), Err(DpopError::InvalidJwk(_))));
        let wrong_curve = serde_json::json!({
            "kty": "OKP", "crv": "X25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        });
        assert!(matches!(
            parse_jwk(&wrong_curve),
            Err(DpopError::InvalidJwk(_))
        ));
    }

    #[test]
    fn normalize_htu_drops_request_query_but_rejects_claim_query() {
        assert_eq!(
            normalize_htu("https://EXAMPLE.test:443/path?x=1", true).unwrap(),
            "https://example.test/path"
        );
        assert!(normalize_htu("https://example.test/path?x=1", false).is_err());
    }

    #[test]
    fn policy_rejects_unbounded_age() {
        assert!(DpopPolicy::new(0, 1).is_err());
    }

    #[test]
    fn access_token_hash_is_rfc9449_shape() {
        let hash = access_token_hash("access-token").unwrap();
        assert_eq!(hash.len(), 43);
        assert_eq!(decode_base64url(hash.as_str()).unwrap().len(), 32);
    }

    #[test]
    fn algorithm_key_matching_is_strict() {
        let key = DpopJwk::Ec {
            crv: "P-256".to_string(),
            x: "AQ".to_string(),
            y: "Ag".to_string(),
            x_bytes: vec![1],
            y_bytes: vec![2],
        };
        assert!(DpopAlgorithm::Es256.matches_key(&key));
        assert!(!DpopAlgorithm::Es384.matches_key(&key));
        assert!(!DpopAlgorithm::Rs256.matches_key(&key));
    }
}
