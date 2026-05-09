use crate::auth_runtime::AuthenticatedUser;
use crate::runtime::RuntimeState;
use anyhow::{anyhow, Result};
use http::header::HeaderName;
use hyper::HeaderMap;
use qpx_core::config::{
    AssertionClaimsMapConfig, IdentitySourceConfig, IdentitySourceHeadersConfig,
    IdentitySourceKind, MtlsIdentityMapConfig, PolicyContextConfig, SignedAssertionConfig,
};
use qpx_observability::access_log::RequestLogContext;
use ring::signature;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sha2::{Sha256, Sha384, Sha512};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

#[cfg(feature = "tls-rustls")]
use x509_parser::certificate::X509Certificate;
#[cfg(feature = "tls-rustls")]
use x509_parser::extensions::GeneralName;
#[cfg(feature = "tls-rustls")]
use x509_parser::prelude::FromDer;

use super::util::{
    compile_optional_header_name, decode_jwt_segment, extend_unique, extract_assertion_token,
    extract_first_header, extract_list_header, json_list_claim, json_string_claim,
    load_hmac_secret_from_env, load_public_key_from_env, merge_identity_source_labels,
    peer_matches, validate_registered_claims, verify_hmac_signature, verify_public_key_signature,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct EffectivePolicyContext {
    pub(crate) identity_sources: Vec<String>,
    pub(crate) ext_authz: Option<String>,
}

impl EffectivePolicyContext {
    pub(crate) fn from_single(policy: Option<&PolicyContextConfig>) -> Self {
        Self::merged(None, policy)
    }

    pub(crate) fn merged(
        base: Option<&PolicyContextConfig>,
        overlay: Option<&PolicyContextConfig>,
    ) -> Self {
        let mut identity_sources = Vec::new();
        let mut seen = HashSet::new();
        for policy in [base, overlay].into_iter().flatten() {
            for source in &policy.identity_sources {
                if seen.insert(source.clone()) {
                    identity_sources.push(source.clone());
                }
            }
        }
        let ext_authz = overlay
            .and_then(|policy| policy.ext_authz.clone())
            .or_else(|| base.and_then(|policy| policy.ext_authz.clone()));
        Self {
            identity_sources,
            ext_authz,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ResolvedIdentity {
    pub(crate) user: Option<String>,
    pub(crate) groups: Vec<String>,
    pub(crate) device_id: Option<String>,
    pub(crate) posture: Vec<String>,
    pub(crate) tenant: Option<String>,
    pub(crate) auth_strength: Option<String>,
    pub(crate) idp: Option<String>,
    pub(crate) identity_source: Option<String>,
}

impl ResolvedIdentity {
    fn merge(&mut self, other: ResolvedIdentity) {
        if self.user.is_none() {
            self.user = other.user;
        }
        if self.device_id.is_none() {
            self.device_id = other.device_id;
        }
        if self.tenant.is_none() {
            self.tenant = other.tenant;
        }
        if self.auth_strength.is_none() {
            self.auth_strength = other.auth_strength;
        }
        if self.idp.is_none() {
            self.idp = other.idp;
        }
        extend_unique(&mut self.groups, other.groups);
        extend_unique(&mut self.posture, other.posture);
        self.identity_source =
            merge_identity_source_labels(self.identity_source.take(), other.identity_source);
    }

    pub(crate) fn supplement_builtin_auth(&mut self, user: Option<&AuthenticatedUser>) {
        let Some(user) = user else {
            return;
        };
        if self.user.is_none() {
            self.user = Some(user.username.clone());
        }
        if self.idp.is_none() && user.provider != "none" {
            self.idp = Some(user.provider.clone());
        }
        extend_unique(&mut self.groups, user.groups.clone());
    }

    pub(crate) fn to_log_context(
        &self,
        matched_rule: Option<&str>,
        matched_route: Option<&str>,
        ext_authz_policy_id: Option<&str>,
    ) -> RequestLogContext {
        RequestLogContext {
            subject: self.user.clone(),
            groups: self.groups.clone(),
            device_id: self.device_id.clone(),
            posture: self.posture.clone(),
            tenant: self.tenant.clone(),
            auth_strength: self.auth_strength.clone(),
            idp: self.idp.clone(),
            identity_source: self.identity_source.clone(),
            policy_tags: Vec::new(),
            ext_authz_policy_id: ext_authz_policy_id.map(str::to_string),
            matched_rule: matched_rule.map(str::to_string),
            matched_route: matched_route.map(str::to_string),
            destination_trace: None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledIdentitySource {
    kind: CompiledIdentitySourceKind,
}

#[derive(Debug, Clone)]
enum CompiledIdentitySourceKind {
    TrustedHeaders(Box<CompiledTrustedHeaders>),
    MtlsSubject(CompiledMtlsIdentityMap),
    SignedAssertion(Box<CompiledSignedAssertion>),
}

#[derive(Debug, Clone)]
struct CompiledTrustedHeaders {
    name: String,
    trusted_peers: Vec<cidr::IpCidr>,
    headers: CompiledIdentityHeaders,
    strip_from_untrusted: bool,
}

#[derive(Debug, Clone)]
struct CompiledIdentityHeaders {
    user: Option<HeaderName>,
    groups: Option<HeaderName>,
    device_id: Option<HeaderName>,
    posture: Option<HeaderName>,
    tenant: Option<HeaderName>,
    auth_strength: Option<HeaderName>,
    idp: Option<HeaderName>,
}

#[derive(Debug, Clone)]
struct CompiledMtlsIdentityMap {
    name: String,
    user_from_san_uri_prefix: Option<String>,
    user_from_subject_cn: bool,
    auth_strength: Option<String>,
    idp: Option<String>,
}

#[derive(Debug, Clone)]
struct CompiledSignedAssertion {
    name: String,
    header: HeaderName,
    prefix: Option<String>,
    algorithms: Vec<JwtAlgorithm>,
    issuer: Option<String>,
    audience: Option<String>,
    hmac_secret: Option<Arc<[u8]>>,
    public_key: Option<Arc<[u8]>>,
    claims: CompiledAssertionClaims,
    strip_from_untrusted: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JwtAlgorithm {
    Hs256,
    Hs384,
    Hs512,
    Rs256,
    Rs384,
    Rs512,
    Es256,
    Es384,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
}

impl CompiledIdentitySource {
    pub(crate) fn from_config(config: &IdentitySourceConfig) -> Result<Self> {
        let kind = match config.kind {
            IdentitySourceKind::TrustedHeaders => {
                let headers = config
                    .headers
                    .as_ref()
                    .ok_or_else(|| anyhow!("trusted_headers source requires headers"))?;
                CompiledIdentitySourceKind::TrustedHeaders(Box::new(CompiledTrustedHeaders {
                    name: config.name.clone(),
                    trusted_peers: config
                        .from
                        .trusted_peers
                        .iter()
                        .map(|raw| raw.parse())
                        .collect::<Result<Vec<cidr::IpCidr>, _>>()?,
                    headers: CompiledIdentityHeaders::from_config(headers)?,
                    strip_from_untrusted: config.strip_from_untrusted,
                }))
            }
            IdentitySourceKind::MtlsSubject => {
                let map = config
                    .map
                    .as_ref()
                    .ok_or_else(|| anyhow!("mtls_subject source requires map"))?;
                CompiledIdentitySourceKind::MtlsSubject(CompiledMtlsIdentityMap::from_config(
                    &config.name,
                    map,
                ))
            }
            IdentitySourceKind::SignedAssertion => {
                let assertion = config
                    .assertion
                    .as_ref()
                    .ok_or_else(|| anyhow!("signed_assertion source requires assertion"))?;
                CompiledIdentitySourceKind::SignedAssertion(Box::new(
                    CompiledSignedAssertion::from_config(
                        &config.name,
                        assertion,
                        config.strip_from_untrusted,
                    )?,
                ))
            }
        };
        Ok(Self { kind })
    }
}

impl CompiledIdentityHeaders {
    fn from_config(config: &IdentitySourceHeadersConfig) -> Result<Self> {
        Ok(Self {
            user: compile_optional_header_name(config.user.as_deref())?,
            groups: compile_optional_header_name(config.groups.as_deref())?,
            device_id: compile_optional_header_name(config.device_id.as_deref())?,
            posture: compile_optional_header_name(config.posture.as_deref())?,
            tenant: compile_optional_header_name(config.tenant.as_deref())?,
            auth_strength: compile_optional_header_name(config.auth_strength.as_deref())?,
            idp: compile_optional_header_name(config.idp.as_deref())?,
        })
    }

    fn all_names(&self) -> Vec<HeaderName> {
        [
            self.user.as_ref(),
            self.groups.as_ref(),
            self.device_id.as_ref(),
            self.posture.as_ref(),
            self.tenant.as_ref(),
            self.auth_strength.as_ref(),
            self.idp.as_ref(),
        ]
        .into_iter()
        .flatten()
        .cloned()
        .collect()
    }
}

impl CompiledMtlsIdentityMap {
    fn from_config(name: &str, map: &MtlsIdentityMapConfig) -> Self {
        Self {
            name: name.to_string(),
            user_from_san_uri_prefix: map.user_from_san_uri_prefix.clone(),
            user_from_subject_cn: map.user_from_subject_cn,
            auth_strength: map.auth_strength.clone(),
            idp: map.idp.clone(),
        }
    }
}

impl CompiledSignedAssertion {
    fn from_config(
        name: &str,
        config: &SignedAssertionConfig,
        strip_from_untrusted: bool,
    ) -> Result<Self> {
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
            strip_from_untrusted,
        })
    }

    fn extract(&self, headers: &HeaderMap) -> ResolvedIdentity {
        let Some(token) = extract_assertion_token(headers, &self.header, self.prefix.as_deref())
        else {
            return ResolvedIdentity::default();
        };
        self.verify_and_extract(token).unwrap_or_default()
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

impl JwtAlgorithm {
    fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "HS256" => Ok(Self::Hs256),
            "HS384" => Ok(Self::Hs384),
            "HS512" => Ok(Self::Hs512),
            "RS256" => Ok(Self::Rs256),
            "RS384" => Ok(Self::Rs384),
            "RS512" => Ok(Self::Rs512),
            "ES256" => Ok(Self::Es256),
            "ES384" => Ok(Self::Es384),
            other => Err(anyhow!("unsupported JWT algorithm: {}", other)),
        }
    }

    fn header_name(self) -> &'static str {
        match self {
            Self::Hs256 => "HS256",
            Self::Hs384 => "HS384",
            Self::Hs512 => "HS512",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
        }
    }

    fn verify(
        self,
        hmac_secret: Option<&[u8]>,
        public_key: Option<&[u8]>,
        data: &[u8],
        signature_bytes: &[u8],
    ) -> Result<()> {
        match self {
            Self::Hs256 => verify_hmac_signature::<Sha256>(hmac_secret, data, signature_bytes, 64),
            Self::Hs384 => verify_hmac_signature::<Sha384>(hmac_secret, data, signature_bytes, 128),
            Self::Hs512 => verify_hmac_signature::<Sha512>(hmac_secret, data, signature_bytes, 128),
            Self::Rs256 => verify_public_key_signature(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                public_key,
                data,
                signature_bytes,
            ),
            Self::Rs384 => verify_public_key_signature(
                &signature::RSA_PKCS1_2048_8192_SHA384,
                public_key,
                data,
                signature_bytes,
            ),
            Self::Rs512 => verify_public_key_signature(
                &signature::RSA_PKCS1_2048_8192_SHA512,
                public_key,
                data,
                signature_bytes,
            ),
            Self::Es256 => verify_public_key_signature(
                &signature::ECDSA_P256_SHA256_FIXED,
                public_key,
                data,
                signature_bytes,
            ),
            Self::Es384 => verify_public_key_signature(
                &signature::ECDSA_P384_SHA384_FIXED,
                public_key,
                data,
                signature_bytes,
            ),
        }
    }
}

pub(crate) fn sanitize_headers_for_policy(
    state: &RuntimeState,
    policy: &EffectivePolicyContext,
    peer_ip: IpAddr,
    headers: &HeaderMap,
) -> Result<HeaderMap> {
    let mut sanitized = headers.clone();
    strip_untrusted_identity_headers(state, policy, peer_ip, &mut sanitized)?;
    Ok(sanitized)
}

pub(crate) fn strip_untrusted_identity_headers(
    state: &RuntimeState,
    policy: &EffectivePolicyContext,
    peer_ip: IpAddr,
    headers: &mut HeaderMap,
) -> Result<()> {
    let mut trusted_names = HashSet::new();
    let mut untrusted_names = HashSet::new();

    for source_name in &policy.identity_sources {
        let source = state
            .security
            .identity_sources
            .sources
            .get(source_name)
            .ok_or_else(|| anyhow!("identity source missing at runtime: {}", source_name))?;
        match &source.kind {
            CompiledIdentitySourceKind::TrustedHeaders(cfg) => {
                if peer_matches(peer_ip, &cfg.trusted_peers) {
                    for name in cfg.headers.all_names() {
                        trusted_names.insert(name);
                    }
                } else if cfg.strip_from_untrusted {
                    for name in cfg.headers.all_names() {
                        untrusted_names.insert(name);
                    }
                }
            }
            CompiledIdentitySourceKind::SignedAssertion(cfg) => {
                if cfg.strip_from_untrusted {
                    untrusted_names.insert(cfg.header.clone());
                }
            }
            CompiledIdentitySourceKind::MtlsSubject(_) => {}
        }
    }

    for name in untrusted_names {
        if !trusted_names.contains(&name) {
            headers.remove(name);
        }
    }
    Ok(())
}

pub(crate) fn resolve_identity(
    state: &RuntimeState,
    policy: &EffectivePolicyContext,
    peer_ip: IpAddr,
    headers: Option<&HeaderMap>,
    peer_certificates: Option<&[Vec<u8>]>,
) -> Result<ResolvedIdentity> {
    let mut resolved = ResolvedIdentity::default();

    for source_name in &policy.identity_sources {
        let source = state
            .security
            .identity_sources
            .sources
            .get(source_name)
            .ok_or_else(|| anyhow!("identity source missing at runtime: {}", source_name))?;
        let extracted = match &source.kind {
            CompiledIdentitySourceKind::TrustedHeaders(cfg) => headers
                .filter(|_| peer_matches(peer_ip, &cfg.trusted_peers))
                .map(|headers| cfg.extract(headers))
                .unwrap_or_default(),
            CompiledIdentitySourceKind::MtlsSubject(cfg) => {
                extract_mtls_identity(cfg, peer_certificates).unwrap_or_default()
            }
            CompiledIdentitySourceKind::SignedAssertion(cfg) => headers
                .map(|headers| cfg.extract(headers))
                .unwrap_or_default(),
        };
        resolved.merge(extracted);
    }

    Ok(resolved)
}

impl CompiledTrustedHeaders {
    fn extract(&self, headers: &HeaderMap) -> ResolvedIdentity {
        let mut identity = ResolvedIdentity {
            user: extract_first_header(headers, self.headers.user.as_ref()),
            groups: extract_list_header(headers, self.headers.groups.as_ref()),
            device_id: extract_first_header(headers, self.headers.device_id.as_ref()),
            posture: extract_list_header(headers, self.headers.posture.as_ref()),
            tenant: extract_first_header(headers, self.headers.tenant.as_ref()),
            auth_strength: extract_first_header(headers, self.headers.auth_strength.as_ref()),
            idp: extract_first_header(headers, self.headers.idp.as_ref()),
            ..ResolvedIdentity::default()
        };
        if identity.user.is_some()
            || !identity.groups.is_empty()
            || identity.device_id.is_some()
            || !identity.posture.is_empty()
            || identity.tenant.is_some()
            || identity.auth_strength.is_some()
            || identity.idp.is_some()
        {
            identity.identity_source = Some(self.name.clone());
        }
        identity
    }
}

#[cfg(feature = "tls-rustls")]
fn extract_mtls_identity(
    cfg: &CompiledMtlsIdentityMap,
    peer_certificates: Option<&[Vec<u8>]>,
) -> Option<ResolvedIdentity> {
    let cert = peer_certificates?.first()?;
    let (_, cert) = X509Certificate::from_der(cert).ok()?;
    let mut identity = ResolvedIdentity::default();

    if let Some(prefix) = cfg.user_from_san_uri_prefix.as_deref() {
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                if let GeneralName::URI(uri) = name {
                    if let Some(user) = uri.strip_prefix(prefix) {
                        if !user.is_empty() {
                            identity.user = Some(user.to_string());
                            break;
                        }
                    }
                }
            }
        }
    }

    if identity.user.is_none() && cfg.user_from_subject_cn {
        if let Some(cn) = cert
            .subject()
            .iter_common_name()
            .filter_map(|attr| attr.as_str().ok())
            .find(|value| !value.trim().is_empty())
        {
            identity.user = Some(cn.trim().to_string());
        }
    }

    identity.auth_strength = cfg.auth_strength.clone();
    identity.idp = cfg.idp.clone();
    if identity.user.is_some() || identity.auth_strength.is_some() || identity.idp.is_some() {
        identity.identity_source = Some(cfg.name.clone());
        return Some(identity);
    }
    None
}

#[cfg(not(feature = "tls-rustls"))]
fn extract_mtls_identity(
    cfg: &CompiledMtlsIdentityMap,
    _peer_certificates: Option<&[Vec<u8>]>,
) -> Option<ResolvedIdentity> {
    let _ = (
        &cfg.name,
        &cfg.user_from_san_uri_prefix,
        cfg.user_from_subject_cn,
        &cfg.auth_strength,
        &cfg.idp,
    );
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
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

    #[test]
    fn signed_assertion_accepts_es256_public_key_tokens() {
        let _guard = crate::test_env_lock().lock().expect("env lock");
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
        let private_key_der = key_pair.serialize_der();
        let public_key_pem = key_pair.public_key_pem();
        let env_name = test_env_name("ASSERTION_PUBLIC_KEY");
        std::env::set_var(&env_name, public_key_pem);

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
            CompiledSignedAssertion::from_config("signed-jwt", &config, false).expect("compile");
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
        let identity = compiled.extract(&headers);

        assert_eq!(identity.user.as_deref(), Some("alice"));
        assert_eq!(identity.groups, vec!["eng".to_string(), "ops".to_string()]);
        assert_eq!(identity.tenant.as_deref(), Some("acme"));
        assert_eq!(identity.identity_source.as_deref(), Some("signed-jwt"));

        std::env::remove_var(env_name);
    }

    #[test]
    fn signed_assertion_defaults_to_public_key_algorithms() {
        let _guard = crate::test_env_lock().lock().expect("env lock");
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
        let private_key_der = key_pair.serialize_der();
        let public_key_pem = key_pair.public_key_pem();
        let env_name = test_env_name("ASSERTION_PUBLIC_KEY_DEFAULT");
        std::env::set_var(&env_name, public_key_pem);

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
            CompiledSignedAssertion::from_config("signed-jwt", &config, false).expect("compile");
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
        let identity = compiled.extract(&headers);

        assert_eq!(identity.user.as_deref(), Some("alice"));

        std::env::remove_var(env_name);
    }
}
