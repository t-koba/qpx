use crate::http::body::Body;
use crate::runtime::RuntimeState;
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use http::header::HeaderName;
use hyper::{HeaderMap, Request, Response};
use qpx_auth::AuthenticatedUser;
use qpx_core::config::{
    ActionConfig, ActionKind, AssertionClaimsMapConfig, AuditIncludeField, ExtAuthzConfig,
    ExtAuthzOnError, HeaderControl, IdentitySourceConfig, IdentitySourceHeadersConfig,
    IdentitySourceKind, LocalResponseConfig, MtlsIdentityMapConfig, PolicyContextConfig,
    SignedAssertionConfig,
};
use qpx_core::rules::CompiledHeaderControl;
use qpx_observability::access_log::RequestLogContext;
use ring::signature;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use tracing::warn;
use tracing::Level;
use url::Url;

#[cfg(feature = "tls-rustls")]
use x509_parser::certificate::X509Certificate;
#[cfg(feature = "tls-rustls")]
use x509_parser::extensions::GeneralName;
#[cfg(feature = "tls-rustls")]
use x509_parser::prelude::FromDer;
#[cfg(feature = "tls-rustls")]
use x509_parser::x509::SubjectPublicKeyInfo;

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

#[derive(Debug, Clone)]
pub(crate) struct CompiledExtAuthz {
    endpoint: Url,
    timeout: Duration,
    send_request: bool,
    send_identity: bool,
    selected_headers: Vec<HeaderName>,
    on_error: ExtAuthzOnError,
    max_response_bytes: usize,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ExtAuthzAllow {
    pub(crate) policy_id: Option<String>,
    pub(crate) override_upstream: Option<String>,
    pub(crate) headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) timeout_override: Option<Duration>,
    pub(crate) cache_bypass: bool,
    pub(crate) mirror_upstreams: Vec<String>,
    pub(crate) rate_limit_profile: Option<String>,
    pub(crate) force_inspect: bool,
    pub(crate) force_tunnel: bool,
    pub(crate) policy_tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtAuthzMode {
    ForwardHttp,
    ForwardConnect,
    #[cfg(feature = "mitm")]
    ForwardMitmHttp,
    ReverseHttp,
    TransparentHttp,
    TransparentTls,
    #[cfg(feature = "http3")]
    TransparentUdp,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ExtAuthzDeny {
    pub(crate) policy_id: Option<String>,
    pub(crate) headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) local_response: Option<LocalResponseConfig>,
    pub(crate) policy_tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum ExtAuthzEnforcement {
    Continue(ExtAuthzAllow),
    Deny(ExtAuthzDeny),
}

#[derive(Debug, Clone)]
pub(crate) struct ExtAuthzInput<'a> {
    pub(crate) proxy_kind: &'static str,
    pub(crate) proxy_name: &'a str,
    pub(crate) scope_name: &'a str,
    pub(crate) remote_ip: IpAddr,
    pub(crate) dst_port: Option<u16>,
    pub(crate) host: Option<&'a str>,
    pub(crate) sni: Option<&'a str>,
    pub(crate) method: Option<&'a str>,
    pub(crate) path: Option<&'a str>,
    pub(crate) uri: Option<&'a str>,
    pub(crate) matched_rule: Option<&'a str>,
    pub(crate) matched_route: Option<&'a str>,
    pub(crate) action: Option<&'a ActionConfig>,
    pub(crate) headers: Option<&'a HeaderMap>,
    pub(crate) identity: &'a ResolvedIdentity,
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

impl CompiledExtAuthz {
    pub(crate) fn from_config(config: &ExtAuthzConfig) -> Result<Self> {
        Ok(Self {
            endpoint: Url::parse(&config.endpoint)?,
            timeout: Duration::from_millis(config.timeout_ms),
            send_request: config.send.request,
            send_identity: config.send.identity,
            selected_headers: config
                .send
                .selected_headers
                .iter()
                .map(|name| HeaderName::from_bytes(name.as_bytes()))
                .collect::<Result<Vec<_>, _>>()?,
            on_error: config.on_error.clone(),
            max_response_bytes: config.max_response_bytes,
        })
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

pub(crate) async fn enforce_ext_authz(
    state: &RuntimeState,
    policy: &EffectivePolicyContext,
    input: ExtAuthzInput<'_>,
) -> Result<ExtAuthzEnforcement> {
    let Some(name) = policy.ext_authz.as_deref() else {
        return Ok(ExtAuthzEnforcement::Continue(ExtAuthzAllow::default()));
    };
    let cfg = state
        .security
        .ext_authz
        .get(name)
        .ok_or_else(|| anyhow!("ext_authz missing at runtime: {}", name))?;

    let result = ext_authz_round_trip(cfg, input).await;
    match result {
        Ok(enforcement) => Ok(enforcement),
        Err(err) => {
            warn!(ext_authz = %name, error = ?err, "ext_authz evaluation failed");
            match cfg.on_error {
                ExtAuthzOnError::Allow => {
                    Ok(ExtAuthzEnforcement::Continue(ExtAuthzAllow::default()))
                }
                ExtAuthzOnError::Deny => Ok(ExtAuthzEnforcement::Deny(ExtAuthzDeny::default())),
            }
        }
    }
}

async fn ext_authz_round_trip(
    cfg: &CompiledExtAuthz,
    input: ExtAuthzInput<'_>,
) -> Result<ExtAuthzEnforcement> {
    let body = serde_json::to_vec(&build_ext_authz_request(cfg, input))?;
    let request = Request::builder()
        .method(http::Method::POST)
        .uri(cfg.endpoint.as_str())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))?;

    let (status, body) = match cfg.endpoint.scheme() {
        "http" => {
            timeout(cfg.timeout, async {
                let response = crate::upstream::origin::shared_reverse_http_client()
                    .request(request)
                    .await?;
                let status = response.status();
                let body = crate::http::body::to_bytes_limited(
                    response.into_body(),
                    cfg.max_response_bytes,
                )
                .await?;
                anyhow::Ok((status, body))
            })
            .await??
        }
        "https" => {
            timeout(cfg.timeout, async {
                let response = crate::upstream::origin::shared_reverse_https_client()
                    .request(request)
                    .await?;
                let status = response.status();
                let body = crate::http::body::to_bytes_limited(
                    response.into_body(),
                    cfg.max_response_bytes,
                )
                .await?;
                anyhow::Ok((status, body))
            })
            .await??
        }
        other => return Err(anyhow!("unsupported ext_authz scheme: {}", other)),
    };
    if !status.is_success() {
        return Err(anyhow!("ext_authz returned {}", status));
    }
    let parsed: ExtAuthzResponse = serde_json::from_slice(&body)
        .with_context(|| "failed to parse ext_authz response body as JSON")?;
    parsed.into_enforcement()
}

#[derive(Debug, Serialize)]
struct ExtAuthzRequestBody {
    proxy: ExtAuthzProxyBody,
    request: Option<ExtAuthzRequestMeta>,
    identity: Option<ExtAuthzIdentityBody>,
}

#[derive(Debug, Serialize)]
struct ExtAuthzProxyBody {
    kind: &'static str,
    proxy_name: String,
    scope_name: String,
    matched_rule: Option<String>,
    matched_route: Option<String>,
    action: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExtAuthzRequestMeta {
    remote_ip: String,
    dst_port: Option<u16>,
    host: Option<String>,
    sni: Option<String>,
    method: Option<String>,
    path: Option<String>,
    uri: Option<String>,
    headers: HashMap<String, Vec<String>>,
}

#[derive(Debug, Serialize)]
struct ExtAuthzIdentityBody {
    user: Option<String>,
    groups: Vec<String>,
    device_id: Option<String>,
    posture: Vec<String>,
    tenant: Option<String>,
    auth_strength: Option<String>,
    idp: Option<String>,
    source: Option<String>,
}

fn build_ext_authz_request(
    cfg: &CompiledExtAuthz,
    input: ExtAuthzInput<'_>,
) -> ExtAuthzRequestBody {
    let request = cfg.send_request.then(|| ExtAuthzRequestMeta {
        remote_ip: input.remote_ip.to_string(),
        dst_port: input.dst_port,
        host: input.host.map(str::to_string),
        sni: input.sni.map(str::to_string),
        method: input.method.map(str::to_string),
        path: input.path.map(str::to_string),
        uri: input.uri.map(str::to_string),
        headers: selected_headers_map(input.headers, &cfg.selected_headers),
    });
    let identity = cfg.send_identity.then(|| ExtAuthzIdentityBody {
        user: input.identity.user.clone(),
        groups: input.identity.groups.clone(),
        device_id: input.identity.device_id.clone(),
        posture: input.identity.posture.clone(),
        tenant: input.identity.tenant.clone(),
        auth_strength: input.identity.auth_strength.clone(),
        idp: input.identity.idp.clone(),
        source: input.identity.identity_source.clone(),
    });
    ExtAuthzRequestBody {
        proxy: ExtAuthzProxyBody {
            kind: input.proxy_kind,
            proxy_name: input.proxy_name.to_string(),
            scope_name: input.scope_name.to_string(),
            matched_rule: input.matched_rule.map(str::to_string),
            matched_route: input.matched_route.map(str::to_string),
            action: input
                .action
                .map(|action| format!("{:?}", action.kind).to_ascii_lowercase()),
        },
        request,
        identity,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtAuthzResponse {
    decision: String,
    #[serde(default)]
    policy_id: Option<String>,
    #[serde(default)]
    override_upstream: Option<String>,
    #[serde(default)]
    inject_headers: Option<HeaderControl>,
    #[serde(default)]
    local_response: Option<LocalResponseConfig>,
    #[serde(default)]
    timeout_override_ms: Option<u64>,
    #[serde(default)]
    cache_bypass: bool,
    #[serde(default)]
    mirror_upstreams: Vec<String>,
    #[serde(default)]
    rate_limit_profile: Option<String>,
    #[serde(default)]
    force_inspect: bool,
    #[serde(default)]
    force_tunnel: bool,
    #[serde(default)]
    policy_tags: Vec<String>,
}

impl ExtAuthzResponse {
    fn into_enforcement(self) -> Result<ExtAuthzEnforcement> {
        if self.force_inspect && self.force_tunnel {
            return Err(anyhow!(
                "ext_authz response cannot set both force_inspect and force_tunnel"
            ));
        }
        let headers = self
            .inject_headers
            .as_ref()
            .map(CompiledHeaderControl::compile)
            .transpose()?
            .map(Arc::new);
        let timeout_override = self
            .timeout_override_ms
            .map(|timeout_ms| Duration::from_millis(timeout_ms.max(1)));
        let rate_limit_profile = self
            .rate_limit_profile
            .map(|profile| profile.trim().to_string())
            .filter(|profile| !profile.is_empty());
        let mirror_upstreams = normalize_string_list(self.mirror_upstreams);
        let policy_tags = normalize_string_list(self.policy_tags);
        match self.decision.trim().to_ascii_lowercase().as_str() {
            "allow" => Ok(ExtAuthzEnforcement::Continue(ExtAuthzAllow {
                policy_id: self.policy_id,
                override_upstream: self.override_upstream,
                headers,
                timeout_override,
                cache_bypass: self.cache_bypass,
                mirror_upstreams,
                rate_limit_profile,
                force_inspect: self.force_inspect,
                force_tunnel: self.force_tunnel,
                policy_tags,
            })),
            "deny" => Ok(ExtAuthzEnforcement::Deny(ExtAuthzDeny {
                policy_id: self.policy_id,
                headers,
                local_response: self.local_response,
                policy_tags,
            })),
            "local_response" => {
                let local_response = self.local_response.ok_or_else(|| {
                    anyhow!("ext_authz local_response decision requires local_response")
                })?;
                Ok(ExtAuthzEnforcement::Deny(ExtAuthzDeny {
                    policy_id: self.policy_id,
                    headers,
                    local_response: Some(local_response),
                    policy_tags,
                }))
            }
            "challenge" => {
                let local_response = self.local_response.ok_or_else(|| {
                    anyhow!("ext_authz challenge decision requires local_response")
                })?;
                Ok(ExtAuthzEnforcement::Deny(ExtAuthzDeny {
                    policy_id: self.policy_id,
                    headers,
                    local_response: Some(local_response),
                    policy_tags,
                }))
            }
            other => Err(anyhow!("unsupported ext_authz decision: {}", other)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ExtAuthzModeCapabilities {
    name: &'static str,
    inject_headers: bool,
    override_upstream: bool,
    timeout_override: bool,
    cache_bypass: bool,
    mirror_upstreams: bool,
    rate_limit_profile: bool,
    force_inspect: bool,
    force_tunnel: bool,
}

impl ExtAuthzMode {
    fn capabilities(self) -> ExtAuthzModeCapabilities {
        match self {
            Self::ForwardHttp => ExtAuthzModeCapabilities {
                name: "forward_http",
                inject_headers: true,
                override_upstream: true,
                timeout_override: true,
                cache_bypass: true,
                mirror_upstreams: false,
                rate_limit_profile: true,
                force_inspect: false,
                force_tunnel: false,
            },
            Self::ForwardConnect => ExtAuthzModeCapabilities {
                name: "forward_connect",
                inject_headers: true,
                override_upstream: true,
                timeout_override: true,
                cache_bypass: false,
                mirror_upstreams: false,
                rate_limit_profile: true,
                force_inspect: true,
                force_tunnel: true,
            },
            #[cfg(feature = "mitm")]
            Self::ForwardMitmHttp => ExtAuthzModeCapabilities {
                name: "forward_mitm_http",
                inject_headers: true,
                override_upstream: false,
                timeout_override: true,
                cache_bypass: false,
                mirror_upstreams: false,
                rate_limit_profile: true,
                force_inspect: false,
                force_tunnel: false,
            },
            Self::ReverseHttp => ExtAuthzModeCapabilities {
                name: "reverse_http",
                inject_headers: true,
                override_upstream: true,
                timeout_override: true,
                cache_bypass: true,
                mirror_upstreams: true,
                rate_limit_profile: true,
                force_inspect: false,
                force_tunnel: false,
            },
            Self::TransparentHttp => ExtAuthzModeCapabilities {
                name: "transparent_http",
                inject_headers: true,
                override_upstream: true,
                timeout_override: true,
                cache_bypass: false,
                mirror_upstreams: false,
                rate_limit_profile: true,
                force_inspect: false,
                force_tunnel: false,
            },
            Self::TransparentTls => ExtAuthzModeCapabilities {
                name: "transparent_tls",
                inject_headers: false,
                override_upstream: true,
                timeout_override: true,
                cache_bypass: false,
                mirror_upstreams: false,
                rate_limit_profile: true,
                force_inspect: true,
                force_tunnel: true,
            },
            #[cfg(feature = "http3")]
            Self::TransparentUdp => ExtAuthzModeCapabilities {
                name: "transparent_udp",
                inject_headers: false,
                override_upstream: false,
                timeout_override: true,
                cache_bypass: false,
                mirror_upstreams: false,
                rate_limit_profile: true,
                force_inspect: false,
                force_tunnel: false,
            },
        }
    }
}

pub(crate) fn validate_ext_authz_allow_mode(
    allow: &ExtAuthzAllow,
    mode: ExtAuthzMode,
) -> Result<()> {
    let caps = mode.capabilities();
    let mut unsupported = Vec::new();
    if allow.headers.is_some() && !caps.inject_headers {
        unsupported.push("inject_headers");
    }
    if allow.override_upstream.is_some() && !caps.override_upstream {
        unsupported.push("override_upstream");
    }
    if allow.timeout_override.is_some() && !caps.timeout_override {
        unsupported.push("timeout_override_ms");
    }
    if allow.cache_bypass && !caps.cache_bypass {
        unsupported.push("cache_bypass");
    }
    if !allow.mirror_upstreams.is_empty() && !caps.mirror_upstreams {
        unsupported.push("mirror_upstreams");
    }
    if allow.rate_limit_profile.is_some() && !caps.rate_limit_profile {
        unsupported.push("rate_limit_profile");
    }
    if allow.force_inspect && !caps.force_inspect {
        unsupported.push("force_inspect");
    }
    if allow.force_tunnel && !caps.force_tunnel {
        unsupported.push("force_tunnel");
    }
    if unsupported.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "ext_authz fields [{}] are not supported for {}",
        unsupported.join(", "),
        caps.name
    ))
}

pub(crate) fn merge_header_controls(
    base: Option<Arc<CompiledHeaderControl>>,
    extra: Option<Arc<CompiledHeaderControl>>,
) -> Option<Arc<CompiledHeaderControl>> {
    match (base, extra) {
        (Some(base), Some(extra)) => Some(Arc::new(base.as_ref().merged(extra.as_ref()))),
        (Some(base), None) => Some(base),
        (None, Some(extra)) => Some(extra),
        (None, None) => None,
    }
}

pub(crate) fn apply_override_upstream(
    action: &mut ActionConfig,
    override_upstream: Option<String>,
) {
    let Some(override_upstream) = override_upstream else {
        return;
    };
    if matches!(action.kind, ActionKind::Direct) {
        action.kind = ActionKind::Proxy;
    }
    action.upstream = Some(override_upstream);
}

pub(crate) fn apply_ext_authz_action_overrides(action: &mut ActionConfig, allow: &ExtAuthzAllow) {
    apply_override_upstream(action, allow.override_upstream.clone());
    if allow.force_inspect {
        action.kind = ActionKind::Inspect;
    } else if allow.force_tunnel {
        action.kind = ActionKind::Tunnel;
    }
}

pub(crate) fn attach_log_context(response: &mut Response<Body>, log_context: &RequestLogContext) {
    response.extensions_mut().insert(log_context.clone());
}

pub(crate) fn merge_policy_tags(into: &mut Vec<String>, extra: &[String]) {
    for tag in extra {
        let tag = tag.trim();
        if !tag.is_empty() && !into.iter().any(|existing| existing == tag) {
            into.push(tag.to_string());
        }
    }
}

pub(crate) struct AuditRecord<'a> {
    pub(crate) kind: &'static str,
    pub(crate) name: &'a str,
    pub(crate) remote_ip: IpAddr,
    pub(crate) host: Option<&'a str>,
    pub(crate) sni: Option<&'a str>,
    pub(crate) method: Option<&'a str>,
    pub(crate) path: Option<&'a str>,
    pub(crate) outcome: &'a str,
    pub(crate) status: Option<u16>,
    pub(crate) matched_rule: Option<&'a str>,
    pub(crate) matched_route: Option<&'a str>,
    pub(crate) ext_authz_policy_id: Option<&'a str>,
}

pub(crate) fn emit_audit_log(
    state: &RuntimeState,
    record: AuditRecord<'_>,
    context: &RequestLogContext,
) {
    if !state.config.audit_log.output.enabled
        || !tracing::enabled!(target: "audit_log", Level::INFO)
    {
        return;
    }
    let include = |field: AuditIncludeField| state.config.audit_log.include.contains(&field);
    tracing::info!(
        target: "audit_log",
        event = "policy",
        kind = record.kind,
        name = record.name,
        remote = %record.remote_ip,
        host = record.host.unwrap_or(""),
        sni = record.sni.unwrap_or(""),
        method = record.method.unwrap_or(""),
        path = record.path.unwrap_or(""),
        outcome = record.outcome,
        status = record.status.unwrap_or(0),
        subject = if include(AuditIncludeField::Subject) {
            context.subject.as_deref().unwrap_or("")
        } else {
            ""
        },
        groups = if include(AuditIncludeField::Groups) {
            context.groups.join(",")
        } else {
            String::new()
        },
        device_id = if include(AuditIncludeField::DeviceId) {
            context.device_id.as_deref().unwrap_or("")
        } else {
            ""
        },
        posture = if include(AuditIncludeField::Posture) {
            context.posture.join(",")
        } else {
            String::new()
        },
        tenant = if include(AuditIncludeField::Tenant) {
            context.tenant.as_deref().unwrap_or("")
        } else {
            ""
        },
        auth_strength = if include(AuditIncludeField::AuthStrength) {
            context.auth_strength.as_deref().unwrap_or("")
        } else {
            ""
        },
        idp = if include(AuditIncludeField::Idp) {
            context.idp.as_deref().unwrap_or("")
        } else {
            ""
        },
        identity_source = if include(AuditIncludeField::IdentitySource) {
            context.identity_source.as_deref().unwrap_or("")
        } else {
            ""
        },
        policy_tags = if include(AuditIncludeField::PolicyTags) {
            context.policy_tags.join(",")
        } else {
            String::new()
        },
        ext_authz_policy_id = if include(AuditIncludeField::ExtAuthzPolicyId) {
            record
                .ext_authz_policy_id
                .or(context.ext_authz_policy_id.as_deref())
                .unwrap_or("")
        } else {
            ""
        },
        matched_rule = if include(AuditIncludeField::MatchedRule) {
            record
                .matched_rule
                .or(context.matched_rule.as_deref())
                .unwrap_or("")
        } else {
            ""
        },
        matched_route = if include(AuditIncludeField::MatchedRoute) {
            record
                .matched_route
                .or(context.matched_route.as_deref())
                .unwrap_or("")
        } else {
            ""
        },
        destination_trace = context.destination_trace.as_deref().unwrap_or(""),
    );
}

fn compile_optional_header_name(name: Option<&str>) -> Result<Option<HeaderName>> {
    name.filter(|value| !value.trim().is_empty())
        .map(|value| HeaderName::from_bytes(value.as_bytes()).map_err(Into::into))
        .transpose()
}

fn peer_matches(peer_ip: IpAddr, trusted_peers: &[cidr::IpCidr]) -> bool {
    trusted_peers.iter().any(|cidr| cidr.contains(&peer_ip))
}

fn extract_first_header(headers: &HeaderMap, name: Option<&HeaderName>) -> Option<String> {
    let name = name?;
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

fn extract_list_header(headers: &HeaderMap, name: Option<&HeaderName>) -> Vec<String> {
    let Some(name) = name else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for value in headers.get_all(name).iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for item in value.split(',') {
            let item = item.trim();
            if !item.is_empty() && !out.iter().any(|existing| existing == item) {
                out.push(item.to_string());
            }
        }
    }
    out
}

fn extend_unique(target: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

fn merge_identity_source_labels(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) if left == right => Some(left),
        (Some(left), Some(right)) => Some(format!("{left},{right}")),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn normalize_string_list(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        let value = value.trim();
        if !value.is_empty() && !out.iter().any(|existing| existing == value) {
            out.push(value.to_string());
        }
    }
    out
}

fn extract_assertion_token<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
    prefix: Option<&str>,
) -> Option<&'a str> {
    for value in headers.get_all(name).iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if let Some(prefix) = prefix {
            if let Some(token) = value.strip_prefix(prefix) {
                let token = token.trim();
                if !token.is_empty() {
                    return Some(token);
                }
            }
            continue;
        }
        return Some(value);
    }
    None
}

fn load_hmac_secret_from_env(env_name: &str) -> Result<Arc<[u8]>> {
    let secret = std::env::var(env_name)
        .map_err(|_| anyhow!("missing environment variable {}", env_name))?;
    Ok(Arc::<[u8]>::from(secret.into_bytes()))
}

fn load_public_key_from_env(env_name: &str) -> Result<Arc<[u8]>> {
    let raw = std::env::var(env_name)
        .map_err(|_| anyhow!("missing environment variable {}", env_name))?;
    Ok(Arc::<[u8]>::from(parse_public_key_material(raw.as_str())?))
}

fn parse_public_key_material(raw: &str) -> Result<Vec<u8>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("signed assertion public key is empty"));
    }
    if raw.contains("-----BEGIN") {
        let blocks = pem::parse_many(raw)?;
        for block in blocks {
            match block.tag() {
                "PUBLIC KEY" => {
                    #[cfg(feature = "tls-rustls")]
                    {
                        let der = block.into_contents();
                        let (_, spki) = SubjectPublicKeyInfo::from_der(der.as_slice())
                            .map_err(|_| anyhow!("invalid PUBLIC KEY PEM"))?;
                        return Ok(spki.subject_public_key.data.to_vec());
                    }
                    #[cfg(not(feature = "tls-rustls"))]
                    {
                        return Ok(block.into_contents());
                    }
                }
                "CERTIFICATE" => {
                    #[cfg(feature = "tls-rustls")]
                    {
                        let der = block.into_contents();
                        let (_, cert) = X509Certificate::from_der(der.as_slice())
                            .map_err(|_| anyhow!("invalid CERTIFICATE PEM"))?;
                        return Ok(cert.public_key().subject_public_key.data.to_vec());
                    }
                    #[cfg(not(feature = "tls-rustls"))]
                    {
                        return Err(anyhow!(
                            "signed assertion certificate PEM requires build feature tls-rustls"
                        ));
                    }
                }
                _ => continue,
            }
        }
        return Err(anyhow!(
            "signed assertion public_key_env did not contain a supported PEM block"
        ));
    }
    if let Ok(decoded) = STANDARD.decode(raw.as_bytes()) {
        return Ok(decoded);
    }
    URL_SAFE_NO_PAD
        .decode(raw.as_bytes())
        .map_err(|e| anyhow!("invalid public key encoding: {}", e))
}

fn decode_jwt_segment(segment: &str) -> Result<Vec<u8>> {
    let segment = segment.trim();
    if segment.is_empty() {
        return Err(anyhow!("empty JWT segment"));
    }
    URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|e| anyhow!("invalid base64url segment: {}", e))
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

fn hmac_digest<D>(secret: &[u8], data: &[u8], block_size: usize) -> Vec<u8>
where
    D: Digest + Default,
{
    let mut key = vec![0u8; block_size];
    if secret.len() > block_size {
        let digest = D::digest(secret);
        key[..digest.len()].copy_from_slice(digest.as_slice());
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5cu8; block_size];
    for i in 0..block_size {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = D::new();
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();

    let mut outer = D::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().to_vec()
}

fn verify_hmac_signature<D>(
    secret: Option<&[u8]>,
    data: &[u8],
    signature_bytes: &[u8],
    block_size: usize,
) -> Result<()>
where
    D: Digest + Default,
{
    let secret = secret
        .ok_or_else(|| anyhow!("JWT algorithm requires assertion.secret_env key material"))?;
    let expected = hmac_digest::<D>(secret, data, block_size);
    if constant_time_eq(signature_bytes, expected.as_slice()) {
        return Ok(());
    }
    Err(anyhow!("JWT signature verification failed"))
}

fn verify_public_key_signature(
    algorithm: &'static dyn signature::VerificationAlgorithm,
    public_key: Option<&[u8]>,
    data: &[u8],
    signature_bytes: &[u8],
) -> Result<()> {
    let public_key = public_key
        .ok_or_else(|| anyhow!("JWT algorithm requires assertion.public_key_env key material"))?;
    signature::UnparsedPublicKey::new(algorithm, public_key)
        .verify(data, signature_bytes)
        .map_err(|_| anyhow!("JWT signature verification failed"))
}

fn validate_registered_claims(
    payload: &JsonValue,
    expected_issuer: Option<&str>,
    expected_audience: Option<&str>,
) -> Result<()> {
    if let Some(expected_issuer) = expected_issuer {
        let issuer =
            json_string_claim(payload, "iss").ok_or_else(|| anyhow!("JWT iss claim is missing"))?;
        if issuer != expected_issuer {
            return Err(anyhow!("JWT issuer mismatch"));
        }
    }
    if let Some(expected_audience) = expected_audience {
        let aud = payload
            .get("aud")
            .ok_or_else(|| anyhow!("JWT aud claim is missing"))?;
        let matched = match aud {
            JsonValue::String(value) => value == expected_audience,
            JsonValue::Array(values) => values
                .iter()
                .filter_map(|value| value.as_str())
                .any(|value| value == expected_audience),
            _ => false,
        };
        if !matched {
            return Err(anyhow!("JWT audience mismatch"));
        }
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if let Some(exp) = json_i64_claim(payload, "exp") {
        if now >= exp {
            return Err(anyhow!("JWT is expired"));
        }
    }
    if let Some(nbf) = json_i64_claim(payload, "nbf") {
        if now < nbf {
            return Err(anyhow!("JWT is not yet valid"));
        }
    }
    Ok(())
}

fn json_string_claim(payload: &JsonValue, claim: &str) -> Option<String> {
    payload
        .get(claim)?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn json_i64_claim(payload: &JsonValue, claim: &str) -> Option<i64> {
    payload.get(claim)?.as_i64()
}

fn json_list_claim(payload: &JsonValue, claim: &str, separator: Option<&str>) -> Vec<String> {
    let Some(value) = payload.get(claim) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    match value {
        JsonValue::String(raw) => {
            let separator = separator.unwrap_or(",");
            for item in raw.split(separator) {
                let item = item.trim();
                if !item.is_empty() && !out.iter().any(|existing| existing == item) {
                    out.push(item.to_string());
                }
            }
        }
        JsonValue::Array(values) => {
            for value in values {
                if let Some(item) = value.as_str().map(str::trim) {
                    if !item.is_empty() && !out.iter().any(|existing| existing == item) {
                        out.push(item.to_string());
                    }
                }
            }
        }
        _ => {}
    }
    out
}

fn selected_headers_map(
    headers: Option<&HeaderMap>,
    selected: &[HeaderName],
) -> HashMap<String, Vec<String>> {
    let Some(headers) = headers else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for name in selected {
        let values = headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if !values.is_empty() {
            out.insert(name.as_str().to_string(), values);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
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

    #[test]
    fn ext_authz_mode_validation_rejects_unsupported_fields() {
        let allow = ExtAuthzAllow {
            force_inspect: true,
            ..Default::default()
        };
        let err = validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ReverseHttp)
            .expect_err("reverse should reject force_inspect");
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
            .expect("reverse http should accept cache_bypass");

        let reverse_allow = ExtAuthzAllow {
            headers: connect_allow.headers.clone(),
            override_upstream: connect_allow.override_upstream.clone(),
            timeout_override: connect_allow.timeout_override,
            mirror_upstreams: vec!["http://mirror.internal:8080".to_string()],
            rate_limit_profile: connect_allow.rate_limit_profile.clone(),
            ..Default::default()
        };
        validate_ext_authz_allow_mode(&reverse_allow, ExtAuthzMode::ReverseHttp)
            .expect("reverse http should accept mirror_upstreams");
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
}
