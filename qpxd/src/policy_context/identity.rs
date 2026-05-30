use crate::runtime::RuntimeState;
use crate::runtime::auth::AuthenticatedUser;
use anyhow::{Result, anyhow};
use http::header::HeaderName;
use hyper::HeaderMap;
use qpx_core::config::{
    IdentitySourceConfig, IdentitySourceHeadersConfig, IdentitySourceKind, MtlsIdentityMapConfig,
    PolicyContextConfig,
};
use qpx_observability::access_log::RequestLogContext;
use std::collections::HashSet;
use std::net::IpAddr;

#[cfg(feature = "tls-rustls")]
use x509_parser::certificate::X509Certificate;
#[cfg(feature = "tls-rustls")]
use x509_parser::extensions::GeneralName;
#[cfg(feature = "tls-rustls")]
use x509_parser::prelude::FromDer;

use super::signed_assertion::CompiledSignedAssertion;
use super::util::{
    compile_optional_header_name, extend_unique, extract_first_header, extract_list_header,
    merge_identity_source_labels, peer_matches,
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
                    CompiledSignedAssertion::from_config(&config.name, assertion)?,
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

pub(crate) fn sanitize_headers_for_policy(
    state: &RuntimeState,
    policy: &EffectivePolicyContext,
    peer_ip: IpAddr,
    headers: &mut HeaderMap,
) -> Result<()> {
    strip_untrusted_identity_headers(state, policy, peer_ip, headers)
}

pub(crate) fn strip_untrusted_identity_headers(
    state: &RuntimeState,
    policy: &EffectivePolicyContext,
    peer_ip: IpAddr,
    headers: &mut HeaderMap,
) -> Result<()> {
    let mut names_to_strip = HashSet::new();

    for source_name in &policy.identity_sources {
        state
            .security
            .identity_sources
            .sources
            .get(source_name)
            .ok_or_else(|| anyhow!("identity source missing at runtime: {}", source_name))?;
    }

    for source in state.security.identity_sources.sources.values() {
        match &source.kind {
            CompiledIdentitySourceKind::TrustedHeaders(cfg) => {
                if cfg.strip_from_untrusted && !peer_matches(peer_ip, &cfg.trusted_peers) {
                    for name in cfg.headers.all_names() {
                        names_to_strip.insert(name);
                    }
                }
            }
            CompiledIdentitySourceKind::SignedAssertion(_) => {}
            CompiledIdentitySourceKind::MtlsSubject(_) => {}
        }
    }

    for name in names_to_strip {
        headers.remove(name);
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
            CompiledIdentitySourceKind::SignedAssertion(cfg) => match headers {
                Some(headers) => cfg.extract(headers)?,
                None => ResolvedIdentity::default(),
            },
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

    if let Some(prefix) = cfg.user_from_san_uri_prefix.as_deref()
        && let Ok(Some(san)) = cert.subject_alternative_name()
    {
        for name in &san.value.general_names {
            if let GeneralName::URI(uri) = name
                && let Some(user) = uri.strip_prefix(prefix)
                && !user.is_empty()
            {
                identity.user = Some(user.to_string());
                break;
            }
        }
    }

    if identity.user.is_none()
        && cfg.user_from_subject_cn
        && let Some(cn) = cert
            .subject()
            .iter_common_name()
            .filter_map(|attr| attr.as_str().ok())
            .find(|value| !value.trim().is_empty())
    {
        identity.user = Some(cn.trim().to_string());
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
mod tests;
