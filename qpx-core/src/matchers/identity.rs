use crate::config::{CertificateMatchConfig, IdentityMatchConfig, TlsFingerprintMatchConfig};
use crate::prefilter::{StringInterner, TextPatternMatcher, compile_text_patterns};
use crate::rules::RuleMatchContext;

use super::Result;

#[derive(Debug, Clone)]
pub(super) struct CompiledIdentityMatch {
    user: Option<TextPatternMatcher>,
    groups: Option<TextPatternMatcher>,
    device_id: Option<TextPatternMatcher>,
    posture: Option<TextPatternMatcher>,
    tenant: Option<TextPatternMatcher>,
    auth_strength: Option<TextPatternMatcher>,
    idp: Option<TextPatternMatcher>,
}

#[derive(Debug, Clone)]
pub(super) struct CompiledTlsFingerprintMatch {
    ja3: Option<TextPatternMatcher>,
    ja4: Option<TextPatternMatcher>,
}

#[derive(Debug, Clone)]
pub(super) struct CompiledCertificateMatch {
    present: Option<bool>,
    subject: Option<TextPatternMatcher>,
    issuer: Option<TextPatternMatcher>,
    san_dns: Option<TextPatternMatcher>,
    san_uri: Option<TextPatternMatcher>,
    fingerprint_sha256: Option<TextPatternMatcher>,
}

impl CompiledIdentityMatch {
    pub(super) fn compile(
        config: &IdentityMatchConfig,
        interner: &mut StringInterner,
    ) -> Result<Self> {
        Ok(Self {
            user: compile_identity_patterns(&config.user, interner)?,
            groups: compile_identity_patterns(&config.groups, interner)?,
            device_id: compile_identity_patterns(&config.device_id, interner)?,
            posture: compile_identity_patterns(&config.posture, interner)?,
            tenant: compile_identity_patterns(&config.tenant, interner)?,
            auth_strength: compile_identity_patterns(&config.auth_strength, interner)?,
            idp: compile_identity_patterns(&config.idp, interner)?,
        })
    }

    pub(super) fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        match_optional_identity(&self.user, ctx.user)
            && match_any_identity(&self.groups, ctx.user_groups)
            && match_optional_identity(&self.device_id, ctx.device_id)
            && match_any_identity(&self.posture, ctx.posture)
            && match_optional_identity(&self.tenant, ctx.tenant)
            && match_optional_identity(&self.auth_strength, ctx.auth_strength)
            && match_optional_identity(&self.idp, ctx.idp)
    }
}

impl CompiledTlsFingerprintMatch {
    pub(super) fn compile(
        config: &TlsFingerprintMatchConfig,
        interner: &mut StringInterner,
    ) -> Result<Self> {
        Ok(Self {
            ja3: compile_identity_patterns(&config.ja3, interner)?,
            ja4: compile_identity_patterns(&config.ja4, interner)?,
        })
    }

    pub(super) fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        match_optional_text(&self.ja3, ctx.ja3) && match_optional_text(&self.ja4, ctx.ja4)
    }

    pub(super) fn requires_tls_fingerprint(&self) -> bool {
        self.ja3.is_some() || self.ja4.is_some()
    }
}

impl CompiledCertificateMatch {
    pub(super) fn compile(
        config: &CertificateMatchConfig,
        interner: &mut StringInterner,
    ) -> Result<Self> {
        Ok(Self {
            present: config.present,
            subject: compile_identity_patterns(&config.subject, interner)?,
            issuer: compile_identity_patterns(&config.issuer, interner)?,
            san_dns: compile_identity_patterns(&config.san_dns, interner)?,
            san_uri: compile_identity_patterns(&config.san_uri, interner)?,
            fingerprint_sha256: compile_identity_patterns(&config.fingerprint_sha256, interner)?,
        })
    }

    pub(super) fn matches(
        &self,
        present: Option<bool>,
        subject: Option<&str>,
        issuer: Option<&str>,
        san_dns: &[String],
        san_uri: &[String],
        fingerprint_sha256: Option<&str>,
    ) -> bool {
        if let Some(expected) = self.present
            && present != Some(expected)
        {
            return false;
        }
        match_optional_text(&self.subject, subject)
            && match_optional_text(&self.issuer, issuer)
            && match_any_text(&self.san_dns, san_dns)
            && match_any_text(&self.san_uri, san_uri)
            && match_optional_text(&self.fingerprint_sha256, fingerprint_sha256)
    }
}

pub(super) fn match_optional_text(
    matcher: &Option<TextPatternMatcher>,
    value: Option<&str>,
) -> bool {
    match matcher {
        Some(matcher) => value.map(|value| matcher.matches(value)).unwrap_or(false),
        None => true,
    }
}

pub(super) fn match_any_text(matcher: &Option<TextPatternMatcher>, values: &[String]) -> bool {
    match matcher {
        Some(matcher) => values.iter().any(|value| matcher.matches(value)),
        None => true,
    }
}

fn compile_identity_patterns(
    items: &[String],
    interner: &mut StringInterner,
) -> Result<Option<TextPatternMatcher>> {
    let (matcher, _) = compile_text_patterns(items, false, false, interner)?;
    Ok(matcher)
}

fn match_optional_identity(matcher: &Option<TextPatternMatcher>, value: Option<&str>) -> bool {
    match_optional_text(matcher, value)
}

fn match_any_identity(matcher: &Option<TextPatternMatcher>, values: &[String]) -> bool {
    match_any_text(matcher, values)
}
