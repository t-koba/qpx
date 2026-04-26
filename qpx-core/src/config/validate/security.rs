use anyhow::{anyhow, Result};
use cidr::IpCidr;
use std::collections::HashSet;

use super::super::types::{
    AuthConfig, DestinationResolutionConfig, DestinationResolutionOverrideConfig, ExtAuthzConfig,
    HttpGuardProfileConfig, IdentitySourceConfig, IdentitySourceKind, NamedSetConfig,
    RateLimitProfileConfig, SignedAssertionConfig, UpstreamTlsTrustProfileConfig,
};
use super::rules::{validate_header_name, validate_rate_limit_config};
use super::upstreams::validate_upstream_tls_trust_config;

pub(super) fn validate_identity_sources(identity_sources: &[IdentitySourceConfig]) -> Result<()> {
    let mut names = HashSet::new();
    for source in identity_sources {
        if source.name.trim().is_empty() {
            return Err(anyhow!("identity_sources[].name must not be empty"));
        }
        if !names.insert(source.name.clone()) {
            return Err(anyhow!("duplicate identity_sources name: {}", source.name));
        }
        if let Some(client_ca) = source.from.client_ca.as_deref() {
            if client_ca.trim().is_empty() {
                return Err(anyhow!(
                    "identity_sources {} from.client_ca must not be empty when set",
                    source.name
                ));
            }
        }
        for cidr in &source.from.trusted_peers {
            if cidr.trim().is_empty() {
                return Err(anyhow!(
                    "identity_sources {} from.trusted_peers entries must not be empty",
                    source.name
                ));
            }
            let _: IpCidr = cidr.parse().map_err(|_| {
                anyhow!(
                    "identity_sources {} has invalid trusted peer CIDR: {}",
                    source.name,
                    cidr
                )
            })?;
        }

        match source.kind {
            IdentitySourceKind::TrustedHeaders => {
                if source.from.trusted_peers.is_empty() {
                    return Err(anyhow!(
                        "identity_sources {} type=trusted_headers requires from.trusted_peers",
                        source.name
                    ));
                }
                if source.from.client_ca.is_some() {
                    return Err(anyhow!(
                        "identity_sources {} type=trusted_headers does not support from.client_ca",
                        source.name
                    ));
                }
                let headers = source.headers.as_ref().ok_or_else(|| {
                    anyhow!(
                        "identity_sources {} type=trusted_headers requires headers",
                        source.name
                    )
                })?;
                let mut any = false;
                for header in [
                    headers.user.as_deref(),
                    headers.groups.as_deref(),
                    headers.device_id.as_deref(),
                    headers.posture.as_deref(),
                    headers.tenant.as_deref(),
                    headers.auth_strength.as_deref(),
                    headers.idp.as_deref(),
                ]
                .into_iter()
                .flatten()
                {
                    any = true;
                    validate_header_name(
                        header,
                        &format!("identity_sources {} headers", source.name),
                    )?;
                }
                if !any {
                    return Err(anyhow!(
                        "identity_sources {} type=trusted_headers requires at least one mapped header",
                        source.name
                    ));
                }
            }
            IdentitySourceKind::MtlsSubject => {
                #[cfg(not(feature = "tls-rustls"))]
                {
                    return Err(anyhow!(
                        "identity_sources {} type=mtls_subject requires tls-rustls build support",
                        source.name
                    ));
                }
                #[cfg(feature = "tls-rustls")]
                {
                    if !source.from.trusted_peers.is_empty() {
                        return Err(anyhow!(
                            "identity_sources {} type=mtls_subject does not support from.trusted_peers",
                            source.name
                        ));
                    }
                    if source.headers.is_some() {
                        return Err(anyhow!(
                            "identity_sources {} type=mtls_subject does not support headers",
                            source.name
                        ));
                    }
                    let map = source.map.as_ref().ok_or_else(|| {
                        anyhow!(
                            "identity_sources {} type=mtls_subject requires map",
                            source.name
                        )
                    })?;
                    if let Some(prefix) = map.user_from_san_uri_prefix.as_deref() {
                        if prefix.trim().is_empty() {
                            return Err(anyhow!(
                                "identity_sources {} map.user_from_san_uri_prefix must not be empty when set",
                                source.name
                            ));
                        }
                    }
                    if let Some(auth_strength) = map.auth_strength.as_deref() {
                        if auth_strength.trim().is_empty() {
                            return Err(anyhow!(
                                "identity_sources {} map.auth_strength must not be empty when set",
                                source.name
                            ));
                        }
                    }
                    if let Some(idp) = map.idp.as_deref() {
                        if idp.trim().is_empty() {
                            return Err(anyhow!(
                                "identity_sources {} map.idp must not be empty when set",
                                source.name
                            ));
                        }
                    }
                    if map.user_from_san_uri_prefix.is_none()
                        && !map.user_from_subject_cn
                        && map.auth_strength.is_none()
                        && map.idp.is_none()
                    {
                        return Err(anyhow!(
                            "identity_sources {} type=mtls_subject must configure at least one map output",
                            source.name
                        ));
                    }
                }
            }
            IdentitySourceKind::SignedAssertion => {
                if !source.from.trusted_peers.is_empty() || source.from.client_ca.is_some() {
                    return Err(anyhow!(
                        "identity_sources {} type=signed_assertion does not support from.*",
                        source.name
                    ));
                }
                if source.headers.is_some() || source.map.is_some() {
                    return Err(anyhow!(
                        "identity_sources {} type=signed_assertion must use assertion config instead of headers/map",
                        source.name
                    ));
                }
                let assertion = source.assertion.as_ref().ok_or_else(|| {
                    anyhow!(
                        "identity_sources {} type=signed_assertion requires assertion",
                        source.name
                    )
                })?;
                validate_header_name(
                    assertion.header.as_str(),
                    &format!("identity_sources {} assertion.header", source.name),
                )?;
                if let Some(prefix) = assertion.prefix.as_deref() {
                    if prefix.trim().is_empty() {
                        return Err(anyhow!(
                            "identity_sources {} assertion.prefix must not be empty when set",
                            source.name
                        ));
                    }
                }
                let secret_env = assertion
                    .secret_env
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                let public_key_env = assertion
                    .public_key_env
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                if secret_env.is_none() && public_key_env.is_none() {
                    return Err(anyhow!(
                        "identity_sources {} type=signed_assertion requires assertion.secret_env or assertion.public_key_env",
                        source.name
                    ));
                }
                if let Some(issuer) = assertion.issuer.as_deref() {
                    if issuer.trim().is_empty() {
                        return Err(anyhow!(
                            "identity_sources {} assertion.issuer must not be empty when set",
                            source.name
                        ));
                    }
                }
                if let Some(audience) = assertion.audience.as_deref() {
                    if audience.trim().is_empty() {
                        return Err(anyhow!(
                            "identity_sources {} assertion.audience must not be empty when set",
                            source.name
                        ));
                    }
                }
                let configured_algorithms = default_signed_assertion_algorithms(assertion);
                let mut needs_secret = false;
                let mut needs_public_key = false;
                for alg in &configured_algorithms {
                    match alg.trim().to_ascii_uppercase().as_str() {
                        "HS256" | "HS384" | "HS512" => {
                            needs_secret = true;
                        }
                        "RS256" | "RS384" | "RS512" | "ES256" | "ES384" => {
                            needs_public_key = true;
                        }
                        other => {
                            return Err(anyhow!(
                                "identity_sources {} assertion.algorithms has unsupported algorithm: {}",
                                source.name,
                                other
                            ))
                        }
                    }
                }
                if needs_secret && secret_env.is_none() {
                    return Err(anyhow!(
                        "identity_sources {} signed_assertion HMAC algorithms require assertion.secret_env",
                        source.name
                    ));
                }
                if needs_public_key && public_key_env.is_none() {
                    return Err(anyhow!(
                        "identity_sources {} signed_assertion public-key algorithms require assertion.public_key_env",
                        source.name
                    ));
                }
                let claims = &assertion.claims;
                if let Some(separator) = claims.groups_separator.as_deref() {
                    if separator.is_empty() {
                        return Err(anyhow!(
                            "identity_sources {} assertion.claims.groups_separator must not be empty when set",
                            source.name
                        ));
                    }
                }
                let mut any = claims.user_from_sub;
                for (label, claim) in [
                    ("user", claims.user.as_deref()),
                    ("groups", claims.groups.as_deref()),
                    ("device_id", claims.device_id.as_deref()),
                    ("posture", claims.posture.as_deref()),
                    ("tenant", claims.tenant.as_deref()),
                    ("auth_strength", claims.auth_strength.as_deref()),
                    ("idp", claims.idp.as_deref()),
                ] {
                    if let Some(claim) = claim {
                        if claim.trim().is_empty() {
                            return Err(anyhow!(
                                "identity_sources {} assertion.claims.{label} must not be empty when set",
                                source.name
                            ));
                        }
                        any = true;
                    }
                }
                if !any {
                    return Err(anyhow!(
                        "identity_sources {} type=signed_assertion must configure at least one claim mapping",
                        source.name
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_named_sets(named_sets: &[NamedSetConfig]) -> Result<()> {
    let mut names = HashSet::new();
    for set in named_sets {
        if set.name.trim().is_empty() {
            return Err(anyhow!("named_sets[].name must not be empty"));
        }
        if !names.insert(set.name.clone()) {
            return Err(anyhow!("duplicate named_sets name: {}", set.name));
        }
        if set.values.is_empty() && set.file.as_deref().unwrap_or("").trim().is_empty() {
            return Err(anyhow!(
                "named_sets {} must set at least one of values or file",
                set.name
            ));
        }
        if let Some(file) = set.file.as_deref() {
            if file.trim().is_empty() {
                return Err(anyhow!(
                    "named_sets {} file must not be empty when set",
                    set.name
                ));
            }
        }
        for value in &set.values {
            if value.trim().is_empty() {
                return Err(anyhow!(
                    "named_sets {} values entries must not be empty",
                    set.name
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_rate_limit_profiles(profiles: &[RateLimitProfileConfig]) -> Result<()> {
    let mut names = HashSet::new();
    for profile in profiles {
        if profile.name.trim().is_empty() {
            return Err(anyhow!("rate_limit_profiles[].name must not be empty"));
        }
        if !names.insert(profile.name.clone()) {
            return Err(anyhow!(
                "duplicate rate_limit_profiles name: {}",
                profile.name
            ));
        }
        validate_rate_limit_config(
            Some(&profile.limit),
            &format!("rate_limit_profiles {}", profile.name),
        )?;
    }
    Ok(())
}

pub(super) fn validate_destination_resolution_config(
    config: &DestinationResolutionConfig,
) -> Result<()> {
    validate_destination_resolution_precedence(
        config.defaults.precedence.as_slice(),
        "destination_resolution.defaults.precedence",
    )?;
    validate_destination_min_confidence(
        &config.defaults.min_confidence,
        "destination_resolution.defaults.min_confidence",
    )
}

pub(super) fn validate_destination_resolution_override(
    config: Option<&DestinationResolutionOverrideConfig>,
    context: &str,
) -> Result<()> {
    let Some(config) = config else {
        return Ok(());
    };
    if let Some(precedence) = config.precedence.as_ref() {
        validate_destination_resolution_precedence(
            precedence.as_slice(),
            &format!("{context}.destination_resolution.precedence"),
        )?;
    }
    if let Some(min_confidence) = config.min_confidence.as_ref() {
        validate_destination_min_confidence(
            min_confidence,
            &format!("{context}.destination_resolution.min_confidence"),
        )?;
    }
    Ok(())
}

pub(super) fn validate_http_guard_profiles(
    profiles: &[HttpGuardProfileConfig],
) -> Result<HashSet<String>> {
    let mut names = HashSet::new();
    for profile in profiles {
        if profile.name.trim().is_empty() {
            return Err(anyhow!("http_guard_profiles[].name must not be empty"));
        }
        if !names.insert(profile.name.clone()) {
            return Err(anyhow!(
                "duplicate http_guard_profiles name: {}",
                profile.name
            ));
        }
        for (field, value) in [
            ("limits.header_count", profile.limits.header_count),
            ("limits.header_bytes", profile.limits.header_bytes),
            ("limits.path_bytes", profile.limits.path_bytes),
            ("limits.query_pairs", profile.limits.query_pairs),
            ("limits.query_key_bytes", profile.limits.query_key_bytes),
            ("limits.query_value_bytes", profile.limits.query_value_bytes),
            ("limits.body_bytes", profile.limits.body_bytes),
            ("json.max_depth", profile.json.max_depth),
            ("json.max_fields", profile.json.max_fields),
            ("multipart.max_parts", profile.multipart.max_parts),
            ("multipart.max_name_bytes", profile.multipart.max_name_bytes),
            (
                "multipart.max_filename_bytes",
                profile.multipart.max_filename_bytes,
            ),
        ] {
            if matches!(value, Some(0)) {
                return Err(anyhow!(
                    "http_guard_profiles {} {} must be >= 1 when set",
                    profile.name,
                    field
                ));
            }
        }
    }
    Ok(names)
}

pub(super) fn validate_http_guard_profile_ref(
    profile: Option<&str>,
    profiles: &HashSet<String>,
    context: &str,
) -> Result<()> {
    let Some(profile) = profile.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if !profiles.contains(profile) {
        return Err(anyhow!(
            "{context} references unknown http_guard_profile: {profile}"
        ));
    }
    Ok(())
}

fn validate_destination_resolution_precedence<T>(precedence: &[T], context: &str) -> Result<()>
where
    T: std::cmp::Eq + std::hash::Hash + Copy,
{
    if precedence.is_empty() {
        return Err(anyhow!("{context} must not be empty"));
    }
    let mut seen = HashSet::new();
    for entry in precedence {
        if !seen.insert(*entry) {
            return Err(anyhow!("{context} must not contain duplicates"));
        }
    }
    Ok(())
}

fn validate_destination_min_confidence(
    min_confidence: &super::super::types::DestinationMinConfidenceConfig,
    context: &str,
) -> Result<()> {
    for (field, value) in [
        ("category", min_confidence.category),
        ("reputation", min_confidence.reputation),
        ("application", min_confidence.application),
    ] {
        if let Some(value) = value {
            if value > 100 {
                return Err(anyhow!("{context}.{field} must be 0..=100"));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_upstream_trust_profiles(
    profiles: &[UpstreamTlsTrustProfileConfig],
) -> Result<HashSet<String>> {
    let mut names = HashSet::new();
    for profile in profiles {
        if profile.name.trim().is_empty() {
            return Err(anyhow!("upstream_trust_profiles[].name must not be empty"));
        }
        if !names.insert(profile.name.clone()) {
            return Err(anyhow!(
                "duplicate upstream_trust_profiles name: {}",
                profile.name
            ));
        }
        validate_upstream_tls_trust_config(
            Some(&profile.trust),
            &format!("upstream_trust_profiles {}", profile.name),
        )?;
    }
    Ok(names)
}

pub(super) fn validate_upstream_trust_profile_ref(
    profile: Option<&str>,
    profiles: &HashSet<String>,
    context: &str,
) -> Result<()> {
    let Some(profile) = profile.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if !profiles.contains(profile) {
        return Err(anyhow!(
            "{context} references unknown upstream_trust_profile: {profile}"
        ));
    }
    Ok(())
}

pub(super) fn validate_ext_authz_configs(ext_authz: &[ExtAuthzConfig]) -> Result<()> {
    let mut names = HashSet::new();
    for cfg in ext_authz {
        if cfg.name.trim().is_empty() {
            return Err(anyhow!("ext_authz[].name must not be empty"));
        }
        if !names.insert(cfg.name.clone()) {
            return Err(anyhow!("duplicate ext_authz name: {}", cfg.name));
        }
        if cfg.timeout_ms == 0 {
            return Err(anyhow!("ext_authz {} timeout_ms must be >= 1", cfg.name));
        }
        if cfg.max_response_bytes == 0 {
            return Err(anyhow!(
                "ext_authz {} max_response_bytes must be >= 1",
                cfg.name
            ));
        }
        let endpoint = cfg.endpoint.trim();
        if endpoint.is_empty() {
            return Err(anyhow!("ext_authz {} endpoint must not be empty", cfg.name));
        }
        let url = url::Url::parse(endpoint)
            .map_err(|e| anyhow!("ext_authz {} endpoint is invalid: {}", cfg.name, e))?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(anyhow!(
                "ext_authz {} endpoint must use http or https",
                cfg.name
            ));
        }
        for header in &cfg.send.selected_headers {
            validate_header_name(
                header,
                &format!("ext_authz {} send.selected_headers", cfg.name),
            )?;
        }
    }
    Ok(())
}

pub(super) fn validate_auth_config(auth: &AuthConfig) -> Result<()> {
    let mut local_usernames = HashSet::new();
    for user in &auth.users {
        if user.username.trim().is_empty() {
            return Err(anyhow!("auth.users[].username must not be empty"));
        }
        if !local_usernames.insert(user.username.clone()) {
            return Err(anyhow!("duplicate auth.users username: {}", user.username));
        }
        if let Some(password) = user.password.as_deref() {
            if password.trim().is_empty() {
                return Err(anyhow!(
                    "auth.users {} password must not be empty when set",
                    user.username
                ));
            }
        }
        if let Some(ha1) = user.ha1.as_deref() {
            if ha1.trim().is_empty() {
                return Err(anyhow!(
                    "auth.users {} ha1 must not be empty when set",
                    user.username
                ));
            }
            if !is_valid_sha256_ha1(ha1) {
                return Err(anyhow!(
                    "auth.users {} ha1 must be SHA-256 HA1 hex (64 chars) or sha-256:<hex>",
                    user.username
                ));
            }
        }
        if user.password.is_none() && user.ha1.is_none() {
            return Err(anyhow!(
                "auth.users {} must set either password or ha1",
                user.username
            ));
        }
    }

    if let Some(ldap) = auth.ldap.as_ref() {
        if ldap.url.starts_with("ldap://") && !ldap.require_starttls {
            return Err(anyhow!(
                "auth.ldap.require_starttls must be true when auth.ldap.url uses ldap://"
            ));
        }
        if ldap.timeout_ms == 0 {
            return Err(anyhow!("auth.ldap.timeout_ms must be >= 1"));
        }
    }
    Ok(())
}

fn is_valid_sha256_ha1(raw: &str) -> bool {
    let raw = raw.trim();
    let hex = if raw.len() > 8 && raw[..8].eq_ignore_ascii_case("sha-256:") {
        &raw[8..]
    } else {
        raw
    };
    let hex = hex.trim();
    hex.len() == 64 && hex.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
}

pub(super) fn default_signed_assertion_algorithms(
    assertion: &SignedAssertionConfig,
) -> Vec<String> {
    if !assertion.algorithms.is_empty() {
        return assertion.algorithms.clone();
    }

    let has_secret = assertion
        .secret_env
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some();
    let has_public_key = assertion
        .public_key_env
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some();

    let mut algorithms = Vec::new();
    if has_secret {
        algorithms.push("HS256".to_string());
    }
    if has_public_key {
        algorithms.extend([
            "RS256".to_string(),
            "RS384".to_string(),
            "RS512".to_string(),
            "ES256".to_string(),
            "ES384".to_string(),
        ]);
    }
    if algorithms.is_empty() {
        algorithms.push("HS256".to_string());
    }
    algorithms
}
