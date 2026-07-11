use anyhow::{Result, anyhow};
use cidr::IpCidr;
use std::collections::HashSet;

use super::super::types::{
    AuthConfig, BearerIdentitySourceConfig, DecisionServiceConfig, DecisionServiceDriver,
    DecisionServiceMappingTargetDocument, DestinationResolutionConfig,
    DestinationResolutionOverrideConfig, HttpGuardProfileConfig, IdentitySourceConfig,
    IdentitySourceKind, NamedSetConfig, OAuth2ClientAuthMethod, RateLimitProfileConfig,
    SignedAssertionConfig, UpstreamTlsTrustProfileConfig,
};
use super::rules::{validate_header_name, validate_rate_limit_config};
use super::upstreams::validate_upstream_tls_trust_config;

fn validate_secure_or_loopback_url(value: &str, context: &str) -> Result<()> {
    let url = url::Url::parse(value).map_err(|error| anyhow!("{context} is invalid: {error}"))?;
    let loopback =
        url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
    if url.scheme() != "https" && !loopback {
        return Err(anyhow!("{context} must use https or loopback http"));
    }
    Ok(())
}

pub(super) fn validate_identity_sources(identity_sources: &[IdentitySourceConfig]) -> Result<()> {
    let mut names = HashSet::new();
    for source in identity_sources {
        if source.name.trim().is_empty() {
            return Err(anyhow!("identity_sources[].name must not be empty"));
        }
        if !names.insert(source.name.clone()) {
            return Err(anyhow!("duplicate identity_sources name: {}", source.name));
        }
        if let Some(client_ca) = source.from.client_ca.as_deref()
            && client_ca.trim().is_empty()
        {
            return Err(anyhow!(
                "identity_sources {} from.client_ca must not be empty when set",
                source.name
            ));
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
            IdentitySourceKind::Bearer => {
                if !source.from.trusted_peers.is_empty()
                    || source.from.client_ca.is_some()
                    || source.headers.is_some()
                    || source.map.is_some()
                    || source.assertion.is_some()
                {
                    return Err(anyhow!(
                        "identity_sources {} type=bearer only supports bearer configuration",
                        source.name
                    ));
                }
                let bearer = source.bearer.as_ref().ok_or_else(|| {
                    anyhow!(
                        "identity_sources {} type=bearer requires bearer configuration",
                        source.name
                    )
                })?;
                validate_header_name(
                    bearer.header.as_deref().unwrap_or("authorization"),
                    &format!("identity_sources {} bearer.header", source.name),
                )?;
                match &bearer.source {
                    BearerIdentitySourceConfig::Jwt {
                        issuer,
                        audience,
                        algorithms,
                        jwks_url,
                        public_key_env,
                        ..
                    } => {
                        if issuer.trim().is_empty() || audience.trim().is_empty() {
                            return Err(anyhow!(
                                "identity_sources {} bearer JWT issuer and audience are required",
                                source.name
                            ));
                        }
                        if jwks_url.is_some() == public_key_env.is_some() {
                            return Err(anyhow!(
                                "identity_sources {} bearer JWT requires exactly one of jwks_url or public_key_env",
                                source.name
                            ));
                        }
                        for algorithm in algorithms {
                            if !matches!(
                                algorithm.as_str(),
                                "RS256" | "RS384" | "RS512" | "ES256" | "ES384"
                            ) {
                                return Err(anyhow!(
                                    "identity_sources {} bearer JWT algorithm is unsupported: {}",
                                    source.name,
                                    algorithm
                                ));
                            }
                        }
                        if let Some(url) = jwks_url {
                            validate_secure_or_loopback_url(
                                url,
                                &format!("identity_sources {} bearer.jwks_url", source.name),
                            )?;
                        }
                    }
                    BearerIdentitySourceConfig::Introspection {
                        endpoint,
                        client_id,
                        client_secret_env,
                        positive_cache_seconds,
                        negative_cache_seconds,
                    } => {
                        if client_id.trim().is_empty() || client_secret_env.trim().is_empty() {
                            return Err(anyhow!(
                                "identity_sources {} introspection client credentials are required",
                                source.name
                            ));
                        }
                        if *positive_cache_seconds == 0 || *negative_cache_seconds == 0 {
                            return Err(anyhow!(
                                "identity_sources {} introspection cache limits must be positive",
                                source.name
                            ));
                        }
                        validate_secure_or_loopback_url(
                            endpoint,
                            &format!(
                                "identity_sources {} bearer.introspection.endpoint",
                                source.name
                            ),
                        )?;
                    }
                }
                if !bearer.claims.user_from_sub
                    && bearer.claims.user.is_none()
                    && bearer.claims.groups.is_none()
                    && bearer.claims.roles.is_none()
                    && bearer.claims.entitlements.is_none()
                    && bearer.claims.device_id.is_none()
                    && bearer.claims.posture.is_none()
                    && bearer.claims.tenant.is_none()
                    && bearer.claims.auth_strength.is_none()
                    && bearer.claims.idp.is_none()
                {
                    return Err(anyhow!(
                        "identity_sources {} bearer requires at least one claim mapping",
                        source.name
                    ));
                }
            }
            IdentitySourceKind::TrustedHeaders => {
                if source.bearer.is_some() || source.assertion.is_some() || source.map.is_some() {
                    return Err(anyhow!(
                        "identity_sources {} type=trusted_headers contains fields for another identity source type",
                        source.name
                    ));
                }
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
                    headers.roles.as_deref(),
                    headers.entitlements.as_deref(),
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
                if source.bearer.is_some() || source.assertion.is_some() {
                    return Err(anyhow!(
                        "identity_sources {} type=mtls_subject contains fields for another identity source type",
                        source.name
                    ));
                }
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
                    if let Some(prefix) = map.user_from_san_uri_prefix.as_deref()
                        && prefix.trim().is_empty()
                    {
                        return Err(anyhow!(
                            "identity_sources {} map.user_from_san_uri_prefix must not be empty when set",
                            source.name
                        ));
                    }
                    if let Some(auth_strength) = map.auth_strength.as_deref()
                        && auth_strength.trim().is_empty()
                    {
                        return Err(anyhow!(
                            "identity_sources {} map.auth_strength must not be empty when set",
                            source.name
                        ));
                    }
                    if let Some(idp) = map.idp.as_deref()
                        && idp.trim().is_empty()
                    {
                        return Err(anyhow!(
                            "identity_sources {} map.idp must not be empty when set",
                            source.name
                        ));
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
                if source.bearer.is_some() {
                    return Err(anyhow!(
                        "identity_sources {} type=signed_assertion does not support bearer configuration",
                        source.name
                    ));
                }
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
                if let Some(prefix) = assertion.prefix.as_deref()
                    && prefix.trim().is_empty()
                {
                    return Err(anyhow!(
                        "identity_sources {} assertion.prefix must not be empty when set",
                        source.name
                    ));
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
                if let Some(issuer) = assertion.issuer.as_deref()
                    && issuer.trim().is_empty()
                {
                    return Err(anyhow!(
                        "identity_sources {} assertion.issuer must not be empty when set",
                        source.name
                    ));
                }
                if let Some(audience) = assertion.audience.as_deref()
                    && audience.trim().is_empty()
                {
                    return Err(anyhow!(
                        "identity_sources {} assertion.audience must not be empty when set",
                        source.name
                    ));
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
                            ));
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
                if let Some(separator) = claims.groups_separator.as_deref()
                    && separator.is_empty()
                {
                    return Err(anyhow!(
                        "identity_sources {} assertion.claims.groups_separator must not be empty when set",
                        source.name
                    ));
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
        if let Some(file) = set.file.as_deref()
            && file.trim().is_empty()
        {
            return Err(anyhow!(
                "named_sets {} file must not be empty when set",
                set.name
            ));
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
        if let Some(value) = value
            && value > 100
        {
            return Err(anyhow!("{context}.{field} must be 0..=100"));
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

pub(super) fn validate_decision_service_configs(
    decision_service: &[DecisionServiceConfig],
    upstream_trust_profiles: &HashSet<String>,
    upstream_trust_profile_configs: &[UpstreamTlsTrustProfileConfig],
) -> Result<()> {
    let mut names = HashSet::new();
    for cfg in decision_service {
        if cfg.name.trim().is_empty() {
            return Err(anyhow!("decisions.services[].name must not be empty"));
        }
        if !names.insert(cfg.name.clone()) {
            return Err(anyhow!("duplicate decisions.services name: {}", cfg.name));
        }
        if cfg.timeout_ms == 0 {
            return Err(anyhow!(
                "decision_service {} timeout_ms must be >= 1",
                cfg.name
            ));
        }
        if cfg.max_response_bytes == 0 {
            return Err(anyhow!(
                "decision_service {} max_response_bytes must be >= 1",
                cfg.name
            ));
        }
        let endpoint = cfg.endpoint.trim();
        if endpoint.is_empty() {
            return Err(anyhow!(
                "decision_service {} endpoint must not be empty",
                cfg.name
            ));
        }
        let url = url::Url::parse(endpoint)
            .map_err(|e| anyhow!("decision_service {} endpoint is invalid: {}", cfg.name, e))?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(anyhow!(
                "decision_service {} endpoint must use http or https",
                cfg.name
            ));
        }
        if cfg.auth.bearer_token_env.is_some() && cfg.auth.oauth2_client_credentials.is_some() {
            return Err(anyhow!(
                "decision_service {} must configure at most one credential source",
                cfg.name
            ));
        }
        if cfg.contract.profile_id.trim().is_empty() {
            return Err(anyhow!(
                "decision_service {} contract.profile_id must not be empty",
                cfg.name
            ));
        }
        if let Some(contract_id) = cfg.contract.contract_id.as_deref()
            && contract_id.trim().is_empty()
        {
            return Err(anyhow!(
                "decision_service {} contract.contract_id must not be empty when set",
                cfg.name
            ));
        }
        if !cfg.schema_resolution.trusted_registries.is_empty() {
            return Err(anyhow!(
                "decision_service {} schema_resolution.trusted_registries is not supported in v1",
                cfg.name
            ));
        }
        if cfg.schema_resolution.local_bundle.is_none()
            && (cfg.contract.schemas.remote.decision_request.is_some()
                || cfg.contract.schemas.remote.decision_response.is_some()
                || cfg.contract.schemas.remote.auth_context.is_some()
                || cfg.contract.schemas.remote.audit_context.is_some())
        {
            return Err(anyhow!(
                "decision_service {} schema_resolution.local_bundle is required for remote schemas",
                cfg.name
            ));
        }
        validate_schema_ref(
            cfg.contract.schemas.remote.decision_request.as_ref(),
            &format!("decision_service {} remote.decision_request", cfg.name),
        )?;
        validate_schema_ref(
            cfg.contract.schemas.remote.decision_response.as_ref(),
            &format!("decision_service {} remote.decision_response", cfg.name),
        )?;
        validate_schema_ref(
            cfg.contract.schemas.remote.auth_context.as_ref(),
            &format!("decision_service {} remote.auth_context", cfg.name),
        )?;
        validate_schema_ref(
            cfg.contract.schemas.remote.audit_context.as_ref(),
            &format!("decision_service {} remote.audit_context", cfg.name),
        )?;
        validate_schema_ref(
            cfg.contract.schemas.qpx.pep_signal.as_ref(),
            &format!("decision_service {} qpx.pep_signal", cfg.name),
        )?;
        validate_schema_ref(
            cfg.contract.schemas.qpx.effect_capability.as_ref(),
            &format!("decision_service {} qpx.effect_capability", cfg.name),
        )?;
        validate_schema_ref(
            cfg.contract.schemas.qpx.enforceable_effect.as_ref(),
            &format!("decision_service {} qpx.enforceable_effect", cfg.name),
        )?;
        validate_schema_ref(
            cfg.contract.schemas.qpx.local_response.as_ref(),
            &format!("decision_service {} qpx.local_response", cfg.name),
        )?;
        validate_schema_ref(
            cfg.contract.schemas.qpx.audit_event.as_ref(),
            &format!("decision_service {} qpx.audit_event", cfg.name),
        )?;
        validate_decision_service_capability_names(cfg)?;
        if cfg
            .policy_composition
            .external_allow_can_override_local_deny
            || !cfg.policy_composition.external_deny_can_stop_local_allow
        {
            return Err(anyhow!(
                "decision_service {} policy_composition overrides are not supported in v1",
                cfg.name
            ));
        }
        validate_mapping_rules(
            &cfg.request_mapping,
            &format!("decision_service {} request_mapping", cfg.name),
        )?;
        if cfg.contract.driver == DecisionServiceDriver::Authzen && !cfg.request_mapping.is_empty()
        {
            return Err(anyhow!(
                "decision_service {} authzen uses its native request and requires empty request_mapping",
                cfg.name
            ));
        }
        validate_mapping_rules(
            &cfg.response_mapping,
            &format!("decision_service {} response_mapping", cfg.name),
        )?;
        if cfg.contract.driver == DecisionServiceDriver::Authzen
            && cfg.response_mapping.iter().any(|mapping| {
                mapping.target_document == DecisionServiceMappingTargetDocument::EnforceableEffect
                    && mapping.target == "/decision"
            })
        {
            return Err(anyhow!(
                "decision_service {} authzen decision is native and must not be remapped",
                cfg.name
            ));
        }
        for header in &cfg.pep_signal.selected_headers {
            validate_header_name(
                header,
                &format!("decision_service {} pep_signal.selected_headers", cfg.name),
            )?;
        }
        for header in &cfg.pep_signal.sensitive_headers {
            validate_header_name(
                header,
                &format!("decision_service {} pep_signal.sensitive_headers", cfg.name),
            )?;
        }
        for header in &cfg.capability.constraints.allowed_request_headers_to_add {
            validate_header_name(
                header,
                &format!(
                    "decision_service {} capability.constraints.allowed_request_headers_to_add",
                    cfg.name
                ),
            )?;
        }
        for header in &cfg.capability.constraints.allowed_response_headers_to_add {
            validate_header_name(
                header,
                &format!(
                    "decision_service {} capability.constraints.allowed_response_headers_to_add",
                    cfg.name
                ),
            )?;
        }
        if let Some(max) = cfg.capability.constraints.max_timeout_override_ms
            && max == 0
        {
            return Err(anyhow!(
                "decision_service {} capability.constraints.max_timeout_override_ms must be >= 1",
                cfg.name
            ));
        }
        if let Some(max_entries) = cfg.cache.max_entries
            && max_entries == 0
        {
            return Err(anyhow!(
                "decision_service {} cache.max_entries must be >= 1",
                cfg.name
            ));
        }
        if let Some(ttl_ms) = cfg.cache.ttl_ms
            && ttl_ms == 0
        {
            return Err(anyhow!(
                "decision_service {} cache.ttl_ms must be >= 1",
                cfg.name
            ));
        }
        if let Some(env) = cfg.auth.bearer_token_env.as_deref()
            && env.trim().is_empty()
        {
            return Err(anyhow!(
                "decision_service {} auth.bearer_token_env must not be empty when set",
                cfg.name
            ));
        }
        let loopback_http = url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
        if cfg.auth.bearer_token_env.is_some() && url.scheme() != "https" && !loopback_http {
            return Err(anyhow!(
                "decision_service {} auth.bearer_token_env requires an https endpoint",
                cfg.name
            ));
        }
        if let Some(oauth) = cfg.auth.oauth2_client_credentials.as_ref() {
            if oauth.client_id.trim().is_empty() {
                return Err(anyhow!(
                    "decision_service {} OAuth client_id must not be empty",
                    cfg.name
                ));
            }
            let has_secret = oauth
                .client_secret_env
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty());
            let has_private_key = oauth
                .private_key_env
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty());
            match oauth.client_auth_method {
                OAuth2ClientAuthMethod::ClientSecretBasic
                | OAuth2ClientAuthMethod::ClientSecretPost
                    if has_secret && !has_private_key => {}
                OAuth2ClientAuthMethod::PrivateKeyJwt if has_private_key && !has_secret => {}
                OAuth2ClientAuthMethod::TlsClientAuth
                    if !has_secret && !has_private_key && cfg.auth.mtls.is_some() => {}
                _ => {
                    return Err(anyhow!(
                        "decision_service {} OAuth client authentication credentials do not match client_auth_method",
                        cfg.name
                    ));
                }
            }
            if oauth
                .scope
                .as_deref()
                .is_some_and(|scope| scope.trim().is_empty())
                || oauth
                    .resource
                    .as_deref()
                    .is_some_and(|resource| resource.trim().is_empty())
            {
                return Err(anyhow!(
                    "decision_service {} OAuth scope and resource must not be empty when set",
                    cfg.name
                ));
            }
            let token_url = url::Url::parse(&oauth.token_endpoint).map_err(|error| {
                anyhow!(
                    "decision_service {} OAuth token_endpoint is invalid: {}",
                    cfg.name,
                    error
                )
            })?;
            let token_loopback = token_url.scheme() == "http"
                && matches!(
                    token_url.host_str(),
                    Some("127.0.0.1" | "::1" | "localhost")
                );
            if token_url.scheme() != "https" && !token_loopback {
                return Err(anyhow!(
                    "decision_service {} OAuth token_endpoint must use https or loopback http",
                    cfg.name
                ));
            }
        }
        if let Some(mtls) = cfg.auth.mtls.as_ref() {
            let context = format!("decision_service {} auth.mtls", cfg.name);
            let profile = mtls.upstream_trust_profile.as_deref();
            let Some(profile_name) = profile.map(str::trim).filter(|value| !value.is_empty())
            else {
                return Err(anyhow!("{context}.upstream_trust_profile is required"));
            };
            validate_upstream_trust_profile_ref(
                profile,
                upstream_trust_profiles,
                context.as_str(),
            )?;
            let Some(profile_config) = upstream_trust_profile_configs
                .iter()
                .find(|profile| profile.name == profile_name)
            else {
                return Err(anyhow!(
                    "{context} references unknown upstream_trust_profile: {profile_name}"
                ));
            };
            let has_client_cert = profile_config
                .trust
                .client_cert
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty());
            let has_client_key = profile_config
                .trust
                .client_key
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty());
            if !has_client_cert || !has_client_key {
                return Err(anyhow!(
                    "{context}.upstream_trust_profile must configure client_cert and client_key"
                ));
            }
            if url.scheme() != "https" {
                return Err(anyhow!(
                    "decision_service {} auth.mtls requires an https endpoint",
                    cfg.name
                ));
            }
        }
        if let Some(hms) = cfg.auth.http_message_signatures.as_ref() {
            if url.scheme() != "https" {
                return Err(anyhow!(
                    "decision_service {} auth.http_message_signatures requires an https endpoint",
                    cfg.name
                ));
            }
            if hms.key_id.trim().is_empty() {
                return Err(anyhow!(
                    "decision_service {} auth.http_message_signatures.key_id must not be empty",
                    cfg.name
                ));
            }
            if hms.secret_env.is_some() == hms.private_key_env.is_some() {
                return Err(anyhow!(
                    "decision_service {} auth.http_message_signatures must set exactly one of secret_env or private_key_env",
                    cfg.name
                ));
            }
        }
    }
    Ok(())
}

fn validate_decision_service_capability_names(cfg: &DecisionServiceConfig) -> Result<()> {
    const MODES: &[&str] = &[
        "forward_http",
        "forward_connect",
        "forward_mitm_http",
        "reverse_http",
        "transparent_http",
        "transparent_tls",
        "transparent_udp",
    ];
    const PHASES: &[&str] = &["request_headers_after_route"];
    const EFFECTS: &[&str] = &[
        "allow",
        "deny",
        "local_response",
        "challenge",
        "inject_headers",
        "override_upstream",
        "timeout_override",
        "cache_bypass",
        "mirror_upstreams",
        "rate_limit_profile",
        "force_inspect",
        "force_tunnel",
    ];
    validate_string_set_members(
        &cfg.capability.modes,
        MODES,
        &format!("decision_service {} capability.modes", cfg.name),
    )?;
    validate_string_set_members(
        &cfg.capability.phases,
        PHASES,
        &format!("decision_service {} capability.phases", cfg.name),
    )?;
    validate_string_set_members(
        &cfg.capability.effects,
        EFFECTS,
        &format!("decision_service {} capability.effects", cfg.name),
    )
}

fn validate_string_set_members(values: &[String], allowed: &[&str], context: &str) -> Result<()> {
    let mut seen = HashSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            return Err(anyhow!("{context} entries must not be empty"));
        }
        let normalized = value.to_ascii_lowercase();
        if !allowed.contains(&normalized.as_str()) {
            return Err(anyhow!("{context} contains unsupported value: {value}"));
        }
        if !seen.insert(normalized) {
            return Err(anyhow!("{context} contains duplicate value: {value}"));
        }
    }
    Ok(())
}

fn validate_schema_ref(
    schema: Option<&super::super::types::DecisionServiceSchemaRefConfig>,
    context: &str,
) -> Result<()> {
    let Some(schema) = schema else {
        return Ok(());
    };
    if schema.id.trim().is_empty() {
        return Err(anyhow!("{context}.id must not be empty"));
    }
    if !schema.digest.starts_with("sha256:") || schema.digest.len() != "sha256:".len() + 64 {
        return Err(anyhow!("{context}.digest must be sha256:<64 hex chars>"));
    }
    if !schema
        .digest
        .strip_prefix("sha256:")
        .unwrap_or_default()
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(anyhow!("{context}.digest must be sha256:<64 hex chars>"));
    }
    Ok(())
}

fn validate_mapping_rules(
    rules: &[super::super::types::DecisionServiceMappingRuleConfig],
    context: &str,
) -> Result<()> {
    let mut targets = HashSet::new();
    for (idx, rule) in rules.iter().enumerate() {
        let context = format!("{context}[{idx}]");
        if rule.source.is_some() == rule.literal.is_some() {
            return Err(anyhow!(
                "{context} must set exactly one of source or literal"
            ));
        }
        if rule.literal.is_some() && !rule.value_map.is_empty() {
            return Err(anyhow!(
                "{context}.value_map is only valid for source mappings"
            ));
        }
        if let Some(source) = rule.source.as_deref()
            && source.trim().is_empty()
        {
            return Err(anyhow!("{context}.source must not be empty when set"));
        }
        if !rule.target.starts_with('/') {
            return Err(anyhow!("{context}.target must be a JSON Pointer"));
        }
        if !targets.insert((rule.target_document.clone(), rule.target.clone())) {
            return Err(anyhow!("{context}.target duplicates another mapping rule"));
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
        if let Some(password) = user.password.as_deref()
            && password.trim().is_empty()
        {
            return Err(anyhow!(
                "auth.users {} password must not be empty when set",
                user.username
            ));
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
