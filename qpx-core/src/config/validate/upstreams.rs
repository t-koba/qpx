use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};

use super::super::types::{CacheConfig, Config, UpstreamDiscoveryKind, UpstreamTlsTrustConfig};
use super::rules::validate_resilience_config;
use super::security::validate_upstream_trust_profile_ref;
use super::UPSTREAM_URL_SCHEMES;

pub(super) fn validate_cache_backends(cache: &CacheConfig) -> Result<HashSet<String>> {
    let mut cache_backends = HashSet::new();
    for backend in &cache.backends {
        if backend.name.trim().is_empty() {
            return Err(anyhow!("cache backend name must not be empty"));
        }
        if !cache_backends.insert(backend.name.clone()) {
            return Err(anyhow!("duplicate cache backend name: {}", backend.name));
        }
        if backend.kind != "http" && backend.kind != "redis" {
            return Err(anyhow!(
                "cache backend {} has unsupported kind: {}",
                backend.name,
                backend.kind
            ));
        }
        if backend.endpoint.trim().is_empty() {
            return Err(anyhow!(
                "cache backend {} endpoint must not be empty",
                backend.name
            ));
        }
        if backend.kind == "http" {
            let url = url::Url::parse(backend.endpoint.as_str()).map_err(|e| {
                anyhow!(
                    "cache backend {} has invalid endpoint url {} ({})",
                    backend.name,
                    backend.endpoint,
                    e
                )
            })?;
            if !url.username().is_empty() || url.password().is_some() {
                return Err(anyhow!(
                    "cache backend {} endpoint must not include userinfo",
                    backend.name
                ));
            }
            let scheme = url.scheme();
            if scheme != "http" && scheme != "https" {
                return Err(anyhow!(
                    "cache backend {} has unsupported http endpoint scheme: {}",
                    backend.name,
                    scheme
                ));
            }
        }
        if backend.timeout_ms == 0 {
            return Err(anyhow!(
                "cache backend {} timeout_ms must be >= 1",
                backend.name
            ));
        }
        if backend.max_object_bytes == 0 {
            return Err(anyhow!(
                "cache backend {} max_object_bytes must be >= 1",
                backend.name
            ));
        }
    }
    Ok(cache_backends)
}

pub(super) fn validate_upstream_configs(
    config: &Config,
    upstream_trust_profiles: &HashSet<String>,
) -> Result<HashMap<String, url::Url>> {
    let mut upstreams = HashMap::new();
    for upstream in &config.upstreams {
        if upstream.name.trim().is_empty() {
            return Err(anyhow!("upstream name must not be empty"));
        }
        if upstreams.contains_key(&upstream.name) {
            return Err(anyhow!("duplicate upstream name: {}", upstream.name));
        }
        if upstream.url.trim().is_empty() {
            return Err(anyhow!("upstream {} url must not be empty", upstream.name));
        }
        let url = url::Url::parse(upstream.url.as_str()).map_err(|e| {
            anyhow!(
                "upstream {} has invalid url {} ({})",
                upstream.name,
                upstream.url,
                e
            )
        })?;
        let scheme = url.scheme();
        if !UPSTREAM_URL_SCHEMES
            .iter()
            .copied()
            .any(|allowed| allowed == scheme)
        {
            return Err(anyhow!(
                "upstream {} has unsupported url scheme: {}",
                upstream.name,
                scheme
            ));
        }
        if (!url.username().is_empty() || url.password().is_some())
            && !scheme.eq_ignore_ascii_case("http")
            && !scheme.eq_ignore_ascii_case("https")
        {
            return Err(anyhow!(
                "upstream {} url includes userinfo but scheme is not http/https",
                upstream.name
            ));
        }
        if let Some(discovery) = upstream.discovery.as_ref() {
            if discovery.interval_ms == 0 {
                return Err(anyhow!(
                    "upstream {} discovery.interval_ms must be >= 1",
                    upstream.name
                ));
            }
            if discovery.min_ttl_ms == 0 {
                return Err(anyhow!(
                    "upstream {} discovery.min_ttl_ms must be >= 1",
                    upstream.name
                ));
            }
            if discovery.max_ttl_ms == 0 {
                return Err(anyhow!(
                    "upstream {} discovery.max_ttl_ms must be >= 1",
                    upstream.name
                ));
            }
            if discovery.min_ttl_ms > discovery.max_ttl_ms {
                return Err(anyhow!(
                    "upstream {} discovery.min_ttl_ms must be <= discovery.max_ttl_ms",
                    upstream.name
                ));
            }
            if matches!(discovery.port, Some(0)) {
                return Err(anyhow!(
                    "upstream {} discovery.port must be >= 1 when set",
                    upstream.name
                ));
            }
            if let Some(name) = discovery.name.as_deref() {
                if name.trim().is_empty() {
                    return Err(anyhow!(
                        "upstream {} discovery.name must not be empty when set",
                        upstream.name
                    ));
                }
            }
            match discovery.kind {
                UpstreamDiscoveryKind::Dns => {}
                UpstreamDiscoveryKind::Srv => {
                    if discovery
                        .name
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or("")
                        .is_empty()
                    {
                        return Err(anyhow!(
                            "upstream {} discovery.kind=srv requires discovery.name",
                            upstream.name
                        ));
                    }
                    if discovery.port.is_some() {
                        return Err(anyhow!(
                            "upstream {} discovery.kind=srv does not support discovery.port",
                            upstream.name
                        ));
                    }
                }
            }
        }
        validate_resilience_config(
            upstream.resilience.as_ref(),
            &format!("upstream {}", upstream.name),
        )?;
        validate_upstream_trust_profile_ref(
            upstream.tls_trust_profile.as_deref(),
            upstream_trust_profiles,
            &format!("upstream {}", upstream.name),
        )?;
        validate_upstream_tls_trust_config(
            upstream.tls_trust.as_ref(),
            &format!("upstream {}", upstream.name),
        )?;
        upstreams.insert(upstream.name.clone(), url);
    }
    Ok(upstreams)
}

pub(super) fn validate_named_upstream_ref(
    upstream_ref: &str,
    upstreams: &HashMap<String, url::Url>,
    context: &str,
    allowed_schemes: &[&str],
    allow_userinfo: bool,
    allow_authority: bool,
) -> Result<()> {
    if !upstream_ref.contains("://")
        && allow_authority
        && (upstream_ref.contains(':') || upstream_ref.starts_with('['))
    {
        upstream_ref.parse::<http::uri::Authority>().map_err(|_| {
            anyhow!(
                "{context} has invalid upstream authority reference: {}",
                upstream_ref
            )
        })?;
        return Ok(());
    }

    let url = if upstream_ref.contains("://") {
        url::Url::parse(upstream_ref).map_err(|e| {
            anyhow!(
                "{context} has invalid upstream URL reference: {} ({})",
                upstream_ref,
                e
            )
        })?
    } else {
        upstreams
            .get(upstream_ref)
            .cloned()
            .ok_or_else(|| anyhow!("{} references unknown upstream: {}", context, upstream_ref))?
    };

    if (!url.username().is_empty() || url.password().is_some()) && !allow_userinfo {
        return Err(anyhow!("{context} upstream URL must not include userinfo"));
    }

    let scheme = url.scheme();
    if !allowed_schemes
        .iter()
        .copied()
        .any(|allowed| allowed == scheme)
    {
        return Err(anyhow!(
            "{context} has unsupported upstream URL scheme: {}",
            scheme
        ));
    }
    Ok(())
}

pub(super) fn validate_upstream_tls_trust_config(
    config: Option<&UpstreamTlsTrustConfig>,
    context: &str,
) -> Result<()> {
    let Some(config) = config else {
        return Ok(());
    };
    super::rules::validate_pattern_list(
        config.issuer.as_slice(),
        &format!("{context} upstream_trust.issuer"),
    )?;
    super::rules::validate_pattern_list(
        config.san_dns.as_slice(),
        &format!("{context} upstream_trust.san_dns"),
    )?;
    super::rules::validate_pattern_list(
        config.san_uri.as_slice(),
        &format!("{context} upstream_trust.san_uri"),
    )?;
    match (
        config
            .client_cert
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
        config
            .client_key
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    ) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => {
            return Err(anyhow!(
                "{context} upstream_trust.client_cert and client_key must be set together"
            ));
        }
    }
    for pin in &config.pin_sha256 {
        let pin = pin.trim();
        if pin.len() != 64 || !pin.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(anyhow!(
                "{context} upstream_trust.pin_sha256 entries must be 64 hex characters"
            ));
        }
    }
    Ok(())
}
