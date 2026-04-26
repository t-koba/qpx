use anyhow::Result;

use super::types::Config;

#[path = "validate/core.rs"]
mod core;
#[path = "validate/listeners.rs"]
mod listeners;
#[path = "validate/observability.rs"]
mod observability;
#[path = "validate/reverse.rs"]
mod reverse;
#[path = "validate/rules.rs"]
mod rules;
#[path = "validate/security.rs"]
mod security;
#[path = "validate/upstreams.rs"]
mod upstreams;

use core::{
    validate_identity_config, validate_listener_topology, validate_messages_config,
    validate_runtime_config,
};
use listeners::validate_listener_configs;
use observability::{
    validate_access_log_config, validate_acme_config, validate_audit_log_config,
    validate_exporter_config, validate_metrics_config, validate_otel_config,
    validate_system_log_config,
};
use reverse::validate_reverse_configs;
use security::{
    validate_auth_config, validate_destination_resolution_config, validate_ext_authz_configs,
    validate_http_guard_profiles, validate_identity_sources, validate_named_sets,
    validate_rate_limit_profiles, validate_upstream_trust_profiles,
};
use upstreams::{validate_cache_backends, validate_upstream_configs};

#[cfg(test)]
use security::validate_upstream_trust_profile_ref;
#[cfg(test)]
use std::collections::HashSet;
#[cfg(test)]
use upstreams::validate_upstream_tls_trust_config;

const UPSTREAM_URL_SCHEMES: &[&str] = &["http", "https", "h3", "ws", "wss"];
const UPSTREAM_PROXY_URL_SCHEMES: &[&str] = &["http", "https"];
const REVERSE_UPSTREAM_URL_SCHEMES: &[&str] = &["http", "https", "ws", "wss"];
const REVERSE_PASSTHROUGH_UPSTREAM_URL_SCHEMES: &[&str] = &["https", "h3"];

pub(super) fn validate_config(config: &Config) -> Result<()> {
    validate_listener_topology(config)?;
    validate_identity_config(&config.identity)?;
    validate_messages_config(&config.messages)?;
    validate_runtime_config(&config.runtime)?;
    validate_system_log_config(&config.system_log)?;
    validate_access_log_config(&config.access_log)?;
    validate_audit_log_config(&config.audit_log)?;
    if let Some(metrics) = config.metrics.as_ref() {
        validate_metrics_config(metrics)?;
    }
    if let Some(otel) = config.otel.as_ref() {
        validate_otel_config(otel)?;
    }
    if let Some(acme) = config.acme.as_ref() {
        validate_acme_config(config, acme)?;
    }
    if let Some(exporter) = config.exporter.as_ref() {
        validate_exporter_config(exporter)?;
    }
    validate_auth_config(&config.auth)?;
    validate_destination_resolution_config(&config.destination_resolution)?;
    validate_named_sets(&config.named_sets)?;
    validate_identity_sources(&config.identity_sources)?;
    validate_ext_authz_configs(&config.ext_authz)?;
    let http_guard_profiles = validate_http_guard_profiles(&config.http_guard_profiles)?;
    validate_rate_limit_profiles(&config.rate_limit_profiles)?;
    let upstream_trust_profiles =
        validate_upstream_trust_profiles(&config.upstream_trust_profiles)?;
    let upstreams = validate_upstream_configs(config, &upstream_trust_profiles)?;
    let cache_backends = validate_cache_backends(&config.cache)?;
    validate_listener_configs(
        config,
        &cache_backends,
        &upstreams,
        &http_guard_profiles,
        &upstream_trust_profiles,
    )?;
    validate_reverse_configs(
        config,
        &cache_backends,
        &upstreams,
        &http_guard_profiles,
        &upstream_trust_profiles,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "validate_tests.rs"]
mod tests;
