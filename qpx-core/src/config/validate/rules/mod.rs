use anyhow::{Result, anyhow};
use std::collections::HashSet;

use crate::config::types::{
    ActionKind, CachePolicyConfig, ExtAuthzConfig, IdentitySourceConfig, IdentitySourceKind,
    MatchConfig, PolicyContextConfig, RuleConfig,
};

mod action;
mod header;
mod http_modules;
mod match_config;
mod rate_limit;
mod resilience;

pub(super) use action::{
    validate_action_config, validate_http_response_effects,
    validate_proxy_tunnel_upstream_requirement,
};
pub(super) use header::{validate_header_control, validate_header_name};
pub(super) use http_modules::{has_cache_purge_module, validate_http_modules};
pub(super) use match_config::{
    validate_identity_match_config, validate_match_config, validate_pattern_list,
};
pub(super) use rate_limit::validate_rate_limit_config;
pub(super) use resilience::{
    validate_affinity_config, validate_endpoint_lifecycle_config, validate_grpc_config,
    validate_health_check_config, validate_resilience_config, validate_sse_policy,
    validate_sse_policy_fields, validate_streaming_config, validate_xdp_config,
};

pub(crate) trait Validate {
    fn validate(&self, context: &str) -> Result<()>;
}

fn validate_optional<T: Validate>(value: Option<&T>, context: &str) -> Result<()> {
    match value {
        Some(value) => value.validate(context),
        None => Ok(()),
    }
}

pub(crate) fn validate_connection_filter_rules(rules: &[RuleConfig], context: &str) -> Result<()> {
    for rule in rules {
        let rule_context = format!("{context} connection_filter rule {}", rule.name);
        let match_cfg = rule
            .r#match
            .as_ref()
            .ok_or_else(|| anyhow!("{rule_context} must set match"))?;
        validate_match_config(Some(match_cfg), &rule_context)?;
        validate_connection_filter_match(match_cfg, &rule_context)?;

        if rule.auth.is_some() {
            return Err(anyhow!("{rule_context} must not set auth"));
        }
        if rule.headers.is_some() {
            return Err(anyhow!("{rule_context} must not set headers"));
        }
        if rule.rate_limit.is_some() {
            return Err(anyhow!("{rule_context} must not set rate_limit"));
        }

        let action = rule
            .action
            .as_ref()
            .ok_or_else(|| anyhow!("{rule_context} must set action.type=block"))?;
        if !matches!(action.kind, ActionKind::Block) {
            return Err(anyhow!("{rule_context} action.type must be block"));
        }
        if action.upstream.is_some() {
            return Err(anyhow!("{rule_context} must not set action.upstream"));
        }
        if action.local_response.is_some() {
            return Err(anyhow!("{rule_context} must not set action.local_response"));
        }
    }
    Ok(())
}

fn validate_connection_filter_match(match_cfg: &MatchConfig, context: &str) -> Result<()> {
    if !match_cfg.host.is_empty() {
        return Err(anyhow!("{context} must not match host"));
    }
    if !match_cfg.method.is_empty() {
        return Err(anyhow!("{context} must not match method"));
    }
    if !match_cfg.path.is_empty() {
        return Err(anyhow!("{context} must not match path"));
    }
    if !match_cfg.query.is_empty() {
        return Err(anyhow!("{context} must not match query"));
    }
    if !match_cfg.authority.is_empty() {
        return Err(anyhow!("{context} must not match authority"));
    }
    if !match_cfg.scheme.is_empty() {
        return Err(anyhow!("{context} must not match scheme"));
    }
    if !match_cfg.http_version.is_empty() {
        return Err(anyhow!("{context} must not match http_version"));
    }
    if match_cfg.destination.is_some() {
        return Err(anyhow!("{context} must not match destination fields"));
    }
    if !match_cfg.request_size.is_empty() {
        return Err(anyhow!("{context} must not match request_size"));
    }
    if !match_cfg.response_status.is_empty() {
        return Err(anyhow!("{context} must not match response_status"));
    }
    if !match_cfg.response_size.is_empty() {
        return Err(anyhow!("{context} must not match response_size"));
    }
    if !match_cfg.headers.is_empty() {
        return Err(anyhow!("{context} must not match headers"));
    }
    if match_cfg.identity.is_some() {
        return Err(anyhow!("{context} must not match identity"));
    }
    if match_cfg.client_cert.is_some() {
        return Err(anyhow!("{context} must not match client_cert"));
    }
    if match_cfg.upstream_cert.is_some() {
        return Err(anyhow!("{context} must not match upstream_cert"));
    }
    if match_cfg.rpc.is_some() {
        return Err(anyhow!("{context} must not match rpc"));
    }
    Ok(())
}

pub(crate) fn validate_lb_config(lb: &str, context: &str) -> Result<()> {
    let lb = lb.trim().to_ascii_lowercase();
    match lb.as_str() {
        "round_robin" | "roundrobin" | "random" | "least_conn" | "least_connections"
        | "consistent_hash" | "consistent-hash" | "sticky" | "sticky_ip" | "sticky-src-ip" => {
            Ok(())
        }
        other => Err(anyhow!("{context} has unknown lb strategy: {other}")),
    }
}
pub(crate) fn validate_policy_context_refs(
    policy: Option<&PolicyContextConfig>,
    identity_sources: &[IdentitySourceConfig],
    ext_authz: &[ExtAuthzConfig],
    context: &str,
    allow_mtls_identity: bool,
) -> Result<()> {
    let Some(policy) = policy else {
        return Ok(());
    };
    for source_name in &policy.identity_sources {
        let source_name = source_name.trim();
        if source_name.is_empty() {
            return Err(anyhow!(
                "{context} policy_context.identity_sources entries must not be empty"
            ));
        }
        let source = identity_sources
            .iter()
            .find(|source| source.name == source_name)
            .ok_or_else(|| {
                anyhow!(
                    "{context} policy_context references unknown identity source: {}",
                    source_name
                )
            })?;
        if matches!(source.kind, IdentitySourceKind::MtlsSubject) && !allow_mtls_identity {
            return Err(anyhow!(
                "{context} policy_context references mtls_subject identity source {}, but this scope has no verified client-certificate context",
                source_name
            ));
        }
    }
    if let Some(ext_authz_name) = policy.ext_authz.as_deref() {
        if ext_authz_name.trim().is_empty() {
            return Err(anyhow!(
                "{context} policy_context.ext_authz must not be empty when set"
            ));
        }
        if !ext_authz.iter().any(|cfg| cfg.name == ext_authz_name) {
            return Err(anyhow!(
                "{context} policy_context references unknown ext_authz: {}",
                ext_authz_name
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_cache_policy(
    policy: &CachePolicyConfig,
    backends: &HashSet<String>,
    context: &str,
) -> Result<()> {
    if policy.backend.trim().is_empty() {
        return Err(anyhow!("{context}: cache.backend must not be empty"));
    }
    if !backends.contains(policy.backend.as_str()) {
        return Err(anyhow!(
            "{context}: cache backend not found: {}",
            policy.backend
        ));
    }
    if policy.max_object_bytes == 0 {
        return Err(anyhow!("{context}: cache.max_object_bytes must be >= 1"));
    }
    if matches!(policy.default_ttl_secs, Some(0)) {
        return Err(anyhow!("{context}: cache.default_ttl_secs must be >= 1"));
    }
    if let Some(ns) = policy.namespace.as_deref() {
        let ns = ns.trim();
        if ns.is_empty() {
            return Err(anyhow!("{context}: cache.namespace must not be empty"));
        }
        if !ns
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(anyhow!(
                "{context}: cache.namespace must contain only [A-Za-z0-9-_.]"
            ));
        }
    }
    Ok(())
}
