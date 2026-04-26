use anyhow::{anyhow, Result};
use cidr::IpCidr;
use std::collections::{HashMap, HashSet};

use super::super::types::{
    ActionConfig, ActionKind, CachePolicyConfig, CachePurgeModuleConfig, CertificateMatchConfig,
    EndpointLifecycleConfig, ExtAuthzConfig, HeaderCaptureConfig, HeaderControl, HealthCheckConfig,
    HttpModuleConfig, HttpResponseEffectsConfig, IdentityMatchConfig, IdentitySourceConfig,
    IdentitySourceKind, LocalResponseConfig, MatchConfig, PolicyContextConfig, RateLimitConfig,
    ResilienceConfig, ResponseCompressionModuleConfig, ReverseAffinityConfig,
    RpcLocalResponseConfig, RpcMatchConfig, RuleConfig, SubrequestModuleConfig, XdpConfig,
};

pub(super) fn validate_rate_limit_config(
    rate: Option<&RateLimitConfig>,
    context: &str,
) -> Result<()> {
    let Some(rate) = rate else {
        return Ok(());
    };
    let key = rate.key.trim().to_ascii_lowercase();
    if key.is_empty() {
        return Err(anyhow!("{context} rate_limit.key must not be empty"));
    }
    if !matches!(
        key.as_str(),
        "global" | "src_ip" | "user" | "group" | "tenant" | "device" | "route" | "upstream"
    ) {
        return Err(anyhow!(
            "{context} rate_limit.key must be one of: global, src_ip, user, group, tenant, device, route, upstream"
        ));
    }

    if rate.apply_to.is_empty() {
        return Err(anyhow!("{context} rate_limit.apply_to must not be empty"));
    }

    if let Some(requests) = rate.requests.as_ref() {
        if matches!(requests.rps, Some(0)) {
            return Err(anyhow!("{context} rate_limit.requests.rps must be >= 1"));
        }
        if matches!(requests.burst, Some(0)) {
            return Err(anyhow!("{context} rate_limit.requests.burst must be >= 1"));
        }
        if requests.burst.is_some() && requests.rps.is_none() {
            return Err(anyhow!(
                "{context} rate_limit.requests.burst requires rate_limit.requests.rps"
            ));
        }
        validate_rate_limit_quota_config(
            requests.quota.as_ref(),
            &format!("{context} rate_limit.requests.quota"),
        )?;
    }

    if let Some(traffic) = rate.traffic.as_ref() {
        if matches!(traffic.bytes_per_sec, Some(0)) {
            return Err(anyhow!(
                "{context} rate_limit.traffic.bytes_per_sec must be >= 1"
            ));
        }
        if matches!(traffic.burst_bytes, Some(0)) {
            return Err(anyhow!(
                "{context} rate_limit.traffic.burst_bytes must be >= 1"
            ));
        }
        if traffic.burst_bytes.is_some() && traffic.bytes_per_sec.is_none() {
            return Err(anyhow!(
                "{context} rate_limit.traffic.burst_bytes requires rate_limit.traffic.bytes_per_sec"
            ));
        }
        validate_rate_limit_quota_config(
            traffic.quota_bytes.as_ref(),
            &format!("{context} rate_limit.traffic.quota_bytes"),
        )?;
    }

    if let Some(sessions) = rate.sessions.as_ref() {
        if matches!(sessions.max_concurrency, Some(0)) {
            return Err(anyhow!(
                "{context} rate_limit.sessions.max_concurrency must be >= 1"
            ));
        }
        validate_rate_limit_quota_config(
            sessions.quota_sessions.as_ref(),
            &format!("{context} rate_limit.sessions.quota_sessions"),
        )?;
    }

    if rate.enabled && rate.requests.is_none() && rate.traffic.is_none() && rate.sessions.is_none()
    {
        return Err(anyhow!(
            "{context} rate_limit.enabled requires at least one of rate_limit.requests, rate_limit.traffic, or rate_limit.sessions"
        ));
    }
    Ok(())
}

fn validate_rate_limit_quota_config(
    quota: Option<&super::super::types::RateLimitQuotaConfig>,
    context: &str,
) -> Result<()> {
    let Some(quota) = quota else {
        return Ok(());
    };
    if quota.interval_secs == 0 {
        return Err(anyhow!("{context}.interval_secs must be >= 1"));
    }
    if matches!(quota.amount, Some(0)) {
        return Err(anyhow!("{context}.amount must be >= 1"));
    }
    if quota.amount.is_none() {
        return Err(anyhow!("{context}.amount must be set"));
    }
    Ok(())
}

pub(super) fn validate_connection_filter_rules(rules: &[RuleConfig], context: &str) -> Result<()> {
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

pub(super) fn validate_lb_config(lb: &str, context: &str) -> Result<()> {
    let lb = lb.trim().to_ascii_lowercase();
    match lb.as_str() {
        "round_robin" | "roundrobin" | "random" | "least_conn" | "least_connections"
        | "consistent_hash" | "consistent-hash" | "sticky" | "sticky_ip" | "sticky-src-ip" => {
            Ok(())
        }
        other => Err(anyhow!("{context} has unknown lb strategy: {other}")),
    }
}

pub(super) fn validate_resilience_config(
    resilience: Option<&ResilienceConfig>,
    context: &str,
) -> Result<()> {
    let Some(resilience) = resilience else {
        return Ok(());
    };
    if let Some(retry) = resilience.retry.as_ref() {
        if retry.attempts == 0 {
            return Err(anyhow!("{context} resilience.retry.attempts must be >= 1"));
        }
        if let Some(budget) = retry.budget.as_ref() {
            if matches!(budget.ratio, Some(0)) {
                return Err(anyhow!(
                    "{context} resilience.retry.budget.ratio must be >= 1"
                ));
            }
            if matches!(budget.min_retry_tokens, Some(0)) {
                return Err(anyhow!(
                    "{context} resilience.retry.budget.min_retry_tokens must be >= 1"
                ));
            }
        }
    }
    if matches!(resilience.max_upstream_concurrency, Some(0)) {
        return Err(anyhow!(
            "{context} resilience.max_upstream_concurrency must be >= 1"
        ));
    }
    if let Some(outlier) = resilience.outlier_detection.as_ref() {
        if let Some(failures) = outlier.consecutive_failures.as_ref() {
            for (name, value) in [
                ("http_5xx", failures.http_5xx),
                ("timeouts", failures.timeouts),
                ("connect_errors", failures.connect_errors),
                ("resets", failures.resets),
            ] {
                if matches!(value, Some(0)) {
                    return Err(anyhow!(
                        "{context} resilience.outlier_detection.consecutive_failures.{name} must be >= 1"
                    ));
                }
            }
        }
        if let Some(success_rate) = outlier.success_rate.as_ref() {
            if matches!(success_rate.min_requests, Some(0)) {
                return Err(anyhow!(
                    "{context} resilience.outlier_detection.success_rate.min_requests must be >= 1"
                ));
            }
        }
        if let Some(latency) = outlier.latency.as_ref() {
            if matches!(latency.p95_ms, Some(0)) {
                return Err(anyhow!(
                    "{context} resilience.outlier_detection.latency.p95_ms must be >= 1"
                ));
            }
            if matches!(latency.min_requests, Some(0)) {
                return Err(anyhow!(
                    "{context} resilience.outlier_detection.latency.min_requests must be >= 1"
                ));
            }
        }
    }
    if let Some(half_open) = resilience.half_open.as_ref() {
        if matches!(half_open.max_probes, Some(0)) {
            return Err(anyhow!(
                "{context} resilience.half_open.max_probes must be >= 1"
            ));
        }
        if matches!(half_open.successes_to_close, Some(0)) {
            return Err(anyhow!(
                "{context} resilience.half_open.successes_to_close must be >= 1"
            ));
        }
        if matches!(half_open.probe_timeout_ms, Some(0)) {
            return Err(anyhow!(
                "{context} resilience.half_open.probe_timeout_ms must be >= 1"
            ));
        }
    }
    if let Some(ejection) = resilience.ejection.as_ref() {
        if matches!(ejection.base_ms, Some(0)) {
            return Err(anyhow!(
                "{context} resilience.ejection.base_ms must be >= 1"
            ));
        }
        if matches!(ejection.max_ms, Some(0)) {
            return Err(anyhow!("{context} resilience.ejection.max_ms must be >= 1"));
        }
    }
    Ok(())
}

pub(super) fn validate_http_modules(modules: &[HttpModuleConfig], context: &str) -> Result<()> {
    for (idx, module) in modules.iter().enumerate() {
        let module_context = format!("{context} http_modules[{idx}]");
        validate_non_empty_ascii(
            module.r#type.as_str(),
            format!("{module_context} type").as_str(),
        )?;
        if let Some(id) = module.id.as_deref() {
            validate_non_empty_ascii(id, format!("{module_context} id").as_str())?;
        }
        match module.r#type.as_str() {
            "response_compression" => {
                let config: ResponseCompressionModuleConfig =
                    module.parse_settings().map_err(|err| {
                        anyhow!("{module_context} response_compression config: {err}")
                    })?;
                let module_context = format!("{context} http_modules[{idx}] response_compression");
                if config.min_body_bytes == 0 {
                    return Err(anyhow!("{module_context} min_body_bytes must be >= 1"));
                }
                if config.max_body_bytes == 0 {
                    return Err(anyhow!("{module_context} max_body_bytes must be >= 1"));
                }
                if config.max_body_bytes < config.min_body_bytes {
                    return Err(anyhow!(
                        "{module_context} max_body_bytes must be >= min_body_bytes"
                    ));
                }
                if !config.gzip && !config.brotli && !config.zstd {
                    return Err(anyhow!(
                        "{module_context} must enable at least one of gzip, brotli, or zstd"
                    ));
                }
                if config.gzip_level > 9 {
                    return Err(anyhow!("{module_context} gzip_level must be <= 9"));
                }
                if config.brotli_level > 11 {
                    return Err(anyhow!("{module_context} brotli_level must be <= 11"));
                }
                if !(0..=22).contains(&config.zstd_level) {
                    return Err(anyhow!("{module_context} zstd_level must be in 0..=22"));
                }
                for pattern in &config.content_types {
                    validate_non_empty_ascii(
                        pattern,
                        format!("{module_context} content_types[]").as_str(),
                    )?;
                }
            }
            "subrequest" => {
                let config: SubrequestModuleConfig = module
                    .parse_settings()
                    .map_err(|err| anyhow!("{module_context} subrequest config: {err}"))?;
                validate_subrequest_module(&config, module_context.as_str())?;
            }
            "cache_purge" => {
                let config: CachePurgeModuleConfig = module
                    .parse_settings()
                    .map_err(|err| anyhow!("{module_context} cache_purge config: {err}"))?;
                let module_context = format!("{context} http_modules[{idx}] cache_purge");
                if config.methods.is_empty() {
                    return Err(anyhow!("{module_context} methods must not be empty"));
                }
                for method in &config.methods {
                    validate_http_token(method, format!("{module_context} methods[]").as_str())?;
                }
                if !(100..=599).contains(&config.response_status) {
                    return Err(anyhow!(
                        "{module_context} response_status must be in 100..=599"
                    ));
                }
                for (name, value) in &config.response_headers {
                    validate_header_name(
                        name,
                        format!("{module_context} response_headers").as_str(),
                    )?;
                    validate_non_empty_ascii(
                        value,
                        format!("{module_context} response_headers[{name}]").as_str(),
                    )?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn has_cache_purge_module(modules: &[HttpModuleConfig]) -> bool {
    modules.iter().any(|module| module.r#type == "cache_purge")
}

fn validate_subrequest_module(config: &SubrequestModuleConfig, context: &str) -> Result<()> {
    let module_context = format!("{context} subrequest");
    validate_non_empty_ascii(
        config.name.as_str(),
        format!("{module_context} name").as_str(),
    )?;
    validate_non_empty_ascii(
        config.url.as_str(),
        format!("{module_context} url").as_str(),
    )?;
    if let Some(method) = config.method.as_deref() {
        validate_http_token(method, format!("{module_context} method").as_str())?;
    }
    if let Some(timeout_ms) = config.timeout_ms {
        if timeout_ms == 0 {
            return Err(anyhow!("{module_context} timeout_ms must be >= 1"));
        }
    }
    for header in &config.pass_headers {
        validate_header_name(header, format!("{module_context} pass_headers[]").as_str())?;
    }
    for (name, value) in &config.request_headers {
        validate_header_name(name, format!("{module_context} request_headers").as_str())?;
        validate_non_empty_ascii(
            value,
            format!("{module_context} request_headers[{name}]").as_str(),
        )?;
    }
    validate_header_captures(
        &config.copy_response_headers_to_request,
        format!("{module_context} copy_response_headers_to_request").as_str(),
    )?;
    validate_header_captures(
        &config.copy_response_headers_to_response,
        format!("{module_context} copy_response_headers_to_response").as_str(),
    )?;
    Ok(())
}

fn validate_header_captures(entries: &[HeaderCaptureConfig], context: &str) -> Result<()> {
    for capture in entries {
        validate_header_name(capture.from.as_str(), format!("{context}.from").as_str())?;
        validate_header_name(capture.to.as_str(), format!("{context}.to").as_str())?;
    }
    Ok(())
}

fn validate_http_token(value: &str, context: &str) -> Result<()> {
    validate_non_empty_ascii(value, context)?;
    if !value.bytes().all(is_http_token_char) {
        return Err(anyhow!("{context} must be a valid HTTP token"));
    }
    Ok(())
}

fn validate_non_empty_ascii(value: &str, context: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("{context} must not be empty"));
    }
    if !value.is_ascii() {
        return Err(anyhow!("{context} must be ASCII"));
    }
    Ok(())
}

fn is_http_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub(super) fn validate_health_check_config(
    reverse_name: &str,
    health: Option<&HealthCheckConfig>,
    context: &str,
) -> Result<()> {
    let Some(health) = health else {
        return Ok(());
    };
    if health.interval_ms == 0 {
        return Err(anyhow!(
            "{} {} health_check.interval_ms must be >= 1",
            context,
            reverse_name
        ));
    }
    if health.timeout_ms == 0 {
        return Err(anyhow!(
            "{} {} health_check.timeout_ms must be >= 1",
            context,
            reverse_name
        ));
    }
    if health.fail_threshold == 0 {
        return Err(anyhow!(
            "{} {} health_check.fail_threshold must be >= 1",
            context,
            reverse_name
        ));
    }
    if health.cooldown_ms == 0 {
        return Err(anyhow!(
            "{} {} health_check.cooldown_ms must be >= 1",
            context,
            reverse_name
        ));
    }
    if let Some(http) = health.http.as_ref() {
        if let Some(path) = http.path.as_deref() {
            let path = path.trim();
            if path.is_empty() {
                return Err(anyhow!(
                    "{} {} health_check.http.path must not be empty when set",
                    context,
                    reverse_name
                ));
            }
            if !path.starts_with('/') {
                return Err(anyhow!(
                    "{} {} health_check.http.path must start with '/'",
                    context,
                    reverse_name
                ));
            }
            path.parse::<http::uri::PathAndQuery>().map_err(|_| {
                anyhow!(
                    "{} {} health_check.http.path is invalid: {}",
                    context,
                    reverse_name,
                    path
                )
            })?;
        }
        if let Some(method) = http.method.as_deref() {
            let normalized = method.trim().to_ascii_uppercase();
            if normalized != "HEAD" && normalized != "GET" {
                return Err(anyhow!(
                    "{} {} health_check.http.method must be HEAD or GET",
                    context,
                    reverse_name
                ));
            }
        }
        if let Some(statuses) = http.expected_status.as_ref() {
            if statuses.is_empty() {
                return Err(anyhow!(
                    "{} {} health_check.http.expected_status must not be empty when set",
                    context,
                    reverse_name
                ));
            }
            for code in statuses {
                if !(100..=599).contains(code) {
                    return Err(anyhow!(
                        "{} {} health_check.http.expected_status has invalid status code: {}",
                        context,
                        reverse_name,
                        code
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_endpoint_lifecycle_config(
    config: Option<&EndpointLifecycleConfig>,
    context: &str,
) -> Result<()> {
    let Some(config) = config else {
        return Ok(());
    };
    if config.slow_start_ms.is_none()
        && config.warmup_ms.is_none()
        && config.drain_timeout_ms.is_none()
    {
        return Err(anyhow!(
            "{context} lifecycle must set at least one of slow_start_ms, warmup_ms, or drain_timeout_ms"
        ));
    }
    if matches!(config.slow_start_ms, Some(0)) {
        return Err(anyhow!("{context} lifecycle.slow_start_ms must be >= 1"));
    }
    if matches!(config.warmup_ms, Some(0)) {
        return Err(anyhow!("{context} lifecycle.warmup_ms must be >= 1"));
    }
    if matches!(config.drain_timeout_ms, Some(0)) {
        return Err(anyhow!("{context} lifecycle.drain_timeout_ms must be >= 1"));
    }
    Ok(())
}

pub(super) fn validate_affinity_config(
    config: Option<&ReverseAffinityConfig>,
    context: &str,
) -> Result<()> {
    let Some(config) = config else {
        return Ok(());
    };
    let key = config.key.trim().to_ascii_lowercase();
    match key.as_str() {
        "src_ip" | "source_ip" | "host" | "user" | "tenant" => {}
        "header" => {
            let header = config.header.as_deref().unwrap_or("").trim();
            if header.is_empty() {
                return Err(anyhow!("{context} affinity.key=header requires affinity.header"));
            }
            validate_header_name(header, &format!("{context} affinity.header"))?;
        }
        "cookie" => {
            if config.cookie.as_deref().unwrap_or("").trim().is_empty() {
                return Err(anyhow!("{context} affinity.key=cookie requires affinity.cookie"));
            }
        }
        "query" => {
            if config.query.as_deref().unwrap_or("").trim().is_empty() {
                return Err(anyhow!("{context} affinity.key=query requires affinity.query"));
            }
        }
        other => {
            return Err(anyhow!(
                "{context} affinity.key must be one of: src_ip, host, header, cookie, user, tenant, query (got {other})"
            ))
        }
    }
    Ok(())
}

pub(super) fn validate_xdp_config(kind: &str, name: &str, xdp: Option<&XdpConfig>) -> Result<()> {
    let Some(xdp) = xdp else {
        return Ok(());
    };
    if xdp.enabled && xdp.metadata_mode != "proxy-v2" {
        return Err(anyhow!(
            "{kind} {} has unsupported xdp metadata_mode: {}",
            name,
            xdp.metadata_mode
        ));
    }
    if xdp.enabled {
        if xdp.trusted_peers.is_empty() {
            return Err(anyhow!(
                "{kind} {} xdp.enabled requires xdp.trusted_peers",
                name
            ));
        }
        for peer in &xdp.trusted_peers {
            let _: IpCidr = peer
                .parse()
                .map_err(|_| anyhow!("{kind} {} invalid xdp trusted peer CIDR: {}", name, peer))?;
        }
    }
    Ok(())
}

pub(super) fn validate_policy_context_refs(
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

pub(super) fn validate_match_config(raw: Option<&MatchConfig>, context: &str) -> Result<()> {
    let Some(raw) = raw else {
        return Ok(());
    };
    validate_pattern_list(raw.query.as_slice(), &format!("{context} match.query"))?;
    validate_pattern_list(
        raw.authority.as_slice(),
        &format!("{context} match.authority"),
    )?;
    validate_pattern_list(raw.scheme.as_slice(), &format!("{context} match.scheme"))?;
    validate_pattern_list(
        raw.http_version.as_slice(),
        &format!("{context} match.http_version"),
    )?;
    validate_pattern_list(raw.alpn.as_slice(), &format!("{context} match.alpn"))?;
    validate_pattern_list(
        raw.tls_version.as_slice(),
        &format!("{context} match.tls_version"),
    )?;
    validate_pattern_list(
        raw.request_size.as_slice(),
        &format!("{context} match.request_size"),
    )?;
    validate_destination_match_config(
        raw.destination.as_ref(),
        &format!("{context} match.destination"),
    )?;
    validate_numeric_patterns(
        raw.response_status.as_slice(),
        &format!("{context} match.response_status"),
    )?;
    validate_numeric_patterns(
        raw.response_size.as_slice(),
        &format!("{context} match.response_size"),
    )?;
    if let Some(fingerprint) = raw.tls_fingerprint.as_ref() {
        validate_pattern_list(
            fingerprint.ja3.as_slice(),
            &format!("{context} match.tls_fingerprint.ja3"),
        )?;
        validate_pattern_list(
            fingerprint.ja4.as_slice(),
            &format!("{context} match.tls_fingerprint.ja4"),
        )?;
    }
    validate_certificate_match_config(
        raw.client_cert.as_ref(),
        &format!("{context} match.client_cert"),
    )?;
    validate_certificate_match_config(
        raw.upstream_cert.as_ref(),
        &format!("{context} match.upstream_cert"),
    )?;
    validate_rpc_match_config(raw.rpc.as_ref(), &format!("{context} match.rpc"))?;
    Ok(())
}

fn validate_destination_match_config(
    raw: Option<&crate::config::DestinationMatchConfig>,
    context: &str,
) -> Result<()> {
    let Some(raw) = raw else {
        return Ok(());
    };
    for (label, dimension) in [
        ("category", raw.category.as_ref()),
        ("reputation", raw.reputation.as_ref()),
        ("application", raw.application.as_ref()),
    ] {
        let Some(dimension) = dimension else {
            continue;
        };
        validate_pattern_list(
            dimension.value.as_slice(),
            &format!("{context}.{label}.value"),
        )?;
        validate_pattern_list(
            dimension.source.as_slice(),
            &format!("{context}.{label}.source"),
        )?;
        validate_numeric_patterns(
            dimension.confidence.as_slice(),
            &format!("{context}.{label}.confidence"),
        )?;
        if dimension.value.is_empty()
            && dimension.source.is_empty()
            && dimension.confidence.is_empty()
        {
            return Err(anyhow!(
                "{context}.{label} must configure at least one field"
            ));
        }
    }
    Ok(())
}

fn validate_rpc_match_config(raw: Option<&RpcMatchConfig>, context: &str) -> Result<()> {
    let Some(raw) = raw else {
        return Ok(());
    };
    validate_pattern_list(raw.protocol.as_slice(), &format!("{context}.protocol"))?;
    validate_pattern_list(raw.service.as_slice(), &format!("{context}.service"))?;
    validate_pattern_list(raw.method.as_slice(), &format!("{context}.method"))?;
    validate_pattern_list(raw.streaming.as_slice(), &format!("{context}.streaming"))?;
    validate_pattern_list(raw.status.as_slice(), &format!("{context}.status"))?;
    validate_numeric_patterns(
        raw.message_size.as_slice(),
        &format!("{context}.message_size"),
    )?;
    validate_pattern_list(raw.message.as_slice(), &format!("{context}.message"))?;
    for (idx, trailer) in raw.trailers.iter().enumerate() {
        validate_header_name(
            trailer.name.as_str(),
            &format!("{context}.trailers[{idx}].name"),
        )?;
        if let Some(value) = trailer.value.as_deref() {
            validate_non_empty_ascii(value, &format!("{context}.trailers[{idx}].value"))?;
        }
        if let Some(regex) = trailer.regex.as_deref() {
            validate_non_empty_ascii(regex, &format!("{context}.trailers[{idx}].regex"))?;
            regex::Regex::new(regex)
                .map_err(|err| anyhow!("{context}.trailers[{idx}].regex is invalid: {err}"))?;
        }
        if trailer.value.is_none() && trailer.regex.is_none() {
            return Err(anyhow!("{context}.trailers[{idx}] must set value or regex"));
        }
    }
    if raw.protocol.is_empty()
        && raw.service.is_empty()
        && raw.method.is_empty()
        && raw.streaming.is_empty()
        && raw.status.is_empty()
        && raw.message_size.is_empty()
        && raw.message.is_empty()
        && raw.trailers.is_empty()
    {
        return Err(anyhow!("{context} must configure at least one field"));
    }
    Ok(())
}

pub(super) fn validate_certificate_match_config(
    raw: Option<&CertificateMatchConfig>,
    context: &str,
) -> Result<()> {
    let Some(raw) = raw else {
        return Ok(());
    };
    validate_pattern_list(raw.subject.as_slice(), &format!("{context}.subject"))?;
    validate_pattern_list(raw.issuer.as_slice(), &format!("{context}.issuer"))?;
    validate_pattern_list(raw.san_dns.as_slice(), &format!("{context}.san_dns"))?;
    validate_pattern_list(raw.san_uri.as_slice(), &format!("{context}.san_uri"))?;
    validate_pattern_list(
        raw.fingerprint_sha256.as_slice(),
        &format!("{context}.fingerprint_sha256"),
    )?;
    if raw.present.is_none()
        && raw.subject.is_empty()
        && raw.issuer.is_empty()
        && raw.san_dns.is_empty()
        && raw.san_uri.is_empty()
        && raw.fingerprint_sha256.is_empty()
    {
        return Err(anyhow!("{context} must configure at least one field"));
    }
    Ok(())
}

pub(super) fn validate_pattern_list(values: &[String], context: &str) -> Result<()> {
    for value in values {
        if value.trim().is_empty() {
            return Err(anyhow!("{context} entries must not be empty"));
        }
    }
    Ok(())
}

fn validate_numeric_patterns(values: &[String], context: &str) -> Result<()> {
    for value in values {
        parse_numeric_matcher(value)
            .map_err(|e| anyhow!("{context} has invalid matcher {value}: {e}"))?;
    }
    Ok(())
}

fn parse_numeric_matcher(raw: &str) -> Result<(Option<u64>, Option<u64>)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("empty matcher"));
    }
    if let Some(rest) = raw.strip_prefix(">=") {
        return Ok((Some(parse_numeric_value(rest)?), None));
    }
    if let Some(rest) = raw.strip_prefix('>') {
        let value = parse_numeric_value(rest)?;
        return Ok((Some(value.saturating_add(1)), None));
    }
    if let Some(rest) = raw.strip_prefix("<=") {
        return Ok((None, Some(parse_numeric_value(rest)?)));
    }
    if let Some(rest) = raw.strip_prefix('<') {
        let value = parse_numeric_value(rest)?;
        return Ok((None, Some(value.saturating_sub(1))));
    }
    if let Some((start, end)) = raw.split_once('-') {
        let start = parse_numeric_value(start)?;
        let end = parse_numeric_value(end)?;
        if start > end {
            return Err(anyhow!("range start must be <= end"));
        }
        return Ok((Some(start), Some(end)));
    }
    let exact = parse_numeric_value(raw)?;
    Ok((Some(exact), Some(exact)))
}

fn parse_numeric_value(raw: &str) -> Result<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("empty numeric value"));
    }
    let (digits, scale) = match raw.chars().last().unwrap_or_default() {
        'k' | 'K' => (&raw[..raw.len() - 1], 1024u64),
        'm' | 'M' => (&raw[..raw.len() - 1], 1024u64 * 1024),
        'g' | 'G' => (&raw[..raw.len() - 1], 1024u64 * 1024 * 1024),
        _ => (raw, 1u64),
    };
    let value = digits
        .trim()
        .parse::<u64>()
        .map_err(|_| anyhow!("must be an integer"))?;
    value
        .checked_mul(scale)
        .ok_or_else(|| anyhow!("numeric value overflow"))
}

pub(super) fn validate_identity_match_config(
    identity: Option<&IdentityMatchConfig>,
    context: &str,
) -> Result<()> {
    let Some(identity) = identity else {
        return Ok(());
    };
    for (label, values) in [
        ("user", identity.user.as_slice()),
        ("groups", identity.groups.as_slice()),
        ("device_id", identity.device_id.as_slice()),
        ("posture", identity.posture.as_slice()),
        ("tenant", identity.tenant.as_slice()),
        ("auth_strength", identity.auth_strength.as_slice()),
        ("idp", identity.idp.as_slice()),
    ] {
        for value in values {
            if value.trim().is_empty() {
                return Err(anyhow!(
                    "{context} match.identity.{label} entries must not be empty"
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_action_config(action: &ActionConfig, context: &str) -> Result<()> {
    let has_local = action.local_response.is_some();
    match action.kind {
        ActionKind::Respond => {
            if !has_local {
                return Err(anyhow!(
                    "{context}: action type respond requires local_response"
                ));
            }
            if action.upstream.is_some() {
                return Err(anyhow!(
                    "{context}: action type respond must not set upstream"
                ));
            }
            validate_local_response_config(
                action.local_response.as_ref(),
                &format!("{context}: local_response"),
            )?;
        }
        ActionKind::Direct | ActionKind::Block => {
            if action.upstream.is_some() {
                return Err(anyhow!(
                    "{context}: action type {:?} must not set upstream",
                    action.kind
                ));
            }
            if has_local {
                return Err(anyhow!(
                    "{context}: local_response is only valid for action type respond"
                ));
            }
        }
        ActionKind::Inspect | ActionKind::Proxy | ActionKind::Tunnel => {
            if has_local {
                return Err(anyhow!(
                    "{context}: local_response is only valid for action type respond"
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_local_response_config(
    local: Option<&LocalResponseConfig>,
    context: &str,
) -> Result<()> {
    let Some(local) = local else {
        return Ok(());
    };
    if let Some(rpc) = local.rpc.as_ref() {
        validate_rpc_local_response_config(rpc, &format!("{context}.rpc"))?;
    }
    Ok(())
}

pub(super) fn validate_http_response_effects(
    effects: &HttpResponseEffectsConfig,
    context: &str,
) -> Result<()> {
    validate_local_response_config(
        effects.local_response.as_ref(),
        &format!("{context}.local_response"),
    )?;
    if let Some(headers) = effects.headers.as_ref() {
        validate_header_control(headers, &format!("{context}.headers"))?;
    }
    if let Some(mirror) = effects.mirror.as_ref() {
        for (idx, upstream) in mirror.upstreams.iter().enumerate() {
            if upstream.trim().is_empty() {
                return Err(anyhow!(
                    "{context}.mirror.upstreams[{idx}] must not be empty"
                ));
            }
        }
    }
    for (idx, tag) in effects.tags.iter().enumerate() {
        if tag.trim().is_empty() {
            return Err(anyhow!("{context}.tags[{idx}] must not be empty"));
        }
    }
    let has_effect = effects.local_response.is_some()
        || effects.headers.is_some()
        || effects
            .cache
            .as_ref()
            .map(|cache| cache.bypass)
            .unwrap_or(false)
        || effects
            .retry
            .as_ref()
            .map(|retry| retry.suppress)
            .unwrap_or(false)
        || effects
            .mirror
            .as_ref()
            .map(|mirror| mirror.enabled.is_some() || !mirror.upstreams.is_empty())
            .unwrap_or(false)
        || !effects.tags.is_empty();
    if !has_effect {
        return Err(anyhow!("{context} must configure at least one effect"));
    }
    Ok(())
}

fn validate_rpc_local_response_config(raw: &RpcLocalResponseConfig, context: &str) -> Result<()> {
    let protocol = raw.protocol.trim().to_ascii_lowercase();
    if protocol.is_empty() {
        return Err(anyhow!("{context}.protocol must not be empty"));
    }
    if !matches!(protocol.as_str(), "grpc" | "connect" | "grpc_web") {
        return Err(anyhow!(
            "{context}.protocol must be one of: grpc, connect, grpc_web"
        ));
    }
    if let Some(status) = raw.status.as_deref() {
        validate_non_empty_ascii(status, &format!("{context}.status"))?;
    }
    if let Some(message) = raw.message.as_deref() {
        if message.trim().is_empty() {
            return Err(anyhow!("{context}.message must not be empty when set"));
        }
    }
    if let Some(http_status) = raw.http_status {
        if !(100..=599).contains(&http_status) {
            return Err(anyhow!("{context}.http_status must be in 100..=599"));
        }
    }
    for (name, value) in &raw.headers {
        validate_header_name(name, &format!("{context}.headers"))?;
        validate_non_empty_ascii(value, &format!("{context}.headers[{name}]"))?;
    }
    for (name, value) in &raw.trailers {
        validate_header_name(name, &format!("{context}.trailers"))?;
        validate_non_empty_ascii(value, &format!("{context}.trailers[{name}]"))?;
    }
    Ok(())
}

pub(super) fn validate_proxy_tunnel_upstream_requirement(
    action: &ActionConfig,
    listener_upstream_proxy: Option<&str>,
    context: &str,
) -> Result<()> {
    if matches!(action.kind, ActionKind::Proxy | ActionKind::Tunnel)
        && action.upstream.is_none()
        && listener_upstream_proxy.is_none()
    {
        return Err(anyhow!(
            "{context}: action type {:?} requires action.upstream or listeners[].upstream_proxy",
            action.kind
        ));
    }
    Ok(())
}

pub(super) fn validate_header_name(name: &str, context: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err(anyhow!("{context} header name must not be empty"));
    }
    http::header::HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| anyhow!("{context} has invalid header name: {name}"))?;
    Ok(())
}

pub(super) fn validate_header_control(control: &HeaderControl, context: &str) -> Result<()> {
    validate_header_map(&control.request_set, &format!("{} request_set", context))?;
    validate_header_map(&control.request_add, &format!("{} request_add", context))?;
    validate_header_remove(
        &control.request_remove,
        &format!("{} request_remove", context),
    )?;

    for (idx, item) in control.request_regex_replace.iter().enumerate() {
        if item.header.trim().is_empty() {
            return Err(anyhow!(
                "{} request_regex_replace[{}] header must not be empty",
                context,
                idx
            ));
        }
        http::header::HeaderName::from_bytes(item.header.as_bytes()).map_err(|_| {
            anyhow!(
                "{} request_regex_replace[{}] invalid header name: {}",
                context,
                idx,
                item.header
            )
        })?;
        regex::Regex::new(item.pattern.as_str()).map_err(|err| {
            anyhow!(
                "{} request_regex_replace[{}] invalid regex {}: {}",
                context,
                idx,
                item.pattern,
                err
            )
        })?;
    }

    validate_header_map(&control.response_set, &format!("{} response_set", context))?;
    validate_header_map(&control.response_add, &format!("{} response_add", context))?;
    validate_header_remove(
        &control.response_remove,
        &format!("{} response_remove", context),
    )?;

    for (idx, item) in control.response_regex_replace.iter().enumerate() {
        if item.header.trim().is_empty() {
            return Err(anyhow!(
                "{} response_regex_replace[{}] header must not be empty",
                context,
                idx
            ));
        }
        http::header::HeaderName::from_bytes(item.header.as_bytes()).map_err(|_| {
            anyhow!(
                "{} response_regex_replace[{}] invalid header name: {}",
                context,
                idx,
                item.header
            )
        })?;
        regex::Regex::new(item.pattern.as_str()).map_err(|err| {
            anyhow!(
                "{} response_regex_replace[{}] invalid regex {}: {}",
                context,
                idx,
                item.pattern,
                err
            )
        })?;
    }
    Ok(())
}

fn validate_header_map(map: &HashMap<String, String>, context: &str) -> Result<()> {
    for (name, value) in map {
        if name.trim().is_empty() {
            return Err(anyhow!("{context}: header name must not be empty"));
        }
        let parsed = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow!("{context}: invalid header name: {name}"))?;
        http::HeaderValue::from_str(value.as_str())
            .map_err(|_| anyhow!("{context}: invalid header value for {parsed}"))?;
    }
    Ok(())
}

fn validate_header_remove(names: &[String], context: &str) -> Result<()> {
    for name in names {
        if name.trim().is_empty() {
            return Err(anyhow!("{context}: header name must not be empty"));
        }
        http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow!("{context}: invalid header name: {name}"))?;
    }
    Ok(())
}

pub(super) fn validate_cache_policy(
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
