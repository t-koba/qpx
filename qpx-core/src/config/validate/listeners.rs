use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};

use super::super::super::uri_template::UriTemplate;
use super::super::types::Config;
use super::rules::{
    has_cache_purge_module, validate_action_config, validate_cache_policy,
    validate_connection_filter_rules, validate_header_control, validate_http_modules,
    validate_http_response_effects, validate_identity_match_config, validate_match_config,
    validate_policy_context_refs, validate_proxy_tunnel_upstream_requirement,
    validate_rate_limit_config, validate_xdp_config,
};
use super::security::{
    validate_destination_resolution_override, validate_http_guard_profile_ref,
    validate_upstream_trust_profile_ref,
};
use super::upstreams::{validate_named_upstream_ref, validate_upstream_tls_trust_config};
use super::UPSTREAM_PROXY_URL_SCHEMES;

pub(super) fn validate_listener_configs(
    config: &Config,
    cache_backends: &HashSet<String>,
    upstreams: &HashMap<String, url::Url>,
    http_guard_profiles: &HashSet<String>,
    upstream_trust_profiles: &HashSet<String>,
) -> Result<()> {
    let mut listener_names = HashSet::new();
    for listener in &config.listeners {
        if listener.name.trim().is_empty() {
            return Err(anyhow!("listener name must not be empty"));
        }
        if !listener_names.insert(listener.name.clone()) {
            return Err(anyhow!("duplicate listener name: {}", listener.name));
        }
        let _: std::net::SocketAddr = listener
            .listen
            .parse()
            .map_err(|e| anyhow!("listener {} listen is invalid: {}", listener.name, e))?;
        validate_rate_limit_config(
            listener.rate_limit.as_ref(),
            &format!("listener {}", listener.name),
        )?;
        validate_policy_context_refs(
            listener.policy_context.as_ref(),
            &config.identity_sources,
            &config.ext_authz,
            &format!("listener {}", listener.name),
            false,
        )?;
        validate_destination_resolution_override(
            listener.destination_resolution.as_ref(),
            &format!("listener {}", listener.name),
        )?;
        validate_action_config(
            &listener.default_action,
            &format!("listener {}", listener.name),
        )?;
        validate_proxy_tunnel_upstream_requirement(
            &listener.default_action,
            listener.upstream_proxy.as_deref(),
            &format!("listener {}", listener.name),
        )?;
        let mut uses_inspect = matches!(
            listener.default_action.kind,
            super::super::types::ActionKind::Inspect
        );
        if let Some(upstream_ref) = listener.default_action.upstream.as_deref() {
            validate_named_upstream_ref(
                upstream_ref,
                upstreams,
                format!("listener {} default_action.upstream", listener.name).as_str(),
                UPSTREAM_PROXY_URL_SCHEMES,
                true,
                true,
            )?;
        }
        if let Some(upstream_proxy) = listener.upstream_proxy.as_deref() {
            validate_named_upstream_ref(
                upstream_proxy,
                upstreams,
                format!("listener {} upstream_proxy", listener.name).as_str(),
                UPSTREAM_PROXY_URL_SCHEMES,
                true,
                true,
            )?;
        }
        for rule in &listener.rules {
            validate_match_config(
                rule.r#match.as_ref(),
                &format!("listener {} rule {}", listener.name, rule.name),
            )?;
            validate_identity_match_config(
                rule.r#match.as_ref().and_then(|m| m.identity.as_ref()),
                &format!("listener {} rule {}", listener.name, rule.name),
            )?;
            validate_rate_limit_config(
                rule.rate_limit.as_ref(),
                &format!("listener {} rule {}", listener.name, rule.name),
            )?;
            if let Some(action) = rule.action.as_ref() {
                validate_action_config(
                    action,
                    &format!("listener {} rule {}", listener.name, rule.name),
                )?;
                validate_proxy_tunnel_upstream_requirement(
                    action,
                    listener.upstream_proxy.as_deref(),
                    &format!("listener {} rule {}", listener.name, rule.name),
                )?;
                uses_inspect =
                    uses_inspect || matches!(action.kind, super::super::types::ActionKind::Inspect);
                if let Some(upstream_ref) = action.upstream.as_deref() {
                    validate_named_upstream_ref(
                        upstream_ref,
                        upstreams,
                        format!(
                            "listener {} rule {} action.upstream",
                            listener.name, rule.name
                        )
                        .as_str(),
                        UPSTREAM_PROXY_URL_SCHEMES,
                        true,
                        true,
                    )?;
                }
            }
            if let Some(headers) = rule.headers.as_ref() {
                validate_header_control(
                    headers,
                    &format!("listener {} rule {}", listener.name, rule.name),
                )?;
            }
        }
        validate_connection_filter_rules(
            listener.connection_filter.as_slice(),
            &format!("listener {}", listener.name),
        )?;
        if uses_inspect
            && !listener
                .tls_inspection
                .as_ref()
                .map(|t| t.enabled)
                .unwrap_or(false)
        {
            return Err(anyhow!(
                "listener {} uses inspect action but tls_inspection.enabled is not true",
                listener.name
            ));
        }
        if let Some(tls) = listener.tls_inspection.as_ref() {
            for pattern in &tls.verify_exceptions {
                if pattern.trim().is_empty() {
                    return Err(anyhow!(
                        "listener {} has empty tls_inspection.verify_exceptions pattern",
                        listener.name
                    ));
                }
                globset::Glob::new(pattern).map_err(|e| {
                    anyhow!(
                        "listener {} invalid tls_inspection.verify_exceptions glob {}: {}",
                        listener.name,
                        pattern,
                        e
                    )
                })?;
            }
            validate_upstream_trust_profile_ref(
                tls.upstream_trust_profile.as_deref(),
                upstream_trust_profiles,
                &format!("listener {} tls_inspection", listener.name),
            )?;
            validate_upstream_tls_trust_config(
                tls.upstream_trust.as_ref(),
                &format!("listener {} tls_inspection", listener.name),
            )?;
        }
        validate_xdp_config("listener", &listener.name, listener.xdp.as_ref())?;
        validate_http_guard_profile_ref(
            listener.http_guard_profile.as_deref(),
            http_guard_profiles,
            &format!("listener {}", listener.name),
        )?;
        if let Some(http) = listener.http.as_ref() {
            for response_rule in &http.response_rules {
                validate_match_config(
                    response_rule.r#match.as_ref(),
                    &format!(
                        "listener {} http.response_rules {}",
                        listener.name, response_rule.name
                    ),
                )?;
                validate_http_response_effects(
                    &response_rule.effects,
                    &format!(
                        "listener {} http.response_rules {} effects",
                        listener.name, response_rule.name
                    ),
                )?;
            }
        }
        validate_http_modules(
            listener.http_modules.as_slice(),
            &format!("listener {}", listener.name),
        )?;
        if let Some(cache) = listener.cache.as_ref().filter(|cache| cache.enabled) {
            validate_cache_policy(
                cache,
                cache_backends,
                &format!("listener {}", listener.name),
            )?;
        } else if has_cache_purge_module(listener.http_modules.as_slice()) {
            return Err(anyhow!(
                "listener {} uses cache_purge http_modules but cache.enabled is not true",
                listener.name
            ));
        }
        if listener.ftp.max_request_body_bytes == 0 {
            return Err(anyhow!(
                "listener {} ftp.max_request_body_bytes must be >= 1",
                listener.name
            ));
        }
        if listener.ftp.max_download_bytes == 0 {
            return Err(anyhow!(
                "listener {} ftp.max_download_bytes must be >= 1",
                listener.name
            ));
        }
        if listener.ftp.timeout_ms == 0 {
            return Err(anyhow!(
                "listener {} ftp.timeout_ms must be >= 1",
                listener.name
            ));
        }
        if let Some(http3) = listener.http3.as_ref() {
            if http3.enabled {
                if let Some(http3_listen) = http3.listen.as_deref() {
                    let _: std::net::SocketAddr = http3_listen.parse().map_err(|e| {
                        anyhow!("listener {} http3.listen is invalid: {}", listener.name, e)
                    })?;
                }
            }
            if let Some(connect_udp) = http3.connect_udp.as_ref() {
                if connect_udp.idle_timeout_secs == 0 {
                    return Err(anyhow!(
                        "listener {} http3.connect_udp.idle_timeout_secs must be >= 1",
                        listener.name
                    ));
                }
                if connect_udp.max_capsule_buffer_bytes == 0 {
                    return Err(anyhow!(
                        "listener {} http3.connect_udp.max_capsule_buffer_bytes must be >= 1",
                        listener.name
                    ));
                }
                if let Some(uri_template) = connect_udp.uri_template.as_deref() {
                    let template = uri_template.trim();
                    if template.is_empty() {
                        return Err(anyhow!(
                            "listener {} http3.connect_udp.uri_template must not be empty",
                            listener.name
                        ));
                    }
                    if !template.is_ascii() {
                        return Err(anyhow!(
                            "listener {} http3.connect_udp.uri_template must be ASCII",
                            listener.name
                        ));
                    }
                    let is_https = template
                        .get(..8)
                        .map(|p| p.eq_ignore_ascii_case("https://"))
                        .unwrap_or(false);
                    if !(template.starts_with('/') || is_https) {
                        return Err(anyhow!(
                            "listener {} http3.connect_udp.uri_template must start with '/' or 'https://'",
                            listener.name
                        ));
                    }
                    if is_https {
                        let rest = &template[8..];
                        let Some(slash) = rest.find('/') else {
                            return Err(anyhow!(
                                "listener {} http3.connect_udp.uri_template absolute form must include a path",
                                listener.name
                            ));
                        };
                        let authority = &rest[..slash];
                        if authority.is_empty() {
                            return Err(anyhow!(
                                "listener {} http3.connect_udp.uri_template authority must not be empty",
                                listener.name
                            ));
                        }
                        if authority.contains('{') || authority.contains('}') {
                            return Err(anyhow!(
                                "listener {} http3.connect_udp.uri_template must not contain variables in authority",
                                listener.name
                            ));
                        }
                    }
                    if !template.contains("target_host") || !template.contains("target_port") {
                        return Err(anyhow!(
                            "listener {} http3.connect_udp.uri_template must contain target_host and target_port",
                            listener.name
                        ));
                    }
                    let mut depth = 0u32;
                    for ch in template.chars() {
                        match ch {
                            '{' => {
                                depth += 1;
                                if depth > 1 {
                                    return Err(anyhow!(
                                        "listener {} http3.connect_udp.uri_template must not contain nested braces",
                                        listener.name
                                    ));
                                }
                            }
                            '}' => {
                                if depth == 0 {
                                    return Err(anyhow!(
                                        "listener {} http3.connect_udp.uri_template has unmatched '}}'",
                                        listener.name
                                    ));
                                }
                                depth -= 1;
                            }
                            _ => {}
                        }
                    }
                    if depth != 0 {
                        return Err(anyhow!(
                            "listener {} http3.connect_udp.uri_template has unmatched '{{'",
                            listener.name
                        ));
                    }
                    let path_query = if is_https {
                        let rest = &template[8..];
                        let slash = rest.find('/').ok_or_else(|| {
                            anyhow!(
                                "listener {} http3.connect_udp.uri_template absolute form must include a path",
                                listener.name
                            )
                        })?;
                        &rest[slash..]
                    } else {
                        template
                    };
                    let parsed = UriTemplate::parse(path_query).map_err(|err| {
                        anyhow!(
                            "listener {} http3.connect_udp.uri_template is invalid: {}",
                            listener.name,
                            err
                        )
                    })?;
                    if !parsed.has_recoverable_variable("target_host")
                        || !parsed.has_recoverable_variable("target_port")
                    {
                        return Err(anyhow!(
                            "listener {} http3.connect_udp.uri_template must include recoverable target_host and target_port variables",
                            listener.name
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
