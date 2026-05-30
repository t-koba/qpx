use anyhow::{Result, anyhow};
use std::collections::{HashMap, HashSet};

use super::super::super::uri_template::UriTemplate;
use super::super::types::{Config, IngressEdgeMode, OriginalDstSource, StreamingRequirement};
use super::UPSTREAM_PROXY_URL_SCHEMES;
use super::observability::validate_capture_policy;
use super::rules::{
    has_cache_purge_module, validate_action_config, validate_cache_policy,
    validate_connection_filter_rules, validate_grpc_config, validate_header_control,
    validate_http_modules, validate_http_response_effects, validate_identity_match_config,
    validate_match_config, validate_policy_context_refs,
    validate_proxy_tunnel_upstream_requirement, validate_rate_limit_config, validate_sse_policy,
    validate_streaming_config, validate_xdp_config,
};
use super::security::{
    validate_destination_resolution_override, validate_http_guard_profile_ref,
    validate_upstream_trust_profile_ref,
};
use super::upstreams::{validate_named_upstream_ref, validate_upstream_tls_trust_config};

pub(super) fn validate_ingress_edge_configs(
    config: &Config,
    cache_backends: &HashSet<String>,
    upstreams: &HashMap<String, url::Url>,
    http_guard_profiles: &HashSet<String>,
    upstream_trust_profiles: &HashSet<String>,
) -> Result<()> {
    let mut edge_names = HashSet::new();
    for edge in config.ingress_edges() {
        if edge.name.trim().is_empty() {
            return Err(anyhow!("edge name must not be empty"));
        }
        if !edge_names.insert(edge.name.clone()) {
            return Err(anyhow!("duplicate edge name: {}", edge.name));
        }
        let _: std::net::SocketAddr = edge
            .listen
            .parse()
            .map_err(|e| anyhow!("edge {} listen is invalid: {}", edge.name, e))?;
        validate_rate_limit_config(edge.rate_limit.as_ref(), &format!("edge {}", edge.name))?;
        validate_streaming_config(edge.streaming.as_ref(), &format!("edge {}", edge.name))?;
        validate_streaming_requirement(
            edge.streaming_requirement.as_ref(),
            &format!("edge {}", edge.name),
        )?;
        validate_grpc_config(edge.grpc.as_ref(), &format!("edge {}", edge.name))?;
        validate_sse_policy(edge.sse.as_ref(), &format!("edge {}", edge.name))?;
        validate_policy_context_refs(
            edge.policy_context.as_ref(),
            &config.security.identity_sources,
            &config.security.decisions.ext_authz,
            &format!("edge {}", edge.name),
            false,
        )?;
        validate_destination_resolution_override(
            edge.destination_resolution.as_ref(),
            &format!("edge {}", edge.name),
        )?;
        validate_action_config(&edge.default_action, &format!("edge {}", edge.name))?;
        if edge.original_dst.is_some() && edge.mode != IngressEdgeMode::Transparent {
            return Err(anyhow!(
                "edge {} original_dst is only valid for transparent edges",
                edge.name
            ));
        }
        if let Some(original_dst) = edge.original_dst.as_ref() {
            match original_dst.source {
                OriginalDstSource::LinuxSoOriginalDst => {}
            }
        }
        validate_proxy_tunnel_upstream_requirement(
            &edge.default_action,
            edge.upstream_proxy.as_deref(),
            &format!("edge {}", edge.name),
        )?;
        let mut uses_inspect = matches!(
            edge.default_action.kind,
            super::super::types::ActionKind::Inspect
        );
        if let Some(upstream_ref) = edge.default_action.upstream.as_deref() {
            validate_named_upstream_ref(
                upstream_ref,
                upstreams,
                format!("edge {} default_action.upstream", edge.name).as_str(),
                UPSTREAM_PROXY_URL_SCHEMES,
                true,
                true,
            )?;
        }
        if let Some(upstream_proxy) = edge.upstream_proxy.as_deref() {
            validate_named_upstream_ref(
                upstream_proxy,
                upstreams,
                format!("edge {} upstream_proxy", edge.name).as_str(),
                UPSTREAM_PROXY_URL_SCHEMES,
                true,
                true,
            )?;
        }
        for rule in &edge.rules {
            validate_match_config(
                rule.r#match.as_ref(),
                &format!("edge {} rule {}", edge.name, rule.name),
            )?;
            validate_identity_match_config(
                rule.r#match.as_ref().and_then(|m| m.identity.as_ref()),
                &format!("edge {} rule {}", edge.name, rule.name),
            )?;
            validate_rate_limit_config(
                rule.rate_limit.as_ref(),
                &format!("edge {} rule {}", edge.name, rule.name),
            )?;
            if let Some(action) = rule.action.as_ref() {
                validate_action_config(action, &format!("edge {} rule {}", edge.name, rule.name))?;
                validate_proxy_tunnel_upstream_requirement(
                    action,
                    edge.upstream_proxy.as_deref(),
                    &format!("edge {} rule {}", edge.name, rule.name),
                )?;
                uses_inspect =
                    uses_inspect || matches!(action.kind, super::super::types::ActionKind::Inspect);
                if let Some(upstream_ref) = action.upstream.as_deref() {
                    validate_named_upstream_ref(
                        upstream_ref,
                        upstreams,
                        format!("edge {} rule {} action.upstream", edge.name, rule.name).as_str(),
                        UPSTREAM_PROXY_URL_SCHEMES,
                        true,
                        true,
                    )?;
                }
            }
            if let Some(headers) = rule.headers.as_ref() {
                validate_header_control(
                    headers,
                    &format!("edge {} rule {}", edge.name, rule.name),
                )?;
            }
        }
        validate_connection_filter_rules(
            edge.connection_filter.as_slice(),
            &format!("edge {}", edge.name),
        )?;
        if uses_inspect
            && !edge
                .tls_inspection
                .as_ref()
                .map(|t| t.enabled)
                .unwrap_or(false)
        {
            return Err(anyhow!(
                "edge {} uses inspect action but tls_inspection.enabled is not true",
                edge.name
            ));
        }
        if let Some(tls) = edge.tls_inspection.as_ref() {
            for pattern in &tls.verify_exceptions {
                if pattern.trim().is_empty() {
                    return Err(anyhow!(
                        "edge {} has empty tls_inspection.verify_exceptions pattern",
                        edge.name
                    ));
                }
                globset::Glob::new(pattern).map_err(|e| {
                    anyhow!(
                        "edge {} invalid tls_inspection.verify_exceptions glob {}: {}",
                        edge.name,
                        pattern,
                        e
                    )
                })?;
            }
            validate_upstream_trust_profile_ref(
                tls.upstream_trust_profile.as_deref(),
                upstream_trust_profiles,
                &format!("edge {} tls_inspection", edge.name),
            )?;
            validate_upstream_tls_trust_config(
                tls.upstream_trust.as_ref(),
                &format!("edge {} tls_inspection", edge.name),
            )?;
        }
        validate_xdp_config("edge", &edge.name, edge.xdp.as_ref())?;
        validate_http_guard_profile_ref(
            edge.http_guard_profile.as_deref(),
            http_guard_profiles,
            &format!("edge {}", edge.name),
        )?;
        if let Some(http) = edge.http.as_ref() {
            for response_rule in &http.response_rules {
                validate_match_config(
                    response_rule.r#match.as_ref(),
                    &format!(
                        "edge {} http.response_rules {}",
                        edge.name, response_rule.name
                    ),
                )?;
                validate_http_response_effects(
                    &response_rule.effects,
                    &format!(
                        "edge {} http.response_rules {} effects",
                        edge.name, response_rule.name
                    ),
                )?;
            }
        }
        validate_http_modules(edge.http_modules.as_slice(), &format!("edge {}", edge.name))?;
        validate_capture_policy(
            edge.capture.as_ref(),
            format!("edge {} capture", edge.name).as_str(),
        )?;
        if let Some(cache) = edge.cache.as_ref().filter(|cache| cache.enabled) {
            validate_cache_policy(cache, cache_backends, &format!("edge {}", edge.name))?;
        } else if has_cache_purge_module(edge.http_modules.as_slice()) {
            return Err(anyhow!(
                "edge {} uses cache_purge http_modules but cache.enabled is not true",
                edge.name
            ));
        }
        if edge.ftp.max_request_body_bytes == 0 {
            return Err(anyhow!(
                "edge {} ftp.max_request_body_bytes must be >= 1",
                edge.name
            ));
        }
        if edge.ftp.max_download_bytes == 0 {
            return Err(anyhow!(
                "edge {} ftp.max_download_bytes must be >= 1",
                edge.name
            ));
        }
        if edge.ftp.timeout_ms == 0 {
            return Err(anyhow!("edge {} ftp.timeout_ms must be >= 1", edge.name));
        }
        if let Some(http3) = edge.http3.as_ref() {
            if http3.enabled
                && let Some(http3_listen) = http3.listen.as_deref()
            {
                let _: std::net::SocketAddr = http3_listen
                    .parse()
                    .map_err(|e| anyhow!("edge {} http3.listen is invalid: {}", edge.name, e))?;
            }
            if let Some(connect_udp) = http3.connect_udp.as_ref() {
                if connect_udp.idle_timeout_secs == 0 {
                    return Err(anyhow!(
                        "edge {} http3.connect_udp.idle_timeout_secs must be >= 1",
                        edge.name
                    ));
                }
                if connect_udp.max_capsule_buffer_bytes == 0 {
                    return Err(anyhow!(
                        "edge {} http3.connect_udp.max_capsule_buffer_bytes must be >= 1",
                        edge.name
                    ));
                }
                if let Some(uri_template) = connect_udp.uri_template.as_deref() {
                    let template = uri_template.trim();
                    if template.is_empty() {
                        return Err(anyhow!(
                            "edge {} http3.connect_udp.uri_template must not be empty",
                            edge.name
                        ));
                    }
                    if !template.is_ascii() {
                        return Err(anyhow!(
                            "edge {} http3.connect_udp.uri_template must be ASCII",
                            edge.name
                        ));
                    }
                    let is_https = template
                        .get(..8)
                        .map(|p| p.eq_ignore_ascii_case("https://"))
                        .unwrap_or(false);
                    if !(template.starts_with('/') || is_https) {
                        return Err(anyhow!(
                            "edge {} http3.connect_udp.uri_template must start with '/' or 'https://'",
                            edge.name
                        ));
                    }
                    if is_https {
                        let rest = &template[8..];
                        let Some(slash) = rest.find('/') else {
                            return Err(anyhow!(
                                "edge {} http3.connect_udp.uri_template absolute form must include a path",
                                edge.name
                            ));
                        };
                        let authority = &rest[..slash];
                        if authority.is_empty() {
                            return Err(anyhow!(
                                "edge {} http3.connect_udp.uri_template authority must not be empty",
                                edge.name
                            ));
                        }
                        if authority.contains('{') || authority.contains('}') {
                            return Err(anyhow!(
                                "edge {} http3.connect_udp.uri_template must not contain variables in authority",
                                edge.name
                            ));
                        }
                    }
                    if !template.contains("target_host") || !template.contains("target_port") {
                        return Err(anyhow!(
                            "edge {} http3.connect_udp.uri_template must contain target_host and target_port",
                            edge.name
                        ));
                    }
                    let mut depth = 0u32;
                    for ch in template.chars() {
                        match ch {
                            '{' => {
                                depth += 1;
                                if depth > 1 {
                                    return Err(anyhow!(
                                        "edge {} http3.connect_udp.uri_template must not contain nested braces",
                                        edge.name
                                    ));
                                }
                            }
                            '}' => {
                                if depth == 0 {
                                    return Err(anyhow!(
                                        "edge {} http3.connect_udp.uri_template has unmatched '}}'",
                                        edge.name
                                    ));
                                }
                                depth -= 1;
                            }
                            _ => {}
                        }
                    }
                    if depth != 0 {
                        return Err(anyhow!(
                            "edge {} http3.connect_udp.uri_template has unmatched '{{'",
                            edge.name
                        ));
                    }
                    let path_query = if is_https {
                        let rest = &template[8..];
                        let slash = rest.find('/').ok_or_else(|| {
                            anyhow!(
                                "edge {} http3.connect_udp.uri_template absolute form must include a path",
                                edge.name
                            )
                        })?;
                        &rest[slash..]
                    } else {
                        template
                    };
                    let parsed = UriTemplate::parse(path_query).map_err(|err| {
                        anyhow!(
                            "edge {} http3.connect_udp.uri_template is invalid: {}",
                            edge.name,
                            err
                        )
                    })?;
                    if !parsed.has_recoverable_variable("target_host")
                        || !parsed.has_recoverable_variable("target_port")
                    {
                        return Err(anyhow!(
                            "edge {} http3.connect_udp.uri_template must include recoverable target_host and target_port variables",
                            edge.name
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_streaming_requirement(
    requirement: Option<&StreamingRequirement>,
    context: &str,
) -> Result<()> {
    if matches!(requirement, Some(StreamingRequirement::Disabled)) {
        return Err(anyhow!(
            "{context}.streaming_requirement: disabled is not supported; omit the field for the default streaming-first mode or use required to reject buffering features"
        ));
    }
    Ok(())
}
