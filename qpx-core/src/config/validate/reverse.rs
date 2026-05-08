use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};

use super::super::types::Config;
use super::observability::validate_capture_policy;
use super::rules::{
    has_cache_purge_module, validate_affinity_config, validate_cache_policy,
    validate_connection_filter_rules, validate_endpoint_lifecycle_config,
    validate_health_check_config, validate_http_modules, validate_http_response_effects,
    validate_identity_match_config, validate_lb_config, validate_match_config,
    validate_policy_context_refs, validate_resilience_config, validate_xdp_config,
};
use super::security::{
    validate_destination_resolution_override, validate_http_guard_profile_ref,
    validate_upstream_trust_profile_ref,
};
use super::upstreams::{validate_named_upstream_ref, validate_upstream_tls_trust_config};
use super::{REVERSE_PASSTHROUGH_UPSTREAM_URL_SCHEMES, REVERSE_UPSTREAM_URL_SCHEMES};

pub(super) fn validate_reverse_edge_configs(
    config: &Config,
    cache_backends: &HashSet<String>,
    upstreams: &HashMap<String, url::Url>,
    http_guard_profiles: &HashSet<String>,
    upstream_trust_profiles: &HashSet<String>,
) -> Result<()> {
    let mut seen_reverse_names: HashSet<String> = HashSet::new();
    for reverse_edge in config.reverse_edge_configs() {
        if reverse_edge.name.trim().is_empty() {
            return Err(anyhow!("reverse_edge name must not be empty"));
        }
        if !seen_reverse_names.insert(reverse_edge.name.clone()) {
            return Err(anyhow!(
                "duplicate reverse_edge name: {}",
                reverse_edge.name
            ));
        }
        if reverse_edge.listen.trim().is_empty() {
            return Err(anyhow!(
                "reverse_edge {} listen must not be empty",
                reverse_edge.name
            ));
        }
        reverse_edge
            .listen
            .parse::<std::net::SocketAddr>()
            .map_err(|e| {
                anyhow!(
                    "reverse_edge {} listen is invalid: {}",
                    reverse_edge.name,
                    e
                )
            })?;

        validate_xdp_config(
            "reverse_edge",
            &reverse_edge.name,
            reverse_edge.xdp.as_ref(),
        )?;
        validate_destination_resolution_override(
            reverse_edge.destination_resolution.as_ref(),
            &format!("reverse_edge {}", reverse_edge.name),
        )?;
        let reverse_has_mtls_identity = reverse_edge
            .tls
            .as_ref()
            .and_then(|tls| tls.client_ca.as_deref())
            .map(str::trim)
            .filter(|ca| !ca.is_empty())
            .is_some();
        validate_policy_context_refs(
            reverse_edge.policy_context.as_ref(),
            &config.security.identity_sources,
            &config.security.decisions.ext_authz,
            &format!("reverse_edge {}", reverse_edge.name),
            reverse_has_mtls_identity,
        )?;
        validate_connection_filter_rules(
            reverse_edge.connection_filter.as_slice(),
            &format!("reverse_edge {}", reverse_edge.name),
        )?;
        for pattern in &reverse_edge.sni_host_exceptions {
            if pattern.trim().is_empty() {
                return Err(anyhow!(
                    "reverse_edge {} has empty sni_host_exceptions pattern",
                    reverse_edge.name
                ));
            }
            globset::Glob::new(pattern).map_err(|e| {
                anyhow!(
                    "reverse_edge {} invalid sni_host_exceptions glob {}: {}",
                    reverse_edge.name,
                    pattern,
                    e
                )
            })?;
        }

        if let Some(tls) = reverse_edge.tls.as_ref() {
            if tls.certificates.is_empty() {
                return Err(anyhow!(
                    "reverse_edge {} tls.certificates must contain at least one entry",
                    reverse_edge.name
                ));
            }
            #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
            {
                return Err(anyhow!(
                    "reverse_edge {} configures tls certificates, but this build has no TLS backend enabled",
                    reverse_edge.name
                ));
            }

            #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
            {
                let mut seen: HashSet<String> = HashSet::new();
                for cert in &tls.certificates {
                    if cert.sni.trim().is_empty() {
                        return Err(anyhow!(
                            "reverse_edge {} tls.certificates[].sni must not be empty",
                            reverse_edge.name
                        ));
                    }
                    #[cfg(feature = "tls-rustls")]
                    {
                        let cert_path = cert.cert.as_deref().unwrap_or("").trim();
                        let key_path = cert.key.as_deref().unwrap_or("").trim();
                        let acme_enabled = config.acme.as_ref().map(|a| a.enabled).unwrap_or(false);
                        let acme_managed = cert_path.is_empty() && key_path.is_empty();
                        if acme_managed {
                            if !acme_enabled {
                                return Err(anyhow!(
                                    "reverse_edge {} tls.certificates[] must set cert+key (PEM) on rustls builds (or leave both empty with acme.enabled=true)",
                                    reverse_edge.name
                                ));
                            }
                            if cert.sni.contains('*') {
                                return Err(anyhow!(
                                    "reverse_edge {} tls.certificates[] uses wildcard sni ({}), but ACME HTTP-01 does not support wildcard certificates",
                                    reverse_edge.name,
                                    cert.sni
                                ));
                            }
                        } else if cert_path.is_empty() || key_path.is_empty() {
                            return Err(anyhow!(
                                "reverse_edge {} tls.certificates[] must set both cert+key (PEM) on rustls builds",
                                reverse_edge.name
                            ));
                        }
                        if !cert.pkcs12.as_deref().unwrap_or("").trim().is_empty()
                            || !cert
                                .pkcs12_password_env
                                .as_deref()
                                .unwrap_or("")
                                .trim()
                                .is_empty()
                        {
                            return Err(anyhow!(
                                "reverse_edge {} tls.certificates[] must not set pkcs12 fields on rustls builds",
                                reverse_edge.name
                            ));
                        }
                    }
                    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
                    {
                        let pkcs12_path = cert.pkcs12.as_deref().unwrap_or("").trim();
                        if pkcs12_path.is_empty() {
                            return Err(anyhow!(
                                "reverse_edge {} tls.certificates[] must set pkcs12 on tls-native builds",
                                reverse_edge.name
                            ));
                        }
                        if !cert.cert.as_deref().unwrap_or("").trim().is_empty()
                            || !cert.key.as_deref().unwrap_or("").trim().is_empty()
                        {
                            return Err(anyhow!(
                                "reverse_edge {} tls.certificates[] must not set cert/key on tls-native builds",
                                reverse_edge.name
                            ));
                        }
                        if let Some(env) = cert.pkcs12_password_env.as_deref() {
                            if env.trim().is_empty() {
                                return Err(anyhow!(
                                    "reverse_edge {} tls.certificates[].pkcs12_password_env must not be empty when set",
                                    reverse_edge.name
                                ));
                            }
                        }
                    }
                    let sni = cert.sni.to_ascii_lowercase();
                    if !seen.insert(sni.clone()) {
                        return Err(anyhow!(
                            "reverse_edge {} has duplicate tls certificate sni: {}",
                            reverse_edge.name,
                            sni
                        ));
                    }
                }
            }

            #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
            if let Some(ca) = tls.client_ca.as_deref() {
                let ca = ca.trim();
                if ca.is_empty() {
                    return Err(anyhow!(
                        "reverse_edge {} tls.client_ca must not be empty when set",
                        reverse_edge.name
                    ));
                }
                #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
                {
                    return Err(anyhow!(
                        "reverse_edge {} tls.client_ca is not supported on tls-native builds",
                        reverse_edge.name
                    ));
                }
            }
        }

        let h3_enabled = reverse_edge
            .http3
            .as_ref()
            .map(|h| h.enabled)
            .unwrap_or(false);
        let h3_passthrough = reverse_edge
            .http3
            .as_ref()
            .map(|h| !h.passthrough_upstreams.is_empty())
            .unwrap_or(false);
        if let Some(h3) = reverse_edge.http3.as_ref() {
            if h3.enabled {
                if let Some(listen) = h3.listen.as_deref() {
                    let listen = listen.trim();
                    if listen.is_empty() {
                        return Err(anyhow!(
                            "reverse_edge {} http3.listen must not be empty when set",
                            reverse_edge.name
                        ));
                    }
                    listen.parse::<std::net::SocketAddr>().map_err(|e| {
                        anyhow!(
                            "reverse_edge {} http3.listen is invalid: {}",
                            reverse_edge.name,
                            e
                        )
                    })?;
                }
                if h3.passthrough_max_sessions == 0 {
                    return Err(anyhow!(
                        "reverse_edge {} http3.passthrough_max_sessions must be >= 1",
                        reverse_edge.name
                    ));
                }
                if h3.passthrough_idle_timeout_secs == 0 {
                    return Err(anyhow!(
                        "reverse_edge {} http3.passthrough_idle_timeout_secs must be >= 1",
                        reverse_edge.name
                    ));
                }
                if h3.passthrough_max_new_sessions_per_sec == 0 {
                    return Err(anyhow!(
                        "reverse_edge {} http3.passthrough_max_new_sessions_per_sec must be >= 1",
                        reverse_edge.name
                    ));
                }
                if h3.passthrough_min_client_bytes == 0 {
                    return Err(anyhow!(
                        "reverse_edge {} http3.passthrough_min_client_bytes must be >= 1",
                        reverse_edge.name
                    ));
                }
                if h3.passthrough_max_amplification == 0 {
                    return Err(anyhow!(
                        "reverse_edge {} http3.passthrough_max_amplification must be >= 1",
                        reverse_edge.name
                    ));
                }
            }
        }
        if h3_passthrough {
            let targets = reverse_edge
                .http3
                .as_ref()
                .map(|h| h.passthrough_upstreams.as_slice())
                .unwrap_or_default();
            for upstream_ref in targets {
                validate_named_upstream_ref(
                    upstream_ref,
                    upstreams,
                    &format!(
                        "reverse_edge {} http3.passthrough_upstreams",
                        reverse_edge.name
                    ),
                    REVERSE_PASSTHROUGH_UPSTREAM_URL_SCHEMES,
                    false,
                    true,
                )?;
            }
        }

        if reverse_edge.routes.is_empty()
            && reverse_edge.tls_passthrough_routes.is_empty()
            && !(h3_enabled && h3_passthrough)
        {
            return Err(anyhow!("reverse_edge {} has no routes", reverse_edge.name));
        }

        if !reverse_edge.tls_passthrough_routes.is_empty() && reverse_edge.tls.is_none() {
            return Err(anyhow!(
                "reverse_edge {} tls_passthrough_routes requires reverse_edge.tls certificates",
                reverse_edge.name
            ));
        }

        let mut seen_route_names = HashSet::new();
        for route in &reverse_edge.routes {
            if let Some(name) = route.name.as_deref() {
                if name.trim().is_empty() {
                    return Err(anyhow!(
                        "reverse_edge {} route name must not be empty when set",
                        reverse_edge.name
                    ));
                }
                if !seen_route_names.insert(name.to_string()) {
                    return Err(anyhow!(
                        "reverse_edge {} has duplicate route name: {}",
                        reverse_edge.name,
                        name
                    ));
                }
            }
            validate_match_config(
                Some(&route.r#match),
                &format!("reverse_edge {} route", reverse_edge.name),
            )?;
            validate_identity_match_config(
                Some(&route.r#match).and_then(|m| m.identity.as_ref()),
                &format!("reverse_edge {} route", reverse_edge.name),
            )?;
            validate_policy_context_refs(
                route.policy_context.as_ref(),
                &config.security.identity_sources,
                &config.security.decisions.ext_authz,
                &format!("reverse_edge {} route", reverse_edge.name),
                reverse_has_mtls_identity,
            )?;
            let has_upstream = !route.upstreams.is_empty();
            let has_backends = !route.backends.is_empty();
            let has_local = route.local_response.is_some();
            let has_ipc = route.ipc.is_some();
            let configured_kinds =
                (has_upstream as u8) + (has_backends as u8) + (has_local as u8) + (has_ipc as u8);
            if configured_kinds != 1 {
                return Err(anyhow!(
                    "reverse_edge {} route must set exactly one of upstreams, backends, ipc, or local_response",
                    reverse_edge.name
                ));
            }
            if let Some(ipc) = route.ipc.as_ref() {
                if ipc.address.trim().is_empty() {
                    return Err(anyhow!(
                        "reverse_edge {} route ipc.address must not be empty",
                        reverse_edge.name
                    ));
                }
                if ipc.timeout_ms == 0 {
                    return Err(anyhow!(
                        "reverse_edge {} route ipc.timeout_ms must be >= 1",
                        reverse_edge.name
                    ));
                }
                if matches!(ipc.body.max_request_bytes, Some(0)) {
                    return Err(anyhow!(
                        "reverse_edge {} route ipc.body.max_request_bytes must be >= 1",
                        reverse_edge.name
                    ));
                }
                if matches!(ipc.body.max_response_bytes, Some(0)) {
                    return Err(anyhow!(
                        "reverse_edge {} route ipc.body.max_response_bytes must be >= 1",
                        reverse_edge.name
                    ));
                }
            }
            validate_lb_config(
                route.lb.as_str(),
                &format!("reverse_edge {} route", reverse_edge.name),
            )?;
            validate_resilience_config(
                route.resilience.as_ref(),
                &format!("reverse_edge {} route", reverse_edge.name),
            )?;
            validate_endpoint_lifecycle_config(
                route.lifecycle.as_ref(),
                &format!("reverse_edge {} route", reverse_edge.name),
            )?;
            validate_affinity_config(
                route.affinity.as_ref(),
                &format!("reverse_edge {} route", reverse_edge.name),
            )?;
            validate_destination_resolution_override(
                route.destination_resolution.as_ref(),
                &format!("reverse_edge {} route", reverse_edge.name),
            )?;
            validate_http_modules(
                route.http_modules.as_slice(),
                &format!("reverse_edge {} route", reverse_edge.name),
            )?;
            validate_capture_policy(
                route.capture.as_ref(),
                format!("reverse_edge {} route capture", reverse_edge.name).as_str(),
            )?;
            validate_http_guard_profile_ref(
                route.http_guard_profile.as_deref(),
                http_guard_profiles,
                &format!("reverse_edge {} route", reverse_edge.name),
            )?;
            if let Some(http) = route.http.as_ref() {
                let mut seen_http_response_rule_names = HashSet::new();
                for response_rule in &http.response_rules {
                    if response_rule.name.trim().is_empty() {
                        return Err(anyhow!(
                            "reverse_edge {} route http.response_rules name must not be empty",
                            reverse_edge.name
                        ));
                    }
                    if !seen_http_response_rule_names.insert(response_rule.name.clone()) {
                        return Err(anyhow!(
                            "reverse_edge {} route duplicate http.response_rules name: {}",
                            reverse_edge.name,
                            response_rule.name
                        ));
                    }
                    validate_match_config(
                        response_rule.r#match.as_ref(),
                        &format!(
                            "reverse_edge {} route http.response_rules {}",
                            reverse_edge.name, response_rule.name
                        ),
                    )?;
                    validate_http_response_effects(
                        &response_rule.effects,
                        &format!(
                            "reverse_edge {} route http.response_rules {} effects",
                            reverse_edge.name, response_rule.name
                        ),
                    )?;
                }
            }
            for upstream_ref in &route.upstreams {
                validate_named_upstream_ref(
                    upstream_ref,
                    upstreams,
                    &format!("reverse_edge {} route upstreams", reverse_edge.name),
                    REVERSE_UPSTREAM_URL_SCHEMES,
                    false,
                    false,
                )?;
            }
            if has_backends {
                for backend in &route.backends {
                    if backend.weight == 0 {
                        return Err(anyhow!(
                            "reverse_edge {} route backend weight must be >= 1",
                            reverse_edge.name
                        ));
                    }
                    if backend.upstreams.is_empty() {
                        return Err(anyhow!(
                            "reverse_edge {} route backend must set upstreams",
                            reverse_edge.name
                        ));
                    }
                    for upstream_ref in &backend.upstreams {
                        validate_named_upstream_ref(
                            upstream_ref,
                            upstreams,
                            &format!("reverse_edge {} route backends", reverse_edge.name),
                            REVERSE_UPSTREAM_URL_SCHEMES,
                            false,
                            false,
                        )?;
                    }
                    if let Some(name) = backend.name.as_deref() {
                        if name.trim().is_empty() {
                            return Err(anyhow!(
                                "reverse_edge {} route backend name must not be empty when set",
                                reverse_edge.name
                            ));
                        }
                    }
                }
            }
            for mirror in &route.mirrors {
                if mirror.percent == 0 || mirror.percent > 100 {
                    return Err(anyhow!(
                        "reverse_edge {} route mirror percent must be 1..=100",
                        reverse_edge.name
                    ));
                }
                if mirror.upstreams.is_empty() {
                    return Err(anyhow!(
                        "reverse_edge {} route mirror must set upstreams",
                        reverse_edge.name
                    ));
                }
                for upstream_ref in &mirror.upstreams {
                    validate_named_upstream_ref(
                        upstream_ref,
                        upstreams,
                        &format!("reverse_edge {} route mirrors", reverse_edge.name),
                        REVERSE_UPSTREAM_URL_SCHEMES,
                        false,
                        false,
                    )?;
                }
                if let Some(name) = mirror.name.as_deref() {
                    if name.trim().is_empty() {
                        return Err(anyhow!(
                            "reverse_edge {} route mirror name must not be empty when set",
                            reverse_edge.name
                        ));
                    }
                }
            }
            if has_local && !route.mirrors.is_empty() {
                return Err(anyhow!(
                    "reverse_edge {} route with local_response cannot configure mirrors",
                    reverse_edge.name
                ));
            }
            if let Some(headers) = route.headers.as_ref() {
                crate::rules::CompiledHeaderControl::compile(headers).map_err(|e| {
                    anyhow!(
                        "reverse_edge {} route header control is invalid: {}",
                        reverse_edge.name,
                        e
                    )
                })?;
            }
            if let Some(regex) = route.path_rewrite.as_ref().and_then(|rw| rw.regex.as_ref()) {
                let pattern = regex.pattern.trim();
                if pattern.is_empty() {
                    return Err(anyhow!(
                        "reverse_edge {} route path_rewrite.regex.pattern must not be empty",
                        reverse_edge.name
                    ));
                }
                regex::Regex::new(pattern).map_err(|e| {
                    anyhow!(
                        "reverse_edge {} route path_rewrite.regex.pattern is invalid: {}",
                        reverse_edge.name,
                        e
                    )
                })?;
                if regex.replace.contains('?') || regex.replace.contains('#') {
                    return Err(anyhow!(
                        "reverse_edge {} route path_rewrite.regex.replace must not contain '?' or '#'",
                        reverse_edge.name
                    ));
                }
            }
            if let Some(cache) = route.cache.as_ref().filter(|cache| cache.enabled) {
                if has_local {
                    return Err(anyhow!(
                        "reverse_edge {} route with local_response cannot enable cache",
                        reverse_edge.name
                    ));
                }
                validate_cache_policy(
                    cache,
                    cache_backends,
                    &format!("reverse_edge {} route", reverse_edge.name),
                )?;
            } else if has_cache_purge_module(route.http_modules.as_slice()) {
                return Err(anyhow!(
                    "reverse_edge {} route uses cache_purge http_modules but cache.enabled is not true",
                    reverse_edge.name
                ));
            }
            validate_health_check_config(
                &reverse_edge.name,
                route.health_check.as_ref(),
                "reverse_edge route",
            )?;
            validate_upstream_trust_profile_ref(
                route.upstream_trust_profile.as_deref(),
                upstream_trust_profiles,
                &format!("reverse_edge {} route", reverse_edge.name),
            )?;
            validate_upstream_tls_trust_config(
                route.upstream_trust.as_ref(),
                &format!("reverse_edge {} route", reverse_edge.name),
            )?;
        }

        for route in &reverse_edge.tls_passthrough_routes {
            if route.upstreams.is_empty() {
                return Err(anyhow!(
                    "reverse_edge {} tls_passthrough_routes entry must set upstreams",
                    reverse_edge.name
                ));
            }
            validate_lb_config(
                route.lb.as_str(),
                &format!("reverse_edge {} tls_passthrough route", reverse_edge.name),
            )?;
            validate_resilience_config(
                route.resilience.as_ref(),
                &format!("reverse_edge {} tls_passthrough route", reverse_edge.name),
            )?;
            validate_endpoint_lifecycle_config(
                route.lifecycle.as_ref(),
                &format!("reverse_edge {} tls_passthrough route", reverse_edge.name),
            )?;
            validate_affinity_config(
                route.affinity.as_ref(),
                &format!("reverse_edge {} tls_passthrough route", reverse_edge.name),
            )?;
            for upstream_ref in &route.upstreams {
                validate_named_upstream_ref(
                    upstream_ref,
                    upstreams,
                    &format!("reverse_edge {} tls_passthrough_routes", reverse_edge.name),
                    REVERSE_PASSTHROUGH_UPSTREAM_URL_SCHEMES,
                    false,
                    true,
                )?;
            }
            validate_health_check_config(
                &reverse_edge.name,
                route.health_check.as_ref(),
                "reverse_edge tls_passthrough route",
            )?;
        }
    }
    Ok(())
}
