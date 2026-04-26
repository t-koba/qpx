use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};

use super::super::types::Config;
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

pub(super) fn validate_reverse_configs(
    config: &Config,
    cache_backends: &HashSet<String>,
    upstreams: &HashMap<String, url::Url>,
    http_guard_profiles: &HashSet<String>,
    upstream_trust_profiles: &HashSet<String>,
) -> Result<()> {
    let mut seen_reverse_names: HashSet<String> = HashSet::new();
    for reverse in &config.reverse {
        if reverse.name.trim().is_empty() {
            return Err(anyhow!("reverse name must not be empty"));
        }
        if !seen_reverse_names.insert(reverse.name.clone()) {
            return Err(anyhow!("duplicate reverse name: {}", reverse.name));
        }
        if reverse.listen.trim().is_empty() {
            return Err(anyhow!("reverse {} listen must not be empty", reverse.name));
        }
        reverse
            .listen
            .parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow!("reverse {} listen is invalid: {}", reverse.name, e))?;

        validate_xdp_config("reverse", &reverse.name, reverse.xdp.as_ref())?;
        validate_destination_resolution_override(
            reverse.destination_resolution.as_ref(),
            &format!("reverse {}", reverse.name),
        )?;
        let reverse_has_mtls_identity = reverse
            .tls
            .as_ref()
            .and_then(|tls| tls.client_ca.as_deref())
            .map(str::trim)
            .filter(|ca| !ca.is_empty())
            .is_some();
        validate_policy_context_refs(
            reverse.policy_context.as_ref(),
            &config.identity_sources,
            &config.ext_authz,
            &format!("reverse {}", reverse.name),
            reverse_has_mtls_identity,
        )?;
        validate_connection_filter_rules(
            reverse.connection_filter.as_slice(),
            &format!("reverse {}", reverse.name),
        )?;
        for pattern in &reverse.sni_host_exceptions {
            if pattern.trim().is_empty() {
                return Err(anyhow!(
                    "reverse {} has empty sni_host_exceptions pattern",
                    reverse.name
                ));
            }
            globset::Glob::new(pattern).map_err(|e| {
                anyhow!(
                    "reverse {} invalid sni_host_exceptions glob {}: {}",
                    reverse.name,
                    pattern,
                    e
                )
            })?;
        }

        if let Some(tls) = reverse.tls.as_ref() {
            if tls.certificates.is_empty() {
                return Err(anyhow!(
                    "reverse {} tls.certificates must contain at least one entry",
                    reverse.name
                ));
            }
            #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
            {
                return Err(anyhow!(
                    "reverse {} configures tls certificates, but this build has no TLS backend enabled",
                    reverse.name
                ));
            }

            #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
            {
                let mut seen: HashSet<String> = HashSet::new();
                for cert in &tls.certificates {
                    if cert.sni.trim().is_empty() {
                        return Err(anyhow!(
                            "reverse {} tls.certificates[].sni must not be empty",
                            reverse.name
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
                                    "reverse {} tls.certificates[] must set cert+key (PEM) on rustls builds (or leave both empty with acme.enabled=true)",
                                    reverse.name
                                ));
                            }
                            if cert.sni.contains('*') {
                                return Err(anyhow!(
                                    "reverse {} tls.certificates[] uses wildcard sni ({}), but ACME HTTP-01 does not support wildcard certificates",
                                    reverse.name,
                                    cert.sni
                                ));
                            }
                        } else if cert_path.is_empty() || key_path.is_empty() {
                            return Err(anyhow!(
                                "reverse {} tls.certificates[] must set both cert+key (PEM) on rustls builds",
                                reverse.name
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
                                "reverse {} tls.certificates[] must not set pkcs12 fields on rustls builds",
                                reverse.name
                            ));
                        }
                    }
                    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
                    {
                        let pkcs12_path = cert.pkcs12.as_deref().unwrap_or("").trim();
                        if pkcs12_path.is_empty() {
                            return Err(anyhow!(
                                "reverse {} tls.certificates[] must set pkcs12 on tls-native builds",
                                reverse.name
                            ));
                        }
                        if !cert.cert.as_deref().unwrap_or("").trim().is_empty()
                            || !cert.key.as_deref().unwrap_or("").trim().is_empty()
                        {
                            return Err(anyhow!(
                                "reverse {} tls.certificates[] must not set cert/key on tls-native builds",
                                reverse.name
                            ));
                        }
                        if let Some(env) = cert.pkcs12_password_env.as_deref() {
                            if env.trim().is_empty() {
                                return Err(anyhow!(
                                    "reverse {} tls.certificates[].pkcs12_password_env must not be empty when set",
                                    reverse.name
                                ));
                            }
                        }
                    }
                    let sni = cert.sni.to_ascii_lowercase();
                    if !seen.insert(sni.clone()) {
                        return Err(anyhow!(
                            "reverse {} has duplicate tls certificate sni: {}",
                            reverse.name,
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
                        "reverse {} tls.client_ca must not be empty when set",
                        reverse.name
                    ));
                }
                #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
                {
                    return Err(anyhow!(
                        "reverse {} tls.client_ca is not supported on tls-native builds",
                        reverse.name
                    ));
                }
            }
        }

        let h3_enabled = reverse.http3.as_ref().map(|h| h.enabled).unwrap_or(false);
        let h3_passthrough = reverse
            .http3
            .as_ref()
            .map(|h| !h.passthrough_upstreams.is_empty())
            .unwrap_or(false);
        if let Some(h3) = reverse.http3.as_ref() {
            if h3.enabled {
                if let Some(listen) = h3.listen.as_deref() {
                    let listen = listen.trim();
                    if listen.is_empty() {
                        return Err(anyhow!(
                            "reverse {} http3.listen must not be empty when set",
                            reverse.name
                        ));
                    }
                    listen.parse::<std::net::SocketAddr>().map_err(|e| {
                        anyhow!("reverse {} http3.listen is invalid: {}", reverse.name, e)
                    })?;
                }
                if h3.passthrough_max_sessions == 0 {
                    return Err(anyhow!(
                        "reverse {} http3.passthrough_max_sessions must be >= 1",
                        reverse.name
                    ));
                }
                if h3.passthrough_idle_timeout_secs == 0 {
                    return Err(anyhow!(
                        "reverse {} http3.passthrough_idle_timeout_secs must be >= 1",
                        reverse.name
                    ));
                }
                if h3.passthrough_max_new_sessions_per_sec == 0 {
                    return Err(anyhow!(
                        "reverse {} http3.passthrough_max_new_sessions_per_sec must be >= 1",
                        reverse.name
                    ));
                }
                if h3.passthrough_min_client_bytes == 0 {
                    return Err(anyhow!(
                        "reverse {} http3.passthrough_min_client_bytes must be >= 1",
                        reverse.name
                    ));
                }
                if h3.passthrough_max_amplification == 0 {
                    return Err(anyhow!(
                        "reverse {} http3.passthrough_max_amplification must be >= 1",
                        reverse.name
                    ));
                }
            }
        }
        if h3_passthrough {
            let targets = reverse
                .http3
                .as_ref()
                .map(|h| h.passthrough_upstreams.as_slice())
                .unwrap_or_default();
            for upstream_ref in targets {
                validate_named_upstream_ref(
                    upstream_ref,
                    upstreams,
                    &format!("reverse {} http3.passthrough_upstreams", reverse.name),
                    REVERSE_PASSTHROUGH_UPSTREAM_URL_SCHEMES,
                    false,
                    true,
                )?;
            }
        }

        if reverse.routes.is_empty()
            && reverse.tls_passthrough_routes.is_empty()
            && !(h3_enabled && h3_passthrough)
        {
            return Err(anyhow!("reverse {} has no routes", reverse.name));
        }

        if !reverse.tls_passthrough_routes.is_empty() && reverse.tls.is_none() {
            return Err(anyhow!(
                "reverse {} tls_passthrough_routes requires reverse.tls certificates",
                reverse.name
            ));
        }

        let mut seen_route_names = HashSet::new();
        for route in &reverse.routes {
            if let Some(name) = route.name.as_deref() {
                if name.trim().is_empty() {
                    return Err(anyhow!(
                        "reverse {} route name must not be empty when set",
                        reverse.name
                    ));
                }
                if !seen_route_names.insert(name.to_string()) {
                    return Err(anyhow!(
                        "reverse {} has duplicate route name: {}",
                        reverse.name,
                        name
                    ));
                }
            }
            validate_match_config(
                Some(&route.r#match),
                &format!("reverse {} route", reverse.name),
            )?;
            validate_identity_match_config(
                Some(&route.r#match).and_then(|m| m.identity.as_ref()),
                &format!("reverse {} route", reverse.name),
            )?;
            validate_policy_context_refs(
                route.policy_context.as_ref(),
                &config.identity_sources,
                &config.ext_authz,
                &format!("reverse {} route", reverse.name),
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
                    "reverse {} route must set exactly one of upstreams, backends, ipc, or local_response",
                    reverse.name
                ));
            }
            if let Some(ipc) = route.ipc.as_ref() {
                if ipc.address.trim().is_empty() {
                    return Err(anyhow!(
                        "reverse {} route ipc.address must not be empty",
                        reverse.name
                    ));
                }
                if ipc.timeout_ms == 0 {
                    return Err(anyhow!(
                        "reverse {} route ipc.timeout_ms must be >= 1",
                        reverse.name
                    ));
                }
            }
            validate_lb_config(
                route.lb.as_str(),
                &format!("reverse {} route", reverse.name),
            )?;
            validate_resilience_config(
                route.resilience.as_ref(),
                &format!("reverse {} route", reverse.name),
            )?;
            validate_endpoint_lifecycle_config(
                route.lifecycle.as_ref(),
                &format!("reverse {} route", reverse.name),
            )?;
            validate_affinity_config(
                route.affinity.as_ref(),
                &format!("reverse {} route", reverse.name),
            )?;
            validate_destination_resolution_override(
                route.destination_resolution.as_ref(),
                &format!("reverse {} route", reverse.name),
            )?;
            validate_http_modules(
                route.http_modules.as_slice(),
                &format!("reverse {} route", reverse.name),
            )?;
            validate_http_guard_profile_ref(
                route.http_guard_profile.as_deref(),
                http_guard_profiles,
                &format!("reverse {} route", reverse.name),
            )?;
            if let Some(http) = route.http.as_ref() {
                let mut seen_http_response_rule_names = HashSet::new();
                for response_rule in &http.response_rules {
                    if response_rule.name.trim().is_empty() {
                        return Err(anyhow!(
                            "reverse {} route http.response_rules name must not be empty",
                            reverse.name
                        ));
                    }
                    if !seen_http_response_rule_names.insert(response_rule.name.clone()) {
                        return Err(anyhow!(
                            "reverse {} route duplicate http.response_rules name: {}",
                            reverse.name,
                            response_rule.name
                        ));
                    }
                    validate_match_config(
                        response_rule.r#match.as_ref(),
                        &format!(
                            "reverse {} route http.response_rules {}",
                            reverse.name, response_rule.name
                        ),
                    )?;
                    validate_http_response_effects(
                        &response_rule.effects,
                        &format!(
                            "reverse {} route http.response_rules {} effects",
                            reverse.name, response_rule.name
                        ),
                    )?;
                }
            }
            for upstream_ref in &route.upstreams {
                validate_named_upstream_ref(
                    upstream_ref,
                    upstreams,
                    &format!("reverse {} route upstreams", reverse.name),
                    REVERSE_UPSTREAM_URL_SCHEMES,
                    false,
                    false,
                )?;
            }
            if has_backends {
                for backend in &route.backends {
                    if backend.weight == 0 {
                        return Err(anyhow!(
                            "reverse {} route backend weight must be >= 1",
                            reverse.name
                        ));
                    }
                    if backend.upstreams.is_empty() {
                        return Err(anyhow!(
                            "reverse {} route backend must set upstreams",
                            reverse.name
                        ));
                    }
                    for upstream_ref in &backend.upstreams {
                        validate_named_upstream_ref(
                            upstream_ref,
                            upstreams,
                            &format!("reverse {} route backends", reverse.name),
                            REVERSE_UPSTREAM_URL_SCHEMES,
                            false,
                            false,
                        )?;
                    }
                    if let Some(name) = backend.name.as_deref() {
                        if name.trim().is_empty() {
                            return Err(anyhow!(
                                "reverse {} route backend name must not be empty when set",
                                reverse.name
                            ));
                        }
                    }
                }
            }
            for mirror in &route.mirrors {
                if mirror.percent == 0 || mirror.percent > 100 {
                    return Err(anyhow!(
                        "reverse {} route mirror percent must be 1..=100",
                        reverse.name
                    ));
                }
                if mirror.upstreams.is_empty() {
                    return Err(anyhow!(
                        "reverse {} route mirror must set upstreams",
                        reverse.name
                    ));
                }
                for upstream_ref in &mirror.upstreams {
                    validate_named_upstream_ref(
                        upstream_ref,
                        upstreams,
                        &format!("reverse {} route mirrors", reverse.name),
                        REVERSE_UPSTREAM_URL_SCHEMES,
                        false,
                        false,
                    )?;
                }
                if let Some(name) = mirror.name.as_deref() {
                    if name.trim().is_empty() {
                        return Err(anyhow!(
                            "reverse {} route mirror name must not be empty when set",
                            reverse.name
                        ));
                    }
                }
            }
            if has_local && !route.mirrors.is_empty() {
                return Err(anyhow!(
                    "reverse {} route with local_response cannot configure mirrors",
                    reverse.name
                ));
            }
            if let Some(headers) = route.headers.as_ref() {
                crate::rules::CompiledHeaderControl::compile(headers).map_err(|e| {
                    anyhow!(
                        "reverse {} route header control is invalid: {}",
                        reverse.name,
                        e
                    )
                })?;
            }
            if let Some(regex) = route.path_rewrite.as_ref().and_then(|rw| rw.regex.as_ref()) {
                let pattern = regex.pattern.trim();
                if pattern.is_empty() {
                    return Err(anyhow!(
                        "reverse {} route path_rewrite.regex.pattern must not be empty",
                        reverse.name
                    ));
                }
                regex::Regex::new(pattern).map_err(|e| {
                    anyhow!(
                        "reverse {} route path_rewrite.regex.pattern is invalid: {}",
                        reverse.name,
                        e
                    )
                })?;
                if regex.replace.contains('?') || regex.replace.contains('#') {
                    return Err(anyhow!(
                        "reverse {} route path_rewrite.regex.replace must not contain '?' or '#'",
                        reverse.name
                    ));
                }
            }
            if let Some(cache) = route.cache.as_ref().filter(|cache| cache.enabled) {
                if has_local {
                    return Err(anyhow!(
                        "reverse {} route with local_response cannot enable cache",
                        reverse.name
                    ));
                }
                validate_cache_policy(
                    cache,
                    cache_backends,
                    &format!("reverse {} route", reverse.name),
                )?;
            } else if has_cache_purge_module(route.http_modules.as_slice()) {
                return Err(anyhow!(
                    "reverse {} route uses cache_purge http_modules but cache.enabled is not true",
                    reverse.name
                ));
            }
            validate_health_check_config(
                &reverse.name,
                route.health_check.as_ref(),
                "reverse route",
            )?;
            validate_upstream_trust_profile_ref(
                route.upstream_trust_profile.as_deref(),
                upstream_trust_profiles,
                &format!("reverse {} route", reverse.name),
            )?;
            validate_upstream_tls_trust_config(
                route.upstream_trust.as_ref(),
                &format!("reverse {} route", reverse.name),
            )?;
        }

        for route in &reverse.tls_passthrough_routes {
            if route.upstreams.is_empty() {
                return Err(anyhow!(
                    "reverse {} tls_passthrough_routes entry must set upstreams",
                    reverse.name
                ));
            }
            validate_lb_config(
                route.lb.as_str(),
                &format!("reverse {} tls_passthrough route", reverse.name),
            )?;
            validate_resilience_config(
                route.resilience.as_ref(),
                &format!("reverse {} tls_passthrough route", reverse.name),
            )?;
            validate_endpoint_lifecycle_config(
                route.lifecycle.as_ref(),
                &format!("reverse {} tls_passthrough route", reverse.name),
            )?;
            validate_affinity_config(
                route.affinity.as_ref(),
                &format!("reverse {} tls_passthrough route", reverse.name),
            )?;
            for upstream_ref in &route.upstreams {
                validate_named_upstream_ref(
                    upstream_ref,
                    upstreams,
                    &format!("reverse {} tls_passthrough_routes", reverse.name),
                    REVERSE_PASSTHROUGH_UPSTREAM_URL_SCHEMES,
                    false,
                    true,
                )?;
            }
            validate_health_check_config(
                &reverse.name,
                route.health_check.as_ref(),
                "reverse tls_passthrough route",
            )?;
        }
    }
    Ok(())
}
