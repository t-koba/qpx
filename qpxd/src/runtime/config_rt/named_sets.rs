use anyhow::{Result, anyhow};
use qpx_core::config::{
    CertificateMatchConfig, Config, IdentityMatchConfig, MatchConfig, NamedSetKind, RuleConfig,
    TlsFingerprintMatchConfig, TlsPassthroughMatchConfig,
};
use std::collections::{HashMap, HashSet};
use std::fs;

#[derive(Debug, Clone)]
struct LoadedNamedSet {
    kind: NamedSetKind,
    values: Vec<String>,
}

pub(in crate::runtime) fn expand_named_sets_in_config(config: &mut Config) -> Result<()> {
    let registry = load_named_set_registry(config)?;
    if registry.is_empty() {
        return Ok(());
    }

    for listener in config.ingress_edges_mut() {
        for rule in &mut listener.rules {
            expand_rule_named_sets(rule, &registry, &format!("listener {}", listener.name))?;
        }
        for rule in &mut listener.connection_filter {
            expand_rule_named_sets(
                rule,
                &registry,
                &format!("listener {} connection_filter", listener.name),
            )?;
        }
    }

    for reverse_edge in config.reverse_edges_mut() {
        for rule in &mut reverse_edge.connection_filter {
            expand_rule_named_sets(
                rule,
                &registry,
                &format!("reverse_edge {} connection_filter", reverse_edge.name),
            )?;
        }
        for (idx, route) in reverse_edge.routes.iter_mut().enumerate() {
            expand_match_config(
                &mut route.r#match,
                &registry,
                &format!("reverse_edge {} route[{idx}]", reverse_edge.name),
            )?;
            if let Some(http) = route.http.as_mut() {
                for (rule_idx, response_rule) in http.response_rules.iter_mut().enumerate() {
                    if let Some(match_cfg) = response_rule.r#match.as_mut() {
                        expand_match_config(
                            match_cfg,
                            &registry,
                            &format!(
                                "reverse_edge {} route[{idx}] http.response_rules[{rule_idx}]",
                                reverse_edge.name
                            ),
                        )?;
                    }
                }
            }
        }
        for (idx, route) in reverse_edge.tls_passthrough_routes.iter_mut().enumerate() {
            expand_tls_passthrough_match(
                &mut route.r#match,
                &registry,
                &format!("reverse_edge {} tls_passthrough[{idx}]", reverse_edge.name),
            )?;
        }
    }

    Ok(())
}

fn load_named_set_registry(config: &Config) -> Result<HashMap<String, LoadedNamedSet>> {
    let mut registry = HashMap::new();
    for set in &config.security.named_sets {
        let mut values = Vec::new();
        append_unique_strings(&mut values, set.values.iter().cloned());
        if let Some(path) = set.file.as_deref() {
            let content = fs::read_to_string(path).map_err(|err| {
                anyhow!(
                    "failed to read named set {} from {}: {}",
                    set.name,
                    path,
                    err
                )
            })?;
            append_unique_strings(
                &mut values,
                content
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(str::to_string),
            );
        }
        registry.insert(
            set.name.clone(),
            LoadedNamedSet {
                kind: set.kind.clone(),
                values,
            },
        );
    }
    Ok(registry)
}

fn append_unique_strings(out: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
    let mut seen = out.iter().cloned().collect::<HashSet<_>>();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if seen.insert(value.to_string()) {
            out.push(value.to_string());
        }
    }
}

fn expand_rule_named_sets(
    rule: &mut RuleConfig,
    registry: &HashMap<String, LoadedNamedSet>,
    context: &str,
) -> Result<()> {
    if let Some(match_cfg) = rule.r#match.as_mut() {
        expand_match_config(
            match_cfg,
            registry,
            &format!("{context} rule {}", rule.name),
        )?;
    }
    Ok(())
}

fn expand_match_config(
    match_cfg: &mut MatchConfig,
    registry: &HashMap<String, LoadedNamedSet>,
    context: &str,
) -> Result<()> {
    expand_named_set_patterns(
        &mut match_cfg.src_ip,
        registry,
        &[NamedSetKind::Cidr],
        &format!("{context} match.src_ip"),
    )?;
    expand_named_set_patterns(
        &mut match_cfg.host,
        registry,
        &[
            NamedSetKind::Domain,
            NamedSetKind::String,
            NamedSetKind::Regex,
        ],
        &format!("{context} match.host"),
    )?;
    expand_named_set_patterns(
        &mut match_cfg.sni,
        registry,
        &[
            NamedSetKind::Domain,
            NamedSetKind::String,
            NamedSetKind::Regex,
        ],
        &format!("{context} match.sni"),
    )?;
    expand_named_set_patterns(
        &mut match_cfg.method,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context} match.method"),
    )?;
    expand_named_set_patterns(
        &mut match_cfg.path,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context} match.path"),
    )?;
    expand_named_set_patterns(
        &mut match_cfg.query,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context} match.query"),
    )?;
    expand_named_set_patterns(
        &mut match_cfg.authority,
        registry,
        &[
            NamedSetKind::Domain,
            NamedSetKind::String,
            NamedSetKind::Regex,
        ],
        &format!("{context} match.authority"),
    )?;
    expand_named_set_patterns(
        &mut match_cfg.scheme,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context} match.scheme"),
    )?;
    expand_named_set_patterns(
        &mut match_cfg.http_version,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context} match.http_version"),
    )?;
    expand_named_set_patterns(
        &mut match_cfg.alpn,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context} match.alpn"),
    )?;
    expand_named_set_patterns(
        &mut match_cfg.tls_version,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context} match.tls_version"),
    )?;
    if let Some(destination) = match_cfg.destination.as_mut() {
        if let Some(category) = destination.category.as_mut() {
            expand_named_set_patterns(
                &mut category.value,
                registry,
                &[
                    NamedSetKind::Category,
                    NamedSetKind::String,
                    NamedSetKind::Regex,
                ],
                &format!("{context} match.destination.category.value"),
            )?;
        }
        if let Some(reputation) = destination.reputation.as_mut() {
            expand_named_set_patterns(
                &mut reputation.value,
                registry,
                &[
                    NamedSetKind::Reputation,
                    NamedSetKind::String,
                    NamedSetKind::Regex,
                ],
                &format!("{context} match.destination.reputation.value"),
            )?;
        }
        if let Some(application) = destination.application.as_mut() {
            expand_named_set_patterns(
                &mut application.value,
                registry,
                &[NamedSetKind::String, NamedSetKind::Regex],
                &format!("{context} match.destination.application.value"),
            )?;
        }
    }

    if let Some(identity) = match_cfg.identity.as_mut() {
        expand_identity_match(identity, registry, context)?;
    }
    if let Some(fingerprint) = match_cfg.tls_fingerprint.as_mut() {
        expand_tls_fingerprint_match(fingerprint, registry, context)?;
    }
    if let Some(cert) = match_cfg.client_cert.as_mut() {
        expand_certificate_match(cert, registry, &format!("{context} client_cert"))?;
    }
    if let Some(cert) = match_cfg.upstream_cert.as_mut() {
        expand_certificate_match(cert, registry, &format!("{context} upstream_cert"))?;
    }

    Ok(())
}

fn expand_tls_passthrough_match(
    match_cfg: &mut TlsPassthroughMatchConfig,
    registry: &HashMap<String, LoadedNamedSet>,
    context: &str,
) -> Result<()> {
    expand_named_set_patterns(
        &mut match_cfg.src_ip,
        registry,
        &[NamedSetKind::Cidr],
        &format!("{context} match.src_ip"),
    )?;
    expand_named_set_patterns(
        &mut match_cfg.sni,
        registry,
        &[
            NamedSetKind::Domain,
            NamedSetKind::String,
            NamedSetKind::Regex,
        ],
        &format!("{context} match.sni"),
    )?;
    Ok(())
}

fn expand_identity_match(
    identity: &mut IdentityMatchConfig,
    registry: &HashMap<String, LoadedNamedSet>,
    context: &str,
) -> Result<()> {
    for (label, values) in [
        ("user", &mut identity.user),
        ("groups", &mut identity.groups),
        ("device_id", &mut identity.device_id),
        ("posture", &mut identity.posture),
        ("tenant", &mut identity.tenant),
        ("auth_strength", &mut identity.auth_strength),
        ("idp", &mut identity.idp),
    ] {
        expand_named_set_patterns(
            values,
            registry,
            &[NamedSetKind::String, NamedSetKind::Regex],
            &format!("{context} identity.{label}"),
        )?;
    }
    Ok(())
}

fn expand_tls_fingerprint_match(
    fingerprint: &mut TlsFingerprintMatchConfig,
    registry: &HashMap<String, LoadedNamedSet>,
    context: &str,
) -> Result<()> {
    expand_named_set_patterns(
        &mut fingerprint.ja3,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context} tls_fingerprint.ja3"),
    )?;
    expand_named_set_patterns(
        &mut fingerprint.ja4,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context} tls_fingerprint.ja4"),
    )?;
    Ok(())
}

fn expand_certificate_match(
    cert: &mut CertificateMatchConfig,
    registry: &HashMap<String, LoadedNamedSet>,
    context: &str,
) -> Result<()> {
    expand_named_set_patterns(
        &mut cert.subject,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context}.subject"),
    )?;
    expand_named_set_patterns(
        &mut cert.issuer,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context}.issuer"),
    )?;
    expand_named_set_patterns(
        &mut cert.san_dns,
        registry,
        &[
            NamedSetKind::Domain,
            NamedSetKind::String,
            NamedSetKind::Regex,
        ],
        &format!("{context}.san_dns"),
    )?;
    expand_named_set_patterns(
        &mut cert.san_uri,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context}.san_uri"),
    )?;
    expand_named_set_patterns(
        &mut cert.fingerprint_sha256,
        registry,
        &[NamedSetKind::String, NamedSetKind::Regex],
        &format!("{context}.fingerprint_sha256"),
    )?;
    Ok(())
}

fn expand_named_set_patterns(
    values: &mut Vec<String>,
    registry: &HashMap<String, LoadedNamedSet>,
    allowed: &[NamedSetKind],
    context: &str,
) -> Result<()> {
    let mut expanded = Vec::new();
    for item in std::mem::take(values) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if let Some(name) = named_set_reference(item) {
            let set = registry
                .get(name)
                .ok_or_else(|| anyhow!("{context}: unknown named set reference {item}"))?;
            if !allowed.iter().any(|kind| kind == &set.kind) {
                return Err(anyhow!(
                    "{context}: named set {} has incompatible type {:?}",
                    name,
                    set.kind
                ));
            }
            append_unique_strings(
                &mut expanded,
                set.values.iter().cloned().map(|value| {
                    if matches!(set.kind, NamedSetKind::Regex) {
                        format!("re:{value}")
                    } else {
                        value
                    }
                }),
            );
        } else {
            append_unique_strings(&mut expanded, [item.to_string()]);
        }
    }
    *values = expanded;
    Ok(())
}

fn named_set_reference(raw: &str) -> Option<&str> {
    raw.strip_prefix('@')
        .or_else(|| raw.strip_prefix("set:"))
        .map(str::trim)
        .filter(|name| !name.is_empty())
}
