use crate::http::modules::{compile_http_modules, CompiledHttpModuleChain, HttpModuleRegistry};
use crate::upstream::pool::{build_named_upstream_proxies, UpstreamProxyCluster};
use anyhow::{anyhow, Result};
use qpx_core::config::{
    CertificateMatchConfig, Config, IdentityMatchConfig, ListenerConfig, MatchConfig, NamedSetKind,
    ReverseConfig, RuleConfig, TlsFingerprintMatchConfig, TlsPassthroughMatchConfig,
    UpstreamTlsTrustConfig,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct ConfigRuntime {
    pub raw: Arc<Config>,
    pub messages: MessageTexts,
    listener_indices: HashMap<String, usize>,
    reverse_indices: HashMap<String, usize>,
    pub ftp_semaphore: Arc<Semaphore>,
    pub connection_semaphore: Arc<Semaphore>,
    pub upstreams: HashMap<String, String>,
    pub(crate) upstream_proxies: HashMap<String, Arc<UpstreamProxyCluster>>,
    pub(crate) http_modules_by_listener: HashMap<String, Arc<CompiledHttpModuleChain>>,
    pub(crate) http_module_registry: Arc<HttpModuleRegistry>,
}

impl Deref for ConfigRuntime {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        self.raw.as_ref()
    }
}

impl ConfigRuntime {
    pub(super) fn build_with_http_module_registry(
        mut config: Config,
        http_module_registry: Arc<HttpModuleRegistry>,
    ) -> Result<Self> {
        expand_upstream_trust_profiles_in_config(&mut config)?;
        expand_named_sets_in_config(&mut config)?;
        let raw = Arc::new(config);
        let mut listener_indices = HashMap::new();
        let mut reverse_indices = HashMap::new();
        for (idx, listener) in raw.listeners.iter().enumerate() {
            listener_indices.insert(listener.name.clone(), idx);
        }
        for (idx, reverse) in raw.reverse.iter().enumerate() {
            reverse_indices.insert(reverse.name.clone(), idx);
        }

        let messages = MessageTexts::from_config(raw.as_ref());
        let ftp_semaphore = Arc::new(Semaphore::new(raw.runtime.max_ftp_concurrency));
        let connection_semaphore = Arc::new(Semaphore::new(raw.runtime.max_concurrent_connections));
        let upstreams = raw
            .upstreams
            .iter()
            .map(|u| (u.name.clone(), u.url.clone()))
            .collect();
        let upstream_proxies = build_named_upstream_proxies(raw.upstreams.as_slice())?;
        let http_modules_by_listener = raw
            .listeners
            .iter()
            .map(|listener| {
                Ok((
                    listener.name.clone(),
                    compile_http_modules(
                        listener.http_modules.as_slice(),
                        http_module_registry.as_ref(),
                    )?,
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        Ok(Self {
            raw,
            messages,
            listener_indices,
            reverse_indices,
            ftp_semaphore,
            connection_semaphore,
            upstreams,
            upstream_proxies,
            http_modules_by_listener,
            http_module_registry,
        })
    }

    pub(super) fn listener_config(&self, name: &str) -> Option<&ListenerConfig> {
        let idx = *self.listener_indices.get(name)?;
        self.raw.listeners.get(idx)
    }

    pub(super) fn reverse_config(&self, name: &str) -> Option<&ReverseConfig> {
        let idx = *self.reverse_indices.get(name)?;
        self.raw.reverse.get(idx)
    }

    pub(super) fn listener_http_modules(
        &self,
        name: &str,
    ) -> Option<&Arc<CompiledHttpModuleChain>> {
        self.http_modules_by_listener.get(name)
    }

    pub(super) fn http_module_registry(&self) -> &Arc<HttpModuleRegistry> {
        &self.http_module_registry
    }
}

#[derive(Debug, Clone)]
struct LoadedNamedSet {
    kind: NamedSetKind,
    values: Vec<String>,
}

pub(super) fn expand_named_sets_in_config(config: &mut Config) -> Result<()> {
    let registry = load_named_set_registry(config)?;
    if registry.is_empty() {
        return Ok(());
    }

    for listener in &mut config.listeners {
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

    for reverse in &mut config.reverse {
        for rule in &mut reverse.connection_filter {
            expand_rule_named_sets(
                rule,
                &registry,
                &format!("reverse {} connection_filter", reverse.name),
            )?;
        }
        for (idx, route) in reverse.routes.iter_mut().enumerate() {
            expand_match_config(
                &mut route.r#match,
                &registry,
                &format!("reverse {} route[{idx}]", reverse.name),
            )?;
            if let Some(http) = route.http.as_mut() {
                for (rule_idx, response_rule) in http.response_rules.iter_mut().enumerate() {
                    if let Some(match_cfg) = response_rule.r#match.as_mut() {
                        expand_match_config(
                            match_cfg,
                            &registry,
                            &format!(
                                "reverse {} route[{idx}] http.response_rules[{rule_idx}]",
                                reverse.name
                            ),
                        )?;
                    }
                }
            }
        }
        for (idx, route) in reverse.tls_passthrough_routes.iter_mut().enumerate() {
            expand_tls_passthrough_match(
                &mut route.r#match,
                &registry,
                &format!("reverse {} tls_passthrough[{idx}]", reverse.name),
            )?;
        }
    }

    Ok(())
}

fn load_named_set_registry(config: &Config) -> Result<HashMap<String, LoadedNamedSet>> {
    let mut registry = HashMap::new();
    for set in &config.named_sets {
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

pub(super) fn expand_upstream_trust_profiles_in_config(config: &mut Config) -> Result<()> {
    if config.upstream_trust_profiles.is_empty() {
        return Ok(());
    }

    let registry = config
        .upstream_trust_profiles
        .iter()
        .map(|profile| (profile.name.clone(), profile.trust.clone()))
        .collect::<HashMap<_, _>>();

    for upstream in &mut config.upstreams {
        upstream.tls_trust = merge_upstream_trust_profile(
            upstream.tls_trust_profile.as_deref(),
            upstream.tls_trust.take(),
            &registry,
            &format!("upstream {}", upstream.name),
        )?;
    }

    for listener in &mut config.listeners {
        if let Some(tls) = listener.tls_inspection.as_mut() {
            tls.upstream_trust = merge_upstream_trust_profile(
                tls.upstream_trust_profile.as_deref(),
                tls.upstream_trust.take(),
                &registry,
                &format!("listener {} tls_inspection", listener.name),
            )?;
        }
    }

    for reverse in &mut config.reverse {
        for (idx, route) in reverse.routes.iter_mut().enumerate() {
            route.upstream_trust = merge_upstream_trust_profile(
                route.upstream_trust_profile.as_deref(),
                route.upstream_trust.take(),
                &registry,
                &format!("reverse {} route[{idx}]", reverse.name),
            )?;
        }
    }

    Ok(())
}

fn merge_upstream_trust_profile(
    profile: Option<&str>,
    inline: Option<UpstreamTlsTrustConfig>,
    registry: &HashMap<String, UpstreamTlsTrustConfig>,
    context: &str,
) -> Result<Option<UpstreamTlsTrustConfig>> {
    let Some(profile_name) = profile.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(inline);
    };
    let base = registry.get(profile_name).cloned().ok_or_else(|| {
        anyhow!("{context} references unknown upstream_trust_profile: {profile_name}")
    })?;
    let Some(inline) = inline else {
        return Ok(Some(base));
    };

    let mut merged = base;
    append_unique_strings(&mut merged.pin_sha256, inline.pin_sha256);
    append_unique_strings(&mut merged.issuer, inline.issuer);
    append_unique_strings(&mut merged.san_dns, inline.san_dns);
    append_unique_strings(&mut merged.san_uri, inline.san_uri);
    if inline.client_cert.is_some() || inline.client_key.is_some() {
        merged.client_cert = inline.client_cert;
        merged.client_key = inline.client_key;
    }
    Ok(Some(merged))
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

#[derive(Clone)]
pub struct MessageTexts {
    pub blocked: String,
    pub forbidden: String,
    pub trace_disabled: String,
    pub proxy_error: String,
    pub proxy_auth_required: String,
    pub reverse_error: String,
    pub cache_miss: String,
    pub unsupported_ftp_method: String,
    pub ftp_disabled: String,
    #[cfg(feature = "http3")]
    pub connect_udp_disabled: String,
    #[cfg(feature = "http3")]
    pub upstream_connect_udp_failed: String,
}

impl MessageTexts {
    fn from_config(config: &Config) -> Self {
        Self {
            blocked: config.messages.blocked.clone(),
            forbidden: config.messages.forbidden.clone(),
            trace_disabled: config.messages.trace_disabled.clone(),
            proxy_error: config.messages.proxy_error.clone(),
            proxy_auth_required: config.messages.proxy_auth_required.clone(),
            reverse_error: config.messages.reverse_error.clone(),
            cache_miss: config.messages.cache_miss.clone(),
            unsupported_ftp_method: config.messages.unsupported_ftp_method.clone(),
            ftp_disabled: config.messages.ftp_disabled.clone(),
            #[cfg(feature = "http3")]
            connect_udp_disabled: config.messages.connect_udp_disabled.clone(),
            #[cfg(feature = "http3")]
            upstream_connect_udp_failed: config.messages.upstream_connect_udp_failed.clone(),
        }
    }
}
