use crate::http::modules::HttpModuleRegistry;
use crate::upstream::pool::{UpstreamProxyCluster, build_named_upstream_proxies};
use anyhow::{Result, anyhow};
use qpx_core::config::{
    AccessLogConfig, AuditLogConfig, CapturePolicyConfig, CaptureRedactionConfig, Config,
    ReverseEdgeConfig, UpstreamTlsTrustConfig,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Semaphore;

mod named_sets;

pub(super) use self::named_sets::expand_named_sets_in_config;

#[derive(Clone)]
pub struct RuntimeResources {
    pub operational: Arc<Config>,
    pub messages: MessageTexts,
    pub access_log: AccessLogConfig,
    pub audit_log: AuditLogConfig,
    reverse_indices: HashMap<String, usize>,
    pub ftp_semaphore: Arc<Semaphore>,
    pub connection_semaphore: Arc<Semaphore>,
    pub upstreams: HashMap<String, String>,
    pub(crate) upstream_proxies: HashMap<String, Arc<UpstreamProxyCluster>>,
    pub(crate) http_module_registry: Arc<HttpModuleRegistry>,
}

impl RuntimeResources {
    pub(super) fn build_with_http_module_registry(
        mut config: Config,
        http_module_registry: Arc<HttpModuleRegistry>,
    ) -> Result<Self> {
        expand_upstream_trust_profiles_in_config(&mut config)?;
        expand_named_sets_in_config(&mut config)?;
        let operational = Arc::new(config);
        let mut reverse_indices = HashMap::new();
        for (idx, reverse_edge) in operational.reverse_edge_configs().iter().enumerate() {
            reverse_indices.insert(reverse_edge.name.clone(), idx);
        }

        let messages = MessageTexts::from_config(operational.as_ref());
        let ftp_semaphore = Arc::new(Semaphore::new(operational.runtime.max_ftp_concurrency));
        let connection_semaphore = Arc::new(Semaphore::new(
            operational.runtime.max_concurrent_connections,
        ));
        let upstreams = operational
            .upstreams
            .iter()
            .map(|u| (u.name.clone(), u.url.clone()))
            .collect();
        let upstream_proxies = build_named_upstream_proxies(operational.upstreams.as_slice())?;
        let access_log = access_log_with_observability_redaction(operational.as_ref());
        Ok(Self {
            operational: operational.clone(),
            messages,
            access_log,
            audit_log: operational.telemetry.audit_log.clone(),
            reverse_indices,
            ftp_semaphore,
            connection_semaphore,
            upstreams,
            upstream_proxies,
            http_module_registry,
        })
    }

    pub(super) fn reverse_config(&self, name: &str) -> Option<&ReverseEdgeConfig> {
        let idx = *self.reverse_indices.get(name)?;
        self.operational.reverse_edges().nth(idx)
    }

    pub(super) fn http_module_registry(&self) -> &Arc<HttpModuleRegistry> {
        &self.http_module_registry
    }
}

fn access_log_with_observability_redaction(config: &Config) -> AccessLogConfig {
    let mut access = config.telemetry.access_log.clone();
    access.redact.query_keys = observability_query_redaction_keys(config);
    access
}

fn observability_query_redaction_keys(config: &Config) -> Vec<String> {
    let mut keys = BTreeSet::new();
    extend_query_keys(
        &mut keys,
        CaptureRedactionConfig::default().query_keys.iter(),
    );
    extend_query_keys(
        &mut keys,
        config.telemetry.access_log.redact.query_keys.iter(),
    );
    if let Some(otel) = config.telemetry.otel.as_ref() {
        extend_query_keys(&mut keys, otel.redact.query_keys.iter());
    }
    if let Some(exporter) = config.telemetry.exporter.as_ref() {
        extend_query_keys(&mut keys, exporter.capture.redact.query_keys.iter());
    }
    for edge in config.ingress_edge_configs() {
        if let Some(capture) = edge.capture.as_ref() {
            extend_capture_query_keys(&mut keys, capture);
        }
    }
    for edge in config.reverse_edge_configs() {
        for route in &edge.routes {
            if let Some(capture) = route.capture.as_ref() {
                extend_capture_query_keys(&mut keys, capture);
            }
        }
    }
    keys.into_iter().collect()
}

fn extend_capture_query_keys(keys: &mut BTreeSet<String>, capture: &CapturePolicyConfig) {
    extend_query_keys(keys, capture.plaintext.redact.query_keys.iter());
}

fn extend_query_keys<'a>(keys: &mut BTreeSet<String>, values: impl Iterator<Item = &'a String>) {
    for key in values {
        keys.insert(key.to_ascii_lowercase());
    }
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
    if config.security.upstream_trust_profiles.is_empty() {
        return Ok(());
    }

    let registry = config
        .security
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

    for listener in config.ingress_edges_mut() {
        if let Some(tls) = listener.tls_inspection.as_mut() {
            tls.upstream_trust = merge_upstream_trust_profile(
                tls.upstream_trust_profile.as_deref(),
                tls.upstream_trust.take(),
                &registry,
                &format!("listener {} tls_inspection", listener.name),
            )?;
        }
    }

    for reverse_edge in config.reverse_edges_mut() {
        for (idx, route) in reverse_edge.routes.iter_mut().enumerate() {
            route.upstream_trust = merge_upstream_trust_profile(
                route.upstream_trust_profile.as_deref(),
                route.upstream_trust.take(),
                &registry,
                &format!("reverse_edge {} route[{idx}]", reverse_edge.name),
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
