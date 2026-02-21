use crate::cache::CacheBackend;
use crate::exporter::{ExportSession, ExporterSink};
use crate::rate_limit::RateLimiters;
use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use qpx_core::auth::Authenticator;
use qpx_core::config::{Config, ListenerConfig, ReverseConfig, XdpConfig};
use qpx_core::rules::RuleEngine;
use qpx_core::tls::CaStore;
#[cfg(feature = "mitm")]
use qpx_core::tls::{load_or_generate_ca, MitmConfig};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct Runtime {
    state: Arc<ArcSwap<RuntimeState>>,
}

#[derive(Clone)]
pub struct RuntimeState {
    pub config: Arc<Config>,
    pub metric_names: MetricNames,
    pub messages: MessageTexts,
    listener_indices: HashMap<String, usize>,
    pub rules_by_listener: HashMap<String, RuleEngine>,
    pub rate_limiters: RateLimiters,
    #[cfg(feature = "mitm")]
    tls_verify_exception_sets: HashMap<String, globset::GlobSet>,
    pub auth: Arc<Authenticator>,
    pub ca: Option<CaStore>,
    #[cfg(feature = "mitm")]
    pub mitm: Option<MitmConfig>,
    pub exporter: Option<ExporterSink>,
    pub ftp_semaphore: Arc<Semaphore>,
    pub connection_semaphore: Arc<Semaphore>,
    pub upstreams: HashMap<String, String>,
    pub cache_backends: HashMap<String, Arc<dyn CacheBackend>>,
}

impl Runtime {
    pub fn new(config: Config) -> Result<Self> {
        let state = Arc::new(RuntimeState::build(config)?);
        Ok(Self {
            state: Arc::new(ArcSwap::from(state)),
        })
    }

    pub fn state(&self) -> Arc<RuntimeState> {
        self.state.load_full()
    }

    pub fn swap(&self, new_state: RuntimeState) {
        self.state.store(Arc::new(new_state));
    }
}

impl RuntimeState {
    pub fn build(config: Config) -> Result<Self> {
        let config = Arc::new(config);
        let mut rules_by_listener = HashMap::new();
        let mut listener_indices = HashMap::new();
        #[cfg(feature = "mitm")]
        let mut tls_verify_exception_sets = HashMap::new();
        for (idx, listener) in config.listeners.iter().enumerate() {
            let engine = RuleEngine::new(listener.rules.clone(), listener.default_action.clone())?;
            rules_by_listener.insert(listener.name.clone(), engine);
            listener_indices.insert(listener.name.clone(), idx);
            #[cfg(feature = "mitm")]
            {
                if let Some(tls) = listener.tls_inspection.as_ref() {
                    if !tls.verify_exceptions.is_empty() {
                        let mut builder = globset::GlobSetBuilder::new();
                        for pattern in &tls.verify_exceptions {
                            builder.add(globset::Glob::new(pattern)?);
                        }
                        tls_verify_exception_sets.insert(listener.name.clone(), builder.build()?);
                    }
                }
            }
        }

        let auth = Arc::new(Authenticator::new(
            &config.auth,
            config.identity.auth_realm.as_str(),
        )?);
        let metric_names = MetricNames::from_prefix(config.identity.metrics_prefix.as_str());
        let messages = MessageTexts::from_config(config.as_ref());
        let rate_limiters = RateLimiters::from_config(config.listeners.as_slice());

        #[cfg(feature = "mitm")]
        let state_dir = config
            .state_dir
            .as_deref()
            .map(expand_tilde)
            .unwrap_or_else(|| PathBuf::from(".qpx"));

        #[cfg(feature = "mitm")]
        let (ca, mitm) = if any_tls_inspection_enabled(&config.listeners) {
            let ca = Some(load_or_generate_ca(&state_dir)?);
            let mitm = Some(ca.as_ref().expect("ca").mitm_config()?);
            (ca, mitm)
        } else {
            (None, None)
        };

        #[cfg(not(feature = "mitm"))]
        let ca = None;

        let exporter = match &config.exporter {
            Some(cfg) if cfg.enabled => Some(ExporterSink::from_config(cfg)?),
            _ => None,
        };

        let ftp_semaphore = Arc::new(Semaphore::new(config.runtime.max_ftp_concurrency));
        let connection_semaphore =
            Arc::new(Semaphore::new(config.runtime.max_concurrent_connections));

        let upstreams = config
            .upstreams
            .iter()
            .map(|u| (u.name.clone(), u.url.clone()))
            .collect();
        let cache_backends = crate::cache::build_backends(
            &config.cache.backends,
            config.identity.generated_user_agent.as_deref(),
        )?;

        Ok(Self {
            config,
            metric_names,
            messages,
            listener_indices,
            rules_by_listener,
            rate_limiters,
            #[cfg(feature = "mitm")]
            tls_verify_exception_sets,
            auth,
            ca,
            #[cfg(feature = "mitm")]
            mitm,
            exporter,
            ftp_semaphore,
            connection_semaphore,
            upstreams,
            cache_backends,
        })
    }

    pub fn export_session(
        &self,
        client: impl ToString,
        server: impl ToString,
    ) -> Option<ExportSession> {
        Some(self.exporter.as_ref()?.session(client, server))
    }

    pub fn ca_cert_path(&self) -> Option<PathBuf> {
        self.ca.as_ref().map(|ca| ca.cert_path())
    }

    pub fn listener_config(&self, name: &str) -> Option<&ListenerConfig> {
        let idx = *self.listener_indices.get(name)?;
        self.config.listeners.get(idx)
    }

    #[cfg(feature = "mitm")]
    pub fn tls_verify_exception_matches(&self, listener: &str, host: &str) -> bool {
        self.tls_verify_exception_sets
            .get(listener)
            .map(|set| set.is_match(host))
            .unwrap_or(false)
    }
}

#[derive(Clone)]
pub struct MetricNames {
    pub forward_requests_total: String,
    pub forward_latency_ms: String,
    pub reverse_local_response_total: String,
    pub reverse_upstream_latency_ms: String,
    pub reverse_requests_total: String,
    pub reverse_upstreams_unhealthy: String,
    pub transparent_requests_total: String,
    pub transparent_latency_ms: String,
}

impl MetricNames {
    fn from_prefix(prefix: &str) -> Self {
        Self {
            forward_requests_total: format!("{}_forward_requests_total", prefix),
            forward_latency_ms: format!("{}_forward_latency_ms", prefix),
            reverse_local_response_total: format!("{}_reverse_local_response_total", prefix),
            reverse_upstream_latency_ms: format!("{}_reverse_upstream_latency_ms", prefix),
            reverse_requests_total: format!("{}_reverse_requests_total", prefix),
            reverse_upstreams_unhealthy: format!("{}_reverse_upstreams_unhealthy", prefix),
            transparent_requests_total: format!("{}_transparent_requests_total", prefix),
            transparent_latency_ms: format!("{}_transparent_latency_ms", prefix),
        }
    }
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

#[cfg(feature = "mitm")]
fn any_tls_inspection_enabled(listeners: &[ListenerConfig]) -> bool {
    listeners.iter().any(|l| {
        l.tls_inspection
            .as_ref()
            .map(|t| t.enabled)
            .unwrap_or(false)
    })
}

#[cfg(feature = "mitm")]
pub fn expand_tilde(input: &str) -> PathBuf {
    if let Some(stripped) = input.strip_prefix("~/") {
        if let Some(home) = dirs_next::home_dir() {
            return home.join(stripped);
        }
    }
    PathBuf::from(input)
}

pub fn ensure_hot_reload_compatible(old: &Config, new: &Config) -> Result<()> {
    if old.state_dir != new.state_dir {
        return Err(anyhow!("state_dir changed; restart required"));
    }
    if old.system_log != new.system_log {
        return Err(anyhow!("system_log changed; restart required"));
    }
    if old.access_log != new.access_log {
        return Err(anyhow!("access_log changed; restart required"));
    }
    if old.audit_log != new.audit_log {
        return Err(anyhow!("audit_log changed; restart required"));
    }
    if old.otel != new.otel {
        return Err(anyhow!("otel changed; restart required"));
    }
    if old.metrics != new.metrics {
        return Err(anyhow!("metrics listener config changed; restart required"));
    }
    if old.identity.metrics_prefix != new.identity.metrics_prefix {
        return Err(anyhow!("identity.metrics_prefix changed; restart required"));
    }
    if runtime_startup_signature(&old.runtime) != runtime_startup_signature(&new.runtime) {
        return Err(anyhow!("runtime startup tuning changed; restart required"));
    }

    if old.listeners.len() != new.listeners.len() {
        return Err(anyhow!("listener set changed; restart required"));
    }
    for (old_listener, new_listener) in old.listeners.iter().zip(new.listeners.iter()) {
        if old_listener.name != new_listener.name
            || old_listener.listen != new_listener.listen
            || listener_mode_tag(old_listener) != listener_mode_tag(new_listener)
            || listener_http3_signature(old_listener) != listener_http3_signature(new_listener)
            || listener_xdp_signature(old_listener) != listener_xdp_signature(new_listener)
        {
            return Err(anyhow!(
                "listener topology changed for {}; restart required",
                old_listener.name
            ));
        }
    }

    if old.reverse.len() != new.reverse.len() {
        return Err(anyhow!("reverse set changed; restart required"));
    }
    for (old_reverse, new_reverse) in old.reverse.iter().zip(new.reverse.iter()) {
        if old_reverse.name != new_reverse.name || old_reverse.listen != new_reverse.listen {
            return Err(anyhow!(
                "reverse topology changed for {}; restart required",
                old_reverse.name
            ));
        }
        if reverse_startup_signature(old_reverse) != reverse_startup_signature(new_reverse) {
            return Err(anyhow!(
                "reverse startup settings changed for {}; restart required",
                old_reverse.name
            ));
        }
    }

    Ok(())
}

fn runtime_startup_signature(
    runtime: &qpx_core::config::RuntimeConfig,
) -> (Option<usize>, Option<usize>, Option<usize>, bool, i32) {
    (
        runtime.worker_threads,
        runtime.max_blocking_threads,
        runtime.acceptor_tasks_per_listener,
        runtime.reuse_port,
        runtime.tcp_backlog,
    )
}

fn listener_mode_tag(listener: &ListenerConfig) -> &'static str {
    match listener.mode {
        qpx_core::config::ListenerMode::Forward => "forward",
        qpx_core::config::ListenerMode::Transparent => "transparent",
    }
}

type XdpSignature = (bool, String, bool, Vec<String>);
type ReverseHttp3Signature = (String, Vec<String>, usize, u64, u64, usize, u32);
type ReverseStartupSignature = (
    bool,
    XdpSignature,
    Option<ReverseHttp3Signature>,
    Option<qpx_core::config::ReverseTlsConfig>,
);

fn listener_http3_signature(
    listener: &ListenerConfig,
) -> (
    bool,
    Option<String>,
    Option<qpx_core::config::ConnectUdpConfig>,
) {
    match listener.http3.as_ref() {
        Some(cfg) => (cfg.enabled, cfg.listen.clone(), cfg.connect_udp.clone()),
        None => (false, None, None),
    }
}

fn listener_xdp_signature(listener: &ListenerConfig) -> XdpSignature {
    xdp_signature(listener.xdp.as_ref())
}

fn reverse_startup_signature(reverse: &ReverseConfig) -> ReverseStartupSignature {
    let tls_enabled = reverse.tls.is_some();
    let xdp = xdp_signature(reverse.xdp.as_ref());
    let http3 = reverse_http3_signature(reverse);
    let h3_terminate_uses_tls = http3
        .as_ref()
        .map(|(_, passthrough_upstreams, ..)| passthrough_upstreams.is_empty())
        .unwrap_or(false);
    let h3_tls = if h3_terminate_uses_tls {
        reverse.tls.clone()
    } else {
        None
    };
    (tls_enabled, xdp, http3, h3_tls)
}

fn reverse_http3_signature(reverse: &ReverseConfig) -> Option<ReverseHttp3Signature> {
    let cfg = reverse.http3.as_ref()?;
    if !cfg.enabled {
        return None;
    }
    let listen = cfg.listen.clone().unwrap_or_else(|| reverse.listen.clone());
    Some((
        listen,
        cfg.passthrough_upstreams.clone(),
        cfg.passthrough_max_sessions,
        cfg.passthrough_idle_timeout_secs,
        cfg.passthrough_max_new_sessions_per_sec,
        cfg.passthrough_min_client_bytes,
        cfg.passthrough_max_amplification,
    ))
}

fn xdp_signature(xdp: Option<&XdpConfig>) -> XdpSignature {
    match xdp {
        Some(xdp) => (
            xdp.enabled,
            xdp.metadata_mode.clone(),
            xdp.require_metadata,
            xdp.trusted_peers.clone(),
        ),
        None => (false, String::new(), false, Vec::new()),
    }
}
