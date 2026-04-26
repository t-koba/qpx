use crate::http::modules::{default_http_module_registry, HttpModuleRegistry};
use anyhow::Result;
use arc_swap::ArcSwap;
use qpx_core::config::{Config, ListenerConfig, ReverseConfig};
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "runtime/cache_rt.rs"]
mod cache_rt;
#[path = "runtime/config_rt.rs"]
mod config_rt;
#[path = "runtime/obs_rt.rs"]
mod obs_rt;
#[path = "runtime/policy_rt.rs"]
mod policy_rt;
#[path = "runtime/reload.rs"]
mod reload;
#[path = "runtime/security_rt.rs"]
mod security_rt;

use cache_rt::CacheRuntime;
use config_rt::ConfigRuntime;
pub(crate) use obs_rt::metric_names;
use obs_rt::ObsRuntime;
use policy_rt::PolicyRuntime;
pub use reload::{ensure_hot_reload_compatible, requires_server_restart};
use security_rt::SecurityRuntime;

#[cfg(test)]
use config_rt::{expand_named_sets_in_config, expand_upstream_trust_profiles_in_config};

#[derive(Clone)]
pub struct Runtime {
    state: Arc<ArcSwap<RuntimeState>>,
}

#[derive(Clone)]
pub struct RuntimeState {
    pub config: ConfigRuntime,
    pub security: SecurityRuntime,
    pub policy: PolicyRuntime,
    pub cache: CacheRuntime,
    pub observability: ObsRuntime,
}

impl Deref for RuntimeState {
    type Target = ConfigRuntime;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl Runtime {
    pub fn new(config: Config) -> Result<Self> {
        Self::with_http_module_registry(config, default_http_module_registry())
    }

    pub fn with_http_module_registry(
        config: Config,
        http_module_registry: Arc<HttpModuleRegistry>,
    ) -> Result<Self> {
        let state = Arc::new(RuntimeState::build_with_http_module_registry(
            config,
            http_module_registry,
        )?);
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

#[cfg(feature = "acme")]
impl qpx_acme::ConfigProvider for Runtime {
    fn current_config(&self) -> Arc<Config> {
        self.state().config.raw.clone()
    }
}

impl RuntimeState {
    pub fn build(config: Config) -> Result<Self> {
        Self::build_with_http_module_registry(config, default_http_module_registry())
    }

    pub fn build_with_http_module_registry(
        config: Config,
        http_module_registry: Arc<HttpModuleRegistry>,
    ) -> Result<Self> {
        let config = ConfigRuntime::build_with_http_module_registry(config, http_module_registry)?;
        let security = SecurityRuntime::build(&config)?;
        let policy = PolicyRuntime::build(&config)?;
        let cache = CacheRuntime::build(&config)?;
        let observability = ObsRuntime::build(&config)?;
        Ok(Self {
            config,
            security,
            policy,
            cache,
            observability,
        })
    }

    pub fn export_session(
        &self,
        client: impl ToString,
        server: impl ToString,
    ) -> Option<crate::exporter::ExportSession> {
        Some(
            self.observability
                .exporter
                .as_ref()?
                .session(client, server),
        )
    }

    pub fn ca_cert_path(&self) -> Option<PathBuf> {
        self.security.ca.as_ref().map(|ca| ca.cert_path())
    }

    pub fn listener_config(&self, name: &str) -> Option<&ListenerConfig> {
        self.config.listener_config(name)
    }

    pub(crate) fn listener_http_modules(
        &self,
        name: &str,
    ) -> Option<&Arc<crate::http::modules::CompiledHttpModuleChain>> {
        self.config.listener_http_modules(name)
    }

    pub fn reverse_config(&self, name: &str) -> Option<&ReverseConfig> {
        self.config.reverse_config(name)
    }

    pub fn http_module_registry(&self) -> &Arc<HttpModuleRegistry> {
        self.config.http_module_registry()
    }

    pub(crate) fn classify_destination(
        &self,
        inputs: &crate::destination::DestinationInputs<'_>,
        resolution_override: Option<&qpx_core::config::DestinationResolutionOverrideConfig>,
    ) -> crate::destination::DestinationMetadata {
        let policy = self
            .policy
            .destination_resolution_defaults
            .with_override(resolution_override);
        self.policy.destination_classifier.classify(inputs, &policy)
    }

    pub(crate) fn http_guard_profile(
        &self,
        name: &str,
    ) -> Option<&Arc<crate::http::guard::CompiledHttpGuardProfile>> {
        self.policy.http_guard_profiles.get(name)
    }

    pub fn tls_verify_exception_matches(&self, listener: &str, host: &str) -> bool {
        #[cfg(feature = "mitm")]
        {
            self.security.tls_verify_exception_matches(listener, host)
        }
        #[cfg(not(feature = "mitm"))]
        {
            let _ = listener;
            let _ = host;
            false
        }
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
