use crate::http::modules::{HttpModuleRegistry, default_http_module_registry};
use anyhow::Result;
use arc_swap::ArcSwap;
use qpx_core::config::{Config, ReverseEdgeConfig};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};
use tokio::sync::Semaphore;
use tokio::time::Instant as TokioInstant;

pub(crate) mod auth;
mod cache_rt;
mod config_rt;
mod obs_rt;
mod plan;
mod policy_rt;
mod reload;
mod security_rt;
pub mod views;

pub use cache_rt::CacheRuntime;
pub use config_rt::{MessageTexts, RuntimeResources};
pub use obs_rt::ObsRuntime;
pub(crate) use obs_rt::metric_names;
#[cfg(test)]
pub(crate) use plan::CompiledPlaintextCapturePlan;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
pub(crate) use plan::CompiledTlsPassthroughRoute;
pub(crate) use plan::{
    CompiledCapturePlan, CompiledEdge, CompiledListenerSettings, CompiledReverseEdge,
    CompiledReverseRoute, CompiledReverseRouteTarget, ExecutionPlan, PlanFlags,
    ResolvedStreamingLimits,
};
pub(crate) use plan::{PlanCompiler, RuntimePlan};
pub use policy_rt::PolicyRuntime;
pub(crate) use reload::{ensure_hot_reload_compatible, requires_server_restart};
pub use security_rt::SecurityRuntime;
pub use views::{AcceptorView, CacheView, DispatchView, ObservabilityView};

#[cfg(test)]
use config_rt::{expand_named_sets_in_config, expand_upstream_trust_profiles_in_config};

pub(crate) const MAX_TIMER_DURATION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

pub(crate) fn clamp_timer_duration(duration: Duration) -> Duration {
    duration.min(MAX_TIMER_DURATION)
}

pub(crate) fn tokio_deadline_after(duration: Duration) -> TokioInstant {
    let now = TokioInstant::now();
    now.checked_add(clamp_timer_duration(duration))
        .unwrap_or(now)
}

pub(crate) fn std_deadline_after(duration: Duration) -> StdInstant {
    let now = StdInstant::now();
    now.checked_add(clamp_timer_duration(duration))
        .unwrap_or(now)
}

#[derive(Clone)]
pub struct Runtime {
    state: Arc<ArcSwap<RuntimeState>>,
}

#[derive(Clone)]
pub struct RuntimeState {
    pub resources: RuntimeResources,
    pub plan: Arc<RuntimePlan>,
    pub messages: MessageTexts,
    pub ftp_semaphore: Arc<Semaphore>,
    pub connection_semaphore: Arc<Semaphore>,
    pub upstreams: HashMap<String, String>,
    pub security: SecurityRuntime,
    pub policy: PolicyRuntime,
    pub cache: CacheRuntime,
    pub observability: ObsRuntime,
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

    pub fn dispatch_view(&self) -> DispatchView {
        RuntimeState::dispatch_view_from_arc(self.state())
    }

    pub fn acceptor_view(&self) -> AcceptorView {
        RuntimeState::acceptor_view_from_arc(self.state())
    }

    pub fn swap(&self, new_state: RuntimeState) {
        self.state.store(Arc::new(new_state));
    }
}

#[cfg(feature = "acme")]
impl qpx_acme::ConfigProvider for Runtime {
    fn current_operational_config(&self) -> Arc<Config> {
        self.state().resources.operational.clone()
    }
}

impl RuntimeState {
    pub fn compile_plan(config: Config) -> Result<RuntimePlan> {
        Self::compile_plan_with_http_module_registry(config, default_http_module_registry())
    }

    pub fn compile_plan_with_http_module_registry(
        config: Config,
        http_module_registry: Arc<HttpModuleRegistry>,
    ) -> Result<RuntimePlan> {
        let resources =
            RuntimeResources::build_with_http_module_registry(config, http_module_registry)?;
        PlanCompiler { config: &resources }.compile()
    }

    pub fn build(config: Config) -> Result<Self> {
        Self::build_with_http_module_registry(config, default_http_module_registry())
    }

    pub fn build_with_http_module_registry(
        config: Config,
        http_module_registry: Arc<HttpModuleRegistry>,
    ) -> Result<Self> {
        let resources =
            RuntimeResources::build_with_http_module_registry(config, http_module_registry)?;
        #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
        crate::upstream::origin::configure_h3_origin_pool(
            resources
                .operational
                .runtime
                .h3_origin_pool_max_connections_per_origin,
            resources
                .operational
                .runtime
                .h3_origin_pool_max_inflight_streams_per_connection,
        );
        #[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
        crate::forward::h3::configure_qpx_h3_upstream_session_pool(
            resources
                .operational
                .runtime
                .h3_origin_pool_max_connections_per_origin,
            resources
                .operational
                .runtime
                .h3_origin_pool_max_inflight_streams_per_connection,
        );
        let plan = Arc::new(PlanCompiler { config: &resources }.compile()?);
        let security = SecurityRuntime::build(&resources)?;
        let policy = PolicyRuntime::build(&resources)?;
        let cache = CacheRuntime::build(&resources)?;
        let observability = ObsRuntime::build(&resources)?;
        Ok(Self {
            plan,
            messages: resources.messages.clone(),
            ftp_semaphore: resources.ftp_semaphore.clone(),
            connection_semaphore: resources.connection_semaphore.clone(),
            upstreams: resources.upstreams.clone(),
            resources,
            security,
            policy,
            cache,
            observability,
        })
    }

    pub fn dispatch_view_from_arc(state: Arc<Self>) -> DispatchView {
        DispatchView::from_state(state)
    }

    pub fn acceptor_view_from_arc(state: Arc<Self>) -> AcceptorView {
        AcceptorView::from_state(state)
    }

    pub fn cache_view_from_arc(state: Arc<Self>) -> CacheView {
        CacheView::from_state(state)
    }

    pub fn observability_view_from_arc(state: Arc<Self>) -> ObservabilityView {
        ObservabilityView::from_state(state)
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

    pub fn export_session_for_plan(
        &self,
        plan: &ExecutionPlan,
        client: impl ToString,
        server: impl ToString,
    ) -> Option<crate::exporter::ExportSession> {
        let flags = plan.flags;
        if !flags.contains(PlanFlags::CAPTURE_ENCRYPTED)
            && !flags.contains(PlanFlags::CAPTURE_PLAINTEXT)
        {
            return None;
        }
        Some(self.observability.exporter.as_ref()?.session_with_capture(
            client,
            server,
            &plan.capture,
        ))
    }

    pub fn ca_cert_path(&self) -> Option<PathBuf> {
        self.security
            .destination
            .tls
            .ca
            .as_ref()
            .map(|ca| ca.cert_path())
    }

    pub fn ingress_edge_settings(&self, name: &str) -> Option<&CompiledListenerSettings> {
        if let Some(edge) = self.plan.forward_edge(name) {
            return Some(&edge.listener);
        }
        self.plan.transparent_edge(name).map(|edge| &edge.listener)
    }

    pub fn reverse_config(&self, name: &str) -> Option<&ReverseEdgeConfig> {
        self.resources.reverse_config(name)
    }

    pub fn http_module_registry(&self) -> &Arc<HttpModuleRegistry> {
        self.resources.http_module_registry()
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
mod tests;
