use super::{ConfigReloadHandler, emit_config_reload_audit};
use crate::{
    ProxyTasks, log_runtime_ready, refresh_watches, runtime, tcp_bindings, udp_bindings,
    validate_runtime_state,
};
use anyhow::Result;
use qpx_core::config::Config as ProxyConfig;
use std::collections::HashSet;
use std::path::PathBuf;
use tracing::{info, warn};

pub(super) struct RestartReloadInput<'a> {
    pub(super) current: &'a mut ProxyConfig,
    pub(super) runtime: &'a mut runtime::Runtime,
    pub(super) proxy: &'a mut ProxyTasks,
    pub(super) watcher: &'a mut dyn notify::Watcher,
    pub(super) watched: &'a mut HashSet<PathBuf>,
    pub(super) watch_sources: Vec<PathBuf>,
    pub(super) new_config: ProxyConfig,
}

impl ConfigReloadHandler {
    pub(super) async fn apply_restart_reload(&self, input: RestartReloadInput<'_>) -> Result<()> {
        let RestartReloadInput {
            current,
            runtime,
            proxy,
            watcher,
            watched,
            watch_sources,
            new_config,
        } = input;
        let new_runtime = match runtime::Runtime::with_http_module_registry(
            new_config.clone(),
            self.http_module_registry.clone(),
        ) {
            Ok(runtime) => runtime,
            Err(err) => {
                warn!(error = ?err, "config reload failed");
                emit_config_reload_audit(
                    "failed",
                    None,
                    None,
                    self.configs_display.as_str(),
                    Some(&err),
                );
                return Ok(());
            }
        };

        let next_state = new_runtime.state();
        if let Err(err) = validate_runtime_state(next_state.as_ref()) {
            warn!(error = ?err, "config reload reverse compile failed");
            emit_config_reload_audit(
                "failed",
                None,
                Some("reverse_compile_error"),
                self.configs_display.as_str(),
                Some(&err),
            );
            return Ok(());
        }

        let tcp_bindings = match tcp_bindings::TcpBindings::bind_for_hot_reload(
            &new_config,
            current,
            proxy.tcp_bindings(),
        ) {
            Ok(bindings) => bindings,
            Err(err) => {
                warn!(error = ?err, "config reload bind failed");
                return Ok(());
            }
        };
        let udp_bindings = match udp_bindings::UdpBindings::bind_for_hot_reload(
            &new_config,
            current,
            proxy.udp_bindings(),
        ) {
            Ok(bindings) => bindings,
            Err(err) => {
                warn!(error = ?err, "config reload udp bind failed");
                return Ok(());
            }
        };

        let old_upstream_limit = current.runtime.upstream_proxy_max_concurrent_per_endpoint;
        crate::upstream::pool::set_upstream_proxy_max_concurrent_per_endpoint(
            next_state
                .plan
                .limits
                .upstream_proxy_max_concurrent_per_endpoint,
        );
        let new_proxy = match ProxyTasks::start(
            &new_config,
            new_runtime.clone(),
            tcp_bindings,
            udp_bindings,
            None,
            #[cfg(feature = "http3")]
            None,
        ) {
            Ok(tasks) => tasks,
            Err(err) => {
                crate::upstream::pool::set_upstream_proxy_max_concurrent_per_endpoint(
                    old_upstream_limit,
                );
                warn!(error = ?err, "config reload start failed; keeping old proxy tasks");
                return Ok(());
            }
        };

        let old_proxy = std::mem::replace(proxy, new_proxy);
        if let Err(err) = old_proxy.stop_all().await {
            warn!(error = ?err, "old proxy tasks failed while draining after reload");
        }
        crate::upstream::origin::clear_direct_origin_connection_pools();
        log_runtime_ready(&new_runtime);
        let _ = refresh_watches(watcher, watched, watch_sources);
        info!("config reloaded; listener/reverse server set restarted");
        emit_config_reload_audit(
            "applied",
            Some("restart"),
            None,
            self.configs_display.as_str(),
            None,
        );
        *current = new_config;
        *runtime = new_runtime;
        Ok(())
    }
}
