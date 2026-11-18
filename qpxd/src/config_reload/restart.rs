use super::{ConfigReloadHandler, emit_config_reload_audit};
use crate::server::ProxyTasks;
use crate::startup::{log_runtime_ready, validate_runtime_state};
use crate::{runtime, tcp_bindings, udp_bindings};
use qpx_core::config::Config as ProxyConfig;
use tracing::{info, warn};

impl ConfigReloadHandler {
    pub(super) async fn apply_restart_reload(
        &self,
        current: &mut ProxyConfig,
        runtime: &mut runtime::Runtime,
        proxy: &mut ProxyTasks,
        new_config: ProxyConfig,
    ) -> bool {
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
                return false;
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
            return false;
        }

        let tcp_bindings = match tcp_bindings::TcpBindings::bind_for_hot_reload(
            &new_config,
            current,
            proxy.tcp_bindings(),
        ) {
            Ok(bindings) => bindings,
            Err(err) => {
                warn!(error = ?err, "config reload bind failed");
                return false;
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
                return false;
            }
        };

        // Pool limits are owned per-runtime: `new_runtime`'s `PoolRegistry` already has
        // the new config's limits applied at build time, so no global toggle is needed.
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
                warn!(error = ?err, "config reload start failed; keeping old proxy tasks");
                return false;
            }
        };

        let old_proxy = std::mem::replace(proxy, new_proxy);
        if let Err(err) = old_proxy.stop_all().await {
            warn!(error = ?err, "old proxy tasks failed while draining after reload");
        }
        // `new_runtime` owns freshly built connection pools, so there is nothing to flush.
        log_runtime_ready(&new_runtime);
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
        true
    }
}
