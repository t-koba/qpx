use crate::http::modules::HttpModuleRegistry;
use crate::{
    AdminTasks, ProxyTasks, load_configs_with_sources, refresh_watches, runtime, upgrade,
    validate_runtime_state, watch_sources_for_config,
};
use anyhow::{Context, Result};
use qpx_core::config::Config as ProxyConfig;
use std::collections::HashSet;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

mod restart;
use restart::RestartReloadInput;

pub(crate) struct ConfigReloadHandler {
    config_paths: Vec<PathBuf>,
    http_module_registry: Arc<HttpModuleRegistry>,
    configs_display: String,
}

impl ConfigReloadHandler {
    pub(crate) fn new(
        config_paths: Vec<PathBuf>,
        http_module_registry: Arc<HttpModuleRegistry>,
    ) -> Self {
        let configs_display = config_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Self {
            config_paths,
            http_module_registry,
            configs_display,
        }
    }

    pub(crate) async fn handle_config_event(
        &self,
        current: &mut ProxyConfig,
        runtime: &mut runtime::Runtime,
        proxy: &mut ProxyTasks,
        watcher: &mut dyn notify::Watcher,
        watched: &mut HashSet<PathBuf>,
    ) -> Result<()> {
        let (new_config, sources) = match load_configs_with_sources(&self.config_paths) {
            Ok(loaded) => loaded,
            Err(err) => {
                warn!(error = ?err, "config reload parse failed");
                emit_config_reload_audit(
                    "failed",
                    None,
                    Some("parse_error"),
                    self.configs_display.as_str(),
                    Some(&err),
                );
                return Ok(());
            }
        };

        if let Err(err) = runtime::ensure_hot_reload_compatible(current, &new_config) {
            warn!(error = ?err, "config reload requires process restart; reload ignored");
            emit_config_reload_audit(
                "ignored",
                None,
                Some("hot_reload_incompatible"),
                self.configs_display.as_str(),
                Some(&err),
            );
            return Ok(());
        }

        let watch_sources = watch_sources_for_config(&new_config, sources);
        if runtime::requires_server_restart(current, &new_config) {
            self.apply_restart_reload(RestartReloadInput {
                current,
                runtime,
                proxy,
                watcher,
                watched,
                watch_sources,
                new_config,
            })
            .await
        } else {
            self.apply_in_place_reload(
                current,
                runtime,
                watcher,
                watched,
                watch_sources,
                new_config,
            )
        }
    }

    fn apply_in_place_reload(
        &self,
        current: &mut ProxyConfig,
        runtime: &runtime::Runtime,
        watcher: &mut dyn notify::Watcher,
        watched: &mut HashSet<PathBuf>,
        watch_sources: Vec<PathBuf>,
        new_config: ProxyConfig,
    ) -> Result<()> {
        match runtime::RuntimeState::build_with_http_module_registry(
            new_config.clone(),
            self.http_module_registry.clone(),
        ) {
            Ok(state) => {
                if let Err(err) = validate_runtime_state(&state) {
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
                let upstream_proxy_max_concurrent_per_endpoint =
                    state.plan.limits.upstream_proxy_max_concurrent_per_endpoint;
                runtime.swap(state);
                crate::upstream::pool::set_upstream_proxy_max_concurrent_per_endpoint(
                    upstream_proxy_max_concurrent_per_endpoint,
                );
                crate::upstream::origin::clear_direct_origin_connection_pools();
                let _ = refresh_watches(watcher, watched, watch_sources);
                info!("config reloaded");
                emit_config_reload_audit(
                    "applied",
                    Some("in_place"),
                    None,
                    self.configs_display.as_str(),
                    None,
                );
                *current = new_config;
            }
            Err(err) => {
                warn!(error = ?err, "config reload failed");
                emit_config_reload_audit(
                    "failed",
                    None,
                    None,
                    self.configs_display.as_str(),
                    Some(&err),
                );
            }
        }
        Ok(())
    }
}

pub(crate) async fn handle_upgrade_request(
    upgrade_trigger: &Option<upgrade::UpgradeTrigger>,
    proxy: &mut ProxyTasks,
    admin: &mut AdminTasks,
    runtime: &runtime::Runtime,
    current: &ProxyConfig,
) -> Result<bool> {
    if let Some(trigger) = upgrade_trigger {
        trigger.acknowledge()?;
    }
    info!("binary upgrade requested");
    let sidecar_handoff = proxy
        .prepare_binary_upgrade(current)
        .await
        .context("failed to prepare sidecars before binary upgrade")?;
    match upgrade::spawn_upgraded_child(
        proxy.tcp_bindings(),
        proxy.udp_bindings(),
        if sidecar_handoff.udp_sessions.is_empty() {
            None
        } else {
            Some(&sidecar_handoff.udp_sessions)
        },
        #[cfg(feature = "http3")]
        sidecar_handoff.quic_brokers.as_ref(),
        current,
    )
    .await
    {
        Ok(()) => {
            admin.abort_all();
            let _ = runtime;
            Ok(true)
        }
        Err(err) => {
            warn!(error = ?err, "binary upgrade failed; restarting exportable UDP sidecars on current process");
            proxy.rollback_failed_upgrade(
                current,
                runtime.clone(),
                sidecar_handoff.udp_sessions,
            )?;
            Ok(false)
        }
    }
}

fn emit_config_reload_audit(
    outcome: &str,
    mode: Option<&str>,
    reason: Option<&str>,
    configs: &str,
    error: Option<&dyn Debug>,
) {
    if outcome == "applied" {
        if tracing::enabled!(target: "audit_log", tracing::Level::INFO) {
            tracing::info!(
                target: "audit_log",
                event = "config_reload",
                outcome,
                mode = mode.unwrap_or(""),
                configs,
            );
        }
        return;
    }
    if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
        tracing::warn!(
            target: "audit_log",
            event = "config_reload",
            outcome,
            reason = reason.unwrap_or(""),
            configs,
            error = ?error,
        );
    }
}
