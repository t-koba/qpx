use crate::cli::{InitTemplate, MatchConfigRequest, SchemaFormat};
use crate::server::sets::wait_for_connection_drain;
use crate::server::{AdminTasks, ProxyTasks};
use anyhow::{Context, Result};
use qpx_core::config::{Config as ProxyConfig, load_configs, load_configs_with_sources};
use qpx_observability::init_logging;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

pub(crate) fn run_with_runtime(
    config_paths: Vec<PathBuf>,
    http_module_registry: Arc<crate::http::modules::HttpModuleRegistry>,
) -> Result<()> {
    let config = load_configs(&config_paths)?;
    let worker_threads = crate::tcp_bindings::net::worker_threads(&config.runtime);
    let max_blocking_threads = crate::tcp_bindings::net::max_blocking_threads(&config.runtime);

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .worker_threads(worker_threads)
        .max_blocking_threads(max_blocking_threads)
        .enable_all();

    let runtime = builder.build()?;
    runtime.block_on(run(config_paths, config, http_module_registry))
}

pub(crate) fn check_with_runtime(
    config_paths: Vec<PathBuf>,
    http_module_registry: Arc<crate::http::modules::HttpModuleRegistry>,
) -> Result<()> {
    let config = load_configs(&config_paths)?;
    let worker_threads = crate::tcp_bindings::net::worker_threads(&config.runtime);
    let max_blocking_threads = crate::tcp_bindings::net::max_blocking_threads(&config.runtime);

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .worker_threads(worker_threads)
        .max_blocking_threads(max_blocking_threads)
        .enable_all();

    let runtime = builder.build()?;
    runtime.block_on(async move {
        let state = crate::runtime::RuntimeState::build_with_http_module_registry(
            config,
            http_module_registry,
        )?;
        for reverse in state.resources.operational.reverse_edge_configs().iter() {
            crate::reverse::check_reverse_runtime(
                reverse,
                state.resources.operational.upstreams.as_slice(),
                state.http_module_registry().as_ref(),
                state
                    .plan
                    .reverse_edge(reverse.name.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!("compiled reverse edge missing for {}", reverse.name)
                    })?,
            )?;
        }
        Ok::<(), anyhow::Error>(())
    })?;
    println!("config ok");
    Ok(())
}

pub(crate) fn init_config_template(template: InitTemplate) -> Result<()> {
    print!("{}", init_template_yaml(template));
    Ok(())
}

pub(crate) fn init_template_yaml(template: InitTemplate) -> &'static str {
    match template {
        InitTemplate::ReverseBasic => include_str!("../config-templates/reverse-basic.yaml"),
        InitTemplate::ForwardEgress => include_str!("../config-templates/forward-egress.yaml"),
        InitTemplate::TransparentLinux => {
            include_str!("../config-templates/transparent-linux.yaml")
        }
        InitTemplate::IpcGateway => include_str!("../config-templates/ipc-gateway.yaml"),
        InitTemplate::TrustedIdentityExtAuthz => {
            include_str!("../config-templates/trusted-identity-ext-authz.yaml")
        }
    }
}

pub(crate) fn print_config_schema(format: SchemaFormat) -> Result<()> {
    let schema = qpx_core::config::canonical_schema_value();
    match format {
        SchemaFormat::Json => println!("{}", serde_json::to_string_pretty(&schema)?),
        SchemaFormat::Yaml => println!("{}", serde_yaml::to_string(&schema)?),
    }
    Ok(())
}

pub(crate) fn explain_config(
    config_paths: Vec<PathBuf>,
    edge_filter: Option<String>,
    route_filter: Option<String>,
    http_module_registry: Arc<crate::http::modules::HttpModuleRegistry>,
) -> Result<()> {
    let config = load_configs(&config_paths)?;
    let plan = crate::runtime::RuntimeState::compile_plan_with_http_module_registry(
        config,
        http_module_registry,
    )?;
    print!(
        "{}",
        crate::cli_render::render_explain_plan(
            &plan,
            edge_filter.as_deref(),
            route_filter.as_deref()
        )
    );
    Ok(())
}

pub(crate) fn match_config(
    config_paths: Vec<PathBuf>,
    request: MatchConfigRequest,
    http_module_registry: Arc<crate::http::modules::HttpModuleRegistry>,
) -> Result<()> {
    let config = load_configs(&config_paths)?;
    let plan = crate::runtime::RuntimeState::compile_plan_with_http_module_registry(
        config,
        http_module_registry,
    )?;
    print!(
        "{}",
        crate::cli_render::render_match_plan(
            &plan,
            crate::cli_render::MatchPlanRequest {
                edge: &request.edge,
                ctx: qpx_core::rules::RuleMatchContext {
                    src_ip: request.src_ip,
                    dst_port: request.dst_port,
                    sni: request.sni.as_deref(),
                    host: request.host.as_deref(),
                    method: request.method.as_deref(),
                    path: request.path.as_deref(),
                    ..Default::default()
                },
            },
        )?
    );
    Ok(())
}

pub(crate) async fn run(
    config_paths: Vec<PathBuf>,
    config: ProxyConfig,
    http_module_registry: Arc<crate::http::modules::HttpModuleRegistry>,
) -> Result<()> {
    let _log_guards = init_logging(
        &config.telemetry.system_log,
        &config.telemetry.access_log,
        &config.telemetry.audit_log,
        config.telemetry.otel.as_ref(),
    )?;
    crate::upstream::pool::set_upstream_proxy_max_concurrent_per_endpoint(
        config.runtime.upstream_proxy_max_concurrent_per_endpoint,
    );
    crate::upstream::origin::clear_direct_origin_connection_pools();
    info!(
        worker_threads = crate::tcp_bindings::net::worker_threads(&config.runtime),
        max_blocking_threads = crate::tcp_bindings::net::max_blocking_threads(&config.runtime),
        acceptor_tasks_per_listener =
            crate::tcp_bindings::net::acceptor_tasks_per_listener(&config.runtime),
        reuse_port = config.runtime.reuse_port,
        tcp_backlog = config.runtime.tcp_backlog,
        upstream_proxy_max_concurrent_per_endpoint =
            config.runtime.upstream_proxy_max_concurrent_per_endpoint,
        "runtime tuning"
    );
    log_binary_upgrade_capabilities(&config);
    let ready_notifier = crate::upgrade::take_ready_notifier_from_env()?;
    let sidecar_restore = crate::udp_session_handoff::UdpSessionRestoreState::take_from_env()?;
    #[cfg(feature = "http3")]
    let quic_broker_restore = crate::http3::quinn_socket::QuinnBrokerRestoreSet::take_from_env()?;
    let tcp_bindings = match crate::tcp_bindings::TcpBindings::from_env(&config)? {
        Some(bindings) => bindings,
        None => crate::tcp_bindings::TcpBindings::bind(&config)?,
    };
    let udp_bindings = match crate::udp_bindings::UdpBindings::from_env(&config)? {
        Some(bindings) => bindings,
        None => crate::udp_bindings::UdpBindings::bind(&config)?,
    };
    let mut runtime = crate::runtime::Runtime::with_http_module_registry(
        config.clone(),
        http_module_registry.clone(),
    )?;
    validate_runtime_state(runtime.state().as_ref())?;
    log_runtime_ready(&runtime);
    let proxy = ProxyTasks::start(
        &config,
        runtime.clone(),
        tcp_bindings,
        udp_bindings,
        sidecar_restore,
        #[cfg(feature = "http3")]
        quic_broker_restore,
    )?;
    let admin = AdminTasks::start(&config, runtime.clone(), proxy.tcp_bindings())?;

    let reload_handler =
        crate::config_reload::ConfigReloadHandler::new(config_paths.clone(), http_module_registry);
    let config_watcher = start_config_watcher(&config_paths)?;
    let mut upgrade_trigger = crate::upgrade::install_upgrade_trigger()?;

    info!("qpxd started");
    if let Some(notifier) = ready_notifier {
        notifier.notify()?;
    }

    run_control_loop(
        config,
        &mut runtime,
        proxy,
        admin,
        &reload_handler,
        config_watcher,
        &mut upgrade_trigger,
    )
    .await
}

struct ConfigWatcher {
    rx: tokio::sync::mpsc::Receiver<notify::Result<notify::Event>>,
    watcher: notify::RecommendedWatcher,
    watched: std::collections::HashSet<PathBuf>,
}

fn start_config_watcher(config_paths: &[PathBuf]) -> Result<ConfigWatcher> {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.blocking_send(res);
    })?;
    let mut watched = std::collections::HashSet::new();
    let (watch_config, sources) = load_configs_with_sources(config_paths)?;
    refresh_watches(
        &mut watcher,
        &mut watched,
        watch_sources_for_config(&watch_config, sources),
    )?;
    Ok(ConfigWatcher {
        rx,
        watcher,
        watched,
    })
}

async fn run_control_loop(
    mut current: ProxyConfig,
    runtime: &mut crate::runtime::Runtime,
    mut proxy: ProxyTasks,
    mut admin: AdminTasks,
    reload_handler: &crate::config_reload::ConfigReloadHandler,
    mut config_watcher: ConfigWatcher,
    upgrade_trigger: &mut Option<crate::upgrade::UpgradeTrigger>,
) -> Result<()> {
    loop {
        let tcp_task = &mut proxy.tcp_task;
        let Some(exportable_sidecar_task) = proxy.exportable_sidecar_task.as_mut() else {
            return Err(anyhow::anyhow!(
                "exportable sidecar task must exist while event loop is active"
            ));
        };
        let brokered_h3_task = &mut proxy.brokered_h3_task;
        tokio::select! {
            joined = tcp_task => {
                return match joined {
                    Ok(Ok(())) => Err(anyhow::anyhow!("tcp listener/reverse set exited")),
                    Ok(Err(err)) => Err(err).context("tcp listener/reverse set failed"),
                    Err(err) => Err(anyhow::anyhow!("tcp listener/reverse join failed: {err}")),
                };
            },
            joined = exportable_sidecar_task => {
                return match joined {
                    Ok(Ok(())) => Err(anyhow::anyhow!("exportable UDP sidecar set exited")),
                    Ok(Err(err)) => Err(err).context("exportable UDP sidecar set failed"),
                    Err(err) => Err(anyhow::anyhow!("exportable UDP sidecar join failed: {err}")),
                };
            },
            joined = brokered_h3_task => {
                return match joined {
                    Ok(Ok(())) => Err(anyhow::anyhow!("brokered HTTP/3 sidecar set exited")),
                    Ok(Err(err)) => Err(err).context("brokered HTTP/3 sidecar set failed"),
                    Err(err) => Err(anyhow::anyhow!("brokered HTTP/3 sidecar join failed: {err}")),
                };
            },
            event = config_watcher.rx.recv() => {
                let Some(event) = event else {
                    return Ok(());
                };
                match event {
                    Ok(_) => {
                        reload_handler
                            .handle_config_event(
                                &mut current,
                                runtime,
                                &mut proxy,
                                &mut config_watcher.watcher,
                                &mut config_watcher.watched,
                            )
                            .await?;
                    }
                    Err(err) => warn!(error = ?err, "watch error"),
                }
            },
            upgrade_requested = async {
                if let Some(trigger) = upgrade_trigger {
                    trigger.recv().await
                } else {
                    std::future::pending::<Result<()>>().await
                }
            } => {
                upgrade_requested?;
                if crate::config_reload::handle_upgrade_request(
                    upgrade_trigger,
                    &mut proxy,
                    &mut admin,
                    runtime,
                    &current,
                )
                .await?
                {
                    proxy.shutdown_tcp().await?;
                    wait_for_connection_drain(runtime).await;
                    return Ok(());
                }
            },
        }
    }
}

pub(crate) fn log_runtime_ready(runtime: &crate::runtime::Runtime) {
    let state = runtime.state();
    if let Some(ca_path) = state.ca_cert_path() {
        info!(ca_cert = %ca_path.display(), "tls inspection ca ready");
    }
}

fn log_binary_upgrade_capabilities(config: &ProxyConfig) {
    let udp_listener_count = config
        .ingress_edge_configs()
        .iter()
        .filter(|listener| {
            listener
                .http3
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false)
        })
        .count()
        + config
            .reverse_edge_configs()
            .iter()
            .filter(|reverse| {
                reverse
                    .http3
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false)
            })
            .count();
    let udp_session_handoff_count = config
        .ingress_edge_configs()
        .iter()
        .filter(|listener| {
            listener
                .http3
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false)
                && matches!(
                    listener.mode,
                    qpx_core::config::IngressEdgeMode::Transparent
                )
        })
        .count()
        + config
            .reverse_edge_configs()
            .iter()
            .filter(|reverse| {
                reverse
                    .http3
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false)
                    && !crate::reverse::requires_tcp_listener(reverse)
            })
            .count();
    let quic_broker_count = config
        .ingress_edge_configs()
        .iter()
        .filter(|listener| {
            listener
                .http3
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false)
                && matches!(listener.mode, qpx_core::config::IngressEdgeMode::Forward)
        })
        .count()
        + config
            .reverse_edge_configs()
            .iter()
            .filter(|reverse| {
                reverse
                    .http3
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false)
                    && crate::reverse::requires_tcp_listener(reverse)
            })
            .count();
    let xdp_enabled = config.ingress_edges().any(|listener| {
        listener
            .xdp
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false)
    }) || config
        .reverse_edge_configs()
        .iter()
        .any(|reverse| reverse.xdp.as_ref().map(|cfg| cfg.enabled).unwrap_or(false));

    #[cfg(any(unix, windows))]
    {
        if udp_listener_count > 0 {
            info!(
                udp_listener_count,
                "binary upgrade inherits UDP listener sockets across process replacement"
            );
        }
        if udp_session_handoff_count > 0 {
            info!(
                udp_session_handoff_count,
                "binary upgrade preserves transparent UDP and reverse HTTP/3 passthrough session sockets"
            );
        }
        if quic_broker_count > 0 {
            info!(
                quic_broker_count,
                "binary upgrade preserves forward HTTP/3 and reverse HTTP/3 terminate sessions via parent-child QUIC broker handoff"
            );
        }
        if xdp_enabled {
            info!("xdp metadata handling stays on the TCP accept path across binary upgrade");
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let has_listeners =
            !config.ingress_edge_configs().is_empty() || !config.reverse_edge_configs().is_empty();
        if has_listeners {
            warn!("binary upgrade is unsupported on this platform; use restart instead");
        }
        let _ = udp_listener_count;
        let _ = xdp_enabled;
    }
}

pub(crate) fn validate_runtime_state(state: &crate::runtime::RuntimeState) -> Result<()> {
    for reverse in state.resources.operational.reverse_edge_configs().iter() {
        crate::reverse::check_reverse_runtime(
            reverse,
            state.resources.operational.upstreams.as_slice(),
            state.http_module_registry().as_ref(),
            state
                .plan
                .reverse_edge(reverse.name.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!("compiled reverse edge missing for {}", reverse.name)
                })?,
        )?;
    }
    Ok(())
}

pub(crate) fn watch_sources_for_config(
    config: &ProxyConfig,
    mut sources: Vec<PathBuf>,
) -> Vec<PathBuf> {
    for set in &config.security.named_sets {
        let Some(path) = set.file.as_deref() else {
            continue;
        };
        let trimmed = path.trim();
        if trimmed.is_empty() {
            continue;
        };
        let path = PathBuf::from(trimmed);
        let canonical = std::fs::canonicalize(&path).unwrap_or(path);
        if !sources.contains(&canonical) {
            sources.push(canonical);
        }
    }
    sources
}

pub(crate) fn refresh_watches(
    watcher: &mut dyn notify::Watcher,
    watched: &mut std::collections::HashSet<PathBuf>,
    sources: Vec<PathBuf>,
) -> Result<()> {
    let next: std::collections::HashSet<PathBuf> = sources.into_iter().collect();

    // Config files are commonly updated via atomic replace. Some notify backends
    // bind file watches to the old inode/handle, so refresh every retained path
    // after a successful reload instead of only adding/removing set differences.
    for stale in watched.iter() {
        let _ = watcher.unwatch(stale);
    }
    for source in &next {
        watcher.watch(source, notify::RecursiveMode::NonRecursive)?;
    }

    *watched = next;
    Ok(())
}
