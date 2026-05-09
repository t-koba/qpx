#![recursion_limit = "256"]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use qpx_core::config::{load_configs, load_configs_with_sources, Config as ProxyConfig};
use qpx_observability::{init_logging, start_metrics};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{info, warn};

#[cfg(test)]
pub(crate) fn test_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(all(feature = "tls-rustls", feature = "tls-native"))]
compile_error!("qpxd: features tls-rustls and tls-native are mutually exclusive");

#[cfg(all(feature = "http3", not(feature = "tls-rustls")))]
compile_error!("qpxd: feature http3 requires tls-rustls");

#[cfg(all(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
compile_error!("qpxd: features http3-backend-h3 and http3-backend-qpx are mutually exclusive");

#[cfg(all(
    feature = "http3",
    not(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))
))]
compile_error!("qpxd: feature http3 requires exactly one HTTP/3 backend feature");

#[cfg(all(feature = "mitm", not(feature = "tls-rustls")))]
compile_error!("qpxd: feature mitm requires tls-rustls");

#[cfg(all(feature = "acme", not(feature = "tls-rustls")))]
compile_error!("qpxd: feature acme requires tls-rustls");

#[cfg(feature = "tls-rustls")]
use qpx_core::tls::write_ca_files;

mod auth_runtime;
mod cache;
mod cli_render;
#[cfg(test)]
use cli_render::{render_explain_plan, render_match_plan};
mod connection_filter;
mod destination;
mod exporter;
mod forward;
mod ftp;
mod http;
#[cfg(feature = "http3")]
mod http3;
mod io_copy;
mod io_prefix;
mod ipc_client;
mod net;
mod policy_context;
mod rate_limit;
mod reverse;
mod runtime;
mod sidecar_control;
mod tcp_bindings;
mod tls;
mod transparent;
mod udp_bindings;
mod udp_session_handoff;
mod udp_socket_handoff;
mod upgrade;
mod upstream;
mod windows_handoff;
mod xdp;

pub mod module_api {
    pub use crate::http::body::{to_bytes, Body, BodyError, Sender};
    pub use crate::http::modules::{
        default_http_module_registry, BodyAccess, CacheLookupStatus, HttpModule,
        HttpModuleCapabilities, HttpModuleContext, HttpModuleEvent, HttpModuleFactory,
        HttpModuleRegistry, HttpModuleRegistryBuilder, HttpModuleRequestView, HttpModuleStage,
        ModuleStages, RequestHeadersOutcome, RetryEvent,
    };
}

pub use qpx_core::config::{Config, HttpModuleConfig};
pub use runtime::{Runtime, RuntimeState};

#[doc(hidden)]
pub mod fuzz_support {
    pub fn parse_proxy_v2_frame(frame: &[u8]) {
        crate::xdp::fuzz_parse_proxy_v2_frame(frame);
    }

    pub fn parse_http1_request_head(bytes: &[u8]) {
        crate::http::http1_codec::fuzz_parse_http1_request_head(bytes);
    }

    pub fn sniff_client_hello(bytes: &[u8]) {
        crate::tls::sniff::fuzz_client_hello_parser(bytes);
    }
}

#[derive(Clone)]
pub struct Daemon {
    http_module_registry: Arc<http::modules::HttpModuleRegistry>,
}

impl Default for Daemon {
    fn default() -> Self {
        Self {
            http_module_registry: crate::http::modules::default_http_module_registry(),
        }
    }
}

impl Daemon {
    pub fn builder() -> DaemonBuilder {
        DaemonBuilder::default()
    }

    pub fn run_cli(&self) -> Result<()> {
        qpx_core::tls::init_rustls_crypto_provider();
        let cli = Cli::parse();
        match cli.command {
            Command::Run { config } => self.run_with_runtime(config),
            Command::Check { config } => self.check_with_runtime(config),
            Command::Init { template } => init_config_template(template),
            Command::Schema { format } => print_config_schema(format),
            Command::Explain {
                config,
                edge,
                route,
            } => explain_config(config, edge, route, self.http_module_registry.clone()),
            Command::Match {
                config,
                edge,
                src_ip,
                dst_port,
                sni,
                host,
                method,
                path,
            } => match_config(
                config,
                edge,
                src_ip,
                dst_port,
                sni,
                host,
                method,
                path,
                self.http_module_registry.clone(),
            ),
            #[cfg(feature = "tls-rustls")]
            Command::GenCa { state_dir } => {
                let (cert, key) = write_ca_files(&state_dir)?;
                println!("generated ca: {} {}", cert.display(), key.display());
                Ok(())
            }
            Command::Upgrade { pid } => upgrade::request_upgrade(pid),
        }
    }

    pub fn run_with_runtime(&self, config_paths: Vec<PathBuf>) -> Result<()> {
        run_with_runtime(config_paths, self.http_module_registry.clone())
    }

    pub fn check_with_runtime(&self, config_paths: Vec<PathBuf>) -> Result<()> {
        check_with_runtime(config_paths, self.http_module_registry.clone())
    }

    pub fn build_runtime(&self, config: ProxyConfig) -> Result<runtime::Runtime> {
        runtime::Runtime::with_http_module_registry(config, self.http_module_registry.clone())
    }

    pub async fn run_loaded_config(
        &self,
        config_paths: Vec<PathBuf>,
        config: ProxyConfig,
    ) -> Result<()> {
        run(config_paths, config, self.http_module_registry.clone()).await
    }
}

pub struct DaemonBuilder {
    http_module_registry: crate::http::modules::HttpModuleRegistryBuilder,
}

impl Default for DaemonBuilder {
    fn default() -> Self {
        Self {
            http_module_registry: crate::http::modules::HttpModuleRegistry::builder(),
        }
    }
}

impl DaemonBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_http_module<F>(
        mut self,
        type_name: impl Into<String>,
        factory: F,
    ) -> Result<Self>
    where
        F: crate::http::modules::HttpModuleFactory + 'static,
    {
        self.http_module_registry
            .register_factory(type_name, factory)?;
        Ok(self)
    }

    pub fn build(self) -> Daemon {
        Daemon {
            http_module_registry: Arc::new(self.http_module_registry.build()),
        }
    }
}

#[derive(Parser)]
#[command(name = "qpxd", about = "qpx proxy daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(short, long, required = true, num_args = 1..)]
        config: Vec<PathBuf>,
    },
    Check {
        #[arg(short, long, required = true, num_args = 1..)]
        config: Vec<PathBuf>,
    },
    Init {
        #[arg(value_enum)]
        template: InitTemplate,
    },
    Schema {
        #[arg(long, value_enum, default_value_t = SchemaFormat::Json)]
        format: SchemaFormat,
    },
    Explain {
        #[arg(short, long, required = true, num_args = 1..)]
        config: Vec<PathBuf>,
        #[arg(long)]
        edge: Option<String>,
        #[arg(long)]
        route: Option<String>,
    },
    Match {
        #[arg(short, long, required = true, num_args = 1..)]
        config: Vec<PathBuf>,
        #[arg(long)]
        edge: String,
        #[arg(long)]
        src_ip: Option<IpAddr>,
        #[arg(long)]
        dst_port: Option<u16>,
        #[arg(long)]
        sni: Option<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        path: Option<String>,
    },
    #[cfg(feature = "tls-rustls")]
    GenCa {
        #[arg(short = 'd', long)]
        state_dir: PathBuf,
    },
    Upgrade {
        #[arg(long)]
        pid: u32,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum InitTemplate {
    ReverseBasic,
    ForwardEgress,
    TransparentLinux,
    IpcGateway,
    TrustedIdentityExtAuthz,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SchemaFormat {
    Json,
    Yaml,
}

pub fn main_entry() -> Result<()> {
    Daemon::default().run_cli()
}

fn run_with_runtime(
    config_paths: Vec<PathBuf>,
    http_module_registry: Arc<http::modules::HttpModuleRegistry>,
) -> Result<()> {
    let config = load_configs(&config_paths)?;
    let worker_threads = net::worker_threads(&config.runtime);
    let max_blocking_threads = net::max_blocking_threads(&config.runtime);

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .worker_threads(worker_threads)
        .max_blocking_threads(max_blocking_threads)
        .enable_all();

    let runtime = builder.build()?;
    runtime.block_on(run(config_paths, config, http_module_registry))
}

fn check_with_runtime(
    config_paths: Vec<PathBuf>,
    http_module_registry: Arc<http::modules::HttpModuleRegistry>,
) -> Result<()> {
    let config = load_configs(&config_paths)?;
    let worker_threads = net::worker_threads(&config.runtime);
    let max_blocking_threads = net::max_blocking_threads(&config.runtime);

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .worker_threads(worker_threads)
        .max_blocking_threads(max_blocking_threads)
        .enable_all();

    let runtime = builder.build()?;
    runtime.block_on(async move {
        let state =
            runtime::RuntimeState::build_with_http_module_registry(config, http_module_registry)?;
        for reverse in state.resources.operational.reverse_edge_configs().iter() {
            reverse::check_reverse_runtime(
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

fn init_config_template(template: InitTemplate) -> Result<()> {
    print!("{}", init_template_yaml(template));
    Ok(())
}

fn init_template_yaml(template: InitTemplate) -> &'static str {
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

fn print_config_schema(format: SchemaFormat) -> Result<()> {
    let schema = qpx_core::config::canonical_schema_value();
    match format {
        SchemaFormat::Json => println!("{}", serde_json::to_string_pretty(&schema)?),
        SchemaFormat::Yaml => println!("{}", serde_yaml::to_string(&schema)?),
    }
    Ok(())
}

fn explain_config(
    config_paths: Vec<PathBuf>,
    edge_filter: Option<String>,
    route_filter: Option<String>,
    http_module_registry: Arc<http::modules::HttpModuleRegistry>,
) -> Result<()> {
    let config = load_configs(&config_paths)?;
    let state =
        runtime::RuntimeState::build_with_http_module_registry(config, http_module_registry)?;
    print!(
        "{}",
        cli_render::render_explain_plan(
            state.plan.as_ref(),
            edge_filter.as_deref(),
            route_filter.as_deref()
        )
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn match_config(
    config_paths: Vec<PathBuf>,
    edge: String,
    src_ip: Option<IpAddr>,
    dst_port: Option<u16>,
    sni: Option<String>,
    host: Option<String>,
    method: Option<String>,
    path: Option<String>,
    http_module_registry: Arc<http::modules::HttpModuleRegistry>,
) -> Result<()> {
    let config = load_configs(&config_paths)?;
    let state =
        runtime::RuntimeState::build_with_http_module_registry(config, http_module_registry)?;
    print!(
        "{}",
        cli_render::render_match_plan(
            state.plan.as_ref(),
            &edge,
            src_ip,
            dst_port,
            sni.as_deref(),
            host.as_deref(),
            method.as_deref(),
            path.as_deref(),
        )?
    );
    Ok(())
}

async fn run(
    config_paths: Vec<PathBuf>,
    config: ProxyConfig,
    http_module_registry: Arc<http::modules::HttpModuleRegistry>,
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
        worker_threads = net::worker_threads(&config.runtime),
        max_blocking_threads = net::max_blocking_threads(&config.runtime),
        acceptor_tasks_per_listener = net::acceptor_tasks_per_listener(&config.runtime),
        reuse_port = config.runtime.reuse_port,
        tcp_backlog = config.runtime.tcp_backlog,
        upstream_proxy_max_concurrent_per_endpoint =
            config.runtime.upstream_proxy_max_concurrent_per_endpoint,
        "runtime tuning"
    );
    log_binary_upgrade_capabilities(&config);
    let ready_notifier = upgrade::take_ready_notifier_from_env()?;
    let sidecar_restore = udp_session_handoff::UdpSessionRestoreState::take_from_env()?;
    #[cfg(feature = "http3")]
    let quic_broker_restore = http3::quinn_socket::QuinnBrokerRestoreSet::take_from_env()?;
    let tcp_bindings = match tcp_bindings::TcpBindings::from_env(&config)? {
        Some(bindings) => bindings,
        None => tcp_bindings::TcpBindings::bind(&config)?,
    };
    let udp_bindings = match udp_bindings::UdpBindings::from_env(&config)? {
        Some(bindings) => bindings,
        None => udp_bindings::UdpBindings::bind(&config)?,
    };
    let mut runtime =
        runtime::Runtime::with_http_module_registry(config.clone(), http_module_registry.clone())?;
    validate_runtime_state(runtime.state().as_ref())?;
    log_runtime_ready(&runtime);
    let mut proxy = ProxyTasks::start(
        &config,
        runtime.clone(),
        tcp_bindings,
        udp_bindings,
        sidecar_restore,
        #[cfg(feature = "http3")]
        quic_broker_restore,
    )?;
    let mut admin = AdminTasks::start(&config, runtime.clone(), proxy.tcp_bindings())?;

    let configs = config_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.blocking_send(res);
    })?;
    let mut watched = std::collections::HashSet::new();
    let (watch_config, sources) = load_configs_with_sources(&config_paths)?;
    refresh_watches(
        &mut watcher,
        &mut watched,
        watch_sources_for_config(&watch_config, sources),
    )?;

    let mut upgrade_trigger = upgrade::install_upgrade_trigger()?;

    let mut current = config;

    info!("qpxd started");
    if let Some(notifier) = ready_notifier {
        notifier.notify()?;
    }

    loop {
        let tcp_task = &mut proxy.tcp_task;
        let exportable_sidecar_task = proxy
            .exportable_sidecar_task
            .as_mut()
            .expect("exportable sidecar task must exist while event loop is active");
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
            event = rx.recv() => {
                let Some(event) = event else {
                    return Ok(());
                };
                match event {
                    Ok(_) => match load_configs_with_sources(&config_paths) {
                        Ok((new_config, sources)) => {
                            if let Err(err) = runtime::ensure_hot_reload_compatible(&current, &new_config) {
                                warn!(error = ?err, "config reload requires process restart; reload ignored");
                                if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
                                    tracing::warn!(
                                        target: "audit_log",
                                        event = "config_reload",
                                        outcome = "ignored",
                                        reason = "hot_reload_incompatible",
                                        configs = %configs,
                                        error = ?err,
                                    );
                                }
                                continue;
                            }

                            let watch_sources = watch_sources_for_config(&new_config, sources);
                            let restart_required = runtime::requires_server_restart(&current, &new_config);
                            if restart_required {
                                match runtime::Runtime::with_http_module_registry(
                                    new_config.clone(),
                                    http_module_registry.clone(),
                                ) {
                                    Ok(new_runtime) => {
                                        let next_state = new_runtime.state();
                                        if let Err(err) = validate_runtime_state(next_state.as_ref()) {
                                            warn!(error = ?err, "config reload reverse compile failed");
                                            if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
                                                tracing::warn!(
                                                    target: "audit_log",
                                                    event = "config_reload",
                                                    outcome = "failed",
                                                    reason = "reverse_compile_error",
                                                    configs = %configs,
                                                    error = ?err,
                                                );
                                            }
                                            continue;
                                        }

                                        let tcp_bindings = match tcp_bindings::TcpBindings::bind_for_hot_reload(
                                            &new_config,
                                            &current,
                                            proxy.tcp_bindings(),
                                        ) {
                                            Ok(bindings) => bindings,
                                            Err(err) => {
                                                warn!(error = ?err, "config reload bind failed");
                                                continue;
                                            }
                                        };
                                        let udp_bindings = match udp_bindings::UdpBindings::bind_for_hot_reload(
                                            &new_config,
                                            &current,
                                            proxy.udp_bindings(),
                                        ) {
                                            Ok(bindings) => bindings,
                                            Err(err) => {
                                                warn!(error = ?err, "config reload udp bind failed");
                                                continue;
                                            }
                                        };
                                        let old_upstream_limit = current
                                            .runtime
                                            .upstream_proxy_max_concurrent_per_endpoint;
                                        crate::upstream::pool::set_upstream_proxy_max_concurrent_per_endpoint(
                                            next_state.plan.limits
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
                                                continue;
                                            }
                                        };
                                        let old_proxy = std::mem::replace(&mut proxy, new_proxy);
                                        if let Err(err) = old_proxy.stop_all().await {
                                            warn!(error = ?err, "old proxy tasks failed while draining after reload");
                                        }
                                        crate::upstream::origin::clear_direct_origin_connection_pools();
                                        log_runtime_ready(&new_runtime);
                                        let _ = refresh_watches(&mut watcher, &mut watched, watch_sources);
                                        info!("config reloaded; listener/reverse server set restarted");
                                        if tracing::enabled!(target: "audit_log", tracing::Level::INFO) {
                                            tracing::info!(
                                                target: "audit_log",
                                                event = "config_reload",
                                                outcome = "applied",
                                                mode = "restart",
                                                configs = %configs,
                                            );
                                        }
                                        current = new_config;
                                        runtime = new_runtime;
                                    }
                                    Err(err) => {
                                        warn!(error = ?err, "config reload failed");
                                        if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
                                            tracing::warn!(
                                                target: "audit_log",
                                                event = "config_reload",
                                                outcome = "failed",
                                                configs = %configs,
                                                error = ?err,
                                            );
                                        }
                                    }
                                }
                            } else {
                                match runtime::RuntimeState::build_with_http_module_registry(
                                    new_config.clone(),
                                    http_module_registry.clone(),
                                ) {
                                    Ok(state) => {
                                        if let Err(err) = validate_runtime_state(&state) {
                                            warn!(error = ?err, "config reload reverse compile failed");
                                            if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
                                                tracing::warn!(
                                                    target: "audit_log",
                                                    event = "config_reload",
                                                    outcome = "failed",
                                                    reason = "reverse_compile_error",
                                                    configs = %configs,
                                                    error = ?err,
                                                );
                                            }
                                            continue;
                                        }
                                        let upstream_proxy_max_concurrent_per_endpoint = state.plan.limits
                                            .upstream_proxy_max_concurrent_per_endpoint;
                                        runtime.swap(state);
                                        crate::upstream::pool::set_upstream_proxy_max_concurrent_per_endpoint(
                                            upstream_proxy_max_concurrent_per_endpoint,
                                        );
                                        crate::upstream::origin::clear_direct_origin_connection_pools();
                                        let _ = refresh_watches(&mut watcher, &mut watched, watch_sources);
                                        info!("config reloaded");
                                        if tracing::enabled!(target: "audit_log", tracing::Level::INFO) {
                                            tracing::info!(
                                                target: "audit_log",
                                                event = "config_reload",
                                                outcome = "applied",
                                                mode = "in_place",
                                                configs = %configs,
                                            );
                                        }
                                        current = new_config;
                                    }
                                    Err(err) => {
                                        warn!(error = ?err, "config reload failed");
                                        if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
                                            tracing::warn!(
                                                target: "audit_log",
                                                event = "config_reload",
                                                outcome = "failed",
                                                configs = %configs,
                                                error = ?err,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            warn!(error = ?err, "config reload parse failed");
                            if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
                                tracing::warn!(
                                    target: "audit_log",
                                    event = "config_reload",
                                    outcome = "failed",
                                    reason = "parse_error",
                                    configs = %configs,
                                    error = ?err,
                                );
                            }
                        }
                    },
                    Err(err) => warn!(error = ?err, "watch error"),
                }
            },
            upgrade_requested = async {
                if let Some(trigger) = &mut upgrade_trigger {
                    trigger.recv().await
                } else {
                    std::future::pending::<Result<()>>().await
                }
            } => {
                upgrade_requested?;
                if let Some(trigger) = &upgrade_trigger {
                    trigger.acknowledge()?;
                }
                info!("binary upgrade requested");
                let sidecar_handoff = proxy
                    .prepare_binary_upgrade(&current)
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
                    &current,
                )
                .await
                {
                    Ok(()) => {
                        admin.abort_all();
                        proxy.shutdown_tcp().await?;
                        wait_for_connection_drain(&runtime).await;
                        return Ok(());
                    }
                    Err(err) => {
                        warn!(error = ?err, "binary upgrade failed; restarting exportable UDP sidecars on current process");
                        proxy.rollback_failed_upgrade(
                            &current,
                            runtime.clone(),
                            sidecar_handoff.udp_sessions,
                        )?;
                    }
                }
            },
        }
    }
}

fn log_runtime_ready(runtime: &runtime::Runtime) {
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
                    && !reverse::requires_tcp_listener(reverse)
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
                    && reverse::requires_tcp_listener(reverse)
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

fn validate_runtime_state(state: &runtime::RuntimeState) -> Result<()> {
    for reverse in state.resources.operational.reverse_edge_configs().iter() {
        reverse::check_reverse_runtime(
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

fn watch_sources_for_config(config: &ProxyConfig, mut sources: Vec<PathBuf>) -> Vec<PathBuf> {
    for set in &config.security.named_sets {
        let Some(path) = set.file.as_deref() else {
            continue;
        };
        let trimmed = path.trim();
        if trimmed.is_empty() {
            continue;
        }
        let path = PathBuf::from(trimmed);
        let canonical = std::fs::canonicalize(&path).unwrap_or(path);
        if !sources.contains(&canonical) {
            sources.push(canonical);
        }
    }
    sources
}

fn refresh_watches(
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

struct PreparedBinaryUpgradeSidecars {
    udp_sessions: udp_session_handoff::UdpSessionRestoreState,
    #[cfg(feature = "http3")]
    quic_brokers: Option<crate::http3::quinn_socket::QuinnBrokerPreparedHandoff>,
}

struct ProxyTasks {
    tcp_bindings: tcp_bindings::TcpBindings,
    udp_bindings: udp_bindings::UdpBindings,
    reverse_runtimes: std::collections::HashMap<String, reverse::ReloadableReverse>,
    tcp_shutdown_tx: watch::Sender<bool>,
    tcp_task: tokio::task::JoinHandle<Result<()>>,
    exportable_sidecar_control_tx: watch::Sender<sidecar_control::SidecarControl>,
    exportable_sidecar_export:
        std::sync::Arc<std::sync::Mutex<udp_session_handoff::UdpSessionRestoreState>>,
    exportable_sidecar_task: Option<tokio::task::JoinHandle<Result<()>>>,
    brokered_h3_control_tx: watch::Sender<sidecar_control::SidecarControl>,
    brokered_h3_task: tokio::task::JoinHandle<Result<()>>,
    #[cfg(feature = "http3")]
    quic_broker_handles: Vec<crate::http3::quinn_socket::LocalQuinnBrokerHandle>,
}

impl ProxyTasks {
    fn start(
        config: &ProxyConfig,
        runtime: runtime::Runtime,
        tcp_bindings: tcp_bindings::TcpBindings,
        udp_bindings: udp_bindings::UdpBindings,
        sidecar_restore: Option<udp_session_handoff::UdpSessionRestoreState>,
        #[cfg(feature = "http3")] quic_broker_restore: Option<
            crate::http3::quinn_socket::QuinnBrokerRestoreSet,
        >,
    ) -> Result<Self> {
        let reverse_runtimes = config
            .reverse_edge_configs()
            .iter()
            .map(|reverse| {
                reverse::build_reloadable_reverse(reverse, &runtime)
                    .map(|compiled| (reverse.name.clone(), compiled))
            })
            .collect::<Result<std::collections::HashMap<_, _>>>()?;
        let listener_bindings = config
            .ingress_edge_configs()
            .iter()
            .map(|listener| {
                tcp_bindings
                    .clone_listener(listener.name.as_str())
                    .map(|bindings| (listener.name.clone(), bindings))
            })
            .collect::<Result<std::collections::HashMap<_, _>>>()?;
        let reverse_bindings = config
            .reverse_edge_configs()
            .iter()
            .filter(|reverse| reverse::requires_tcp_listener(reverse))
            .map(|reverse| {
                tcp_bindings
                    .clone_reverse(reverse.name.as_str())
                    .map(|bindings| (reverse.name.clone(), bindings))
            })
            .collect::<Result<std::collections::HashMap<_, _>>>()?;
        let exportable_listener_udp_bindings =
            exportable_listener_udp_bindings(config, &udp_bindings)?;
        let exportable_reverse_udp_bindings =
            exportable_reverse_udp_bindings(config, &udp_bindings)?;
        #[cfg(feature = "http3")]
        let mut quic_broker_restore = quic_broker_restore.unwrap_or_default();
        #[cfg(feature = "http3")]
        let mut quic_broker_handles = Vec::new();
        #[cfg(feature = "http3")]
        let brokered_forward_h3_sockets = brokered_forward_h3_sockets(
            config,
            &udp_bindings,
            &mut quic_broker_restore,
            &mut quic_broker_handles,
        )?;
        #[cfg(feature = "http3")]
        let brokered_reverse_h3_sockets = brokered_reverse_h3_sockets(
            config,
            &udp_bindings,
            &reverse_runtimes,
            &mut quic_broker_restore,
            &mut quic_broker_handles,
        )?;
        #[cfg(feature = "http3")]
        quic_broker_restore.ensure_consumed()?;

        let ingress_edge_configs = config.ingress_edges().cloned().collect();
        let reverse_edge_configs = config.reverse_edges().cloned().collect();
        let (tcp_shutdown_tx, tcp_shutdown_rx) = watch::channel(false);
        let tcp_runtime = runtime.clone();
        let tcp_reverse_runtimes = reverse_runtimes.clone();
        let tcp_task = tokio::spawn(async move {
            run_tcp_server_set(
                ingress_edge_configs,
                reverse_edge_configs,
                tcp_runtime,
                listener_bindings,
                reverse_bindings,
                tcp_reverse_runtimes,
                tcp_shutdown_rx,
            )
            .await
        });

        let (exportable_sidecar_control_tx, exportable_sidecar_control_rx) =
            watch::channel(sidecar_control::SidecarControl::Running);
        let exportable_sidecar_export = std::sync::Arc::new(std::sync::Mutex::new(
            udp_session_handoff::UdpSessionRestoreState::default(),
        ));
        let exportable_sidecar_task = Some(spawn_exportable_sidecar_server_set(
            ExportableSidecarServerSet {
                ingress_edge_configs: config.ingress_edges().cloned().collect(),
                reverse_edge_configs: config.reverse_edges().cloned().collect(),
                runtime: runtime.clone(),
                reverse_runtimes: reverse_runtimes.clone(),
                listener_udp_bindings: exportable_listener_udp_bindings,
                reverse_udp_bindings: exportable_reverse_udp_bindings,
                control: exportable_sidecar_control_rx,
                sidecar_restore,
                sidecar_export: exportable_sidecar_export.clone(),
            },
        ));

        let (brokered_h3_control_tx, brokered_h3_control_rx) =
            watch::channel(sidecar_control::SidecarControl::Running);
        #[cfg(feature = "http3")]
        let brokered_h3_task = spawn_brokered_h3_server_set(
            config.ingress_edges().cloned().collect(),
            config.reverse_edges().cloned().collect(),
            runtime,
            reverse_runtimes.clone(),
            brokered_forward_h3_sockets,
            brokered_reverse_h3_sockets,
            brokered_h3_control_rx,
        );
        #[cfg(not(feature = "http3"))]
        let brokered_h3_task = spawn_empty_sidecar_server_set(brokered_h3_control_rx);

        Ok(Self {
            tcp_bindings,
            udp_bindings,
            reverse_runtimes,
            tcp_shutdown_tx,
            tcp_task,
            exportable_sidecar_control_tx,
            exportable_sidecar_export,
            exportable_sidecar_task,
            brokered_h3_control_tx,
            brokered_h3_task,
            #[cfg(feature = "http3")]
            quic_broker_handles,
        })
    }

    fn tcp_bindings(&self) -> &tcp_bindings::TcpBindings {
        &self.tcp_bindings
    }

    fn udp_bindings(&self) -> &udp_bindings::UdpBindings {
        &self.udp_bindings
    }

    async fn stop_all(self) -> Result<()> {
        let _ = self
            .exportable_sidecar_control_tx
            .send(sidecar_control::SidecarControl::Stop);
        let _ = self
            .brokered_h3_control_tx
            .send(sidecar_control::SidecarControl::Stop);
        let _ = self.tcp_shutdown_tx.send(true);
        if let Some(exportable_sidecar_task) = self.exportable_sidecar_task {
            match exportable_sidecar_task.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    return Err(err).context("exportable UDP sidecar set failed while stopping");
                }
                Err(err) => {
                    return Err(anyhow::anyhow!(
                        "exportable UDP sidecar join failed while stopping: {err}"
                    ));
                }
            }
        }
        match self.brokered_h3_task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                return Err(err).context("brokered HTTP/3 sidecar set failed while stopping");
            }
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "brokered HTTP/3 sidecar join failed while stopping: {err}"
                ));
            }
        }
        match self.tcp_task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err).context("tcp listener/reverse set failed while stopping"),
            Err(err) => Err(anyhow::anyhow!(
                "tcp listener/reverse join failed while stopping: {err}"
            )),
        }
    }

    async fn prepare_binary_upgrade(
        &mut self,
        config: &ProxyConfig,
    ) -> Result<PreparedBinaryUpgradeSidecars> {
        let udp_sessions = self.export_exportable_sidecars().await?;
        #[cfg(not(feature = "http3"))]
        let _ = config;
        #[cfg(feature = "http3")]
        let quic_brokers = crate::http3::quinn_socket::prepare_quic_broker_handoff(
            self.quic_broker_handles.as_slice(),
            config,
        )?;
        Ok(PreparedBinaryUpgradeSidecars {
            udp_sessions,
            #[cfg(feature = "http3")]
            quic_brokers,
        })
    }

    fn rollback_failed_upgrade(
        &mut self,
        config: &ProxyConfig,
        runtime: runtime::Runtime,
        sidecar_restore: udp_session_handoff::UdpSessionRestoreState,
    ) -> Result<()> {
        #[cfg(feature = "http3")]
        crate::http3::quinn_socket::detach_quic_broker_handoff(self.quic_broker_handles.as_slice());
        self.restart_exportable_sidecars(config, runtime, Some(sidecar_restore))
    }

    async fn export_exportable_sidecars(
        &mut self,
    ) -> Result<udp_session_handoff::UdpSessionRestoreState> {
        let Some(task) = self.exportable_sidecar_task.take() else {
            return Ok(udp_session_handoff::UdpSessionRestoreState::default());
        };
        let _ = self
            .exportable_sidecar_control_tx
            .send(sidecar_control::SidecarControl::ExportForUpgrade);
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                return Err(err).context("exportable UDP sidecar set failed while exporting");
            }
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "exportable UDP sidecar join failed while exporting: {err}"
                ));
            }
        }
        let exported = std::mem::take(
            &mut *self
                .exportable_sidecar_export
                .lock()
                .expect("exportable sidecar export lock"),
        );
        self.reset_exportable_sidecar_control();
        Ok(exported)
    }

    fn restart_exportable_sidecars(
        &mut self,
        config: &ProxyConfig,
        runtime: runtime::Runtime,
        sidecar_restore: Option<udp_session_handoff::UdpSessionRestoreState>,
    ) -> Result<()> {
        if self.exportable_sidecar_task.is_some() {
            return Err(anyhow::anyhow!(
                "exportable UDP sidecars are already running"
            ));
        }
        let (control_tx, control_rx) = watch::channel(sidecar_control::SidecarControl::Running);
        self.exportable_sidecar_control_tx = control_tx;
        self.exportable_sidecar_export = std::sync::Arc::new(std::sync::Mutex::new(
            udp_session_handoff::UdpSessionRestoreState::default(),
        ));
        self.exportable_sidecar_task = Some(spawn_exportable_sidecar_server_set(
            ExportableSidecarServerSet {
                ingress_edge_configs: config.ingress_edges().cloned().collect(),
                reverse_edge_configs: config.reverse_edges().cloned().collect(),
                runtime,
                reverse_runtimes: self.reverse_runtimes.clone(),
                listener_udp_bindings: exportable_listener_udp_bindings(
                    config,
                    &self.udp_bindings,
                )?,
                reverse_udp_bindings: exportable_reverse_udp_bindings(config, &self.udp_bindings)?,
                control: control_rx,
                sidecar_restore,
                sidecar_export: self.exportable_sidecar_export.clone(),
            },
        ));
        Ok(())
    }

    fn reset_exportable_sidecar_control(&mut self) {
        let (control_tx, _control_rx) = watch::channel(sidecar_control::SidecarControl::Running);
        self.exportable_sidecar_control_tx = control_tx;
        self.exportable_sidecar_export = std::sync::Arc::new(std::sync::Mutex::new(
            udp_session_handoff::UdpSessionRestoreState::default(),
        ));
    }

    async fn shutdown_tcp(self) -> Result<()> {
        let _ = self.tcp_shutdown_tx.send(true);
        match self.tcp_task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err).context("tcp listener/reverse set failed while draining"),
            Err(err) => Err(anyhow::anyhow!(
                "tcp listener/reverse join failed while draining: {err}"
            )),
        }
    }
}

struct AdminTasks {
    metrics_task: Option<tokio::task::JoinHandle<()>>,
    http01_task: Option<tokio::task::JoinHandle<Result<()>>>,
    manager_task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl AdminTasks {
    fn start(
        config: &ProxyConfig,
        runtime: runtime::Runtime,
        tcp_bindings: &tcp_bindings::TcpBindings,
    ) -> Result<Self> {
        let metrics_task = config
            .telemetry
            .metrics
            .as_ref()
            .map(|metrics| start_metrics(metrics, tcp_bindings.clone_metrics()?))
            .transpose()?;

        #[cfg(feature = "acme")]
        let (http01_task, manager_task) =
            if let Some(acme_state) = qpx_acme::init(config, std::sync::Arc::new(runtime))? {
                let http_listener = tcp_bindings.clone_acme_http01()?.ok_or_else(|| {
                    anyhow::anyhow!("acme http-01 binding missing while ACME is enabled")
                })?;
                let http_state = acme_state.clone();
                let http01_task = tokio::spawn(async move {
                    qpx_acme::run_http01_server_with_std_listener(http_listener, http_state).await
                });
                let manager_state = acme_state.clone();
                let manager_task =
                    tokio::spawn(async move { qpx_acme::run_manager(manager_state).await });
                (Some(http01_task), Some(manager_task))
            } else {
                (None, None)
            };

        #[cfg(not(feature = "acme"))]
        let (http01_task, manager_task) = {
            let _ = runtime;
            (None, None)
        };

        Ok(Self {
            metrics_task,
            http01_task,
            manager_task,
        })
    }

    fn abort_all(&mut self) {
        if let Some(task) = self.metrics_task.take() {
            task.abort();
        }
        if let Some(task) = self.http01_task.take() {
            task.abort();
        }
        if let Some(task) = self.manager_task.take() {
            task.abort();
        }
    }
}

fn exportable_listener_udp_bindings(
    config: &ProxyConfig,
    udp_bindings: &udp_bindings::UdpBindings,
) -> Result<std::collections::HashMap<String, std::net::UdpSocket>> {
    #[cfg(feature = "http3")]
    {
        config
            .ingress_edge_configs()
            .iter()
            .filter(|listener| {
                matches!(
                    listener.mode,
                    qpx_core::config::IngressEdgeMode::Transparent
                ) && listener
                    .http3
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false)
            })
            .map(|listener| {
                udp_bindings
                    .clone_listener(listener.name.as_str())?
                    .ok_or_else(|| {
                        anyhow::anyhow!("udp listener binding missing for {}", listener.name)
                    })
                    .map(|socket| (listener.name.clone(), socket))
            })
            .collect::<Result<std::collections::HashMap<_, _>>>()
    }

    #[cfg(not(feature = "http3"))]
    {
        let _ = config;
        let _ = udp_bindings;
        Ok(std::collections::HashMap::new())
    }
}

fn exportable_reverse_udp_bindings(
    config: &ProxyConfig,
    udp_bindings: &udp_bindings::UdpBindings,
) -> Result<std::collections::HashMap<String, std::net::UdpSocket>> {
    #[cfg(feature = "http3")]
    {
        config
            .reverse_edge_configs()
            .iter()
            .filter(|reverse| {
                reverse
                    .http3
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false)
                    && !reverse::requires_tcp_listener(reverse)
            })
            .map(|reverse| {
                udp_bindings
                    .clone_reverse(reverse.name.as_str())?
                    .ok_or_else(|| {
                        anyhow::anyhow!("udp reverse binding missing for {}", reverse.name)
                    })
                    .map(|socket| (reverse.name.clone(), socket))
            })
            .collect::<Result<std::collections::HashMap<_, _>>>()
    }

    #[cfg(not(feature = "http3"))]
    {
        let _ = config;
        let _ = udp_bindings;
        Ok(std::collections::HashMap::new())
    }
}

#[cfg(feature = "http3")]
fn brokered_forward_h3_sockets(
    config: &ProxyConfig,
    udp_bindings: &udp_bindings::UdpBindings,
    quic_broker_restore: &mut crate::http3::quinn_socket::QuinnBrokerRestoreSet,
    quic_broker_handles: &mut Vec<crate::http3::quinn_socket::LocalQuinnBrokerHandle>,
) -> Result<std::collections::HashMap<String, crate::http3::quinn_socket::QuinnEndpointSocket>> {
    config
        .ingress_edge_configs()
        .iter()
        .filter(|listener| {
            matches!(listener.mode, qpx_core::config::IngressEdgeMode::Forward)
                && listener
                    .http3
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false)
        })
        .map(|listener| {
            let udp_socket = udp_bindings
                .clone_listener(listener.name.as_str())?
                .ok_or_else(|| {
                    anyhow::anyhow!("udp listener binding missing for {}", listener.name)
                })?;
            let prepared = crate::forward::h3::prepare_http3_listener_socket(
                listener.name.as_str(),
                udp_socket,
                quic_broker_restore.take_forward(listener.name.as_str()),
            )?;
            if let Some(handle) = prepared.local_broker_handle {
                quic_broker_handles.push(handle);
            }
            Ok((listener.name.clone(), prepared.endpoint_socket))
        })
        .collect::<Result<std::collections::HashMap<_, _>>>()
}

#[cfg(feature = "http3")]
fn brokered_reverse_h3_sockets(
    config: &ProxyConfig,
    udp_bindings: &udp_bindings::UdpBindings,
    reverse_runtimes: &std::collections::HashMap<String, reverse::ReloadableReverse>,
    quic_broker_restore: &mut crate::http3::quinn_socket::QuinnBrokerRestoreSet,
    quic_broker_handles: &mut Vec<crate::http3::quinn_socket::LocalQuinnBrokerHandle>,
) -> Result<std::collections::HashMap<String, crate::http3::quinn_socket::QuinnEndpointSocket>> {
    config
        .reverse_edge_configs()
        .iter()
        .filter(|reverse| {
            reverse
                .http3
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false)
                && reverse::requires_tcp_listener(reverse)
        })
        .map(|reverse| {
            let reverse_rt = reverse_runtimes
                .get(reverse.name.as_str())
                .cloned()
                .ok_or_else(|| {
                    anyhow::anyhow!("reloadable reverse missing for {}", reverse.name)
                })?;
            let udp_socket = udp_bindings
                .clone_reverse(reverse.name.as_str())?
                .ok_or_else(|| {
                    anyhow::anyhow!("udp reverse binding missing for {}", reverse.name)
                })?;
            let prepared = crate::reverse::h3_terminate::prepare_reverse_terminate_socket(
                reverse.name.as_str(),
                reverse_rt,
                udp_socket,
                quic_broker_restore.take_reverse(reverse.name.as_str()),
            )?;
            if let Some(handle) = prepared.local_broker_handle {
                quic_broker_handles.push(handle);
            }
            Ok((reverse.name.clone(), prepared.endpoint_socket))
        })
        .collect::<Result<std::collections::HashMap<_, _>>>()
}

struct ExportableSidecarServerSet {
    ingress_edge_configs: Vec<qpx_core::config::IngressEdgeConfig>,
    reverse_edge_configs: Vec<qpx_core::config::ReverseEdgeConfig>,
    runtime: runtime::Runtime,
    reverse_runtimes: std::collections::HashMap<String, reverse::ReloadableReverse>,
    listener_udp_bindings: std::collections::HashMap<String, std::net::UdpSocket>,
    reverse_udp_bindings: std::collections::HashMap<String, std::net::UdpSocket>,
    control: watch::Receiver<sidecar_control::SidecarControl>,
    sidecar_restore: Option<udp_session_handoff::UdpSessionRestoreState>,
    sidecar_export: std::sync::Arc<std::sync::Mutex<udp_session_handoff::UdpSessionRestoreState>>,
}

fn spawn_exportable_sidecar_server_set(
    args: ExportableSidecarServerSet,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move { run_exportable_sidecar_server_set(args).await })
}

#[cfg(feature = "http3")]
fn spawn_brokered_h3_server_set(
    ingress_edge_configs: Vec<qpx_core::config::IngressEdgeConfig>,
    reverse_edge_configs: Vec<qpx_core::config::ReverseEdgeConfig>,
    runtime: runtime::Runtime,
    reverse_runtimes: std::collections::HashMap<String, reverse::ReloadableReverse>,
    listener_h3_sockets: std::collections::HashMap<
        String,
        crate::http3::quinn_socket::QuinnEndpointSocket,
    >,
    reverse_h3_sockets: std::collections::HashMap<
        String,
        crate::http3::quinn_socket::QuinnEndpointSocket,
    >,
    control: watch::Receiver<sidecar_control::SidecarControl>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        run_brokered_h3_server_set(
            ingress_edge_configs,
            reverse_edge_configs,
            runtime,
            reverse_runtimes,
            listener_h3_sockets,
            reverse_h3_sockets,
            control,
        )
        .await
    })
}

#[cfg(not(feature = "http3"))]
fn spawn_empty_sidecar_server_set(
    mut control: watch::Receiver<sidecar_control::SidecarControl>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            if control.changed().await.is_err() || control.borrow().should_stop() {
                return Ok(());
            }
        }
    })
}

async fn run_tcp_server_set(
    ingress_edge_configs: Vec<qpx_core::config::IngressEdgeConfig>,
    reverse_edge_configs: Vec<qpx_core::config::ReverseEdgeConfig>,
    runtime: runtime::Runtime,
    mut listener_bindings: std::collections::HashMap<String, Vec<tokio::net::TcpListener>>,
    mut reverse_bindings: std::collections::HashMap<String, Vec<tokio::net::TcpListener>>,
    reverse_runtimes: std::collections::HashMap<String, reverse::ReloadableReverse>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut tasks: JoinSet<(String, Result<()>)> = JoinSet::new();

    for listener in ingress_edge_configs {
        let rt = runtime.clone();
        let name = listener.name.clone();
        let tcp_listeners = listener_bindings
            .remove(name.as_str())
            .ok_or_else(|| anyhow::anyhow!("listener binding missing for {}", name))?;
        let task_shutdown = shutdown.clone();
        tasks.spawn(async move {
            let res = match listener.mode {
                qpx_core::config::IngressEdgeMode::Forward => {
                    forward::run_tcp(listener, rt, task_shutdown, tcp_listeners).await
                }
                qpx_core::config::IngressEdgeMode::Transparent => {
                    transparent::run_tcp(listener, rt, task_shutdown, tcp_listeners).await
                }
            };
            (format!("listener {}", name), res)
        });
    }

    for reverse_cfg in reverse_edge_configs {
        if !reverse::requires_tcp_listener(&reverse_cfg) {
            continue;
        }
        let rt = reverse_runtimes
            .get(reverse_cfg.name.as_str())
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("reloadable reverse missing for {}", reverse_cfg.name)
            })?;
        let tcp_listeners = reverse_bindings
            .remove(reverse_cfg.name.as_str())
            .ok_or_else(|| anyhow::anyhow!("reverse binding missing for {}", reverse_cfg.name))?;
        let name = reverse_cfg.name.clone();
        let task_shutdown = shutdown.clone();
        tasks.spawn(async move {
            (
                format!("reverse {}", name),
                reverse::run_tcp(reverse_cfg, rt, task_shutdown, tcp_listeners).await,
            )
        });
    }

    if tasks.is_empty() {
        loop {
            if shutdown.changed().await.is_err() || *shutdown.borrow() {
                return Ok(());
            }
        }
    }

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            joined = tasks.join_next() => {
                match joined {
                    Some(Ok((label, Ok(())))) => {
                        tasks.abort_all();
                        return Err(anyhow::anyhow!("{label} exited"));
                    }
                    Some(Ok((label, Err(err)))) => {
                        tasks.abort_all();
                        return Err(err).with_context(|| format!("{label} failed"));
                    }
                    Some(Err(err)) => {
                        tasks.abort_all();
                        return Err(anyhow::anyhow!("task join failed: {err}"));
                    }
                    None => return Err(anyhow::anyhow!("no tcp listener/reverse tasks running")),
                }
            }
        }
    }

    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((_label, Ok(()))) => {}
            Ok((label, Err(err))) => return Err(err).with_context(|| format!("{label} failed")),
            Err(err) => return Err(anyhow::anyhow!("task join failed: {err}")),
        }
    }
    Ok(())
}

async fn run_exportable_sidecar_server_set(args: ExportableSidecarServerSet) -> Result<()> {
    let ExportableSidecarServerSet {
        ingress_edge_configs,
        reverse_edge_configs,
        runtime,
        reverse_runtimes,
        mut listener_udp_bindings,
        mut reverse_udp_bindings,
        mut control,
        sidecar_restore,
        sidecar_export,
    } = args;
    let mut tasks: JoinSet<(String, Result<()>)> = JoinSet::new();
    let mut restore = sidecar_restore.unwrap_or_default();

    for listener in ingress_edge_configs {
        if !matches!(
            listener.mode,
            qpx_core::config::IngressEdgeMode::Transparent
        ) || !listener
            .http3
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false)
        {
            continue;
        }
        let rt = runtime.clone();
        let name = listener.name.clone();
        let listen = listener
            .http3
            .as_ref()
            .and_then(|cfg| cfg.listen.clone())
            .unwrap_or_else(|| listener.listen.clone());
        let udp_socket = listener_udp_bindings
            .remove(name.as_str())
            .ok_or_else(|| anyhow::anyhow!("udp listener binding missing for {}", name))?;
        let task_control = control.clone();
        let transparent_restore = if matches!(
            listener.mode,
            qpx_core::config::IngressEdgeMode::Transparent
        ) {
            restore.take_transparent(name.as_str(), listen.as_str())?
        } else {
            None
        };
        let export_sink = sidecar_export.clone();
        tasks.spawn(async move {
            let res = {
                #[cfg(feature = "http3")]
                {
                    transparent::run_udp(
                        listener,
                        rt,
                        task_control,
                        udp_socket,
                        transparent_restore,
                        export_sink,
                    )
                    .await
                }
                #[cfg(not(feature = "http3"))]
                {
                    let _ = rt;
                    let _ = task_control;
                    let _ = transparent_restore;
                    let _ = export_sink;
                    let _ = udp_socket;
                    let _ = listener;
                    Err(anyhow::anyhow!(
                        "transparent UDP sidecar requires http3 feature"
                    ))
                }
            };
            (format!("transparent-sidecar {}", name), res)
        });
    }

    for reverse_cfg in reverse_edge_configs {
        if !reverse_cfg
            .http3
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false)
            || reverse::requires_tcp_listener(&reverse_cfg)
        {
            continue;
        }
        let reverse_rt = reverse_runtimes
            .get(reverse_cfg.name.as_str())
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("reloadable reverse missing for {}", reverse_cfg.name)
            })?;
        let name = reverse_cfg.name.clone();
        let h3_cfg = reverse_cfg.http3.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "reverse {} enables http3 sidecar without http3 config",
                reverse_cfg.name
            )
        })?;
        let listen = reverse_cfg
            .http3
            .as_ref()
            .and_then(|cfg| cfg.listen.clone())
            .unwrap_or_else(|| reverse_cfg.listen.clone());
        let listen_addr: std::net::SocketAddr = listen.parse()?;
        let resolve_timeout =
            std::time::Duration::from_millis(runtime.state().plan.limits.upstream_http_timeout_ms);
        let udp_socket = reverse_udp_bindings
            .remove(reverse_cfg.name.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!("udp reverse binding missing for {}", reverse_cfg.name)
            })?;
        let task_control = control.clone();
        let passthrough_restore = if !reverse::requires_tcp_listener(&reverse_cfg) {
            restore.take_reverse_passthrough(name.as_str(), listen.as_str())?
        } else {
            None
        };
        let export_sink = sidecar_export.clone();
        tasks.spawn(async move {
            let res = {
                #[cfg(feature = "http3")]
                {
                    let passthrough_targets = h3_cfg.passthrough_upstreams.clone();
                    reverse::h3_passthrough::run_http3_passthrough(
                        listen_addr,
                        passthrough_targets,
                        &h3_cfg,
                        reverse::h3_passthrough::Http3PassthroughRuntime {
                            reverse: reverse_rt,
                            upstream_resolve_timeout: resolve_timeout,
                            shutdown: task_control,
                            listener_socket: udp_socket,
                            restore: passthrough_restore,
                            export_sink,
                        },
                    )
                    .await
                }
                #[cfg(not(feature = "http3"))]
                {
                    let _ = h3_cfg;
                    let _ = listen_addr;
                    let _ = resolve_timeout;
                    let _ = passthrough_restore;
                    let _ = export_sink;
                    let _ = reverse_rt;
                    let _ = task_control;
                    let _ = udp_socket;
                    Err(anyhow::anyhow!(
                        "reverse HTTP/3 sidecar requires http3 feature"
                    ))
                }
            };
            (format!("reverse-passthrough-sidecar {}", name), res)
        });
    }

    restore.ensure_consumed()?;

    if tasks.is_empty() {
        loop {
            if control.changed().await.is_err() || control.borrow().should_stop() {
                return Ok(());
            }
        }
    }

    let mut stop_mode = sidecar_control::SidecarControl::Running;
    loop {
        tokio::select! {
            changed = control.changed(), if !stop_mode.should_stop() => {
                if changed.is_err() {
                    stop_mode = sidecar_control::SidecarControl::Stop;
                } else {
                    stop_mode = *control.borrow();
                }
                if tasks.is_empty() {
                    return Ok(());
                }
            }
            joined = tasks.join_next() => {
                match joined {
                    Some(Ok((label, Ok(())))) => {
                        if stop_mode.should_stop() {
                            if tasks.is_empty() {
                                return Ok(());
                            }
                        } else {
                            return Err(anyhow::anyhow!("{label} exited"));
                        }
                    }
                    Some(Ok((label, Err(err)))) => {
                        return Err(err).with_context(|| format!("{label} failed"));
                    }
                    Some(Err(err)) => {
                        return Err(anyhow::anyhow!("task join failed: {err}"));
                    }
                    None => {
                        if stop_mode.should_stop() {
                            return Ok(());
                        }
                        return Err(anyhow::anyhow!("no udp/http3 sidecar tasks running"));
                    }
                }
            }
        }
    }
}

#[cfg(feature = "http3")]
async fn run_brokered_h3_server_set(
    ingress_edge_configs: Vec<qpx_core::config::IngressEdgeConfig>,
    reverse_edge_configs: Vec<qpx_core::config::ReverseEdgeConfig>,
    runtime: runtime::Runtime,
    reverse_runtimes: std::collections::HashMap<String, reverse::ReloadableReverse>,
    mut listener_h3_sockets: std::collections::HashMap<
        String,
        crate::http3::quinn_socket::QuinnEndpointSocket,
    >,
    mut reverse_h3_sockets: std::collections::HashMap<
        String,
        crate::http3::quinn_socket::QuinnEndpointSocket,
    >,
    mut control: watch::Receiver<sidecar_control::SidecarControl>,
) -> Result<()> {
    let mut tasks: JoinSet<(String, Result<()>)> = JoinSet::new();

    for listener in ingress_edge_configs {
        if !matches!(listener.mode, qpx_core::config::IngressEdgeMode::Forward)
            || !listener
                .http3
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false)
        {
            continue;
        }
        let rt = runtime.clone();
        let name = listener.name.clone();
        let endpoint_socket = listener_h3_sockets
            .remove(name.as_str())
            .ok_or_else(|| anyhow::anyhow!("forward HTTP/3 endpoint missing for {}", name))?;
        let task_control = control.clone();
        tasks.spawn(async move {
            (
                format!("forward-h3-sidecar {}", name),
                forward::run_h3(listener, rt, task_control, endpoint_socket).await,
            )
        });
    }

    for reverse_cfg in reverse_edge_configs {
        if !reverse_cfg
            .http3
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false)
            || !reverse::requires_tcp_listener(&reverse_cfg)
        {
            continue;
        }
        let reverse_rt = reverse_runtimes
            .get(reverse_cfg.name.as_str())
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("reloadable reverse missing for {}", reverse_cfg.name)
            })?;
        let name = reverse_cfg.name.clone();
        let listen_addr: std::net::SocketAddr = reverse_cfg
            .http3
            .as_ref()
            .and_then(|cfg| cfg.listen.clone())
            .unwrap_or_else(|| reverse_cfg.listen.clone())
            .parse()?;
        let endpoint_socket = reverse_h3_sockets
            .remove(name.as_str())
            .ok_or_else(|| anyhow::anyhow!("reverse HTTP/3 endpoint missing for {}", name))?;
        let task_control = control.clone();
        tasks.spawn(async move {
            (
                format!("reverse-terminate-h3-sidecar {}", name),
                reverse::h3_terminate::run_http3_terminate(
                    reverse_cfg,
                    listen_addr,
                    reverse_rt,
                    task_control,
                    endpoint_socket,
                )
                .await,
            )
        });
    }

    if tasks.is_empty() {
        loop {
            if control.changed().await.is_err() || control.borrow().should_stop() {
                return Ok(());
            }
        }
    }

    loop {
        tokio::select! {
            changed = control.changed() => {
                if changed.is_err() || control.borrow().should_stop() {
                    break;
                }
            }
            joined = tasks.join_next() => {
                match joined {
                    Some(Ok((label, Ok(())))) => {
                        tasks.abort_all();
                        return Err(anyhow::anyhow!("{label} exited"));
                    }
                    Some(Ok((label, Err(err)))) => {
                        tasks.abort_all();
                        return Err(err).with_context(|| format!("{label} failed"));
                    }
                    Some(Err(err)) => {
                        tasks.abort_all();
                        return Err(anyhow::anyhow!("task join failed: {err}"));
                    }
                    None => return Err(anyhow::anyhow!("no brokered HTTP/3 sidecar tasks running")),
                }
            }
        }
    }

    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((_label, Ok(()))) => {}
            Ok((label, Err(err))) => return Err(err).with_context(|| format!("{label} failed")),
            Err(err) => return Err(anyhow::anyhow!("task join failed: {err}")),
        }
    }
    Ok(())
}

async fn wait_for_connection_drain(runtime: &runtime::Runtime) {
    let semaphore = runtime.state().resources.connection_semaphore.clone();
    let target = runtime.state().plan.limits.max_concurrent_connections;
    while semaphore.available_permits() < target {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn init_templates_are_valid_canonical_configs() {
        for template in [
            InitTemplate::ReverseBasic,
            InitTemplate::ForwardEgress,
            InitTemplate::TransparentLinux,
            InitTemplate::IpcGateway,
            InitTemplate::TrustedIdentityExtAuthz,
        ] {
            let path = temp_config_path(template);
            fs::write(&path, init_template_yaml(template)).expect("write template config");
            let loaded = qpx_core::config::load_config(&path)
                .unwrap_or_else(|err| panic!("{template:?} template failed to load: {err:?}"));
            let _runtime = RuntimeState::build(loaded).unwrap_or_else(|err| {
                panic!("{template:?} template failed runtime build: {err:?}")
            });
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn schema_command_covers_canonical_cli_surface() {
        let schema = qpx_core::config::canonical_schema_value();
        assert_eq!(
            schema
                .pointer("/$schema")
                .and_then(serde_json::Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
        assert_eq!(
            schema
                .pointer("/required/0")
                .and_then(serde_json::Value::as_str),
            Some("edges")
        );
        assert!(schema.pointer("/$defs/capturePolicy").is_some());
        assert!(schema.pointer("/$defs/routeTarget/oneOf").is_some());
        assert!(schema.pointer("/$defs/ipcBodyLimit").is_some());
        assert!(schema.pointer("/$defs/originalDst").is_some());
        assert_eq!(
            schema
                .pointer("/$defs/httpModule/additionalProperties")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert!(schema
            .pointer("/$defs/httpModule/properties/settings")
            .is_some());
        assert!(schema.pointer("/properties/edges/items/oneOf").is_some());

        let json = serde_json::to_string_pretty(&schema).expect("json schema render");
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"reverse\""));
        assert!(json.contains("\"original_dst\""));
        assert!(json.contains("\"max_request_bytes\""));
        assert!(json.contains("\"module_chains\""));

        let yaml = serde_yaml::to_string(&schema).expect("yaml schema render");
        assert!(yaml.contains("capturePolicy"));
        assert!(yaml.contains("routeTarget"));
    }

    #[test]
    fn explain_renderer_uses_compiled_runtime_plan_flags() {
        let state = runtime_state_from_template(InitTemplate::ReverseBasic);
        let output = render_explain_plan(state.plan.as_ref(), Some("public-http"), Some("app"));

        assert!(output.contains("edge public-http"));
        assert!(output.contains("  kind: reverse"));
        assert!(output.contains("  route app match_criteria"));
        assert!(output.contains("    host"));
        assert!(output.contains("      mode: exact"));
        assert!(output.contains("  route app target"));
        assert!(output.contains("    type: upstream"));
        assert!(output.contains("  route app"));
        assert!(output.contains("    cache_lookup: off"));
        assert!(output.contains("    capture_plaintext: off"));
    }

    #[test]
    fn match_renderer_uses_compiled_matchers() {
        let state = runtime_state_from_template(InitTemplate::ReverseBasic);
        let matched = render_match_plan(
            state.plan.as_ref(),
            "public-http",
            None,
            None,
            None,
            Some("localhost"),
            Some("GET"),
            Some("/"),
        )
        .expect("match render");
        assert!(matched.contains("edge: public-http"));
        assert!(matched.contains("kind: reverse"));
        assert!(matched.contains("route: app"));
        assert!(matched.contains("matched_by\n"));
        assert!(matched.contains("  host\n"));
        assert!(matched.contains("    mode: exact\n"));
        assert!(matched.contains("    configured: localhost\n"));
        assert!(matched.contains("    actual: localhost\n"));
        assert!(matched.contains("    result: on\n"));
        assert!(matched.contains("target"));
        assert!(matched.contains("type: upstream"));

        let missed = render_match_plan(
            state.plan.as_ref(),
            "public-http",
            None,
            None,
            None,
            Some("example.invalid"),
            Some("GET"),
            Some("/"),
        )
        .expect("match render");
        assert!(missed.contains("route: <no match>"));
    }

    #[test]
    fn match_renderer_reports_reverse_forward_and_transparent_reasons() {
        let state = runtime_state_from_yaml(
            "trace",
            r#"
edges:
- kind: reverse
  name: trace-reverse
  listen: 127.0.0.1:0
  routes:
  - name: api
    match:
      src_ip: [10.0.0.0/8]
      sni: [api.example.com]
      host: [api.example.com]
      method: [GET]
      path:
      - /v1/*
      - /files/*.json
      - re:^/v[0-9]+/users$
    target:
      type: upstream
      upstreams: [http://127.0.0.1:8080]
- kind: forward
  name: trace-forward
  listen: 127.0.0.1:0
  default_action:
    type: block
  rules:
  - name: upload
    match:
      src_ip: [192.0.2.0/24]
      method: [POST]
      path: [/upload/*]
    action:
      type: direct
- kind: transparent
  name: trace-transparent
  listen: 127.0.0.1:0
  original_dst:
    source: linux_so_original_dst
  default_action:
    type: block
  rules:
  - name: internal
    match:
      host: [internal.example.com]
      dst_port: [8080]
    action:
      type: direct
"#,
        );

        let reverse = render_match_plan(
            state.plan.as_ref(),
            "trace-reverse",
            Some("10.1.2.3".parse().expect("ip")),
            None,
            Some("api.example.com"),
            Some("api.example.com"),
            Some("GET"),
            Some("/v2/users"),
        )
        .expect("reverse match");
        assert!(reverse.contains("route: api"));
        assert!(reverse.contains("  src_ip\n"));
        assert!(reverse.contains("    mode: cidr\n"));
        assert!(reverse.contains("  sni\n"));
        assert!(reverse.contains("  host\n"));
        assert!(reverse.contains("  method\n"));
        assert!(reverse.contains("    mode: prefix\n"));
        assert!(reverse.contains("    mode: glob\n"));
        assert!(reverse.contains("    mode: regex\n"));

        let forward = render_match_plan(
            state.plan.as_ref(),
            "trace-forward",
            Some("192.0.2.44".parse().expect("ip")),
            None,
            None,
            None,
            Some("POST"),
            Some("/upload/file"),
        )
        .expect("forward match");
        assert!(forward.contains("kind: forward"));
        assert!(forward.contains("rule: upload"));
        assert!(forward.contains("  src_ip\n"));
        assert!(forward.contains("  path\n"));

        let transparent = render_match_plan(
            state.plan.as_ref(),
            "trace-transparent",
            None,
            Some(8080),
            None,
            Some("internal.example.com"),
            Some("GET"),
            Some("/"),
        )
        .expect("transparent match");
        assert!(transparent.contains("kind: transparent"));
        assert!(transparent.contains("rule: internal"));
        assert!(transparent.contains("  host\n"));
        assert!(transparent.contains("  dst_port\n"));
    }

    #[test]
    fn explain_renderer_reports_all_reverse_target_kinds_and_generated_route_id() {
        let state = runtime_state_from_yaml(
            "target-kinds",
            r#"
edges:
- kind: reverse
  name: targets
  listen: 127.0.0.1:0
  tls:
    certificates:
    - sni: fallback.example.com
      cert: /tmp/qpx-test.crt
      key: /tmp/qpx-test.key
  routes:
  - match:
      host: [upstream.example.com]
    target:
      type: upstream
      upstreams: [http://127.0.0.1:8080]
  - name: weighted
    match:
      host: [weighted.example.com]
    target:
      type: weighted
      backends:
      - name: stable
        weight: 90
        upstreams: [http://127.0.0.1:8081]
      - name: canary
        weight: 10
        upstreams: [http://127.0.0.1:8082]
  - name: ipc
    match:
      host: [ipc.example.com]
    target:
      type: ipc
      endpoint: 127.0.0.1:19090
      mode: tcp
  - name: local
    match:
      host: [local.example.com]
    target:
      type: local_response
      response:
        status: 204
  tls_passthrough_routes:
  - match:
      dst_port: [443]
      sni: [tls.example.com]
    upstreams: [127.0.0.1:8443]
"#,
        );

        let output = render_explain_plan(state.plan.as_ref(), Some("targets"), None);
        assert!(output.contains("  route route[0] match_criteria"));
        assert!(output.contains("  route route[0] target"));
        assert!(output.contains("    type: upstream"));
        assert!(output.contains("  route weighted target"));
        assert!(output.contains("    type: weighted"));
        assert!(output.contains("  route ipc target"));
        assert!(output.contains("    type: ipc"));
        assert!(output.contains("  route local target"));
        assert!(output.contains("    type: local_response"));
        assert!(output.contains("  route tls_passthrough[0] target"));
        assert!(output.contains("    type: tls_passthrough"));
    }

    fn runtime_state_from_template(template: InitTemplate) -> RuntimeState {
        let path = temp_config_path(template);
        fs::write(&path, init_template_yaml(template)).expect("write template config");
        let loaded = qpx_core::config::load_config(&path).expect("template config loads");
        let _ = fs::remove_file(path);
        RuntimeState::build(loaded).expect("template runtime builds")
    }

    fn runtime_state_from_yaml(name: &str, yaml: &str) -> RuntimeState {
        let mut path = std::env::temp_dir();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        path.push(format!("qpxd-cli-{name}-{}-{now}.yaml", std::process::id()));
        fs::write(&path, yaml).expect("write config");
        let loaded = qpx_core::config::load_config(&path).expect("config loads");
        let _ = fs::remove_file(path);
        RuntimeState::build(loaded).expect("runtime builds")
    }

    fn temp_config_path(template: InitTemplate) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        path.push(format!(
            "qpxd-cli-template-{}-{}-{template:?}.yaml",
            std::process::id(),
            now
        ));
        path
    }
}
