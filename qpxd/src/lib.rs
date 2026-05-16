#![recursion_limit = "256"]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use qpx_core::config::{Config as ProxyConfig, load_configs, load_configs_with_sources};
use qpx_observability::init_logging;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{info, warn};

#[cfg(test)]
pub(crate) fn test_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(all(feature = "http3", not(feature = "tls-rustls")))]
compile_error!("qpxd: feature http3 requires tls-rustls");

#[cfg(all(
    feature = "http3",
    not(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))
))]
compile_error!("qpxd: feature http3 requires at least one HTTP/3 backend feature");

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
mod config_reload;
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
mod server_sets;
mod server_tasks;
mod sidecar_control;
mod tcp_bindings;
#[cfg(test)]
mod test_util;
mod tls;
mod transparent;
mod tunnel;
mod udp_bindings;
mod udp_session_handoff;
mod udp_socket_handoff;
mod upgrade;
mod upstream;
mod windows_handoff;
mod xdp;

pub mod module_api {
    pub use crate::http::body::{Body, BodyError, Sender, to_bytes};
    pub use crate::http::modules::{
        BodyAccess, CacheLookupStatus, HttpModule, HttpModuleCapabilities, HttpModuleContext,
        HttpModuleEvent, HttpModuleFactory, HttpModuleRegistry, HttpModuleRegistryBuilder,
        HttpModuleRequestView, HttpModuleStage, ModuleStages, RequestHeadersOutcome, RetryEvent,
        default_http_module_registry,
    };
}

pub use qpx_core::config::{Config, HttpModuleConfig};
pub use runtime::{Runtime, RuntimeState};
use server_sets::wait_for_connection_drain;
use server_tasks::{AdminTasks, ProxyTasks};

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
                MatchConfigRequest {
                    edge,
                    src_ip,
                    dst_port,
                    sni,
                    host,
                    method,
                    path,
                },
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
    let plan = runtime::RuntimeState::compile_plan_with_http_module_registry(
        config,
        http_module_registry,
    )?;
    print!(
        "{}",
        cli_render::render_explain_plan(&plan, edge_filter.as_deref(), route_filter.as_deref())
    );
    Ok(())
}

struct MatchConfigRequest {
    edge: String,
    src_ip: Option<IpAddr>,
    dst_port: Option<u16>,
    sni: Option<String>,
    host: Option<String>,
    method: Option<String>,
    path: Option<String>,
}

fn match_config(
    config_paths: Vec<PathBuf>,
    request: MatchConfigRequest,
    http_module_registry: Arc<http::modules::HttpModuleRegistry>,
) -> Result<()> {
    let config = load_configs(&config_paths)?;
    let plan = runtime::RuntimeState::compile_plan_with_http_module_registry(
        config,
        http_module_registry,
    )?;
    print!(
        "{}",
        cli_render::render_match_plan(
            &plan,
            cli_render::MatchPlanRequest {
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
        config_reload::ConfigReloadHandler::new(config_paths.clone(), http_module_registry.clone());
    let config_watcher = start_config_watcher(&config_paths)?;
    let mut upgrade_trigger = upgrade::install_upgrade_trigger()?;

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
    runtime: &mut runtime::Runtime,
    mut proxy: ProxyTasks,
    mut admin: AdminTasks,
    reload_handler: &config_reload::ConfigReloadHandler,
    mut config_watcher: ConfigWatcher,
    upgrade_trigger: &mut Option<upgrade::UpgradeTrigger>,
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
                if config_reload::handle_upgrade_request(
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

#[cfg(test)]
mod cli_tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn render_test_match_plan(
        plan: &runtime::RuntimePlan,
        edge: &str,
        ctx: qpx_core::rules::RuleMatchContext<'_>,
    ) -> Result<String> {
        render_match_plan(plan, cli_render::MatchPlanRequest { edge, ctx })
    }

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
        assert!(
            schema
                .pointer("/$defs/httpModule/properties/settings")
                .is_some()
        );
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
        let matched = render_test_match_plan(
            state.plan.as_ref(),
            "public-http",
            qpx_core::rules::RuleMatchContext {
                host: Some("localhost"),
                method: Some("GET"),
                path: Some("/"),
                ..Default::default()
            },
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

        let missed = render_test_match_plan(
            state.plan.as_ref(),
            "public-http",
            qpx_core::rules::RuleMatchContext {
                host: Some("example.invalid"),
                method: Some("GET"),
                path: Some("/"),
                ..Default::default()
            },
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

        let reverse = render_test_match_plan(
            state.plan.as_ref(),
            "trace-reverse",
            qpx_core::rules::RuleMatchContext {
                src_ip: Some("10.1.2.3".parse().expect("ip")),
                sni: Some("api.example.com"),
                host: Some("api.example.com"),
                method: Some("GET"),
                path: Some("/v2/users"),
                ..Default::default()
            },
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

        let forward = render_test_match_plan(
            state.plan.as_ref(),
            "trace-forward",
            qpx_core::rules::RuleMatchContext {
                src_ip: Some("192.0.2.44".parse().expect("ip")),
                method: Some("POST"),
                path: Some("/upload/file"),
                ..Default::default()
            },
        )
        .expect("forward match");
        assert!(forward.contains("kind: forward"));
        assert!(forward.contains("rule: upload"));
        assert!(forward.contains("  src_ip\n"));
        assert!(forward.contains("  path\n"));

        let transparent = render_test_match_plan(
            state.plan.as_ref(),
            "trace-transparent",
            qpx_core::rules::RuleMatchContext {
                dst_port: Some(8080),
                host: Some("internal.example.com"),
                method: Some("GET"),
                path: Some("/"),
                ..Default::default()
            },
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
