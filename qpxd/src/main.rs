use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use qpx_core::config::{load_configs, load_configs_with_sources, Config};
use qpx_core::observability::{init_logging, start_metrics};
use std::path::PathBuf;
use tokio::task::JoinSet;
use tracing::{info, warn};

#[cfg(all(feature = "tls-rustls", feature = "tls-native"))]
compile_error!("qpxd: features tls-rustls and tls-native are mutually exclusive");

#[cfg(all(feature = "http3", not(feature = "tls-rustls")))]
compile_error!("qpxd: feature http3 requires tls-rustls");

#[cfg(all(feature = "mitm", not(feature = "tls-rustls")))]
compile_error!("qpxd: feature mitm requires tls-rustls");

#[cfg(feature = "tls-rustls")]
use qpx_core::tls::write_ca_files;

mod cache;
mod exporter;
mod fastcgi_client;
mod forward;
mod ftp;
mod http;
#[cfg(feature = "http3")]
mod http3;
mod io_copy;
mod io_prefix;
mod net;
mod rate_limit;
mod reverse;
mod runtime;
mod tls;
mod transparent;
mod upstream;
mod xdp;

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
    #[cfg(feature = "tls-rustls")]
    GenCa {
        #[arg(short = 'd', long)]
        state_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { config } => run_with_runtime(config),
        Command::Check { config } => check_with_runtime(config),
        #[cfg(feature = "tls-rustls")]
        Command::GenCa { state_dir } => {
            let (cert, key) = write_ca_files(&state_dir)?;
            println!("generated ca: {} {}", cert.display(), key.display());
            Ok(())
        }
    }
}

fn run_with_runtime(config_paths: Vec<PathBuf>) -> Result<()> {
    let config = load_configs(&config_paths)?;
    let worker_threads = net::worker_threads(&config.runtime);
    let max_blocking_threads = net::max_blocking_threads(&config.runtime);

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .worker_threads(worker_threads)
        .max_blocking_threads(max_blocking_threads)
        .enable_all();

    let runtime = builder.build()?;
    runtime.block_on(run(config_paths, config))
}

fn check_with_runtime(config_paths: Vec<PathBuf>) -> Result<()> {
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
        let reverse_configs = config.reverse.clone();
        let _ = runtime::RuntimeState::build(config)?;
        for reverse in &reverse_configs {
            reverse::check_reverse_runtime(reverse)?;
        }
        Ok::<(), anyhow::Error>(())
    })?;
    println!("config ok");
    Ok(())
}

async fn run(config_paths: Vec<PathBuf>, config: Config) -> Result<()> {
    let _log_guards = init_logging(
        &config.system_log,
        &config.access_log,
        &config.audit_log,
        config.otel.as_ref(),
    )?;
    info!(
        worker_threads = net::worker_threads(&config.runtime),
        max_blocking_threads = net::max_blocking_threads(&config.runtime),
        acceptor_tasks_per_listener = net::acceptor_tasks_per_listener(&config.runtime),
        reuse_port = config.runtime.reuse_port,
        tcp_backlog = config.runtime.tcp_backlog,
        "runtime tuning"
    );
    if let Some(metrics) = &config.metrics {
        start_metrics(metrics)?;
    }

    let runtime = runtime::Runtime::new(config.clone())?;
    {
        let state = runtime.state();
        if let Some(ca_path) = state.ca_cert_path() {
            info!(ca_cert = %ca_path.display(), "tls inspection ca ready");
        }
    }
    let mut tasks: JoinSet<(String, Result<()>)> = JoinSet::new();

    for listener in config.listeners.clone() {
        let rt = runtime.clone();
        let name = listener.name.clone();
        tasks.spawn(async move {
            let res = match listener.mode {
                qpx_core::config::ListenerMode::Forward => forward::run(listener, rt).await,
                qpx_core::config::ListenerMode::Transparent => transparent::run(listener, rt).await,
            };
            (format!("listener {}", name), res)
        });
    }

    for reverse_cfg in config.reverse.clone() {
        let rt = runtime.clone();
        let name = reverse_cfg.name.clone();
        tasks.spawn(async move {
            (
                format!("reverse {}", name),
                reverse::run(reverse_cfg, rt).await,
            )
        });
    }

    let reload_rt = runtime.clone();
    let reload_paths = config_paths.clone();
    let reload_config = config.clone();
    tokio::spawn(async move {
        if let Err(err) = watch_config(reload_paths, reload_config, reload_rt).await {
            warn!(error = ?err, "config watcher failed");
        }
    });

    info!("qpxd started");
    if let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((label, Ok(()))) => {
                tasks.abort_all();
                return Err(anyhow::anyhow!("{label} exited"));
            }
            Ok((label, Err(err))) => {
                tasks.abort_all();
                return Err(err).with_context(|| format!("{label} failed"));
            }
            Err(err) => {
                tasks.abort_all();
                return Err(anyhow::anyhow!("task join failed: {err}"));
            }
        }
    }
    Err(anyhow::anyhow!("no listener/reverse tasks running"))
}

async fn watch_config(
    paths: Vec<PathBuf>,
    current: qpx_core::config::Config,
    runtime: runtime::Runtime,
) -> Result<()> {
    use std::collections::HashSet;
    use tokio::sync::mpsc;

    let configs = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let (tx, mut rx) = mpsc::channel(4);
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.blocking_send(res);
    })?;
    let mut watched = HashSet::new();
    let (_, sources) = load_configs_with_sources(&paths)?;
    refresh_watches(&mut watcher, &mut watched, sources)?;

    let mut current = current;
    while let Some(event) = rx.recv().await {
        match event {
            Ok(_) => match load_configs_with_sources(&paths) {
                Ok((new_config, sources)) => {
                    if runtime::ensure_hot_reload_compatible(&current, &new_config).is_err() {
                        warn!("listener/reverse topology changed; reload ignored");
                        if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
                            tracing::warn!(
                                target: "audit_log",
                                event = "config_reload",
                                outcome = "ignored",
                                reason = "hot_reload_incompatible",
                                configs = %configs,
                            );
                        }
                        continue;
                    }
                    if let Err(err) = new_config
                        .reverse
                        .iter()
                        .try_for_each(reverse::check_reverse_runtime)
                    {
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
                    match runtime::RuntimeState::build(new_config.clone()) {
                        Ok(state) => {
                            runtime.swap(state);
                            let _ = refresh_watches(&mut watcher, &mut watched, sources);
                            info!("config reloaded");
                            if tracing::enabled!(target: "audit_log", tracing::Level::INFO) {
                                tracing::info!(
                                    target: "audit_log",
                                    event = "config_reload",
                                    outcome = "applied",
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
    }
    Ok(())
}

fn refresh_watches(
    watcher: &mut dyn notify::Watcher,
    watched: &mut std::collections::HashSet<PathBuf>,
    sources: Vec<PathBuf>,
) -> Result<()> {
    let next: std::collections::HashSet<PathBuf> = sources.into_iter().collect();

    for stale in watched.difference(&next) {
        let _ = watcher.unwatch(stale);
    }
    for added in next.difference(watched) {
        watcher.watch(added, notify::RecursiveMode::NonRecursive)?;
    }

    *watched = next;
    Ok(())
}
