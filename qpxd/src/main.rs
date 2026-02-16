use anyhow::Result;
use clap::{Parser, Subcommand};
use qpx_core::config::{load_config, Config};
use qpx_core::observability::{init_logging, start_metrics};
use std::path::PathBuf;
use tokio::task::JoinHandle;
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
mod forward;
mod ftp;
mod http;
#[cfg(feature = "http3")]
mod http3;
mod io_copy;
mod net;
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
        #[arg(short, long)]
        config: PathBuf,
    },
    Check {
        #[arg(short, long)]
        config: PathBuf,
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
        Command::Check { config } => {
            let _ = load_config(&config)?;
            println!("config ok");
            Ok(())
        }
        #[cfg(feature = "tls-rustls")]
        Command::GenCa { state_dir } => {
            let (cert, key) = write_ca_files(&state_dir)?;
            println!("generated ca: {} {}", cert.display(), key.display());
            Ok(())
        }
    }
}

fn run_with_runtime(config_path: PathBuf) -> Result<()> {
    let config = load_config(&config_path)?;
    let worker_threads = net::worker_threads(&config.runtime);
    let max_blocking_threads = net::max_blocking_threads(&config.runtime);

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .worker_threads(worker_threads)
        .max_blocking_threads(max_blocking_threads)
        .enable_all();

    let runtime = builder.build()?;
    runtime.block_on(run(config_path, config))
}

async fn run(config_path: PathBuf, config: Config) -> Result<()> {
    init_logging(&config.logging)?;
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
    let mut tasks: Vec<JoinHandle<Result<()>>> = Vec::new();

    for listener in config.listeners.clone() {
        let rt = runtime.clone();
        tasks.push(tokio::spawn(async move {
            match listener.mode {
                qpx_core::config::ListenerMode::Forward => forward::run(listener, rt).await,
                qpx_core::config::ListenerMode::Transparent => transparent::run(listener, rt).await,
            }
        }));
    }

    for reverse_cfg in config.reverse.clone() {
        let rt = runtime.clone();
        tasks.push(tokio::spawn(
            async move { reverse::run(reverse_cfg, rt).await },
        ));
    }

    let reload_rt = runtime.clone();
    let reload_path = config_path.clone();
    let reload_config = config.clone();
    tokio::spawn(async move {
        if let Err(err) = watch_config(reload_path, reload_config, reload_rt).await {
            warn!(error = ?err, "config watcher failed");
        }
    });

    info!("qpxd started");
    for task in tasks {
        if let Ok(Err(err)) = task.await {
            warn!(error = ?err, "task exited");
        }
    }
    Ok(())
}

async fn watch_config(
    path: PathBuf,
    current: qpx_core::config::Config,
    runtime: runtime::Runtime,
) -> Result<()> {
    use std::collections::HashSet;
    use tokio::sync::mpsc;

    let (tx, mut rx) = mpsc::channel(4);
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.blocking_send(res);
    })?;
    let mut watched = HashSet::new();
    let (_, sources) = qpx_core::config::load_config_with_sources(&path)?;
    refresh_watches(&mut watcher, &mut watched, sources)?;

    let mut current = current;
    while let Some(event) = rx.recv().await {
        match event {
            Ok(_) => match qpx_core::config::load_config_with_sources(&path) {
                Ok((new_config, sources)) => {
                    if runtime::ensure_hot_reload_compatible(&current, &new_config).is_err() {
                        warn!("listener/reverse topology changed; reload ignored");
                        continue;
                    }
                    match runtime::RuntimeState::build(new_config.clone()) {
                        Ok(state) => {
                            runtime.swap(state);
                            let _ = refresh_watches(&mut watcher, &mut watched, sources);
                            info!("config reloaded");
                            current = new_config;
                        }
                        Err(err) => warn!(error = ?err, "config reload failed"),
                    }
                }
                Err(err) => warn!(error = ?err, "config reload parse failed"),
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
