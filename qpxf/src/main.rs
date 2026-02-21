use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::Duration;
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "qpxf", about = "qpx FastCGI function executor")]
struct Cli {
    /// Listen address (TCP "host:port" or Unix socket path prefixed with "unix://").
    /// Overrides the config file's `listen` field when provided.
    #[arg(short, long)]
    listen: Option<String>,

    /// Path to configuration file.
    #[arg(short, long)]
    config: PathBuf,

    /// Number of worker tasks (concurrency limit). Overrides config.
    #[arg(short, long)]
    workers: Option<usize>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut cfg = qpxf::config::load_config(&cli.config)?;
    if let Some(listen) = cli.listen {
        cfg.listen = listen;
    }
    if let Some(workers) = cli.workers {
        cfg.workers = workers;
    }
    cfg.validate()?;

    let listen = cfg.listen.clone();
    let workers = cfg.workers;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let router = Arc::new(qpxf::router::Router::new(&cfg)?);
    let semaphore = Arc::new(Semaphore::new(workers));
    let conn_semaphore = Arc::new(Semaphore::new(cfg.max_connections));
    let limits = Arc::new(qpxf::fastcgi::RequestLimits {
        max_params_bytes: cfg.max_params_bytes,
        max_stdin_bytes: cfg.max_stdin_bytes,
    });
    let max_conns = cfg.max_connections;
    let max_reqs_per_conn = cfg.max_requests_per_connection;
    let input_idle = Duration::from_millis(cfg.input_idle_timeout_ms);
    let conn_idle = Duration::from_millis(cfg.conn_idle_timeout_ms);

    if listen.starts_with("unix://") {
        #[cfg(unix)]
        {
            let path = listen.strip_prefix("unix://").unwrap();
            // Only remove existing path if it is a Unix socket.
            if let Ok(meta) = std::fs::symlink_metadata(path) {
                use std::os::unix::fs::FileTypeExt;
                if meta.file_type().is_socket() {
                    let _ = std::fs::remove_file(path);
                } else {
                    return Err(anyhow::anyhow!(
                        "path '{}' exists and is not a Unix socket",
                        path
                    ));
                }
            }
            let listener = tokio::net::UnixListener::bind(path)?;
            info!(listen = %listen, workers = workers, "qpxf listening (Unix socket)");
            loop {
                let (stream, _) = listener.accept().await?;
                let permit = match Arc::clone(&conn_semaphore).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("too many concurrent connections; dropping unix connection");
                        continue;
                    }
                };
                let router = Arc::clone(&router);
                let sem = Arc::clone(&semaphore);
                let lim = Arc::clone(&limits);
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = qpxf::server::handle_connection(
                        stream,
                        router,
                        sem,
                        lim,
                        input_idle,
                        conn_idle,
                        max_conns,
                        max_reqs_per_conn,
                    )
                    .await
                    {
                        warn!(error = %e, "connection error");
                    }
                });
            }
        }
        #[cfg(not(unix))]
        {
            return Err(anyhow::anyhow!(
                "Unix sockets are not supported on this platform"
            ));
        }
    } else {
        let listener = TcpListener::bind(&listen).await?;
        info!(listen = %listen, workers = workers, "qpxf listening (TCP)");
        loop {
            let (stream, peer) = listener.accept().await?;
            let permit = match Arc::clone(&conn_semaphore).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(peer = %peer, "too many concurrent connections; dropping");
                    continue;
                }
            };
            let router = Arc::clone(&router);
            let sem = Arc::clone(&semaphore);
            let lim = Arc::clone(&limits);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = qpxf::server::handle_connection(
                    stream,
                    router,
                    sem,
                    lim,
                    input_idle,
                    conn_idle,
                    max_conns,
                    max_reqs_per_conn,
                )
                .await
                {
                    warn!(peer = %peer, error = %e, "connection error");
                }
            });
        }
    }
}
