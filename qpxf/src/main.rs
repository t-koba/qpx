use anyhow::Result;
use clap::{Args, Parser, Subcommand};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::Duration;
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "qpxf", about = "qpx IPC function executor")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    run: RunArgs,
}

#[derive(Args, Default)]
struct RunArgs {
    /// Listen address (TCP "host:port" or Unix socket path prefixed with "unix://").
    /// Overrides the config file's `listen` field when provided.
    #[arg(short, long)]
    listen: Option<String>,

    /// Path to configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Number of worker tasks (concurrency limit). Overrides config.
    #[arg(short, long)]
    workers: Option<usize>,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a qpxf config, including backend-specific handler initialization.
    Check {
        /// Path to configuration file.
        #[arg(short, long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Check { config }) => check_config(config),
        None => run_server(cli.run).await,
    }
}

fn check_config(config_path: PathBuf) -> Result<()> {
    let cfg = qpxf::config::load_config(&config_path)?;
    cfg.validate()?;
    let _router = Arc::new(qpxf::router::Router::new(&cfg)?);
    println!("config ok");
    Ok(())
}

async fn run_server(args: RunArgs) -> Result<()> {
    let config_path = args
        .config
        .ok_or_else(|| anyhow::anyhow!("--config is required"))?;

    let mut cfg = qpxf::config::load_config(&config_path)?;
    if let Some(listen) = args.listen {
        cfg.listen = listen;
    }
    if let Some(workers) = args.workers {
        cfg.workers = workers;
    }
    cfg.validate()?;

    let listen = cfg.listen.clone();
    let workers = cfg.workers;
    let max_requests_per_connection = cfg.max_requests_per_connection;
    let max_params_bytes = cfg.max_params_bytes;
    let max_stdin_bytes = cfg.max_stdin_bytes;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let router = Arc::new(qpxf::router::Router::new(&cfg)?);
    let semaphore = Arc::new(Semaphore::new(workers));
    let conn_semaphore = Arc::new(Semaphore::new(cfg.max_connections));
    let input_idle = Duration::from_millis(cfg.input_idle_timeout_ms);
    let conn_idle = Duration::from_millis(cfg.conn_idle_timeout_ms);

    if listen.starts_with("unix://") {
        #[cfg(unix)]
        {
            let path = listen.strip_prefix("unix://").unwrap();
            ensure_unix_socket_parent_secure(Path::new(path))?;
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
            // Avoid umask-dependent exposure: this IPC surface must be local-user only by default.
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
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
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = qpxf::server::handle_connection(
                        stream,
                        qpxf::server::ConnectionContext {
                            router,
                            semaphore: sem,
                            input_idle,
                            conn_idle,
                            max_requests_per_connection,
                            max_params_bytes,
                            max_stdin_bytes,
                        },
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
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = qpxf::server::handle_connection(
                    stream,
                    qpxf::server::ConnectionContext {
                        router,
                        semaphore: sem,
                        input_idle,
                        conn_idle,
                        max_requests_per_connection,
                        max_params_bytes,
                        max_stdin_bytes,
                    },
                )
                .await
                {
                    warn!(peer = %peer, error = %e, "connection error");
                }
            });
        }
    }
}

#[cfg(unix)]
fn ensure_unix_socket_parent_secure(path: &Path) -> Result<()> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    ensure_secure_dir_components(parent, "qpxf Unix socket")?;
    Ok(())
}

#[cfg(unix)]
fn ensure_secure_dir_components(path: &Path, label: &str) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    current = resolve_trusted_symlink_component(&current, &meta, label)?;
                    continue;
                }
                if !meta.is_dir() {
                    return Err(anyhow::anyhow!(
                        "{label} path component is not a directory: {}",
                        current.display()
                    ));
                }
                reject_untrusted_dir_component(&current, &meta, label)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current)?;
                std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o700))?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn resolve_trusted_symlink_component(
    path: &Path,
    meta: &std::fs::Metadata,
    label: &str,
) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow::anyhow!(
            "{label} path must not contain untrusted symlink component: {}",
            path.display()
        ));
    }
    let resolved = std::fs::canonicalize(path)?;
    let resolved_meta = std::fs::metadata(&resolved)?;
    if !resolved_meta.is_dir() {
        return Err(anyhow::anyhow!(
            "{label} symlink target is not a directory: {}",
            resolved.display()
        ));
    }
    reject_untrusted_dir_component(&resolved, &resolved_meta, label)?;
    Ok(resolved)
}

#[cfg(unix)]
fn reject_untrusted_dir_component(
    path: &Path,
    meta: &std::fs::Metadata,
    label: &str,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let mode = meta.mode();
    let sticky = mode & libc::S_ISVTX as u32 != 0;
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow::anyhow!(
            "refusing {label} ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if sticky && mode & 0o022 != 0 && meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow::anyhow!(
            "refusing sticky writable {label} ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if mode & 0o002 != 0 && !sticky {
        return Err(anyhow::anyhow!(
            "refusing attacker-writable {label} ancestor directory {}",
            path.display()
        ));
    }
    if !sticky && mode & 0o020 != 0 && meta.uid() != euid {
        return Err(anyhow::anyhow!(
            "refusing group-writable {label} ancestor directory not owned by current user: {}",
            path.display()
        ));
    }
    Ok(())
}
