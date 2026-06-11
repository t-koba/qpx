mod cli;
mod hub;
mod ingest;
mod pcap;
mod security;
mod stream;

use anyhow::{Context, Result};
use clap::Parser;
use cli::Cli;
use hub::ExporterHub;
use ingest::run_event_ingest_loop;
use pcap::build_pcap_preface;
use qpx_core::shm_ring::ShmRingBuffer;
use security::{SecurityPosture, build_tls_acceptor, load_required_env, parse_allowlist};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stream::{StreamAcceptContext, run_stream_accept_loop};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::info;

#[cfg(feature = "tls-rustls")]
type TlsAcceptor = tokio_rustls::TlsAcceptor;

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
type TlsAcceptor = tokio_native_tls::TlsAcceptor;

#[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
#[derive(Clone)]
struct NoTlsAcceptor;

#[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
type TlsAcceptor = NoTlsAcceptor;

pub async fn run() -> Result<()> {
    qpx_core::tls::init_rustls_crypto_provider();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let stream_listen: SocketAddr = cli.stream_listen.parse()?;
    let stream_allow = parse_allowlist(&cli.stream_allow)?;

    let token = match cli.token_env.as_deref() {
        Some(env) => Some(load_required_env(env)?),
        None => None,
    };

    let tls = build_tls_acceptor(&cli)?;
    validate_runtime_security(
        &cli,
        stream_listen,
        !stream_allow.is_empty(),
        token.is_some(),
        &tls,
    )?;

    let pcap_preface = Arc::new(build_pcap_preface()?);
    let hub = ExporterHub::new(
        cli.save_dir,
        cli.rotate_bytes,
        cli.history_bytes,
        Duration::from_secs(cli.history_secs),
        pcap_preface,
        cli.max_payload_bytes.max(1),
    )?;

    let shm_path = cli.shm_path.unwrap_or_else(|| {
        ShmRingBuffer::default_capture_shm_path()
            .to_string_lossy()
            .into_owned()
    });
    let ring = ShmRingBuffer::create_or_open(&shm_path, cli.shm_size_mb * 1024 * 1024)?;

    let stream_listener = TcpListener::bind(stream_listen)
        .await
        .with_context(|| format!("failed to bind stream listener: {}", stream_listen))?;

    info!(
        shm_path = %shm_path,
        stream_listen = %stream_listen,
        tls = %tls.is_some(),
        "qpxr started"
    );

    let event_task = tokio::spawn(run_event_ingest_loop(ring, hub.clone()));
    let stream_task = tokio::spawn(run_stream_accept_loop(
        stream_listener,
        StreamAcceptContext {
            hub,
            allow: stream_allow,
            token,
            tls,
            tls_accept_timeout: Duration::from_millis(cli.tls_accept_timeout_ms.max(1)),
            max_control_line_bytes: cli.max_control_line_bytes.max(1),
            handshake_timeout: Duration::from_millis(cli.handshake_timeout_ms.max(1)),
            connections: Arc::new(Semaphore::new(cli.max_connections.max(1))),
        },
    ));
    tokio::try_join!(event_task, stream_task).map(|(event, stream)| event.and(stream))??;
    Ok(())
}

fn validate_runtime_security(
    cli: &Cli,
    stream_listen: SocketAddr,
    stream_allow_configured: bool,
    token_enabled: bool,
    tls: &Option<TlsAcceptor>,
) -> Result<()> {
    security::validate_security_posture(&SecurityPosture {
        stream_listen,
        tls_enabled: tls.is_some(),
        stream_allow_configured,
        token_enabled,
        #[cfg(feature = "tls-rustls")]
        mtls_enabled: cli.tls_client_ca.is_some(),
        unsafe_allow_insecure: cli.unsafe_allow_insecure,
    })
}
