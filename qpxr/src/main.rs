use anyhow::{anyhow, Context, Result};
use byteorder_slice::LittleEndian;
use bytes::Bytes;
use cidr::IpCidr;
use clap::Parser;
use etherparse::PacketBuilder;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::blocks::section_header::{SectionHeaderBlock, SectionHeaderOption};
use pcap_file::pcapng::Block;
use pcap_file::{DataLink, Endianness};

use qpx_core::exporter::STREAM_PREFACE_LINE;
use qpx_core::exporter::{CaptureDirection, CaptureEvent, CapturePlane};
use qpx_core::shm_ring::ShmRingBuffer;
use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock, Semaphore};
use tokio::task::spawn_blocking;
use tokio::time::timeout;
use tracing::{info, warn};

#[cfg(all(feature = "tls-rustls", feature = "tls-native"))]
compile_error!("qpxr: features tls-rustls and tls-native are mutually exclusive");

#[cfg(feature = "tls-rustls")]
use qpx_core::tls::{load_cert_chain, load_private_key};
#[cfg(feature = "tls-rustls")]
use rustls::server::WebPkiClientVerifier;
#[cfg(feature = "tls-rustls")]
use rustls::RootCertStore;

#[cfg(feature = "tls-rustls")]
type TlsAcceptor = tokio_rustls::TlsAcceptor;

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
type TlsAcceptor = tokio_native_tls::TlsAcceptor;

#[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
#[derive(Clone)]
struct NoTlsAcceptor;

#[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
type TlsAcceptor = NoTlsAcceptor;

const DEFAULT_HISTORY_SECS: u64 = 3600;
const DEFAULT_MAX_CONTROL_LINE_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_SEQUENCE_KEYS: usize = 100_000;
const SEQUENCE_GC_INTERVAL_NANOS: u64 = 5_000_000_000;

#[derive(Parser)]
#[command(name = "qpxr", about = "qpx capture reader")]
struct Cli {
    #[arg(long)]
    shm_path: Option<String>,
    #[arg(long, default_value_t = 16)]
    shm_size_mb: usize,

    #[arg(short = 's', long, default_value = "127.0.0.1:19101")]
    stream_listen: String,

    /// Allowlist for qpxc stream clients (repeatable CIDR)
    #[arg(short = 'S', long, value_name = "CIDR")]
    stream_allow: Vec<String>,

    /// Require AUTH token (value is read from this env var)
    #[arg(short = 't', long)]
    token_env: Option<String>,

    /// Enable TLS with this server certificate (PEM)
    #[cfg(feature = "tls-rustls")]
    #[arg(short = 'C', long)]
    tls_cert: Option<PathBuf>,
    /// TLS private key for --tls-cert (PEM)
    #[cfg(feature = "tls-rustls")]
    #[arg(short = 'K', long)]
    tls_key: Option<PathBuf>,
    /// Require client certificates signed by this CA (PEM)
    #[cfg(feature = "tls-rustls")]
    #[arg(short = 'A', long)]
    tls_client_ca: Option<PathBuf>,

    /// Enable TLS with this PKCS#12 identity (.p12/.pfx)
    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
    #[arg(long)]
    tls_pkcs12: Option<PathBuf>,
    /// Password env var for --tls-pkcs12 (optional)
    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
    #[arg(long)]
    tls_pkcs12_password_env: Option<String>,
    #[arg(long, default_value_t = 5_000)]
    tls_accept_timeout_ms: u64,

    /// Allow insecure non-loopback operation (DANGEROUS)
    #[arg(long)]
    unsafe_allow_insecure: bool,

    #[arg(long, default_value_t = 1024)]
    max_connections: usize,
    #[arg(long, default_value_t = 10_000)]
    handshake_timeout_ms: u64,

    #[arg(short = 'd', long)]
    save_dir: Option<PathBuf>,
    #[arg(short = 'r', long, default_value_t = 100 * 1024 * 1024)]
    rotate_bytes: u64,
    #[arg(short = 'H', long, default_value_t = 256 * 1024 * 1024)]
    history_bytes: usize,
    #[arg(short = 'T', long, default_value_t = DEFAULT_HISTORY_SECS)]
    history_secs: u64,
    #[arg(long, default_value_t = DEFAULT_MAX_CONTROL_LINE_BYTES)]
    max_control_line_bytes: usize,
    #[arg(short = 'p', long, default_value_t = DEFAULT_MAX_PAYLOAD_BYTES)]
    max_payload_bytes: usize,
}

#[derive(Clone)]
struct ExporterHub {
    sequences: Arc<Mutex<SequencesState>>,
    history: Arc<RwLock<HistoryState>>,
    file_sink: Option<mpsc::Sender<Bytes>>,
    live_tx: broadcast::Sender<Bytes>,
    history_limit_bytes: usize,
    history_limit_age: Duration,
    pcap_preface: Arc<Vec<u8>>,
    max_payload_bytes: usize,
}

struct SequencesState {
    sequences: HashMap<SequenceKey, SequenceState>,
    sequences_last_gc_unix_nanos: u64,
}

struct HistoryState {
    history: VecDeque<HistoryItem>,
    history_bytes: usize,
}

struct HistoryItem {
    ts_unix_nanos: u64,
    bytes: Bytes,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct SequenceKey {
    session_id: String,
    plane: CapturePlane,
    direction: CaptureDirection,
}

#[derive(Clone, Copy)]
struct SequenceState {
    next: u32,
    last_seen_unix_nanos: u64,
}

struct RotatingFileSink {
    dir: PathBuf,
    rotate_bytes: u64,
    current_size: u64,
    index: u64,
    file: File,
    preface: Arc<Vec<u8>>,
    blocks_since_flush: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamMode {
    Live,
    History,
    Follow,
}

#[derive(Clone, Copy)]
struct Endpoint {
    ip: Ipv4Addr,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
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
    validate_security_posture(&SecurityPosture {
        stream_listen,
        tls_enabled: tls.is_some(),
        stream_allow_configured: !stream_allow.is_empty(),
        token_enabled: token.is_some(),
        #[cfg(feature = "tls-rustls")]
        mtls_enabled: cli.tls_client_ca.is_some(),
        unsafe_allow_insecure: cli.unsafe_allow_insecure,
    })?;

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
    let shm_size_bytes = cli.shm_size_mb * 1024 * 1024;
    let ring = ShmRingBuffer::create_or_open(&shm_path, shm_size_bytes)?;

    let stream_listener = TcpListener::bind(stream_listen)
        .await
        .with_context(|| format!("failed to bind stream listener: {}", stream_listen))?;

    info!(
        shm_path = %shm_path,
        stream_listen = %stream_listen,
        tls = %tls.is_some(),
        "qpxr started"
    );

    let tls_accept_timeout = Duration::from_millis(cli.tls_accept_timeout_ms.max(1));
    let max_control = cli.max_control_line_bytes.max(1);
    let handshake_timeout = Duration::from_millis(cli.handshake_timeout_ms.max(1));
    let connections = Arc::new(Semaphore::new(cli.max_connections.max(1)));

    let event_task = tokio::spawn(run_event_ingest_loop(ring, hub.clone()));
    let stream_task = tokio::spawn(run_stream_accept_loop(
        stream_listener,
        hub,
        stream_allow,
        token,
        tls,
        tls_accept_timeout,
        max_control,
        handshake_timeout,
        connections,
    ));
    let _ = tokio::try_join!(event_task, stream_task)?;
    Ok(())
}

fn parse_allowlist(raw: &[String]) -> Result<Vec<IpCidr>> {
    let mut out = Vec::new();
    for item in raw {
        let cidr: IpCidr = item
            .parse()
            .map_err(|_| anyhow!("invalid CIDR in allowlist: {}", item))?;
        out.push(cidr);
    }
    Ok(out)
}

fn load_required_env(name: &str) -> Result<String> {
    let value = std::env::var(name)
        .with_context(|| format!("{name} is required but not set"))?
        .trim()
        .to_string();
    if value.is_empty() {
        return Err(anyhow::Error::msg(format!("{name} is set but empty")));
    }
    Ok(value)
}

struct SecurityPosture {
    stream_listen: SocketAddr,
    tls_enabled: bool,
    stream_allow_configured: bool,
    token_enabled: bool,
    #[cfg(feature = "tls-rustls")]
    mtls_enabled: bool,
    unsafe_allow_insecure: bool,
}

fn validate_security_posture(sp: &SecurityPosture) -> Result<()> {
    for (label, addr, allow) in [("stream", sp.stream_listen, sp.stream_allow_configured)] {
        if addr.ip().is_loopback() {
            continue;
        }
        if sp.unsafe_allow_insecure {
            continue;
        }
        if !sp.tls_enabled {
            #[cfg(feature = "tls-rustls")]
            {
                return Err(anyhow!(
                    "{label}.listen is non-loopback ({addr}) but TLS is not enabled; set --tls-cert/--tls-key or --unsafe-allow-insecure"
                ));
            }
            #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
            {
                return Err(anyhow!(
                    "{label}.listen is non-loopback ({addr}) but TLS is not enabled; set --tls-pkcs12 or --unsafe-allow-insecure"
                ));
            }
            #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
            {
                return Err(anyhow!(
                    "{label}.listen is non-loopback ({addr}) but TLS is not supported in this build; rebuild with --features tls-rustls or tls-native (or set --unsafe-allow-insecure)"
                ));
            }
        }
        #[cfg(feature = "tls-rustls")]
        let has_access_control = allow || sp.token_enabled || sp.mtls_enabled;
        #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
        let has_access_control = allow || sp.token_enabled;
        #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
        let has_access_control = allow || sp.token_enabled;

        if !has_access_control {
            #[cfg(feature = "tls-rustls")]
            {
                return Err(anyhow!(
                    "{label}.listen is non-loopback ({addr}) but no access control is configured; set --{label}-allow and/or --token-env and/or --tls-client-ca (or --unsafe-allow-insecure)"
                ));
            }
            #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
            {
                return Err(anyhow!(
                    "{label}.listen is non-loopback ({addr}) but no access control is configured; set --{label}-allow and/or --token-env (or --unsafe-allow-insecure)"
                ));
            }
            #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
            {
                return Err(anyhow!(
                    "{label}.listen is non-loopback ({addr}) but no access control is configured; set --{label}-allow and/or --token-env (or --unsafe-allow-insecure)"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(feature = "tls-rustls")]
fn build_tls_acceptor(cli: &Cli) -> Result<Option<TlsAcceptor>> {
    let tls_requested =
        cli.tls_cert.is_some() || cli.tls_key.is_some() || cli.tls_client_ca.is_some();
    if !tls_requested {
        return Ok(None);
    }

    let cert = cli
        .tls_cert
        .as_ref()
        .ok_or_else(|| anyhow!("--tls-cert is required to enable TLS"))?;
    let key = cli
        .tls_key
        .as_ref()
        .ok_or_else(|| anyhow!("--tls-key is required when --tls-cert is set"))?;

    let cert_chain = load_cert_chain(cert)?;
    let key = load_private_key(key)?;
    let mut config = if let Some(ca) = cli.tls_client_ca.as_ref() {
        let mut roots = RootCertStore::empty();
        let certs = load_cert_chain(ca)?;
        let (added, _) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(anyhow!("no CA certs loaded from {}", ca.display()));
        }
        let verifier = WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(|_| anyhow!("invalid tls client CA"))?;
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, key)?
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?
    };
    config.alpn_protocols = Vec::new();
    Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))))
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
fn build_tls_acceptor(cli: &Cli) -> Result<Option<TlsAcceptor>> {
    let tls_requested = cli.tls_pkcs12.is_some() || cli.tls_pkcs12_password_env.is_some();
    if !tls_requested {
        return Ok(None);
    }

    let pkcs12_path = cli
        .tls_pkcs12
        .as_ref()
        .ok_or_else(|| anyhow!("--tls-pkcs12 is required to enable TLS"))?;
    ensure_not_symlink(pkcs12_path, "--tls-pkcs12")?;
    let password = cli
        .tls_pkcs12_password_env
        .as_deref()
        .map(load_required_env)
        .transpose()?
        .unwrap_or_default();

    let der = fs::read(pkcs12_path)
        .with_context(|| format!("failed to read --tls-pkcs12: {}", pkcs12_path.display()))?;
    let identity = native_tls::Identity::from_pkcs12(&der, password.as_str())
        .map_err(|_| anyhow!("invalid pkcs12 identity: {}", pkcs12_path.display()))?;
    let acceptor = native_tls::TlsAcceptor::new(identity)?;
    Ok(Some(tokio_native_tls::TlsAcceptor::from(acceptor)))
}

#[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
fn build_tls_acceptor(_cli: &Cli) -> Result<Option<TlsAcceptor>> {
    Ok(None)
}

impl ExporterHub {
    fn new(
        save_dir: Option<PathBuf>,
        rotate_bytes: u64,
        history_limit_bytes: usize,
        history_limit_age: Duration,
        pcap_preface: Arc<Vec<u8>>,
        max_payload_bytes: usize,
    ) -> Result<Self> {
        let file_sink = match save_dir {
            Some(dir) => {
                const FILE_SINK_QUEUE: usize = 4096;
                let sink = RotatingFileSink::new(dir, rotate_bytes.max(1), pcap_preface.clone())?;
                let (tx, mut rx) = mpsc::channel::<Bytes>(FILE_SINK_QUEUE);
                spawn_blocking(move || {
                    let mut sink = sink;
                    while let Some(block) = rx.blocking_recv() {
                        if let Err(err) = sink.write_block(block.as_ref()) {
                            warn!(error = ?err, "failed to persist pcapng block");
                        }
                    }
                });
                Some(tx)
            }
            None => None,
        };
        let (live_tx, _) = broadcast::channel::<Bytes>(4096);
        Ok(Self {
            sequences: Arc::new(Mutex::new(SequencesState {
                sequences: HashMap::new(),
                sequences_last_gc_unix_nanos: 0,
            })),
            history: Arc::new(RwLock::new(HistoryState {
                history: VecDeque::new(),
                history_bytes: 0,
            })),
            file_sink,
            live_tx,
            history_limit_bytes,
            history_limit_age,
            pcap_preface,
            max_payload_bytes,
        })
    }

    async fn publish_encoded_block(&self, ts_unix_nanos: u64, encoded: Bytes) {
        if let Some(tx) = self.file_sink.as_ref() {
            if let Err(err) = tx.send(encoded.clone()).await {
                warn!(error = ?err, "pcapng file sink disconnected");
            }
        }
        {
            let mut history = self.history.write().await;
            self.push_history_locked(&mut history, ts_unix_nanos, encoded.clone());
        }
        let _ = self.live_tx.send(encoded);
    }

    fn push_history_locked(&self, state: &mut HistoryState, ts_unix_nanos: u64, bytes: Bytes) {
        if self.history_limit_bytes == 0 {
            return;
        }
        state.history_bytes += bytes.len();
        state.history.push_back(HistoryItem {
            ts_unix_nanos,
            bytes,
        });
        self.evict_history_locked(state, ts_unix_nanos);
    }

    fn evict_history_locked(&self, state: &mut HistoryState, now_unix_nanos: u64) {
        let min_ts = now_unix_nanos.saturating_sub(self.history_limit_age.as_nanos() as u64);
        while let Some(front) = state.history.front() {
            if front.ts_unix_nanos >= min_ts {
                break;
            }
            if let Some(old) = state.history.pop_front() {
                state.history_bytes = state.history_bytes.saturating_sub(old.bytes.len());
            }
        }
        while state.history_bytes > self.history_limit_bytes {
            if let Some(old) = state.history.pop_front() {
                state.history_bytes = state.history_bytes.saturating_sub(old.bytes.len());
            } else {
                break;
            }
        }
    }

    async fn history_snapshot(&self) -> Vec<Bytes> {
        let state = self.history.read().await;
        state.history.iter().map(|h| h.bytes.clone()).collect()
    }

    fn gc_sequences_locked(&self, state: &mut SequencesState, now_unix_nanos: u64) {
        if state.sequences.len() <= MAX_SEQUENCE_KEYS
            && now_unix_nanos.saturating_sub(state.sequences_last_gc_unix_nanos)
                < SEQUENCE_GC_INTERVAL_NANOS
        {
            return;
        }
        state.sequences_last_gc_unix_nanos = now_unix_nanos;

        let cutoff = now_unix_nanos
            .saturating_sub(self.history_limit_age.as_nanos().min(u64::MAX as u128) as u64);
        state
            .sequences
            .retain(|_, v| v.last_seen_unix_nanos >= cutoff);

        if state.sequences.len() > MAX_SEQUENCE_KEYS {
            warn!(
                sequences = state.sequences.len(),
                max = MAX_SEQUENCE_KEYS,
                "sequence state too large; clearing"
            );
            state.sequences.clear();
        }
    }
}

impl RotatingFileSink {
    fn new(dir: PathBuf, rotate_bytes: u64, preface: Arc<Vec<u8>>) -> Result<Self> {
        ensure_dir_secure(&dir)?;
        let tmp = dir.join(".bootstrap.tmp");
        let file = open_secure_file(&tmp)?;
        let mut sink = Self {
            dir,
            rotate_bytes,
            current_size: 0,
            index: 0,
            file,
            preface,
            blocks_since_flush: 0,
        };
        sink.rotate()?;
        let _ = fs::remove_file(tmp);
        Ok(sink)
    }

    fn write_block(&mut self, block: &[u8]) -> Result<()> {
        const FLUSH_EVERY_BLOCKS: usize = 128;
        if self.current_size > 0 && self.current_size + block.len() as u64 > self.rotate_bytes {
            self.rotate()?;
        }
        self.file.write_all(block)?;
        self.current_size += block.len() as u64;
        self.blocks_since_flush = self.blocks_since_flush.saturating_add(1);
        if self.blocks_since_flush >= FLUSH_EVERY_BLOCKS {
            self.file.flush()?;
            self.blocks_since_flush = 0;
        }
        Ok(())
    }

    fn rotate(&mut self) -> Result<()> {
        self.index = self.index.saturating_add(1);
        let filename = format!(
            "capture-{}-{:06}.pcapng",
            chrono::Utc::now().format("%Y%m%d%H%M%S"),
            self.index
        );
        let path = self.dir.join(filename);
        self.file = open_secure_file(&path)?;
        self.current_size = 0;
        self.file.write_all(&self.preface)?;
        self.file.flush()?;
        self.current_size = self.preface.len() as u64;
        self.blocks_since_flush = 0;
        Ok(())
    }
}

fn ensure_dir_secure(dir: &Path) -> Result<()> {
    ensure_not_symlink(dir, "save dir")?;
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to chmod {}", dir.display()))?;
    }
    Ok(())
}

fn open_secure_file(path: &Path) -> Result<File> {
    ensure_not_symlink(path, "pcapng file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("failed to open {}", path.display()))
    }
    #[cfg(not(unix))]
    {
        File::create(path).with_context(|| format!("failed to open {}", path.display()))
    }
}

fn ensure_not_symlink(path: &Path, label: &str) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(anyhow!("{label} must not be a symlink: {}", path.display()));
        }
    }
    Ok(())
}

async fn run_event_ingest_loop(mut ring: ShmRingBuffer, hub: ExporterHub) -> Result<()> {
    use std::collections::BTreeMap;

    const MAX_ENCODE_WORKERS: usize = 32;
    const WORKER_QUEUE_DEPTH: usize = 256;
    const RESULT_QUEUE_DEPTH: usize = 4096;

    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, MAX_ENCODE_WORKERS);

    #[derive(Clone, Copy)]
    struct EncodeJob {
        index: u64,
        interface_id: u32,
        timestamp_unix_nanos: u64,
        src: Endpoint,
        dst: Endpoint,
        sequence_number: u32,
    }

    struct EncodeResult {
        index: u64,
        timestamp_unix_nanos: u64,
        encoded: Option<Bytes>,
    }

    let (res_tx, mut res_rx) = mpsc::channel::<EncodeResult>(RESULT_QUEUE_DEPTH);
    let mut job_txs = Vec::with_capacity(workers);

    for _ in 0..workers {
        let (job_tx, mut job_rx) = mpsc::channel::<(EncodeJob, Bytes)>(WORKER_QUEUE_DEPTH);
        job_txs.push(job_tx);
        let res_tx = res_tx.clone();
        tokio::spawn(async move {
            while let Some((job, payload)) = job_rx.recv().await {
                let builder = PacketBuilder::ipv4(job.src.ip.octets(), job.dst.ip.octets(), 64)
                    .tcp(job.src.port, job.dst.port, job.sequence_number, 1024);
                let mut packet = Vec::with_capacity(payload.len() + 96);
                if builder.write(&mut packet, payload.as_ref()).is_err() {
                    let _ = res_tx
                        .send(EncodeResult {
                            index: job.index,
                            timestamp_unix_nanos: job.timestamp_unix_nanos,
                            encoded: None,
                        })
                        .await;
                    continue;
                }
                let encoded = match encode_enhanced_packet(
                    job.interface_id,
                    job.timestamp_unix_nanos,
                    packet,
                ) {
                    Ok(bytes) => Some(Bytes::from(bytes)),
                    Err(err) => {
                        warn!(error = ?err, "failed to encode enhanced packet");
                        None
                    }
                };
                let _ = res_tx
                    .send(EncodeResult {
                        index: job.index,
                        timestamp_unix_nanos: job.timestamp_unix_nanos,
                        encoded,
                    })
                    .await;
            }
        });
    }
    drop(res_tx);

    let publish_hub = hub.clone();
    let publish_task = tokio::spawn(async move {
        let mut pending: BTreeMap<u64, EncodeResult> = BTreeMap::new();
        let mut next = 0u64;
        while let Some(res) = res_rx.recv().await {
            pending.insert(res.index, res);
            while let Some(res) = pending.remove(&next) {
                if let Some(encoded) = res.encoded {
                    publish_hub
                        .publish_encoded_block(res.timestamp_unix_nanos, encoded)
                        .await;
                }
                next = next.saturating_add(1);
            }
        }
    });

    let mut index = 0u64;
    loop {
        match ring.try_pop() {
            Ok(Some(frame)) => {
                if frame.is_empty() {
                    continue;
                }
                let event = match CaptureEvent::decode_wire(Bytes::from(frame)) {
                    Ok(event) => event,
                    Err(err) => {
                        warn!(error = ?err, "failed to decode capture event frame");
                        continue;
                    }
                };
                if event.payload.len() > hub.max_payload_bytes {
                    warn!(
                        payload_len = event.payload.len(),
                        max_payload_bytes = hub.max_payload_bytes,
                        "payload too large; dropped"
                    );
                    continue;
                }

                let sequence_number = {
                    let seq_key = SequenceKey {
                        session_id: event.session_id.clone(),
                        plane: event.plane.clone(),
                        direction: event.direction.clone(),
                    };
                    let mut state = hub.sequences.lock().await;
                    let seq = state.sequences.entry(seq_key).or_insert(SequenceState {
                        next: 1,
                        last_seen_unix_nanos: event.timestamp_unix_nanos,
                    });
                    let sequence_number = seq.next;
                    seq.next = seq.next.wrapping_add(event.payload.len() as u32);
                    seq.last_seen_unix_nanos = event.timestamp_unix_nanos;
                    hub.gc_sequences_locked(&mut state, event.timestamp_unix_nanos);
                    sequence_number
                };

                let (src, dst) = endpoints_for_event(&event);
                let job = EncodeJob {
                    index,
                    interface_id: interface_id(event.plane.clone()),
                    timestamp_unix_nanos: event.timestamp_unix_nanos,
                    src,
                    dst,
                    sequence_number,
                };
                let worker = (index as usize) % job_txs.len();
                if job_txs[worker]
                    .send((job, event.payload.clone()))
                    .await
                    .is_err()
                {
                    break;
                }
                index = index.saturating_add(1);
            }
            Ok(None) => {
                ring.wait_for_data().await?;
            }
            Err(e) => {
                warn!(error = ?e, "fatal error reading from shared memory ring buffer");
                break;
            }
        }
    }

    drop(job_txs);
    let _ = publish_task.await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_stream_accept_loop(
    listener: TcpListener,
    hub: ExporterHub,
    allow: Vec<IpCidr>,
    token: Option<String>,
    tls: Option<TlsAcceptor>,
    tls_accept_timeout: Duration,
    max_control_line_bytes: usize,
    handshake_timeout: Duration,
    connections: Arc<Semaphore>,
) -> Result<()> {
    #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
    let _ = tls_accept_timeout;
    loop {
        let permit = connections.clone().acquire_owned().await?;
        let (stream, peer) = listener.accept().await?;
        if !ip_allowed(peer.ip(), &allow) {
            continue;
        }
        let hub = hub.clone();
        let token = token.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let res = match tls {
                Some(acceptor) => {
                    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
                    {
                        match timeout(tls_accept_timeout, acceptor.accept(stream)).await {
                            Ok(Ok(tls_stream)) => {
                                handle_stream_client(
                                    tls_stream,
                                    hub,
                                    token,
                                    max_control_line_bytes,
                                    handshake_timeout,
                                )
                                .await
                            }
                            Ok(Err(err)) => Err(anyhow!("tls accept failed: {err}")),
                            Err(_) => Err(anyhow!("tls accept timed out")),
                        }
                    }
                    #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
                    {
                        let _ = acceptor;
                        drop(stream);
                        Err(anyhow!("TLS is not supported in this build"))
                    }
                }
                None => {
                    handle_stream_client(
                        stream,
                        hub,
                        token,
                        max_control_line_bytes,
                        handshake_timeout,
                    )
                    .await
                }
            };
            if let Err(err) = res {
                warn!(error = ?err, peer = %peer, "stream client disconnected");
            }
        });
    }
}

async fn handle_stream_client<S>(
    stream: S,
    hub: ExporterHub,
    token: Option<String>,
    max_control_line_bytes: usize,
    handshake_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let Some(preface) =
        read_line_limited_with_timeout(&mut reader, max_control_line_bytes, handshake_timeout)
            .await?
    else {
        return Ok(());
    };
    if preface != STREAM_PREFACE_LINE.as_bytes() {
        return Err(anyhow!("invalid stream preface"));
    }

    let mut next =
        read_line_limited_with_timeout(&mut reader, max_control_line_bytes, handshake_timeout)
            .await?;
    if let Some(line) = next.as_ref().and_then(|l| parse_auth_line(l)) {
        if let Some(expected) = token.as_deref() {
            if !constant_time_eq(line, expected) {
                return Err(anyhow!("invalid token"));
            }
        } else {
            // AUTH provided but not required: accept.
        }
        next =
            read_line_limited_with_timeout(&mut reader, max_control_line_bytes, handshake_timeout)
                .await?;
    } else if token.is_some() {
        return Err(anyhow!("missing AUTH line"));
    }

    let mode = parse_mode(next.ok_or_else(|| anyhow!("missing MODE line"))?.as_slice())?;

    // Always start the stream with a valid section header + interfaces.
    writer.write_all(&hub.pcap_preface).await?;

    if matches!(mode, StreamMode::History | StreamMode::Follow) {
        for block in hub.history_snapshot().await {
            writer.write_all(&block).await?;
        }
    }
    if matches!(mode, StreamMode::Live | StreamMode::Follow) {
        let mut rx = hub.live_tx.subscribe();
        loop {
            match rx.recv().await {
                Ok(block) => writer.write_all(&block).await?,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
    Ok(())
}

async fn read_line_limited<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            if out.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if out.len() + take > max_bytes {
                return Err(anyhow!("line too long"));
            }
            out.extend_from_slice(&buf[..take]);
            reader.consume(take);
            break;
        }
        if out.len() + buf.len() > max_bytes {
            return Err(anyhow!("line too long"));
        }
        out.extend_from_slice(buf);
        let len = buf.len();
        reader.consume(len);
    }

    if out.ends_with(b"\n") {
        out.pop();
    }
    if out.ends_with(b"\r") {
        out.pop();
    }
    Ok(Some(out))
}

async fn read_line_limited_with_timeout<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
    timeout_dur: Duration,
) -> Result<Option<Vec<u8>>> {
    timeout(timeout_dur, read_line_limited(reader, max_bytes))
        .await
        .map_err(|_| anyhow!("read timed out"))?
}

fn parse_auth_line(line: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(line).ok()?;
    let text = text.trim();
    let rest = text.strip_prefix("AUTH ")?;
    Some(rest.trim())
}

fn parse_mode(line: &[u8]) -> Result<StreamMode> {
    let text = std::str::from_utf8(line).map_err(|_| anyhow!("MODE line is not utf-8"))?;
    let trimmed = text.trim();
    let body = trimmed.strip_prefix("MODE ").unwrap_or(trimmed);
    let normalized = body.trim().to_ascii_uppercase();
    Ok(match normalized.as_str() {
        "HISTORY" => StreamMode::History,
        "FOLLOW" => StreamMode::Follow,
        "LIVE" => StreamMode::Live,
        other => return Err(anyhow!("unknown mode: {}", other)),
    })
}

/// Constant-time string comparison to prevent timing side-channel attacks
/// on authentication tokens.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn ip_allowed(peer: IpAddr, allow: &[IpCidr]) -> bool {
    if allow.is_empty() {
        return true;
    }
    allow.iter().any(|cidr| cidr.contains(&peer))
}

fn encode_enhanced_packet(
    interface_id: u32,
    timestamp_unix_nanos: u64,
    packet: Vec<u8>,
) -> Result<Vec<u8>> {
    let block = EnhancedPacketBlock {
        interface_id,
        timestamp: Duration::from_nanos(timestamp_unix_nanos),
        original_len: packet.len() as u32,
        data: Cow::Owned(packet),
        options: vec![],
    };
    let mut out = Vec::with_capacity(block.data.len() + 128);
    Block::EnhancedPacket(block).write_to::<LittleEndian, _>(&mut out)?;
    Ok(out)
}

fn build_pcap_preface() -> Result<Vec<u8>> {
    let section = SectionHeaderBlock {
        endianness: Endianness::Little,
        major_version: 1,
        minor_version: 0,
        section_length: -1,
        options: vec![SectionHeaderOption::UserApplication(Cow::Borrowed("qpxr"))],
    };

    let interfaces = [
        ("client-proxy-tls", "Client <-> Proxy encrypted bytes"),
        ("proxy-server-tls", "Proxy <-> Server encrypted bytes"),
        ("client-server", "Decrypted plaintext (client <-> server)"),
    ]
    .into_iter()
    .map(|(name, desc)| InterfaceDescriptionBlock {
        linktype: DataLink::IPV4,
        snaplen: 0xFFFF,
        options: vec![
            InterfaceDescriptionOption::IfName(Cow::Borrowed(name)),
            InterfaceDescriptionOption::IfDescription(Cow::Borrowed(desc)),
        ],
    })
    .collect::<Vec<_>>();

    let mut out = Vec::new();
    Block::SectionHeader(section).write_to::<LittleEndian, _>(&mut out)?;
    for iface in interfaces {
        Block::InterfaceDescription(iface).write_to::<LittleEndian, _>(&mut out)?;
    }
    Ok(out)
}

fn interface_id(plane: CapturePlane) -> u32 {
    match plane {
        CapturePlane::ClientProxyEncrypted => 0,
        CapturePlane::ProxyServerEncrypted => 1,
        CapturePlane::ClientServerPlaintext => 2,
    }
}

fn endpoints_for_event(event: &CaptureEvent) -> (Endpoint, Endpoint) {
    let default_server_port = match event.plane {
        CapturePlane::ClientServerPlaintext => 80,
        _ => 443,
    };
    let client = parse_endpoint(event.client.as_str(), 49152, "client");
    let server = parse_endpoint(event.server.as_str(), default_server_port, "server");
    match event.direction {
        CaptureDirection::ClientToServer => (client, server),
        CaptureDirection::ServerToClient => (server, client),
    }
}

fn parse_endpoint(input: &str, default_port: u16, label: &str) -> Endpoint {
    if let Ok(addr) = input.parse::<SocketAddr>() {
        return Endpoint {
            ip: to_ipv4(addr.ip(), input),
            port: addr.port(),
        };
    }

    let (host, port) = if let Some((host, raw_port)) = input.rsplit_once(':') {
        match raw_port.parse::<u16>() {
            Ok(port) => (host, port),
            Err(_) => (input, default_port),
        }
    } else {
        (input, default_port)
    };

    if let Ok(ip) = host.parse::<IpAddr>() {
        Endpoint {
            ip: to_ipv4(ip, input),
            port,
        }
    } else {
        Endpoint {
            ip: synthetic_ipv4(format!("{}:{}", label, host).as_str()),
            port,
        }
    }
}

fn to_ipv4(ip: IpAddr, seed: &str) -> Ipv4Addr {
    match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => synthetic_ipv4(seed),
    }
}

fn synthetic_ipv4(seed: &str) -> Ipv4Addr {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    let value = hasher.finish();
    Ipv4Addr::new(
        198,
        18,
        ((value >> 8) & 0xff) as u8,
        ((value >> 16) & 0xff) as u8,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_accepts_follow() {
        assert!(matches!(
            parse_mode(b"MODE FOLLOW").unwrap(),
            StreamMode::Follow
        ));
    }

    #[test]
    fn parse_mode_accepts_history() {
        assert!(matches!(
            parse_mode(b"MODE HISTORY").unwrap(),
            StreamMode::History
        ));
    }

    #[test]
    fn parse_mode_accepts_live() {
        assert!(matches!(
            parse_mode(b"MODE LIVE").unwrap(),
            StreamMode::Live
        ));
    }

    #[test]
    fn parse_mode_case_insensitive() {
        assert!(matches!(
            parse_mode(b"MODE follow").unwrap(),
            StreamMode::Follow
        ));
        assert!(matches!(
            parse_mode(b"MODE Live").unwrap(),
            StreamMode::Live
        ));
    }

    #[test]
    fn parse_mode_without_prefix() {
        assert!(matches!(parse_mode(b"FOLLOW").unwrap(), StreamMode::Follow));
    }

    #[test]
    fn parse_mode_rejects_unknown() {
        assert!(parse_mode(b"MODE INVALID").is_err());
    }

    #[test]
    fn parse_mode_trims_whitespace() {
        assert!(matches!(
            parse_mode(b"  MODE FOLLOW  ").unwrap(),
            StreamMode::Follow
        ));
    }

    #[test]
    fn constant_time_eq_matches_equal_strings() {
        assert!(constant_time_eq("secret", "secret"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn constant_time_eq_rejects_different_strings() {
        assert!(!constant_time_eq("secret", "Secret"));
        assert!(!constant_time_eq("abc", "abx"));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths() {
        assert!(!constant_time_eq("short", "longer"));
        assert!(!constant_time_eq("a", ""));
    }

    #[test]
    fn parse_endpoint_supports_socket_addr() {
        let endpoint = parse_endpoint("127.0.0.1:8443", 80, "server");
        assert_eq!(endpoint.ip, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(endpoint.port, 8443);
    }
}
