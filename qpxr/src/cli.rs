use clap::Parser;
use std::path::PathBuf;

const DEFAULT_HISTORY_SECS: u64 = 3600;
const DEFAULT_MAX_CONTROL_LINE_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Parser)]
#[command(name = "qpxr", about = "qpx capture reader")]
pub(crate) struct Cli {
    #[arg(long)]
    pub(crate) shm_path: Option<String>,
    #[arg(long, default_value_t = 16)]
    pub(crate) shm_size_mb: usize,

    #[arg(short = 's', long, default_value = "127.0.0.1:19101")]
    pub(crate) stream_listen: String,

    /// Allowlist for qpxc stream clients (repeatable CIDR)
    #[arg(short = 'S', long, value_name = "CIDR")]
    pub(crate) stream_allow: Vec<String>,

    /// Require AUTH token (value is read from this env var)
    #[arg(short = 't', long)]
    pub(crate) token_env: Option<String>,

    /// Enable TLS with this server certificate (PEM)
    #[cfg(feature = "tls-rustls")]
    #[arg(short = 'C', long)]
    pub(crate) tls_cert: Option<PathBuf>,
    /// TLS private key for --tls-cert (PEM)
    #[cfg(feature = "tls-rustls")]
    #[arg(short = 'K', long)]
    pub(crate) tls_key: Option<PathBuf>,
    /// Require client certificates signed by this CA (PEM)
    #[cfg(feature = "tls-rustls")]
    #[arg(short = 'A', long)]
    pub(crate) tls_client_ca: Option<PathBuf>,

    /// Enable TLS with this PKCS#12 identity (.p12/.pfx)
    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
    #[arg(long)]
    pub(crate) tls_pkcs12: Option<PathBuf>,
    /// Password env var for --tls-pkcs12 (optional)
    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
    #[arg(long)]
    pub(crate) tls_pkcs12_password_env: Option<String>,
    #[arg(long, default_value_t = 5_000)]
    pub(crate) tls_accept_timeout_ms: u64,

    /// Allow insecure non-loopback operation (DANGEROUS)
    #[arg(long)]
    pub(crate) unsafe_allow_insecure: bool,

    #[arg(long, default_value_t = 1024)]
    pub(crate) max_connections: usize,
    #[arg(long, default_value_t = 10_000)]
    pub(crate) handshake_timeout_ms: u64,

    #[arg(short = 'd', long)]
    pub(crate) save_dir: Option<PathBuf>,
    #[arg(short = 'r', long, default_value_t = 100 * 1024 * 1024)]
    pub(crate) rotate_bytes: u64,
    #[arg(short = 'H', long, default_value_t = 256 * 1024 * 1024)]
    pub(crate) history_bytes: usize,
    #[arg(short = 'T', long, default_value_t = DEFAULT_HISTORY_SECS)]
    pub(crate) history_secs: u64,
    #[arg(long, default_value_t = DEFAULT_MAX_CONTROL_LINE_BYTES)]
    pub(crate) max_control_line_bytes: usize,
    #[arg(short = 'p', long, default_value_t = DEFAULT_MAX_PAYLOAD_BYTES)]
    pub(crate) max_payload_bytes: usize,
}
