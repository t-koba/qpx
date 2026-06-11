#[cfg(feature = "tls-rustls")]
mod ca;
mod cert_info;
mod client_hello;
#[cfg(feature = "tls-rustls")]
mod config;
#[cfg(feature = "tls-rustls")]
mod resolver;
mod trust;

#[cfg(all(test, feature = "tls-rustls", unix))]
mod tests;

#[cfg(feature = "tls-rustls")]
pub use ca::{CaStore, load_or_generate_ca, write_ca_files};
pub use cert_info::UpstreamCertificateInfo;
#[cfg(feature = "tls-cert-info")]
pub use cert_info::extract_upstream_certificate_info;
pub use client_hello::TlsClientHelloInfo;
#[cfg(feature = "tls-rustls")]
pub use config::{build_client_config, build_server_config, load_cert_chain, load_private_key};
#[cfg(feature = "tls-rustls")]
pub use resolver::{DynamicCertResolver, MitmConfig};
pub use trust::{CompiledUpstreamTlsTrust, UpstreamTlsClientAuth};

#[cfg(feature = "tls-rustls")]
/// Result type used by rustls-backed TLS helpers.
pub type TlsResult<T> = std::result::Result<T, TlsError>;

#[cfg(feature = "tls-rustls")]
/// TLS helper error type.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Wrapped backend error.
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

#[cfg(feature = "tls-rustls")]
impl From<std::io::Error> for TlsError {
    fn from(source: std::io::Error) -> Self {
        Self::Backend(source.into())
    }
}

#[cfg(feature = "tls-rustls")]
impl From<rcgen::Error> for TlsError {
    fn from(source: rcgen::Error) -> Self {
        Self::Backend(source.into())
    }
}

#[cfg(feature = "tls-rustls")]
impl From<rustls::Error> for TlsError {
    fn from(source: rustls::Error) -> Self {
        Self::Backend(source.into())
    }
}

#[cfg(feature = "tls-rustls")]
impl From<rustls::pki_types::pem::Error> for TlsError {
    fn from(source: rustls::pki_types::pem::Error) -> Self {
        Self::Backend(source.into())
    }
}

#[cfg(feature = "tls-rustls")]
impl From<globset::Error> for TlsError {
    fn from(source: globset::Error) -> Self {
        Self::Backend(source.into())
    }
}

#[cfg(feature = "tls-rustls")]
impl From<regex::Error> for TlsError {
    fn from(source: regex::Error) -> Self {
        Self::Backend(source.into())
    }
}

#[cfg(feature = "tls-rustls")]
/// Installs the default rustls crypto provider if one is not already present.
pub fn init_rustls_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

// --- Stub implementation when tls-rustls is not enabled ---

#[cfg(not(feature = "tls-rustls"))]
use anyhow::anyhow;
#[cfg(not(feature = "tls-rustls"))]
use std::path::{Path, PathBuf};

#[cfg(not(feature = "tls-rustls"))]
/// Result type returned by TLS helpers in builds without rustls support.
pub type TlsResult<T> = std::result::Result<T, TlsError>;

#[cfg(not(feature = "tls-rustls"))]
/// TLS helper error type for builds without rustls support.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Wrapped backend error.
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

#[cfg(not(feature = "tls-rustls"))]
impl From<globset::Error> for TlsError {
    fn from(source: globset::Error) -> Self {
        Self::Backend(source.into())
    }
}

#[cfg(not(feature = "tls-rustls"))]
impl From<regex::Error> for TlsError {
    fn from(source: regex::Error) -> Self {
        Self::Backend(source.into())
    }
}

#[cfg(not(feature = "tls-rustls"))]
/// Stub CA store used when rustls support is disabled.
#[derive(Clone)]
pub struct CaStore {
    state_dir: PathBuf,
}

#[cfg(not(feature = "tls-rustls"))]
/// Stub MITM TLS configuration used when rustls support is disabled.
#[derive(Clone)]
pub struct MitmConfig;

#[cfg(not(feature = "tls-rustls"))]
/// Reports that CA generation requires the `tls-rustls` feature.
pub fn load_or_generate_ca(state_dir: &Path) -> TlsResult<CaStore> {
    Err(anyhow!(
        "TLS (rustls) support is not enabled in this build (enable feature tls-rustls); state_dir={}",
        state_dir.display()
    )
    .into())
}

#[cfg(not(feature = "tls-rustls"))]
/// Reports that writing CA files requires the `tls-rustls` feature.
pub fn write_ca_files(state_dir: &Path) -> TlsResult<(PathBuf, PathBuf)> {
    Err(anyhow!(
        "TLS (rustls) support is not enabled in this build (enable feature tls-rustls); state_dir={}",
        state_dir.display()
    )
    .into())
}

#[cfg(not(feature = "tls-rustls"))]
/// No-op crypto-provider initializer in builds without rustls support.
pub fn init_rustls_crypto_provider() {}

#[cfg(not(feature = "tls-rustls"))]
impl CaStore {
    /// State directory requested for this stub CA store.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Path where the CA certificate would be stored with rustls enabled.
    pub fn cert_path(&self) -> PathBuf {
        self.state_dir().join("ca.crt")
    }

    /// Path where the CA private key would be stored with rustls enabled.
    pub fn key_path(&self) -> PathBuf {
        self.state_dir().join("ca.key")
    }

    /// Reports that MITM configuration requires the `tls-rustls` feature.
    pub fn mitm_config(&self) -> TlsResult<MitmConfig> {
        Err(anyhow!(
            "TLS MITM is not available without the rustls backend (enable feature tls-rustls)"
        )
        .into())
    }
}
