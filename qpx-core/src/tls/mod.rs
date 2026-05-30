#[cfg(feature = "tls-rustls")]
mod ca;
#[cfg(feature = "tls-rustls")]
mod config;
#[cfg(feature = "tls-rustls")]
mod resolver;

#[cfg(all(test, feature = "tls-rustls", unix))]
mod tests;

#[cfg(feature = "tls-rustls")]
pub use ca::{CaStore, load_or_generate_ca, write_ca_files};
#[cfg(feature = "tls-rustls")]
pub use config::{build_client_config, build_server_config, load_cert_chain, load_private_key};
#[cfg(feature = "tls-rustls")]
pub use resolver::{DynamicCertResolver, MitmConfig};

#[cfg(feature = "tls-rustls")]
pub fn init_rustls_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

// --- Stub implementation when tls-rustls is not enabled ---

#[cfg(not(feature = "tls-rustls"))]
use anyhow::{Result, anyhow};
#[cfg(not(feature = "tls-rustls"))]
use std::path::{Path, PathBuf};

#[cfg(not(feature = "tls-rustls"))]
#[derive(Clone)]
pub struct CaStore {
    state_dir: PathBuf,
}

#[cfg(not(feature = "tls-rustls"))]
#[derive(Clone)]
pub struct MitmConfig;

#[cfg(not(feature = "tls-rustls"))]
pub fn load_or_generate_ca(state_dir: &Path) -> Result<CaStore> {
    Err(anyhow!(
        "TLS (rustls) support is not enabled in this build (enable feature tls-rustls); state_dir={}",
        state_dir.display()
    ))
}

#[cfg(not(feature = "tls-rustls"))]
pub fn write_ca_files(state_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    Err(anyhow!(
        "TLS (rustls) support is not enabled in this build (enable feature tls-rustls); state_dir={}",
        state_dir.display()
    ))
}

#[cfg(not(feature = "tls-rustls"))]
pub fn init_rustls_crypto_provider() {}

#[cfg(not(feature = "tls-rustls"))]
impl CaStore {
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn cert_path(&self) -> PathBuf {
        self.state_dir().join("ca.crt")
    }

    pub fn key_path(&self) -> PathBuf {
        self.state_dir().join("ca.key")
    }

    pub fn mitm_config(&self) -> Result<MitmConfig> {
        Err(anyhow!(
            "TLS MITM is not available without the rustls backend (enable feature tls-rustls)"
        ))
    }
}
