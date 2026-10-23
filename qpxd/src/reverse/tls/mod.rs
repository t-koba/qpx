mod security;

#[cfg(feature = "tls-rustls")]
mod write_coalescer;

#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
mod accept;

#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
pub(in crate::reverse) use accept::{ReverseTlsAcceptor, build_tls_acceptor};
pub(crate) use security::ReverseTlsHostPolicy;
#[cfg(feature = "tls-rustls")]
pub(in crate::reverse) use write_coalescer::AdaptiveWriteCoalescer;

#[cfg(feature = "tls-rustls")]
use anyhow::{Result, anyhow};
#[cfg(feature = "tls-rustls")]
use qpx_core::config::TlsCertConfig;
#[cfg(feature = "tls-rustls")]
use std::path::Path;

/// Returns the trimmed certificate and key paths, or `None` for an ACME-managed pair.
#[cfg(feature = "tls-rustls")]
pub(in crate::reverse) fn certificate_file_paths(
    cert: &TlsCertConfig,
) -> Result<Option<(&Path, &Path)>> {
    let cert_path = cert.cert.as_deref().unwrap_or("").trim();
    let key_path = cert.key.as_deref().unwrap_or("").trim();
    if cert_path.is_empty() && key_path.is_empty() {
        return Ok(None);
    }
    if cert_path.is_empty() {
        return Err(anyhow!("reverse.tls.certificates[].cert must not be empty"));
    }
    if key_path.is_empty() {
        return Err(anyhow!("reverse.tls.certificates[].key must not be empty"));
    }
    Ok(Some((Path::new(cert_path), Path::new(key_path))))
}

#[cfg(all(test, feature = "tls-rustls"))]
mod tests {
    use super::*;

    fn tls_cert(cert: Option<&str>, key: Option<&str>) -> TlsCertConfig {
        TlsCertConfig {
            sni: "example.com".to_string(),
            pkcs12: None,
            pkcs12_password_env: None,
            cert: cert.map(str::to_owned),
            key: key.map(str::to_owned),
        }
    }

    #[test]
    fn certificate_paths_trim_file_names_and_recognize_acme_pair() {
        assert_eq!(certificate_file_paths(&tls_cert(None, None)).unwrap(), None);
        assert_eq!(
            certificate_file_paths(&tls_cert(Some(" cert.pem "), Some(" key.pem "))).unwrap(),
            Some((Path::new("cert.pem"), Path::new("key.pem")))
        );
    }

    #[test]
    fn certificate_paths_reject_incomplete_file_pair() {
        assert_eq!(
            certificate_file_paths(&tls_cert(Some(" "), Some("key.pem")))
                .unwrap_err()
                .to_string(),
            "reverse.tls.certificates[].cert must not be empty"
        );
        assert_eq!(
            certificate_file_paths(&tls_cert(Some("cert.pem"), Some(" ")))
                .unwrap_err()
                .to_string(),
            "reverse.tls.certificates[].key must not be empty"
        );
    }
}
