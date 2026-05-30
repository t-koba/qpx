use crate::TlsAcceptor;
use crate::cli::Cli;
use anyhow::{Context, Result, anyhow};
use cidr::IpCidr;
#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
use std::fs;
use std::net::SocketAddr;
#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
use std::path::Path;
#[cfg(feature = "tls-rustls")]
use std::sync::Arc;

#[cfg(feature = "tls-rustls")]
use qpx_core::tls::{load_cert_chain, load_private_key};
#[cfg(feature = "tls-rustls")]
use rustls::RootCertStore;
#[cfg(feature = "tls-rustls")]
use rustls::server::WebPkiClientVerifier;

pub(crate) fn parse_allowlist(raw: &[String]) -> Result<Vec<IpCidr>> {
    let mut out = Vec::new();
    for item in raw {
        let cidr: IpCidr = item
            .parse()
            .map_err(|_| anyhow!("invalid CIDR in allowlist: {}", item))?;
        out.push(cidr);
    }
    Ok(out)
}

pub(crate) fn load_required_env(name: &str) -> Result<String> {
    let value = std::env::var(name)
        .with_context(|| format!("{name} is required but not set"))?
        .trim()
        .to_string();
    if value.is_empty() {
        return Err(anyhow::Error::msg(format!("{name} is set but empty")));
    }
    Ok(value)
}

pub(crate) struct SecurityPosture {
    pub(crate) stream_listen: SocketAddr,
    pub(crate) tls_enabled: bool,
    pub(crate) stream_allow_configured: bool,
    pub(crate) token_enabled: bool,
    #[cfg(feature = "tls-rustls")]
    pub(crate) mtls_enabled: bool,
    pub(crate) unsafe_allow_insecure: bool,
}

pub(crate) fn validate_security_posture(sp: &SecurityPosture) -> Result<()> {
    for (label, addr, allow) in [("stream", sp.stream_listen, sp.stream_allow_configured)] {
        if addr.ip().is_loopback() {
            if sp.unsafe_allow_insecure {
                continue;
            }
            #[cfg(feature = "tls-rustls")]
            let has_local_access_control = sp.token_enabled || sp.mtls_enabled;
            #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
            let has_local_access_control = sp.token_enabled;
            #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
            let has_local_access_control = sp.token_enabled;

            if !has_local_access_control {
                #[cfg(feature = "tls-rustls")]
                {
                    return Err(anyhow!(
                        "{label}.listen is loopback ({addr}) but local users are not authenticated; set --token-env and/or --tls-client-ca (or --unsafe-allow-insecure)"
                    ));
                }
                #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
                {
                    return Err(anyhow!(
                        "{label}.listen is loopback ({addr}) but local users are not authenticated; set --token-env (or --unsafe-allow-insecure)"
                    ));
                }
                #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
                {
                    return Err(anyhow!(
                        "{label}.listen is loopback ({addr}) but local users are not authenticated; set --token-env (or --unsafe-allow-insecure)"
                    ));
                }
            }
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
pub(crate) fn build_tls_acceptor(cli: &Cli) -> Result<Option<TlsAcceptor>> {
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
pub(crate) fn build_tls_acceptor(cli: &Cli) -> Result<Option<TlsAcceptor>> {
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

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
fn ensure_not_symlink(path: &Path, label: &str) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label}: {}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!("{label} must not be a symlink: {}", path.display()));
    }
    Ok(())
}

#[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
pub(crate) fn build_tls_acceptor(_cli: &Cli) -> Result<Option<TlsAcceptor>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_security_posture_rejects_unauthenticated_loopback_stream() {
        let err = validate_security_posture(&SecurityPosture {
            stream_listen: "127.0.0.1:19101".parse().unwrap(),
            tls_enabled: false,
            stream_allow_configured: false,
            token_enabled: false,
            #[cfg(feature = "tls-rustls")]
            mtls_enabled: false,
            unsafe_allow_insecure: false,
        })
        .expect_err("loopback stream should require auth");
        assert!(
            err.to_string()
                .contains("local users are not authenticated")
        );
    }

    #[test]
    fn validate_security_posture_accepts_loopback_stream_with_token() {
        validate_security_posture(&SecurityPosture {
            stream_listen: "127.0.0.1:19101".parse().unwrap(),
            tls_enabled: false,
            stream_allow_configured: false,
            token_enabled: true,
            #[cfg(feature = "tls-rustls")]
            mtls_enabled: false,
            unsafe_allow_insecure: false,
        })
        .expect("loopback token auth should be accepted");
    }
}
