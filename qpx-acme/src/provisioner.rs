use crate::{AcmeResult, AcmeRuntime};
use anyhow::{Context, Result, anyhow};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use qpx_core::config::{AcmeConfig, Config};
use qpx_core::tls::{load_cert_chain, load_private_key};
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::time::sleep;
use tracing::{info, warn};
use x509_parser::pem::Pem;

/// Runs the ACME account and certificate renewal manager.
pub async fn run_manager(state: Arc<AcmeRuntime>) -> AcmeResult<()> {
    if !state.tos_agreed {
        return Err(
            anyhow!("acme.terms_of_service_agreed must be true when acme.enabled=true").into(),
        );
    }

    let mut account: Option<Account> = None;
    loop {
        let acct = match account.take() {
            Some(a) => a,
            None => match load_or_create_account(state.as_ref()).await {
                Ok(a) => a,
                Err(err) => {
                    warn!(error = ?err, "acme account init failed; retrying");
                    sleep(Duration::from_secs(30)).await;
                    continue;
                }
            },
        };

        let current_operational = state
            .operational_config_provider
            .current_operational_config();
        let snis = desired_acme_snis(current_operational.as_ref());
        for sni in snis {
            if let Err(err) = ensure_certificate(state.as_ref(), &acct, &sni).await {
                warn!(sni = %sni, error = ?err, "acme certificate ensure failed");
            }
        }

        account = Some(acct);
        sleep(Duration::from_secs(3600)).await;
    }
}
pub(crate) fn acme_directory_url(acme: &AcmeConfig) -> String {
    if let Some(url) = acme
        .directory_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return url.to_string();
    }
    if acme.staging {
        return "https://acme-staging-v02.api.letsencrypt.org/directory".to_string();
    }
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn desired_acme_snis(config: &Config) -> Vec<String> {
    let mut snis = HashSet::new();
    for reverse_edges in config.reverse_edge_configs() {
        let Some(tls) = reverse_edges.tls.as_ref() else {
            continue;
        };
        for cert in &tls.certificates {
            let cert_path = cert.cert.as_deref().unwrap_or("").trim();
            let key_path = cert.key.as_deref().unwrap_or("").trim();
            if cert_path.is_empty() && key_path.is_empty() {
                snis.insert(cert.sni.to_ascii_lowercase());
            }
        }
    }
    let mut out = snis.into_iter().collect::<Vec<_>>();
    out.sort();
    out
}

fn cert_paths_for_sni(state: &AcmeRuntime, sni: &str) -> (PathBuf, PathBuf) {
    let dir = state.certs_dir.join(sanitize_sni(sni));
    (dir.join("cert.pem"), dir.join("key.pem"))
}

pub(crate) fn preload_certs(state: &AcmeRuntime) -> Result<()> {
    let current_operational = state
        .operational_config_provider
        .current_operational_config();
    for sni in desired_acme_snis(current_operational.as_ref()) {
        if let Err(err) = load_cert_into_store(state, &sni) {
            warn!(sni = %sni, error = ?err, "failed to preload acme cert (will retry later)");
        }
    }
    Ok(())
}

fn load_cert_into_store(state: &AcmeRuntime, sni: &str) -> Result<()> {
    let (cert_path, key_path) = cert_paths_for_sni(state, sni);
    if !cert_path.exists() || !key_path.exists() {
        return Ok(());
    }
    let chain = load_cert_chain(&cert_path)?;
    #[cfg(feature = "http3")]
    let quic_chain = chain.clone();
    let key = load_private_key(&key_path)?;
    let signing_key = any_supported_type(&key).map_err(|_| anyhow!("unsupported key"))?;
    state.store.upsert(
        sni.to_string(),
        Arc::new(CertifiedKey::new(chain, signing_key)),
    );
    #[cfg(feature = "http3")]
    {
        let signing_key = quinn::rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|_| anyhow!("unsupported key"))?;
        let certified = Arc::new(quinn::rustls::sign::CertifiedKey::new(
            quic_chain,
            signing_key,
        ));
        state.quic_store.upsert(sni.to_string(), certified);
    }
    Ok(())
}

async fn load_or_create_account(state: &AcmeRuntime) -> Result<Account> {
    if let Ok(data) = fs::read(&state.account_path)
        && !data.is_empty()
    {
        let credentials: AccountCredentials = serde_json::from_slice(&data)
            .with_context(|| format!("invalid acme account {}", state.account_path.display()))?;
        let builder = Account::builder().with_context(|| "acme client init failed")?;
        return builder
            .from_credentials(credentials)
            .await
            .with_context(|| "failed to load acme account credentials");
    }

    let contact = state
        .contact_email
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|email| vec![format!("mailto:{email}")])
        .unwrap_or_default();
    let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
    let new_account = NewAccount {
        contact: &contact_refs,
        terms_of_service_agreed: state.tos_agreed,
        only_return_existing: false,
    };
    let builder = Account::builder().with_context(|| "acme client init failed")?;
    let (account, credentials) = builder
        .create(&new_account, state.directory_url.clone(), None)
        .await
        .with_context(|| "acme account create failed")?;

    let serialized = serde_json::to_vec_pretty(&credentials)?;
    write_bytes_file(&state.account_path, &serialized, 0o600)
        .with_context(|| format!("failed to write {}", state.account_path.display()))?;
    Ok(account)
}

async fn ensure_certificate(state: &AcmeRuntime, account: &Account, sni: &str) -> Result<()> {
    let (cert_path, key_path) = cert_paths_for_sni(state, sni);
    if cert_path.exists()
        && key_path.exists()
        && let Ok(not_after) = read_leaf_not_after(&cert_path)
    {
        match should_renew(not_after, state.renew_before_days) {
            Ok(false) => {
                let _ = load_cert_into_store(state, sni);
                return Ok(());
            }
            Ok(true) => {}
            Err(_) => {}
        }
    }

    info!(sni = %sni, "acme issuing/renewing certificate");
    let identifiers = vec![Identifier::Dns(sni.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .with_context(|| "acme new_order failed")?;

    let mut cleanups: Vec<ChallengeCleanup> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = match result {
            Ok(v) => v,
            Err(err) => {
                cleanup_challenges(state, cleanups).await;
                return Err(err.into());
            }
        };
        if authz.status == instant_acme::AuthorizationStatus::Valid {
            continue;
        }
        let challenge_type = configured_challenge_type(state)?;
        let mut challenge = authz.challenge(challenge_type).ok_or_else(|| {
            anyhow!(
                "no {} challenge for authorization",
                configured_challenge_name(state)
            )
        })?;
        prepare_challenge(state, &challenge, &mut cleanups).await?;
        if let Err(err) = challenge
            .set_ready()
            .await
            .with_context(|| "acme challenge set_ready failed")
        {
            cleanup_challenges(state, cleanups).await;
            return Err(err);
        }
    }

    let status_res = order
        .poll_ready(&RetryPolicy::default())
        .await
        .with_context(|| "acme order poll_ready failed");
    cleanup_challenges(state, cleanups).await;
    let status = status_res?;
    if status != OrderStatus::Ready {
        return Err(anyhow!("acme order not ready (status={:?})", status));
    }

    let key_pem = order
        .finalize()
        .await
        .with_context(|| "acme finalize failed")?;
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .with_context(|| "acme poll_certificate failed")?;

    ensure_dir(cert_path.parent().unwrap_or(&state.certs_dir), 0o700)?;
    write_bytes_file(&key_path, key_pem.as_bytes(), 0o600)?;
    write_bytes_file(&cert_path, cert_chain_pem.as_bytes(), 0o644)?;

    load_cert_into_store(state, sni)?;
    Ok(())
}

enum ChallengeCleanup {
    Http01Token(String),
    Dns01Record { domain: String, value: String },
    TlsAlpn01Cert(String),
}

fn configured_challenge_name(state: &AcmeRuntime) -> &str {
    state.challenge.trim()
}

fn configured_challenge_type(state: &AcmeRuntime) -> Result<ChallengeType> {
    match configured_challenge_name(state) {
        "http-01" => Ok(ChallengeType::Http01),
        "dns-01" => Ok(ChallengeType::Dns01),
        "tls-alpn-01" => Ok(ChallengeType::TlsAlpn01),
        other => Err(anyhow!("unsupported acme.challenge {other}")),
    }
}

async fn prepare_challenge(
    state: &AcmeRuntime,
    challenge: &instant_acme::ChallengeHandle<'_>,
    cleanups: &mut Vec<ChallengeCleanup>,
) -> Result<()> {
    match configured_challenge_name(state) {
        "http-01" => {
            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization().as_str().to_string();
            state.tokens.insert(token.clone(), key_auth);
            cleanups.push(ChallengeCleanup::Http01Token(token));
            Ok(())
        }
        "dns-01" => {
            let hook = state
                .dns_hook
                .as_ref()
                .ok_or_else(|| anyhow!("acme.dns_hook missing for dns-01"))?;
            let domain = challenge.identifier().to_string();
            let value = challenge.key_authorization().dns_value();
            run_dns_hook(hook.set_command.as_str(), &domain, &value).await?;
            cleanups.push(ChallengeCleanup::Dns01Record {
                domain,
                value: value.clone(),
            });
            if hook.propagation_wait_secs > 0 {
                sleep(Duration::from_secs(hook.propagation_wait_secs)).await;
            }
            Ok(())
        }
        "tls-alpn-01" => {
            let sni = challenge.identifier().to_string().to_ascii_lowercase();
            let key_auth = challenge.key_authorization();
            let cert = tls_alpn01_challenge_cert(&sni, key_auth.digest().as_ref())?;
            state.tls_alpn01.upsert(sni.clone(), Arc::new(cert));
            cleanups.push(ChallengeCleanup::TlsAlpn01Cert(sni));
            Ok(())
        }
        other => Err(anyhow!("unsupported acme.challenge {other}")),
    }
}

async fn cleanup_challenges(state: &AcmeRuntime, cleanups: Vec<ChallengeCleanup>) {
    for cleanup in cleanups {
        match cleanup {
            ChallengeCleanup::Http01Token(token) => {
                state.tokens.remove(&token);
            }
            ChallengeCleanup::Dns01Record { domain, value } => {
                if let Some(hook) = state.dns_hook.as_ref()
                    && let Err(err) =
                        run_dns_hook(hook.clear_command.as_str(), &domain, &value).await
                {
                    warn!(domain = %domain, error = ?err, "acme dns-01 cleanup hook failed");
                }
            }
            ChallengeCleanup::TlsAlpn01Cert(sni) => {
                state.tls_alpn01.remove(&sni);
            }
        }
    }
}

fn tls_alpn01_challenge_cert(sni: &str, digest: &[u8]) -> Result<CertifiedKey> {
    let mut params = CertificateParams::new(vec![sni.to_string()])?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, sni);
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(digest));
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let signing_key = any_supported_type(&key).map_err(|_| anyhow!("unsupported key"))?;
    Ok(CertifiedKey::new(vec![cert.der().clone()], signing_key))
}

async fn run_dns_hook(command: &str, domain: &str, value: &str) -> Result<()> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("acme dns hook command must not be empty"));
    }
    #[cfg(unix)]
    let status = Command::new("sh")
        .arg("-c")
        .arg(trimmed)
        .env("QPX_ACME_DOMAIN", domain)
        .env("QPX_ACME_TXT_VALUE", value)
        .status()
        .await?;
    #[cfg(windows)]
    let status = Command::new("cmd")
        .arg("/C")
        .arg(trimmed)
        .env("QPX_ACME_DOMAIN", domain)
        .env("QPX_ACME_TXT_VALUE", value)
        .status()
        .await?;
    #[cfg(not(any(unix, windows)))]
    let status = {
        let _ = (trimmed, domain, value);
        return Err(anyhow!(
            "acme dns hook commands are not supported on this platform"
        ));
    };
    if !status.success() {
        return Err(anyhow!("acme dns hook command failed with status {status}"));
    }
    Ok(())
}

fn should_renew(not_after: SystemTime, renew_before_days: u64) -> Result<bool> {
    let renew_before = Duration::from_secs(renew_before_days.saturating_mul(86_400));
    let now = SystemTime::now();
    let renew_at = not_after
        .checked_sub(renew_before)
        .ok_or_else(|| anyhow!("invalid cert not_after (too early)"))?;
    Ok(now >= renew_at)
}

fn read_leaf_not_after(cert_path: &Path) -> Result<SystemTime> {
    let data = fs::read(cert_path)?;
    for pem in Pem::iter_from_buffer(&data) {
        let pem = pem.map_err(|e| anyhow!("invalid PEM in {}: {e}", cert_path.display()))?;
        if pem.label != "CERTIFICATE" {
            continue;
        }
        let cert = pem
            .parse_x509()
            .map_err(|e| anyhow!("invalid x509 in {}: {e:?}", cert_path.display()))?;
        let ts = cert.validity().not_after.to_datetime().unix_timestamp();
        if ts < 0 {
            return Err(anyhow!("invalid x509 not_after in {}", cert_path.display()));
        }
        return Ok(UNIX_EPOCH + Duration::from_secs(ts as u64));
    }
    Err(anyhow!("no certificate found in {}", cert_path.display()))
}

fn sanitize_sni(sni: &str) -> String {
    sni.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    ensure_directory_components(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    Ok(())
}

pub(crate) fn ensure_directory_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current.exists() {
            let meta = fs::symlink_metadata(&current)?;
            if meta.file_type().is_symlink() {
                return Err(anyhow!(
                    "refusing to use symlinked ACME path component {}",
                    current.display()
                ));
            }
            if !meta.is_dir() {
                return Err(anyhow!(
                    "ACME path component is not a directory: {}",
                    current.display()
                ));
            }
            reject_untrusted_ancestor(&current, &meta)?;
            continue;
        }
        fs::create_dir(&current)?;
        set_private_directory_permissions(&current)?;
    }
    Ok(())
}

fn set_private_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(unix)]
fn reject_untrusted_ancestor(path: &Path, meta: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let mode = meta.mode();
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let sticky_bit = u32::from(libc::S_ISVTX);
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let sticky_bit = libc::S_ISVTX;
    let sticky = mode & sticky_bit != 0;
    // SAFETY: geteuid has no preconditions and only reads the current process credentials.
    let euid = unsafe { libc::geteuid() };

    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing ACME ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if sticky && mode & 0o022 != 0 && meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing sticky writable ACME ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if mode & 0o002 != 0 && !sticky {
        return Err(anyhow!(
            "refusing attacker-writable ACME ancestor directory {}",
            path.display()
        ));
    }
    if !sticky && mode & 0o020 != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing group-writable ACME ancestor directory not owned by current user: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_untrusted_ancestor(_path: &Path, _meta: &fs::Metadata) -> Result<()> {
    Ok(())
}

fn write_bytes_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;

    let mut file = qpx_core::secure_file::open_secure_output_file(path)
        .map_err(|err| anyhow!("failed to open ACME material {}: {err}", path.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{acme_directory_url, run_dns_hook, tls_alpn01_challenge_cert};
    use qpx_core::config::AcmeConfig;

    fn base_acme_config() -> AcmeConfig {
        AcmeConfig {
            enabled: true,
            challenge: "http-01".to_string(),
            staging: false,
            directory_url: None,
            email: None,
            terms_of_service_agreed: false,
            http01_listen: None,
            dns_hook: None,
            renew_before_days: 30,
        }
    }

    #[test]
    fn directory_url_defaults_to_production() {
        assert_eq!(
            acme_directory_url(&base_acme_config()),
            "https://acme-v02.api.letsencrypt.org/directory"
        );
    }

    #[test]
    fn directory_url_uses_staging_when_requested() {
        let config = AcmeConfig {
            staging: true,
            ..base_acme_config()
        };
        assert_eq!(
            acme_directory_url(&config),
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
    }

    #[test]
    fn directory_url_prefers_explicit_url_over_staging() {
        let config = AcmeConfig {
            staging: true,
            directory_url: Some("  https://custom.example/dir  ".to_string()),
            ..base_acme_config()
        };
        assert_eq!(acme_directory_url(&config), "https://custom.example/dir");
    }

    #[test]
    fn directory_url_ignores_blank_explicit_url() {
        let config = AcmeConfig {
            directory_url: Some("   ".to_string()),
            ..base_acme_config()
        };
        assert_eq!(
            acme_directory_url(&config),
            "https://acme-v02.api.letsencrypt.org/directory"
        );
    }

    #[test]
    fn tls_alpn01_challenge_cert_contains_acme_extension() {
        let digest = [7u8; 32];
        let cert = tls_alpn01_challenge_cert("acme.example", &digest).expect("cert");
        let der = cert.cert.first().expect("leaf");
        let (_, parsed) = x509_parser::parse_x509_certificate(der.as_ref()).expect("x509");
        let ext = parsed
            .extensions()
            .iter()
            .find(|ext| ext.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .expect("acme extension");
        assert!(ext.critical);
        assert!(
            ext.value.contains(&7),
            "extension should contain challenge digest"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dns_hook_receives_domain_and_txt_value_env() {
        let path = std::env::temp_dir().join(format!(
            "qpx-acme-dns-hook-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let command = format!(
            "printf '%s|%s' \"$QPX_ACME_DOMAIN\" \"$QPX_ACME_TXT_VALUE\" > {}",
            path.display()
        );
        run_dns_hook(&command, "example.com", "txt-value")
            .await
            .expect("hook");
        let text = std::fs::read_to_string(&path).expect("read hook output");
        assert_eq!(text, "example.com|txt-value");
        let _ = std::fs::remove_file(path);
    }
}
