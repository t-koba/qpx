use crate::AcmeRuntime;
use anyhow::{Context, Result, anyhow};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use qpx_core::config::{AcmeConfig, Config};
use qpx_core::tls::{load_cert_chain, load_private_key};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::sign::CertifiedKey;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tracing::{info, warn};
use x509_parser::pem::Pem;

pub async fn run_manager(state: Arc<AcmeRuntime>) -> Result<()> {
    if !state.tos_agreed {
        return Err(anyhow!(
            "acme.terms_of_service_agreed must be true when acme.enabled=true"
        ));
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

    let mut tokens_to_cleanup: Vec<String> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = match result {
            Ok(v) => v,
            Err(err) => {
                for token in tokens_to_cleanup {
                    state.tokens.remove(&token);
                }
                return Err(err.into());
            }
        };
        if authz.status == instant_acme::AuthorizationStatus::Valid {
            continue;
        }
        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| anyhow!("no http-01 challenge for authorization"))?;
        let token = challenge.token.clone();
        let key_auth = challenge.key_authorization().as_str().to_string();
        state.tokens.insert(token.clone(), key_auth);
        if let Err(err) = challenge
            .set_ready()
            .await
            .with_context(|| "acme challenge set_ready failed")
        {
            state.tokens.remove(&token);
            for token in tokens_to_cleanup {
                state.tokens.remove(&token);
            }
            return Err(err);
        }
        tokens_to_cleanup.push(token);
    }

    let status_res = order
        .poll_ready(&RetryPolicy::default())
        .await
        .with_context(|| "acme order poll_ready failed");
    for token in tokens_to_cleanup {
        state.tokens.remove(&token);
    }
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
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        if let Ok(meta) = fs::symlink_metadata(path)
            && meta.file_type().is_symlink()
        {
            return Err(anyhow!(
                "refusing to write through symlink path {}",
                path.display()
            ));
        }
        fs::write(path, contents)?;
        Ok(())
    }
}
