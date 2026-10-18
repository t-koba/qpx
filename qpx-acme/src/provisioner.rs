use crate::{AcmeResult, AcmeRuntime};
use anyhow::{Context, Result, anyhow};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use qpx_core::config::{AcmeConfig, Config};
use qpx_core::tls::{load_cert_chain, load_private_key};
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair};
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
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

fn load_cert_into_store(state: &AcmeRuntime, sni: &str) -> Result<bool> {
    let (cert_path, key_path) = cert_paths_for_sni(state, sni);
    if !cert_path.exists() || !key_path.exists() {
        return Ok(false);
    }
    let chain = load_cert_chain(&cert_path)?;
    #[cfg(feature = "http3")]
    let quic_chain = chain.clone();
    let key = load_private_key(&key_path)?;
    let signing_key = any_supported_type(&key).map_err(|_| anyhow!("unsupported key"))?;
    let certified = CertifiedKey::new(chain, signing_key);
    certified
        .keys_match()
        .with_context(|| format!("invalid ACME TLS certificate/key pair for {sni}"))?;
    #[cfg(feature = "http3")]
    let quic_certified = {
        let signing_key = quinn::rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
            .map_err(|_| anyhow!("unsupported key"))?;
        let certified = quinn::rustls::sign::CertifiedKey::new(quic_chain, signing_key);
        certified
            .keys_match()
            .with_context(|| format!("invalid ACME QUIC certificate/key pair for {sni}"))?;
        certified
    };

    // Prepare and validate both representations before replacing either last-known-good pair.
    state.store.upsert(sni.to_string(), Arc::new(certified));
    #[cfg(feature = "http3")]
    state
        .quic_store
        .upsert(sni.to_string(), Arc::new(quic_certified));
    Ok(true)
}

// A not-due leaf alone is insufficient: an interrupted write may have replaced only its key.
fn reuse_existing_certificate(state: &AcmeRuntime, sni: &str) -> Result<bool> {
    let (cert_path, key_path) = cert_paths_for_sni(state, sni);
    if !cert_path.exists() || !key_path.exists() {
        return Ok(false);
    }
    if should_renew(read_leaf_not_after(&cert_path)?, state.renew_before_days)? {
        return Ok(false);
    }
    load_cert_into_store(state, sni)
}

async fn load_or_create_account(state: &AcmeRuntime) -> Result<Account> {
    if let Ok(data) = fs::read(&state.account_path)
        && !data.is_empty()
    {
        let credentials: AccountCredentials = serde_json::from_slice(&data)
            .with_context(|| format!("invalid acme account {}", state.account_path.display()))?;
        let builder = account_builder().with_context(|| "acme client init failed")?;
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
    let builder = account_builder().with_context(|| "acme client init failed")?;
    let (account, credentials) = builder
        .create(&new_account, state.directory_url.clone(), None)
        .await
        .with_context(|| "acme account create failed")?;

    let serialized = serde_json::to_vec_pretty(&credentials)?;
    write_bytes_file(&state.account_path, &serialized, 0o600)
        .with_context(|| format!("failed to write {}", state.account_path.display()))?;
    Ok(account)
}

fn account_builder() -> Result<instant_acme::AccountBuilder> {
    if let Some(root) = std::env::var_os("QPX_ACME_ROOT_CERT") {
        let path = std::path::PathBuf::from(root);
        return Account::builder_with_root(path).map_err(Into::into);
    }
    Account::builder().map_err(Into::into)
}

async fn ensure_certificate(state: &AcmeRuntime, account: &Account, sni: &str) -> Result<()> {
    let (cert_path, key_path) = cert_paths_for_sni(state, sni);
    match reuse_existing_certificate(state, sni) {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(err) => {
            warn!(sni = %sni, error = ?err, "cannot reuse persisted acme certificate; attempting renewal");
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
    // These writes are not a transaction. If interrupted, pair validation prevents publication
    // and the next ensure retries issuance even if the old leaf is not yet due for renewal.
    write_bytes_file(&key_path, key_pem.as_bytes(), 0o600)?;
    write_bytes_file(&cert_path, cert_chain_pem.as_bytes(), 0o644)?;

    if !load_cert_into_store(state, sni)? {
        return Err(anyhow!(
            "ACME certificate/key pair missing after issuance for {sni}"
        ));
    }
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
    use super::*;
    #[cfg(unix)]
    use crate::ConfigProvider;
    #[cfg(unix)]
    use crate::store::{AcmeCertStore, Http01TokenStore, TlsAlpn01CertStore};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    const TEST_SNI: &str = "acme.example";

    #[cfg(unix)]
    struct UnusedConfigProvider;

    #[cfg(unix)]
    impl ConfigProvider for UnusedConfigProvider {
        fn current_operational_config(&self) -> Arc<Config> {
            panic!("certificate loading does not consult operational configuration")
        }
    }

    #[cfg(unix)]
    struct CertFixture(AcmeRuntime);

    #[cfg(unix)]
    impl CertFixture {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            // Canonicalize so macOS /var (/private/var symlink) does not trip ensure_dir.
            let base = std::fs::canonicalize(std::env::temp_dir())
                .expect("canonicalize system temp directory");
            let dir = base.join(format!(
                "qpx-acme-pair-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            ensure_dir(&dir, 0o700).unwrap();
            Self(AcmeRuntime {
                operational_config_provider: Arc::new(UnusedConfigProvider),
                directory_url: String::new(),
                challenge: "http-01".to_string(),
                renew_before_days: 30,
                contact_email: None,
                tos_agreed: true,
                http01_listen: None,
                dns_hook: None,
                account_path: dir.join("account.json"),
                certs_dir: dir,
                store: Arc::new(AcmeCertStore::new()),
                #[cfg(feature = "http3")]
                quic_store: Arc::new(crate::AcmeQuicCertStore::new()),
                tokens: Arc::new(Http01TokenStore::new()),
                tls_alpn01: Arc::new(TlsAlpn01CertStore::new()),
            })
        }

        fn write_pair(&self, cert: &rcgen::Certificate, key: &KeyPair) {
            let (cert_path, key_path) = cert_paths_for_sni(&self.0, TEST_SNI);
            ensure_dir(cert_path.parent().unwrap(), 0o700).unwrap();
            write_bytes_file(&key_path, key.serialize_pem().as_bytes(), 0o600).unwrap();
            write_bytes_file(&cert_path, cert.pem().as_bytes(), 0o644).unwrap();
        }

        fn assert_empty(&self) {
            assert!(self.0.store.get(TEST_SNI).is_none());
            #[cfg(feature = "http3")]
            assert!(self.0.quic_store.get(TEST_SNI).is_none());
        }
    }

    #[cfg(unix)]
    impl Drop for CertFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0.certs_dir);
        }
    }

    #[cfg(unix)]
    fn test_pair() -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![TEST_SNI.to_string()]).unwrap();
        params.not_after = rcgen::date_time_ymd(4096, 1, 1);
        (params.self_signed(&key).unwrap(), key)
    }

    #[cfg(unix)]
    #[test]
    fn matching_not_due_pair_is_loaded_and_reused() {
        let fixture = CertFixture::new();
        let (cert, key) = test_pair();
        fixture.write_pair(&cert, &key);
        assert!(reuse_existing_certificate(&fixture.0, TEST_SNI).unwrap());
        let loaded = fixture.0.store.get(TEST_SNI).unwrap();
        assert_eq!(loaded.cert, vec![cert.der().clone()]);
        loaded.keys_match().unwrap();
        #[cfg(feature = "http3")]
        {
            let loaded = fixture.0.quic_store.get(TEST_SNI).unwrap();
            assert_eq!(loaded.cert, vec![cert.der().clone()]);
            loaded.keys_match().unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let (cert_path, key_path) = cert_paths_for_sni(&fixture.0, TEST_SNI);
            assert_eq!(
                fs::metadata(cert_path).unwrap().permissions().mode() & 0o777,
                0o644
            );
            assert_eq!(
                fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn key_only_replacement_is_rejected_and_requests_renewal_without_publication() {
        let fixture = CertFixture::new();
        let (cert, key) = test_pair();
        fixture.write_pair(&cert, &key);
        let (cert_path, key_path) = cert_paths_for_sni(&fixture.0, TEST_SNI);
        assert!(!should_renew(read_leaf_not_after(&cert_path).unwrap(), 30).unwrap());
        let (replacement_cert, replacement_key) = test_pair();
        // Simulate interruption after key.pem is replaced but before cert.pem is written.
        write_bytes_file(&key_path, replacement_key.serialize_pem().as_bytes(), 0o600).unwrap();
        let err = load_cert_into_store(&fixture.0, TEST_SNI).unwrap_err();
        assert!(format!("{err:#}").contains("certificate/key pair"));
        fixture.assert_empty();
        // This is the decision used by ensure: only Ok(true) avoids renewal.
        assert!(reuse_existing_certificate(&fixture.0, TEST_SNI).is_err());
        fixture.assert_empty();

        // Completing/retrying issuance repairs the persisted pair and permits reuse.
        fixture.write_pair(&replacement_cert, &replacement_key);
        assert!(reuse_existing_certificate(&fixture.0, TEST_SNI).unwrap());
        assert_eq!(
            fixture.0.store.get(TEST_SNI).unwrap().cert,
            vec![replacement_cert.der().clone()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn invalid_persisted_material_preserves_last_known_good_stores() {
        let fixture = CertFixture::new();
        let (cert, key) = test_pair();
        fixture.write_pair(&cert, &key);
        assert!(load_cert_into_store(&fixture.0, TEST_SNI).unwrap());
        let good = fixture.0.store.get(TEST_SNI).unwrap();
        #[cfg(feature = "http3")]
        let quic_good = fixture.0.quic_store.get(TEST_SNI).unwrap();
        let (_, key_path) = cert_paths_for_sni(&fixture.0, TEST_SNI);
        let assert_rejected = || {
            assert!(!matches!(
                load_cert_into_store(&fixture.0, TEST_SNI),
                Ok(true)
            ));
            assert!(!matches!(
                reuse_existing_certificate(&fixture.0, TEST_SNI),
                Ok(true)
            ));
            assert!(Arc::ptr_eq(&good, &fixture.0.store.get(TEST_SNI).unwrap()));
            #[cfg(feature = "http3")]
            assert!(Arc::ptr_eq(
                &quic_good,
                &fixture.0.quic_store.get(TEST_SNI).unwrap()
            ));
        };
        let replacement_key = KeyPair::generate().unwrap();
        for contents in [
            Some(replacement_key.serialize_pem()),
            Some("invalid key".to_string()),
            None,
        ] {
            match contents {
                Some(contents) => write_bytes_file(&key_path, contents.as_bytes(), 0o600).unwrap(),
                None => fs::remove_file(&key_path).unwrap(),
            }
            assert_rejected();
        }
        // A directory causes a deterministic read failure even when tests run as root.
        fs::create_dir(&key_path).unwrap();
        assert_rejected();
    }

    #[cfg(unix)]
    #[test]
    fn due_or_missing_certificate_is_not_reused() {
        let fixture = CertFixture::new();
        assert!(!reuse_existing_certificate(&fixture.0, TEST_SNI).unwrap());
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![TEST_SNI.to_string()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2000, 1, 1);
        fixture.write_pair(&params.self_signed(&key).unwrap(), &key);
        assert!(!reuse_existing_certificate(&fixture.0, TEST_SNI).unwrap());
        fixture.assert_empty();
    }

    /// ACME secure file output fails closed where owner-only semantics are
    /// unavailable (Windows): no output file may be left behind.
    #[cfg(windows)]
    #[test]
    fn secure_file_output_fails_closed_on_unsupported_platform() {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "qpx-acme-unsupported-{}-{}-{}.pem",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_file(&path);
        let err = write_bytes_file(&path, b"synthetic-acme-contents", 0o600).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains(
                "secure file creation is not supported on this platform without owner-only file permissions"
            ),
            "ACME secure file output must fail closed on unsupported platform: {message}"
        );
        assert!(
            !path.exists(),
            "ACME secure file output must not create output on unsupported platform"
        );
        let _ = fs::remove_file(&path);
    }

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
