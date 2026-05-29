use anyhow::{Context, Result, anyhow};
use chrono::Datelike as _;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone)]
pub struct CaStore {
    pub(super) issuer: Arc<Issuer<'static, KeyPair>>,
    pub(super) ca_pem: String,
    pub(super) ca_key_pem: String,
    pub(super) ca_der: Vec<u8>,
    state_dir: PathBuf,
}

pub fn load_or_generate_ca(state_dir: &Path) -> Result<CaStore> {
    ensure_private_state_dir(state_dir)?;
    let cert_path = state_dir.join("ca.crt");
    let key_path = state_dir.join("ca.key");
    if cert_path.exists() && key_path.exists() {
        ensure_path_not_symlink(&cert_path, "ca cert")?;
        ensure_path_not_symlink(&key_path, "ca key")?;
        enforce_private_key_permissions(&key_path)?;
        let ca_pem = fs::read_to_string(&cert_path)?;
        let ca_key_pem = fs::read_to_string(&key_path)?;
        let key_pair = KeyPair::from_pem(&ca_key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, key_pair)?;
        let ca_der = {
            let mut certs = CertificateDer::pem_slice_iter(ca_pem.as_bytes())
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("invalid CA pem: {e}"))?;
            certs.pop().ok_or_else(|| anyhow!("no CA cert found"))?
        };
        return Ok(CaStore {
            issuer: Arc::new(issuer),
            ca_pem,
            ca_key_pem,
            ca_der: ca_der.to_vec(),
            state_dir: state_dir.to_path_buf(),
        });
    }

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "qpx Proxy CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let now = chrono::Utc::now();
    let not_before = now.date_naive();
    let not_after = (now + chrono::Duration::days(365 * 10)).date_naive();
    params.not_before = rcgen::date_time_ymd(
        not_before.year(),
        not_before.month() as u8,
        not_before.day() as u8,
    );
    params.not_after = rcgen::date_time_ymd(
        not_after.year(),
        not_after.month() as u8,
        not_after.day() as u8,
    );

    let key_pair = KeyPair::generate()?;
    let ca_cert = params.self_signed(&key_pair)?;
    let ca_pem = ca_cert.pem();
    let ca_key_pem = key_pair.serialize_pem();
    write_cert_file(&cert_path, &ca_pem)?;
    write_private_key_file(&key_path, &ca_key_pem)?;
    let ca_der = ca_cert.der().to_vec();
    let issuer = Issuer::new(params, key_pair);
    Ok(CaStore {
        issuer: Arc::new(issuer),
        ca_pem,
        ca_key_pem,
        ca_der,
        state_dir: state_dir.to_path_buf(),
    })
}

pub fn write_ca_files(state_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let ca = load_or_generate_ca(state_dir)?;
    let cert_path = ca.cert_path();
    let key_path = ca.key_path();
    write_cert_file(&cert_path, &ca.ca_pem)?;
    write_private_key_file(&key_path, &ca.ca_key_pem)?;
    Ok((cert_path, key_path))
}

#[cfg(unix)]
fn write_cert_file(path: &Path, contents: &str) -> Result<()> {
    write_text_file(path, contents, 0o644)
}

#[cfg(not(unix))]
fn write_cert_file(path: &Path, contents: &str) -> Result<()> {
    write_text_file(path, contents)
}

#[cfg(unix)]
fn write_private_key_file(path: &Path, contents: &str) -> Result<()> {
    write_text_file(path, contents, 0o600)?;
    enforce_private_key_permissions(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_key_file(path: &Path, contents: &str) -> Result<()> {
    write_text_file(path, contents)?;
    enforce_private_key_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn write_text_file(path: &Path, contents: &str, mode: u32) -> Result<()> {
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
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_text_file(path: &Path, contents: &str) -> Result<()> {
    let _ = (path, contents);
    Err(anyhow!(
        "refusing to write MITM CA material on this platform: private ACL and reparse-point protection is not implemented"
    ))
}

#[cfg(unix)]
fn enforce_private_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_private_key_permissions(path: &Path) -> Result<()> {
    let _ = path;
    Err(anyhow!(
        "refusing to use MITM CA private key on this platform: private ACL and reparse-point protection is not implemented"
    ))
}

fn ensure_path_not_symlink(path: &Path, label: &str) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(anyhow!(
            "{label} path must not be a symlink: {}",
            path.display()
        ));
    }
    Ok(())
}

fn ensure_private_state_dir(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    current = resolve_trusted_state_symlink(&current, &meta)?;
                    continue;
                }
                if !meta.is_dir() {
                    return Err(anyhow!(
                        "state dir component is not a directory: {}",
                        current.display()
                    ));
                }
                reject_untrusted_state_ancestor(&current, &meta)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).with_context(|| {
                    format!("failed to create state dir component {}", current.display())
                })?;
                set_private_directory_permissions(&current)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
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
fn reject_untrusted_state_ancestor(path: &Path, meta: &fs::Metadata) -> Result<()> {
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
            "refusing state dir ancestor not owned by root or current user: {}",
            path.display()
        ));
    }
    if sticky && mode & 0o022 != 0 && meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing sticky writable state dir ancestor not owned by root or current user: {}",
            path.display()
        ));
    }
    if mode & 0o002 != 0 && !sticky {
        return Err(anyhow!(
            "refusing attacker-writable state dir ancestor {}",
            path.display()
        ));
    }
    if !sticky && mode & 0o020 != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing group-writable state dir ancestor not owned by current user: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn resolve_trusted_state_symlink(path: &Path, meta: &fs::Metadata) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "state dir path must not contain untrusted symlink component: {}",
            path.display()
        ));
    }
    let resolved = fs::canonicalize(path).with_context(|| {
        format!(
            "failed to resolve trusted state dir symlink {}",
            path.display()
        )
    })?;
    let resolved_meta = fs::metadata(&resolved)?;
    if !resolved_meta.is_dir() {
        return Err(anyhow!(
            "state dir symlink target is not a directory: {}",
            resolved.display()
        ));
    }
    reject_untrusted_state_ancestor(&resolved, &resolved_meta)?;
    Ok(resolved)
}

#[cfg(not(unix))]
fn resolve_trusted_state_symlink(path: &Path, _meta: &fs::Metadata) -> Result<PathBuf> {
    Err(anyhow!(
        "state dir path must not contain symlinks: {}",
        path.display()
    ))
}

#[cfg(not(unix))]
fn reject_untrusted_state_ancestor(_path: &Path, _meta: &fs::Metadata) -> Result<()> {
    Err(anyhow!(
        "refusing to use MITM state directory on this platform: private ACL and reparse-point protection is not implemented"
    ))
}
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

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn issue_server_cert(
        &self,
        subject_alt_names: &[String],
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let mut sans: Vec<String> = subject_alt_names
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if sans.is_empty() {
            sans.push("localhost".to_string());
        }

        let mut params = CertificateParams::new(sans.clone())?;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, sans[0].clone());
        let key_pair = KeyPair::generate()?;
        let leaf = params.signed_by(&key_pair, self.issuer.as_ref())?;
        let chain = vec![
            leaf.der().clone(),
            CertificateDer::from(self.ca_der.clone()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        Ok((chain, key))
    }
}
