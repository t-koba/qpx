use anyhow::{Context, anyhow};
use chrono::Datelike as _;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::TlsResult as Result;

/// Local MITM CA material and issuer state.
#[derive(Clone)]
pub struct CaStore {
    pub(super) issuer: Arc<Issuer<'static, KeyPair>>,
    pub(super) ca_pem: String,
    pub(super) ca_key_pem: String,
    pub(super) ca_der: Vec<u8>,
    state_dir: PathBuf,
}

/// Loads an existing CA from `state_dir` or generates and stores a new one.
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

/// Rewrites CA certificate and key files and returns their paths.
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
    write_text_file(path, contents, false)
}

#[cfg(unix)]
fn write_private_key_file(path: &Path, contents: &str) -> Result<()> {
    write_text_file(path, contents, 0o600)?;
    enforce_private_key_permissions(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_key_file(path: &Path, contents: &str) -> Result<()> {
    write_text_file(path, contents, true)?;
    enforce_private_key_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn write_text_file(path: &Path, contents: &str, mode: u32) -> Result<()> {
    use std::io::Write;

    let mut file =
        crate::secure_file::open_secure_output_file(path).map_err(|err| anyhow!("{err}"))?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(windows)]
fn write_text_file(path: &Path, contents: &str, owner_only_acl: bool) -> Result<()> {
    use std::io::Write;

    ensure_path_not_symlink(path, "MITM CA material")?;
    let mut file = match fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => {
            validate_windows_ca_material_handle(&file, path)?;
            file
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("failed to create MITM CA material {}", path.display()))?,
        Err(err) => {
            return Err(
                anyhow!("failed to open MITM CA material {}: {err}", path.display()).into(),
            );
        }
    };
    validate_windows_ca_material_handle(&file, path)?;
    if owner_only_acl {
        set_owner_only_acl(path)?;
    }
    file.set_len(0)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    if owner_only_acl {
        set_owner_only_acl(path)?;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn write_text_file(path: &Path, _contents: &str) -> Result<()> {
    Err(anyhow!(
        "refusing to write MITM CA material on this platform: private ACL and reparse-point protection is not implemented: {}",
        path.display()
    ))
}

#[cfg(unix)]
fn enforce_private_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    ensure_path_not_symlink(path, "ca key")?;
    let file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    crate::secure_file::validate_secure_file_handle(&file, path).map_err(|err| anyhow!("{err}"))?;
    let metadata = file.metadata()?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(windows)]
fn enforce_private_key_permissions(path: &Path) -> Result<()> {
    ensure_path_not_symlink(path, "ca key")?;
    let file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    validate_windows_ca_material_handle(&file, path)?;
    set_owner_only_acl(path)
}

#[cfg(not(any(unix, windows)))]
fn enforce_private_key_permissions(path: &Path) -> Result<()> {
    Err(anyhow!(
        "refusing to use MITM CA private key on this platform: private ACL and reparse-point protection is not implemented: {}",
        path.display()
    )
    .into())
}

fn ensure_path_not_symlink(path: &Path, label: &str) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(anyhow!("{label} path must not be a symlink: {}", path.display()).into());
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
                    )
                    .into());
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
    #[cfg(windows)]
    {
        set_private_directory_permissions(path)?;
    }
    Ok(())
}

fn set_private_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        set_owner_only_directory_acl(path)?;
    }
    #[cfg(not(any(unix, windows)))]
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
    // SAFETY: geteuid has no preconditions and only reads the current process credentials.
    let euid = unsafe { libc::geteuid() };

    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing state dir ancestor not owned by root or current user: {}",
            path.display()
        )
        .into());
    }
    if sticky && mode & 0o022 != 0 && meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing sticky writable state dir ancestor not owned by root or current user: {}",
            path.display()
        )
        .into());
    }
    if mode & 0o002 != 0 && !sticky {
        return Err(anyhow!(
            "refusing attacker-writable state dir ancestor {}",
            path.display()
        )
        .into());
    }
    if !sticky && mode & 0o020 != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing group-writable state dir ancestor not owned by current user: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(unix)]
fn resolve_trusted_state_symlink(path: &Path, meta: &fs::Metadata) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid has no preconditions and only reads the current process credentials.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "state dir path must not contain untrusted symlink component: {}",
            path.display()
        )
        .into());
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
        )
        .into());
    }
    reject_untrusted_state_ancestor(&resolved, &resolved_meta)?;
    Ok(resolved)
}

#[cfg(not(unix))]
fn resolve_trusted_state_symlink(path: &Path, _meta: &fs::Metadata) -> Result<PathBuf> {
    Err(anyhow!(
        "state dir path must not contain symlinks: {}",
        path.display()
    )
    .into())
}

#[cfg(windows)]
fn reject_untrusted_state_ancestor(_path: &Path, _meta: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn validate_windows_ca_material_handle(file: &fs::File, path: &Path) -> Result<()> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        GetFileInformationByHandle,
    };

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "MITM CA material must be a regular file: {}",
            path.display()
        )
        .into());
    }
    let mut info = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file` is an open file handle and `info` points to writable storage.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), info.as_mut_ptr()) };
    if ok == 0 {
        return Err(anyhow!(
            "failed to inspect MITM CA material handle {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )
        .into());
    }
    // SAFETY: the API succeeded and initialized the structure.
    let info = unsafe { info.assume_init() };
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(anyhow!(
            "MITM CA material must not be a reparse point: {}",
            path.display()
        )
        .into());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(anyhow!(
            "MITM CA material must not be a directory: {}",
            path.display()
        )
        .into());
    }
    if info.nNumberOfLinks != 1 {
        return Err(anyhow!(
            "MITM CA material must not have hard links: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn reject_untrusted_state_ancestor(path: &Path, _meta: &fs::Metadata) -> Result<()> {
    Err(anyhow!(
        "refusing to use MITM state directory on this platform: private ACL and reparse-point protection is not implemented: {}",
        path.display()
    ))
}

#[cfg(windows)]
fn set_owner_only_acl(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR,
    };

    // Protected DACL: LocalSystem, Administrators and the current owner get full access.
    // This keeps generated MITM CA private material out of inherited temp-directory ACLs.
    let sddl_text = concat!("D:P(A;;FA;;;SY)(A;;FA;;;", "\x42", "\x41", ")(A;;FA;;;OW)");
    let sddl: Vec<u16> = sddl_text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and `descriptor` is an out pointer freed with LocalFree.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(anyhow!(
            "failed to build owner-only security descriptor: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: descriptor is a valid security descriptor produced by the Win32 conversion API.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        // SAFETY: descriptor came from ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(descriptor.cast());
        }
        return Err(anyhow!(
            "failed to extract owner-only DACL for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )
        .into());
    }
    if dacl_present == 0 || dacl.is_null() {
        // SAFETY: descriptor came from ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(descriptor.cast());
        }
        return Err(anyhow!(
            "owner-only security descriptor did not contain a DACL for {}",
            path.display()
        )
        .into());
    }
    let mut path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: path_wide is NUL-terminated and DACL belongs to the live descriptor.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    // SAFETY: descriptor came from ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe {
        let _ = LocalFree(descriptor.cast());
    }
    if status != 0 {
        return Err(anyhow!(
            "failed to set owner-only ACL on MITM CA material {}: {}",
            path.display(),
            std::io::Error::from_raw_os_error(status as i32)
        )
        .into());
    }
    Ok(())
}

#[cfg(windows)]
fn set_owner_only_directory_acl(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetFileSecurityW,
    };

    let sddl_text = concat!("D:P(A;;FA;;;SY)(A;;FA;;;", "\x42", "\x41", ")(A;;FA;;;OW)");
    let sddl: Vec<u16> = sddl_text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and `descriptor` is an out pointer freed with LocalFree.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(anyhow!(
            "failed to build owner-only directory security descriptor: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }

    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: both pointers are valid NUL-terminated/Windows-owned buffers for the call.
    let ok = unsafe { SetFileSecurityW(path_wide.as_ptr(), DACL_SECURITY_INFORMATION, descriptor) };
    // SAFETY: descriptor came from ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe {
        let _ = LocalFree(descriptor.cast());
    }
    if ok == 0 {
        return Err(anyhow!(
            "failed to set owner-only ACL on MITM CA state directory {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )
        .into());
    }
    Ok(())
}

impl CaStore {
    /// State directory holding `ca.crt` and `ca.key`.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Path to the CA certificate file.
    pub fn cert_path(&self) -> PathBuf {
        self.state_dir().join("ca.crt")
    }

    /// Path to the CA private key file.
    pub fn key_path(&self) -> PathBuf {
        self.state_dir().join("ca.key")
    }

    /// PEM-encoded CA certificate.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// Issues a leaf server certificate signed by this CA.
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
