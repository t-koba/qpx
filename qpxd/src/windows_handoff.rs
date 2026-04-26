#[cfg(windows)]
use anyhow::anyhow;
#[cfg(windows)]
use anyhow::{Context, Result};
use qpx_core::config::Config;
#[cfg(windows)]
use serde::de::DeserializeOwned;
#[cfg(windows)]
use serde::Serialize;
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(windows)]
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;
#[cfg(windows)]
use uuid::Uuid;

#[cfg(windows)]
use std::mem::MaybeUninit;
#[cfg(windows)]
use std::net::{TcpListener, UdpSocket};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, FromRawSocket, RawSocket};
#[cfg(windows)]
use std::sync::OnceLock;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    WSADuplicateSocketW, WSASocketW, WSAStartup, FROM_PROTOCOL_INFO, INVALID_SOCKET, MAKEWORD,
    SOCKET_ERROR, WSADATA, WSAPROTOCOL_INFOW, WSA_FLAG_OVERLAPPED,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateEventW, OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE, SYNCHRONIZE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};

#[cfg(windows)]
pub(crate) const HANDOFF_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn handoff_dir(config: &Config) -> PathBuf {
    config
        .state_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(default_handoff_root)
        .join("upgrade")
}

#[cfg(windows)]
fn default_handoff_root() -> PathBuf {
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("qpx")
            .join("upgrade-handoff");
    }
    if let Some(user_profile) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(user_profile)
            .join("AppData")
            .join("Local")
            .join("qpx")
            .join("upgrade-handoff");
    }
    PathBuf::from(r"C:\qpx").join("upgrade-handoff")
}

#[cfg(not(windows))]
fn default_handoff_root() -> PathBuf {
    std::env::temp_dir().join("qpx-upgrade")
}

#[cfg(windows)]
pub(crate) fn create_handoff_path(config: &Config, prefix: &str) -> Result<PathBuf> {
    let dir = handoff_dir(config);
    ensure_secure_handoff_dir(&dir)?;
    Ok(dir.join(format!("{prefix}-{}.json", Uuid::new_v4())))
}

#[cfg(windows)]
pub(crate) fn write_json_file(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_secure_handoff_dir(parent)?;
    }
    reject_existing_reparse_point(path)?;
    let serialized = serde_json::to_vec(value).context("failed to serialize handoff payload")?;
    let tmp = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    reject_existing_reparse_point(&tmp)?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .with_context(|| format!("failed to create handoff file {}", tmp.display()))?;
    use std::io::Write;
    file.write_all(&serialized)
        .with_context(|| format!("failed to write handoff file {}", tmp.display()))?;
    file.flush().ok();
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to publish handoff file {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn read_json_wait<T: DeserializeOwned>(path: &Path) -> Result<T> {
    if let Some(parent) = path.parent() {
        ensure_secure_handoff_dir(parent)?;
    }
    let deadline = Instant::now() + HANDOFF_WAIT_TIMEOUT;
    loop {
        reject_existing_reparse_point(path)?;
        match std::fs::read(path) {
            Ok(buf) => return serde_json::from_slice(&buf).context("invalid handoff payload"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if Instant::now() >= deadline {
                    return Err(anyhow!(
                        "timed out waiting for handoff file {}",
                        path.display()
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to read handoff file {}", path.display()));
            }
        }
    }
}

#[cfg(windows)]
fn ensure_secure_handoff_dir(dir: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in dir.components() {
        current.push(component.as_os_str());
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                reject_reparse_point(&current, &meta)?;
                if !meta.is_dir() {
                    return Err(anyhow!(
                        "handoff path component is not a directory: {}",
                        current.display()
                    ));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).with_context(|| {
                    format!("failed to create handoff dir {}", current.display())
                })?;
                let meta = std::fs::symlink_metadata(&current)?;
                reject_reparse_point(&current, &meta)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn reject_existing_reparse_point(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => reject_reparse_point(path, &meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(windows)]
fn reject_reparse_point(path: &Path, meta: &std::fs::Metadata) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(anyhow!(
            "refusing reparse-point handoff path component {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_winsock_started() -> Result<()> {
    static START: OnceLock<Result<()>> = OnceLock::new();
    START
        .get_or_init(|| {
            let mut data = MaybeUninit::<WSADATA>::uninit();
            let rc = unsafe { WSAStartup(MAKEWORD(2, 2), data.as_mut_ptr()) };
            if rc == 0 {
                Ok(())
            } else {
                Err(anyhow!("WSAStartup failed with {}", rc))
            }
        })
        .clone()
}

#[cfg(windows)]
fn protocol_info_to_bytes(info: &WSAPROTOCOL_INFOW) -> Vec<u8> {
    unsafe {
        std::slice::from_raw_parts(
            (info as *const WSAPROTOCOL_INFOW).cast::<u8>(),
            std::mem::size_of::<WSAPROTOCOL_INFOW>(),
        )
        .to_vec()
    }
}

#[cfg(windows)]
fn protocol_info_from_bytes(bytes: &[u8]) -> Result<WSAPROTOCOL_INFOW> {
    if bytes.len() != std::mem::size_of::<WSAPROTOCOL_INFOW>() {
        return Err(anyhow!(
            "invalid WSAPROTOCOL_INFO length: expected {}, got {}",
            std::mem::size_of::<WSAPROTOCOL_INFOW>(),
            bytes.len()
        ));
    }
    let mut info = MaybeUninit::<WSAPROTOCOL_INFOW>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), info.as_mut_ptr().cast::<u8>(), bytes.len());
        Ok(info.assume_init())
    }
}

#[cfg(windows)]
pub(crate) fn duplicate_socket_for_child<T: AsRawSocket>(
    socket: &T,
    child_pid: u32,
) -> Result<Vec<u8>> {
    ensure_winsock_started()?;
    let mut info = MaybeUninit::<WSAPROTOCOL_INFOW>::zeroed();
    let rc = unsafe {
        WSADuplicateSocketW(
            socket.as_raw_socket() as usize,
            child_pid,
            info.as_mut_ptr(),
        )
    };
    if rc == SOCKET_ERROR {
        return Err(anyhow!(
            "WSADuplicateSocketW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let info = unsafe { info.assume_init() };
    Ok(protocol_info_to_bytes(&info))
}

#[cfg(windows)]
fn recreate_socket(bytes: &[u8]) -> Result<RawSocket> {
    ensure_winsock_started()?;
    let mut info = protocol_info_from_bytes(bytes)?;
    let socket = unsafe {
        WSASocketW(
            FROM_PROTOCOL_INFO,
            FROM_PROTOCOL_INFO,
            FROM_PROTOCOL_INFO,
            &mut info,
            0,
            WSA_FLAG_OVERLAPPED,
        )
    };
    if socket == INVALID_SOCKET {
        return Err(anyhow!(
            "WSASocketW(FROM_PROTOCOL_INFO) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(socket as RawSocket)
}

#[cfg(windows)]
pub(crate) fn adopt_tcp_listener(bytes: &[u8]) -> Result<TcpListener> {
    let listener = unsafe { TcpListener::from_raw_socket(recreate_socket(bytes)?) };
    listener
        .set_nonblocking(true)
        .context("failed to set inherited tcp listener nonblocking")?;
    Ok(listener)
}

#[cfg(windows)]
pub(crate) fn adopt_udp_socket(bytes: &[u8]) -> Result<UdpSocket> {
    let socket = unsafe { UdpSocket::from_raw_socket(recreate_socket(bytes)?) };
    socket
        .set_nonblocking(true)
        .context("failed to set inherited udp socket nonblocking")?;
    Ok(socket)
}

#[cfg(windows)]
fn upgrade_event_name(pid: u32) -> Vec<u16> {
    format!("Local\\qpx-upgrade-{pid}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
pub(crate) struct EventHandle(HANDLE);

#[cfg(windows)]
impl EventHandle {
    pub(crate) fn raw(&self) -> HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for EventHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
pub(crate) fn create_upgrade_event(pid: u32) -> Result<EventHandle> {
    let name = upgrade_event_name(pid);
    let handle = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) };
    if handle == 0 {
        return Err(anyhow!(
            "CreateEventW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(EventHandle(handle))
}

#[cfg(windows)]
pub(crate) fn open_upgrade_event(pid: u32) -> Result<EventHandle> {
    let name = upgrade_event_name(pid);
    let handle = unsafe { OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, 0, name.as_ptr()) };
    if handle == 0 {
        return Err(anyhow!(
            "OpenEventW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(EventHandle(handle))
}

#[cfg(windows)]
pub(crate) fn signal_event(event: &EventHandle) -> Result<()> {
    if unsafe { SetEvent(event.raw()) } == 0 {
        return Err(anyhow!(
            "SetEvent failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn wait_for_event(event: &EventHandle, timeout: Duration) -> Result<bool> {
    wait_for_event_raw(event.raw(), timeout)
}

#[cfg(windows)]
pub(crate) fn wait_for_event_raw(handle: HANDLE, timeout: Duration) -> Result<bool> {
    let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
    match unsafe { WaitForSingleObject(handle, timeout_ms) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(anyhow!(
            "WaitForSingleObject failed: {}",
            std::io::Error::last_os_error()
        )),
    }
}
