use crate::rate_limit::RateLimitContext;
use crate::udp_socket_handoff::{adopt_inherited_udp_socket, duplicate_std_udp_socket_for_handoff};
#[cfg(windows)]
use crate::udp_socket_handoff::{
    adopt_inherited_udp_socket_windows, duplicate_std_udp_socket_for_child,
};
use anyhow::{anyhow, Context, Result};
use qpx_core::config::Config;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[cfg(unix)]
use std::os::fd::OwnedFd;

const ENV_INHERITED_UDP_SESSIONS: &str = "QPX_INHERITED_UDP_SESSIONS";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct ExportedQuicConnectionId {
    pub(crate) len: u8,
    pub(crate) bytes: [u8; 20],
}

#[derive(Debug)]
pub(crate) struct TransparentUdpSessionRestore {
    pub(crate) session_id: u64,
    pub(crate) socket: std::net::UdpSocket,
    pub(crate) upstream_local_addr: SocketAddr,
    pub(crate) upstream_peer_addr: SocketAddr,
    pub(crate) client_addr: SocketAddr,
    pub(crate) target_key: String,
    pub(crate) last_seen_ms: u64,
    pub(crate) client_cid_len: Option<u8>,
    pub(crate) server_cid_len: Option<u8>,
    pub(crate) cids: Vec<ExportedQuicConnectionId>,
    pub(crate) matched_rule: Option<String>,
    pub(crate) rate_limit_profile: Option<String>,
    pub(crate) rate_limit_ctx: RateLimitContext,
}

#[derive(Debug)]
pub(crate) struct TransparentUdpListenerRestore {
    pub(crate) listen: String,
    pub(crate) exported_elapsed_ms: u64,
    pub(crate) sessions: Vec<TransparentUdpSessionRestore>,
}

#[derive(Debug)]
pub(crate) struct ReversePassthroughSessionRestore {
    pub(crate) session_id: u64,
    pub(crate) socket: std::net::UdpSocket,
    pub(crate) upstream_local_addr: SocketAddr,
    pub(crate) upstream_peer_addr: SocketAddr,
    pub(crate) client_addr: SocketAddr,
    pub(crate) last_seen_ms: u64,
    pub(crate) bytes_in: u64,
    pub(crate) bytes_out: u64,
    pub(crate) client_cid_len: Option<u8>,
    pub(crate) server_cid_len: Option<u8>,
    pub(crate) cids: Vec<ExportedQuicConnectionId>,
}

#[derive(Debug)]
pub(crate) struct ReversePassthroughListenerRestore {
    pub(crate) listen: String,
    pub(crate) exported_elapsed_ms: u64,
    pub(crate) sessions: Vec<ReversePassthroughSessionRestore>,
}

#[derive(Debug, Default)]
pub(crate) struct UdpSessionRestoreState {
    transparent: HashMap<String, TransparentUdpListenerRestore>,
    reverse_passthrough: HashMap<String, ReversePassthroughListenerRestore>,
}

pub(crate) struct UdpSessionPreparedHandoff {
    pub(crate) env_value: String,
    pub(crate) cleanup_path: PathBuf,
    #[cfg(unix)]
    pub(crate) kept_fds: Vec<OwnedFd>,
    #[cfg(windows)]
    pending: WindowsUdpSessionPreparedHandoff,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedUdpSessionHandoff {
    transparent: Vec<PersistedTransparentUdpListenerRestore>,
    reverse_passthrough: Vec<PersistedReversePassthroughListenerRestore>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedTransparentUdpListenerRestore {
    name: String,
    listen: String,
    exported_elapsed_ms: u64,
    sessions: Vec<PersistedTransparentUdpSessionRestore>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedTransparentUdpSessionRestore {
    session_id: u64,
    #[cfg(unix)]
    fd: i32,
    #[cfg(windows)]
    socket: Vec<u8>,
    upstream_local_addr: SocketAddr,
    upstream_peer_addr: SocketAddr,
    client_addr: SocketAddr,
    target_key: String,
    last_seen_ms: u64,
    client_cid_len: Option<u8>,
    server_cid_len: Option<u8>,
    cids: Vec<ExportedQuicConnectionId>,
    matched_rule: Option<String>,
    rate_limit_profile: Option<String>,
    rate_limit_ctx: RateLimitContext,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedReversePassthroughListenerRestore {
    name: String,
    listen: String,
    exported_elapsed_ms: u64,
    sessions: Vec<PersistedReversePassthroughSessionRestore>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedReversePassthroughSessionRestore {
    session_id: u64,
    #[cfg(unix)]
    fd: i32,
    #[cfg(windows)]
    socket: Vec<u8>,
    upstream_local_addr: SocketAddr,
    upstream_peer_addr: SocketAddr,
    client_addr: SocketAddr,
    last_seen_ms: u64,
    bytes_in: u64,
    bytes_out: u64,
    client_cid_len: Option<u8>,
    server_cid_len: Option<u8>,
    cids: Vec<ExportedQuicConnectionId>,
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsUdpSessionPreparedHandoff {
    transparent: Vec<WindowsTransparentUdpListenerRestore>,
    reverse_passthrough: Vec<WindowsReversePassthroughListenerRestore>,
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsTransparentUdpListenerRestore {
    name: String,
    listen: String,
    exported_elapsed_ms: u64,
    sessions: Vec<WindowsTransparentUdpSessionRestore>,
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsTransparentUdpSessionRestore {
    session_id: u64,
    socket: std::net::UdpSocket,
    upstream_local_addr: SocketAddr,
    upstream_peer_addr: SocketAddr,
    client_addr: SocketAddr,
    target_key: String,
    last_seen_ms: u64,
    client_cid_len: Option<u8>,
    server_cid_len: Option<u8>,
    cids: Vec<ExportedQuicConnectionId>,
    matched_rule: Option<String>,
    rate_limit_profile: Option<String>,
    rate_limit_ctx: RateLimitContext,
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsReversePassthroughListenerRestore {
    name: String,
    listen: String,
    exported_elapsed_ms: u64,
    sessions: Vec<WindowsReversePassthroughSessionRestore>,
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsReversePassthroughSessionRestore {
    session_id: u64,
    socket: std::net::UdpSocket,
    upstream_local_addr: SocketAddr,
    upstream_peer_addr: SocketAddr,
    client_addr: SocketAddr,
    last_seen_ms: u64,
    bytes_in: u64,
    bytes_out: u64,
    client_cid_len: Option<u8>,
    server_cid_len: Option<u8>,
    cids: Vec<ExportedQuicConnectionId>,
}

impl UdpSessionRestoreState {
    pub(crate) fn is_empty(&self) -> bool {
        self.transparent.is_empty() && self.reverse_passthrough.is_empty()
    }

    pub(crate) fn insert_transparent(
        &mut self,
        name: String,
        restore: TransparentUdpListenerRestore,
    ) {
        self.transparent.insert(name, restore);
    }

    pub(crate) fn insert_reverse_passthrough(
        &mut self,
        name: String,
        restore: ReversePassthroughListenerRestore,
    ) {
        self.reverse_passthrough.insert(name, restore);
    }

    pub(crate) fn take_transparent(
        &mut self,
        name: &str,
        expected_listen: &str,
    ) -> Result<Option<TransparentUdpListenerRestore>> {
        let Some(restore) = self.transparent.remove(name) else {
            return Ok(None);
        };
        if restore.listen != expected_listen {
            return Err(anyhow!(
                "transparent UDP handoff for {} expected listen {}, got {}",
                name,
                expected_listen,
                restore.listen
            ));
        }
        Ok(Some(restore))
    }

    pub(crate) fn take_reverse_passthrough(
        &mut self,
        name: &str,
        expected_listen: &str,
    ) -> Result<Option<ReversePassthroughListenerRestore>> {
        let Some(restore) = self.reverse_passthrough.remove(name) else {
            return Ok(None);
        };
        if restore.listen != expected_listen {
            return Err(anyhow!(
                "reverse HTTP/3 passthrough handoff for {} expected listen {}, got {}",
                name,
                expected_listen,
                restore.listen
            ));
        }
        Ok(Some(restore))
    }

    pub(crate) fn ensure_consumed(&self) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let transparent = self.transparent.keys().cloned().collect::<Vec<_>>();
        let reverse_passthrough = self.reverse_passthrough.keys().cloned().collect::<Vec<_>>();
        Err(anyhow!(
            "unused UDP session handoff entries remain: transparent={transparent:?}, reverse_passthrough={reverse_passthrough:?}"
        ))
    }

    pub(crate) fn prepare_handoff(
        &self,
        config: &Config,
    ) -> Result<Option<UdpSessionPreparedHandoff>> {
        #[cfg(not(any(unix, windows)))]
        {
            let _ = self;
            let _ = config;
            return Err(anyhow!(
                "UDP session handoff is only supported on unix and windows"
            ));
        }

        #[cfg(unix)]
        {
            if self.is_empty() {
                return Ok(None);
            }

            let mut persisted = PersistedUdpSessionHandoff::default();
            let mut kept_fds = Vec::new();

            for (name, restore) in &self.transparent {
                let mut sessions = Vec::with_capacity(restore.sessions.len());
                for session in &restore.sessions {
                    sessions.push(PersistedTransparentUdpSessionRestore {
                        session_id: session.session_id,
                        fd: duplicate_std_udp_socket_for_handoff(&session.socket, &mut kept_fds)?,
                        upstream_local_addr: session.upstream_local_addr,
                        upstream_peer_addr: session.upstream_peer_addr,
                        client_addr: session.client_addr,
                        target_key: session.target_key.clone(),
                        last_seen_ms: session.last_seen_ms,
                        client_cid_len: session.client_cid_len,
                        server_cid_len: session.server_cid_len,
                        cids: session.cids.clone(),
                        matched_rule: session.matched_rule.clone(),
                        rate_limit_profile: session.rate_limit_profile.clone(),
                        rate_limit_ctx: session.rate_limit_ctx.clone(),
                    });
                }
                persisted
                    .transparent
                    .push(PersistedTransparentUdpListenerRestore {
                        name: name.clone(),
                        listen: restore.listen.clone(),
                        exported_elapsed_ms: restore.exported_elapsed_ms,
                        sessions,
                    });
            }

            for (name, restore) in &self.reverse_passthrough {
                let mut sessions = Vec::with_capacity(restore.sessions.len());
                for session in &restore.sessions {
                    sessions.push(PersistedReversePassthroughSessionRestore {
                        session_id: session.session_id,
                        fd: duplicate_std_udp_socket_for_handoff(&session.socket, &mut kept_fds)?,
                        upstream_local_addr: session.upstream_local_addr,
                        upstream_peer_addr: session.upstream_peer_addr,
                        client_addr: session.client_addr,
                        last_seen_ms: session.last_seen_ms,
                        bytes_in: session.bytes_in,
                        bytes_out: session.bytes_out,
                        client_cid_len: session.client_cid_len,
                        server_cid_len: session.server_cid_len,
                        cids: session.cids.clone(),
                    });
                }
                persisted
                    .reverse_passthrough
                    .push(PersistedReversePassthroughListenerRestore {
                        name: name.clone(),
                        listen: restore.listen.clone(),
                        exported_elapsed_ms: restore.exported_elapsed_ms,
                        sessions,
                    });
            }

            let dir = crate::windows_handoff::handoff_dir(config);
            ensure_secure_handoff_dir(&dir)?;
            let path = dir.join(format!("udp-sessions-{}.json", Uuid::new_v4()));
            write_handoff_file(path.as_path(), &persisted)?;
            Ok(Some(UdpSessionPreparedHandoff {
                env_value: path.display().to_string(),
                cleanup_path: path,
                kept_fds,
            }))
        }

        #[cfg(windows)]
        {
            if self.is_empty() {
                return Ok(None);
            }

            let path = crate::windows_handoff::create_handoff_path(config, "udp-sessions")?;
            let transparent =
                self.transparent
                    .iter()
                    .map(|(name, restore)| {
                        let sessions = restore
                            .sessions
                            .iter()
                            .map(|session| {
                                Ok(WindowsTransparentUdpSessionRestore {
                                    session_id: session.session_id,
                                    socket: session.socket.try_clone().context(
                                        "failed to clone transparent udp session socket",
                                    )?,
                                    upstream_local_addr: session.upstream_local_addr,
                                    upstream_peer_addr: session.upstream_peer_addr,
                                    client_addr: session.client_addr,
                                    target_key: session.target_key.clone(),
                                    last_seen_ms: session.last_seen_ms,
                                    client_cid_len: session.client_cid_len,
                                    server_cid_len: session.server_cid_len,
                                    cids: session.cids.clone(),
                                    matched_rule: session.matched_rule.clone(),
                                    rate_limit_profile: session.rate_limit_profile.clone(),
                                    rate_limit_ctx: session.rate_limit_ctx.clone(),
                                })
                            })
                            .collect::<Result<Vec<_>>>()?;
                        Ok(WindowsTransparentUdpListenerRestore {
                            name: name.clone(),
                            listen: restore.listen.clone(),
                            exported_elapsed_ms: restore.exported_elapsed_ms,
                            sessions,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;

            let reverse_passthrough = self
                .reverse_passthrough
                .iter()
                .map(|(name, restore)| {
                    let sessions = restore
                        .sessions
                        .iter()
                        .map(|session| {
                            Ok(WindowsReversePassthroughSessionRestore {
                                session_id: session.session_id,
                                socket: session.socket.try_clone().context(
                                    "failed to clone reverse passthrough udp session socket",
                                )?,
                                upstream_local_addr: session.upstream_local_addr,
                                upstream_peer_addr: session.upstream_peer_addr,
                                client_addr: session.client_addr,
                                last_seen_ms: session.last_seen_ms,
                                bytes_in: session.bytes_in,
                                bytes_out: session.bytes_out,
                                client_cid_len: session.client_cid_len,
                                server_cid_len: session.server_cid_len,
                                cids: session.cids.clone(),
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    Ok(WindowsReversePassthroughListenerRestore {
                        name: name.clone(),
                        listen: restore.listen.clone(),
                        exported_elapsed_ms: restore.exported_elapsed_ms,
                        sessions,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            Ok(Some(UdpSessionPreparedHandoff {
                env_value: path.display().to_string(),
                cleanup_path: path,
                pending: WindowsUdpSessionPreparedHandoff {
                    transparent,
                    reverse_passthrough,
                },
            }))
        }
    }

    pub(crate) fn take_from_env() -> Result<Option<Self>> {
        let Some(raw) = std::env::var_os(ENV_INHERITED_UDP_SESSIONS) else {
            return Ok(None);
        };
        unsafe {
            std::env::remove_var(ENV_INHERITED_UDP_SESSIONS);
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = raw;
            return Err(anyhow!(
                "UDP session handoff is only supported on unix and windows"
            ));
        }

        #[cfg(unix)]
        {
            let path = PathBuf::from(raw);
            let result = read_handoff_file(path.as_path()).and_then(Self::from_persisted_handoff);
            let _ = fs::remove_file(&path);
            result.map(Some)
        }

        #[cfg(windows)]
        {
            let path = PathBuf::from(raw);
            let result = crate::windows_handoff::read_json_wait(path.as_path())
                .and_then(Self::from_persisted_handoff);
            let _ = fs::remove_file(&path);
            result.map(Some)
        }
    }

    pub(crate) fn handoff_env_key() -> &'static str {
        ENV_INHERITED_UDP_SESSIONS
    }

    fn from_persisted_handoff(persisted: PersistedUdpSessionHandoff) -> Result<Self> {
        let mut state = Self::default();

        for listener in persisted.transparent {
            let mut sessions = Vec::with_capacity(listener.sessions.len());
            for session in listener.sessions {
                #[cfg(unix)]
                let socket = adopt_inherited_udp_socket(session.fd)?;
                #[cfg(windows)]
                let socket = adopt_inherited_udp_socket_windows(session.socket.as_slice())?;
                validate_connected_socket(
                    &socket,
                    session.upstream_local_addr,
                    session.upstream_peer_addr,
                )?;
                sessions.push(TransparentUdpSessionRestore {
                    session_id: session.session_id,
                    socket,
                    upstream_local_addr: session.upstream_local_addr,
                    upstream_peer_addr: session.upstream_peer_addr,
                    client_addr: session.client_addr,
                    target_key: session.target_key,
                    last_seen_ms: session.last_seen_ms,
                    client_cid_len: session.client_cid_len,
                    server_cid_len: session.server_cid_len,
                    cids: session.cids,
                    matched_rule: session.matched_rule,
                    rate_limit_profile: session.rate_limit_profile,
                    rate_limit_ctx: session.rate_limit_ctx,
                });
            }
            state.insert_transparent(
                listener.name,
                TransparentUdpListenerRestore {
                    listen: listener.listen,
                    exported_elapsed_ms: listener.exported_elapsed_ms,
                    sessions,
                },
            );
        }

        for listener in persisted.reverse_passthrough {
            let mut sessions = Vec::with_capacity(listener.sessions.len());
            for session in listener.sessions {
                #[cfg(unix)]
                let socket = adopt_inherited_udp_socket(session.fd)?;
                #[cfg(windows)]
                let socket = adopt_inherited_udp_socket_windows(session.socket.as_slice())?;
                validate_connected_socket(
                    &socket,
                    session.upstream_local_addr,
                    session.upstream_peer_addr,
                )?;
                sessions.push(ReversePassthroughSessionRestore {
                    session_id: session.session_id,
                    socket,
                    upstream_local_addr: session.upstream_local_addr,
                    upstream_peer_addr: session.upstream_peer_addr,
                    client_addr: session.client_addr,
                    last_seen_ms: session.last_seen_ms,
                    bytes_in: session.bytes_in,
                    bytes_out: session.bytes_out,
                    client_cid_len: session.client_cid_len,
                    server_cid_len: session.server_cid_len,
                    cids: session.cids,
                });
            }
            state.insert_reverse_passthrough(
                listener.name,
                ReversePassthroughListenerRestore {
                    listen: listener.listen,
                    exported_elapsed_ms: listener.exported_elapsed_ms,
                    sessions,
                },
            );
        }

        Ok(state)
    }

    #[cfg(windows)]
    pub(crate) fn finalize_handoff_for_child(
        handoff: &UdpSessionPreparedHandoff,
        child_pid: u32,
    ) -> Result<()> {
        let transparent = handoff
            .pending
            .transparent
            .iter()
            .map(|listener| {
                let sessions = listener
                    .sessions
                    .iter()
                    .map(|session| {
                        Ok(PersistedTransparentUdpSessionRestore {
                            session_id: session.session_id,
                            socket: duplicate_std_udp_socket_for_child(&session.socket, child_pid)?,
                            upstream_local_addr: session.upstream_local_addr,
                            upstream_peer_addr: session.upstream_peer_addr,
                            client_addr: session.client_addr,
                            target_key: session.target_key.clone(),
                            last_seen_ms: session.last_seen_ms,
                            client_cid_len: session.client_cid_len,
                            server_cid_len: session.server_cid_len,
                            cids: session.cids.clone(),
                            matched_rule: session.matched_rule.clone(),
                            rate_limit_profile: session.rate_limit_profile.clone(),
                            rate_limit_ctx: session.rate_limit_ctx.clone(),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(PersistedTransparentUdpListenerRestore {
                    name: listener.name.clone(),
                    listen: listener.listen.clone(),
                    exported_elapsed_ms: listener.exported_elapsed_ms,
                    sessions,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let reverse_passthrough = handoff
            .pending
            .reverse_passthrough
            .iter()
            .map(|listener| {
                let sessions = listener
                    .sessions
                    .iter()
                    .map(|session| {
                        Ok(PersistedReversePassthroughSessionRestore {
                            session_id: session.session_id,
                            socket: duplicate_std_udp_socket_for_child(&session.socket, child_pid)?,
                            upstream_local_addr: session.upstream_local_addr,
                            upstream_peer_addr: session.upstream_peer_addr,
                            client_addr: session.client_addr,
                            last_seen_ms: session.last_seen_ms,
                            bytes_in: session.bytes_in,
                            bytes_out: session.bytes_out,
                            client_cid_len: session.client_cid_len,
                            server_cid_len: session.server_cid_len,
                            cids: session.cids.clone(),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(PersistedReversePassthroughListenerRestore {
                    name: listener.name.clone(),
                    listen: listener.listen.clone(),
                    exported_elapsed_ms: listener.exported_elapsed_ms,
                    sessions,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        crate::windows_handoff::write_json_file(
            handoff.cleanup_path.as_path(),
            &PersistedUdpSessionHandoff {
                transparent,
                reverse_passthrough,
            },
        )
    }

    #[cfg(windows)]
    pub(crate) fn cleanup_handoff_file(handoff: &UdpSessionPreparedHandoff) {
        let _ = fs::remove_file(&handoff.cleanup_path);
    }
}

#[cfg(unix)]
fn ensure_secure_handoff_dir(dir: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in dir.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    current = resolve_trusted_handoff_symlink(&current, &meta)?;
                    continue;
                }
                if !meta.is_dir() {
                    return Err(anyhow!(
                        "udp handoff path component is not a directory: {}",
                        current.display()
                    ));
                }
                reject_untrusted_handoff_ancestor(&current, &meta)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).with_context(|| {
                    format!(
                        "failed to create udp handoff directory component {}",
                        current.display()
                    )
                })?;
                set_private_handoff_dir_permissions(&current)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    set_private_handoff_dir_permissions(dir)?;
    Ok(())
}

#[cfg(unix)]
fn resolve_trusted_handoff_symlink(path: &Path, meta: &fs::Metadata) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing untrusted symlinked udp handoff path component {}",
            path.display()
        ));
    }
    let resolved = fs::canonicalize(path).with_context(|| {
        format!(
            "failed to resolve udp handoff symlink component {}",
            path.display()
        )
    })?;
    let resolved_meta = fs::metadata(&resolved)?;
    if !resolved_meta.is_dir() {
        return Err(anyhow!(
            "udp handoff symlink target is not a directory: {}",
            resolved.display()
        ));
    }
    reject_untrusted_handoff_ancestor(&resolved, &resolved_meta)?;
    Ok(resolved)
}

#[cfg(unix)]
fn set_private_handoff_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).with_context(|| {
        format!(
            "failed to set private permissions on udp handoff directory {}",
            path.display()
        )
    })
}

#[cfg(unix)]
fn reject_untrusted_handoff_ancestor(path: &Path, meta: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let mode = meta.mode();
    let sticky = mode & libc::S_ISVTX as u32 != 0;
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing udp handoff ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if sticky && mode & 0o022 != 0 && meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing sticky writable udp handoff ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if mode & 0o002 != 0 && !sticky {
        return Err(anyhow!(
            "refusing attacker-writable udp handoff ancestor directory {}",
            path.display()
        ));
    }
    if !sticky && mode & 0o020 != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing group-writable udp handoff ancestor directory not owned by current user: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn write_handoff_file(path: &Path, handoff: &PersistedUdpSessionHandoff) -> Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let serialized =
        serde_json::to_vec(handoff).context("failed to serialize udp session handoff")?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to create udp session handoff {}", path.display()))?;
    file.write_all(&serialized)
        .with_context(|| format!("failed to write udp session handoff {}", path.display()))?;
    file.flush().ok();
    Ok(())
}

#[cfg(unix)]
fn read_handoff_file(path: &Path) -> Result<PersistedUdpSessionHandoff> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to open udp session handoff {}", path.display()))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .with_context(|| format!("failed to read udp session handoff {}", path.display()))?;
    serde_json::from_slice(&buf).context("invalid udp session handoff")
}

fn validate_connected_socket(
    socket: &std::net::UdpSocket,
    expected_local_addr: SocketAddr,
    expected_peer_addr: SocketAddr,
) -> Result<()> {
    let local_addr = socket
        .local_addr()
        .context("failed to resolve restored udp local addr")?;
    let peer_addr = socket
        .peer_addr()
        .context("failed to resolve restored udp peer addr")?;
    if local_addr != expected_local_addr {
        return Err(anyhow!(
            "restored udp local addr mismatch: expected {}, got {}",
            expected_local_addr,
            local_addr
        ));
    }
    if peer_addr != expected_peer_addr {
        return Err(anyhow!(
            "restored udp peer addr mismatch: expected {}, got {}",
            expected_peer_addr,
            peer_addr
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use qpx_core::config::{
        AccessLogConfig, AuditLogConfig, AuthConfig, CacheConfig, Config, IdentityConfig,
        MessagesConfig, RuntimeConfig, SystemLogConfig,
    };
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn test_config() -> Config {
        Config {
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig::default(),
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            acme: None,
            exporter: None,
            auth: AuthConfig::default(),
            identity_sources: Vec::new(),
            ext_authz: Vec::new(),
            destination_resolution: Default::default(),
            listeners: Vec::new(),
            named_sets: Vec::new(),
            http_guard_profiles: Vec::new(),
            rate_limit_profiles: Vec::new(),
            upstream_trust_profiles: Vec::new(),
            reverse: Vec::new(),
            upstreams: Vec::new(),
            cache: CacheConfig::default(),
        }
    }

    #[test]
    fn udp_session_handoff_round_trip_restores_connected_sockets() {
        let _guard = env_lock().lock().expect("env lock");

        let upstream = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind upstream");
        let transparent_socket =
            std::net::UdpSocket::bind("127.0.0.1:0").expect("bind transparent socket");
        transparent_socket
            .connect(upstream.local_addr().expect("upstream local"))
            .expect("connect transparent");
        transparent_socket
            .set_nonblocking(true)
            .expect("nonblocking");

        let mut state = UdpSessionRestoreState::default();
        state.insert_transparent(
            "transparent".to_string(),
            TransparentUdpListenerRestore {
                listen: "127.0.0.1:19443".to_string(),
                exported_elapsed_ms: 42,
                sessions: vec![TransparentUdpSessionRestore {
                    session_id: 7,
                    upstream_local_addr: transparent_socket.local_addr().expect("local"),
                    upstream_peer_addr: transparent_socket.peer_addr().expect("peer"),
                    socket: duplicate_std_udp_socket_for_test(&transparent_socket),
                    client_addr: "127.0.0.1:39001".parse().expect("client"),
                    target_key: "example.com:443".to_string(),
                    last_seen_ms: 37,
                    client_cid_len: Some(8),
                    server_cid_len: Some(4),
                    cids: vec![ExportedQuicConnectionId {
                        len: 4,
                        bytes: {
                            let mut bytes = [0u8; 20];
                            bytes[..4].copy_from_slice(&[1, 2, 3, 4]);
                            bytes
                        },
                    }],
                    matched_rule: Some("allow".to_string()),
                    rate_limit_profile: Some("profile".to_string()),
                    rate_limit_ctx: RateLimitContext::default(),
                }],
            },
        );

        let handoff = state
            .prepare_handoff(&test_config())
            .expect("prepare handoff")
            .expect("handoff");
        unsafe {
            std::env::set_var(
                UdpSessionRestoreState::handoff_env_key(),
                &handoff.env_value,
            );
        }
        std::mem::forget(handoff.kept_fds);

        let mut restored = UdpSessionRestoreState::take_from_env()
            .expect("from env")
            .expect("restore state");
        let listener = restored
            .take_transparent("transparent", "127.0.0.1:19443")
            .expect("take transparent")
            .expect("listener restore");
        assert_eq!(listener.exported_elapsed_ms, 42);
        assert_eq!(listener.sessions.len(), 1);
        assert_eq!(
            listener.sessions[0].socket.peer_addr().expect("peer"),
            upstream.local_addr().expect("upstream addr")
        );
        assert!(restored.is_empty());
        let _ = fs::remove_file(handoff.cleanup_path);
    }

    fn duplicate_std_udp_socket_for_test(socket: &std::net::UdpSocket) -> std::net::UdpSocket {
        crate::udp_socket_handoff::duplicate_std_udp_socket(socket).expect("duplicate socket")
    }
}
