use super::types::*;
use super::{ReversePassthroughListenerRestore, TransparentUdpListenerRestore};
use crate::udp_socket_handoff::{
    adopt_inherited_udp_socket_windows, duplicate_std_udp_socket_for_child,
};
use anyhow::{Context, Result, anyhow};
use qpx_core::config::Config;
use std::ffi::OsString;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;

pub(super) fn prepare_handoff(
    state: &UdpSessionRestoreState,
    config: &Config,
) -> Result<Option<UdpSessionPreparedHandoff>> {
    if state.is_empty() {
        return Ok(None);
    }

    let path = crate::windows_handoff::create_handoff_path(config, "udp-sessions")?;
    let transparent = state
        .transparent
        .iter()
        .map(|(name, restore)| {
            let sessions = restore
                .sessions
                .iter()
                .map(|session| {
                    Ok(WindowsTransparentUdpSessionRestore {
                        session_id: session.session_id,
                        socket: session
                            .socket
                            .try_clone()
                            .context("failed to clone transparent udp session socket")?,
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

    let reverse_passthrough = state
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
                            "failed to clone reverse_edge passthrough udp session socket",
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

pub(super) fn take_from_env(raw: OsString) -> Result<Option<UdpSessionRestoreState>> {
    let path = PathBuf::from(raw);
    let result =
        crate::windows_handoff::read_json_wait(path.as_path()).and_then(from_persisted_handoff);
    let _ = std::fs::remove_file(&path);
    result.map(Some)
}

pub(super) fn finalize_handoff_for_child(
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

pub(super) fn cleanup_handoff_file(handoff: &UdpSessionPreparedHandoff) {
    let _ = std::fs::remove_file(&handoff.cleanup_path);
}

fn from_persisted_handoff(persisted: PersistedUdpSessionHandoff) -> Result<UdpSessionRestoreState> {
    let mut state = UdpSessionRestoreState::default();

    for listener in persisted.transparent {
        let mut sessions = Vec::with_capacity(listener.sessions.len());
        for session in listener.sessions {
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

fn validate_connected_socket(
    socket: &UdpSocket,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> Result<()> {
    let actual_local = socket.local_addr()?;
    let actual_peer = socket.peer_addr()?;
    if actual_local != local_addr || actual_peer != peer_addr {
        return Err(anyhow!(
            "udp session socket mismatch: expected local={} peer={}, got local={} peer={}",
            local_addr,
            peer_addr,
            actual_local,
            actual_peer
        ));
    }
    Ok(())
}
