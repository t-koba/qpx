use super::file::{
    ensure_secure_handoff_dir, read_handoff_file, validate_connected_socket, write_handoff_file,
};
use super::types::*;
use super::{ReversePassthroughListenerRestore, TransparentUdpListenerRestore};
use crate::udp_socket_handoff::{adopt_inherited_udp_socket, duplicate_std_udp_socket_for_handoff};
use anyhow::Result;
use qpx_core::config::Config;
use std::ffi::OsString;
use std::path::PathBuf;
use uuid::Uuid;

pub(super) fn prepare_handoff(
    state: &UdpSessionRestoreState,
    config: &Config,
) -> Result<Option<UdpSessionPreparedHandoff>> {
    if state.is_empty() {
        return Ok(None);
    }

    let mut persisted = PersistedUdpSessionHandoff::default();
    let mut kept_fds = Vec::new();

    for (name, restore) in &state.transparent {
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

    for (name, restore) in &state.reverse_passthrough {
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

pub(super) fn take_from_env(raw: OsString) -> Result<Option<UdpSessionRestoreState>> {
    let path = PathBuf::from(raw);
    let result = read_handoff_file(path.as_path()).and_then(from_persisted_handoff);
    let _ = std::fs::remove_file(&path);
    result.map(Some)
}

pub(super) fn finalize_handoff_for_child(
    _handoff: &UdpSessionPreparedHandoff,
    _child_pid: u32,
) -> Result<()> {
    Ok(())
}

pub(super) fn cleanup_handoff_file(handoff: &UdpSessionPreparedHandoff) {
    let _ = std::fs::remove_file(&handoff.cleanup_path);
}

fn from_persisted_handoff(persisted: PersistedUdpSessionHandoff) -> Result<UdpSessionRestoreState> {
    let mut state = UdpSessionRestoreState::default();

    for listener in persisted.transparent {
        let mut sessions = Vec::with_capacity(listener.sessions.len());
        for session in listener.sessions {
            let socket = adopt_inherited_udp_socket(session.fd)?;
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
            let socket = adopt_inherited_udp_socket(session.fd)?;
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
