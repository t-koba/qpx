use crate::rate_limit::RateLimitContext;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::fd::OwnedFd;

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
    pub(super) transparent: HashMap<String, TransparentUdpListenerRestore>,
    pub(super) reverse_passthrough: HashMap<String, ReversePassthroughListenerRestore>,
}

pub(crate) struct UdpSessionPreparedHandoff {
    pub(crate) env_value: String,
    pub(crate) cleanup_path: PathBuf,
    #[cfg(unix)]
    pub(crate) kept_fds: Vec<OwnedFd>,
    #[cfg(windows)]
    pub(super) pending: WindowsUdpSessionPreparedHandoff,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct PersistedUdpSessionHandoff {
    pub(super) transparent: Vec<PersistedTransparentUdpListenerRestore>,
    pub(super) reverse_passthrough: Vec<PersistedReversePassthroughListenerRestore>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PersistedTransparentUdpListenerRestore {
    pub(super) name: String,
    pub(super) listen: String,
    pub(super) exported_elapsed_ms: u64,
    pub(super) sessions: Vec<PersistedTransparentUdpSessionRestore>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PersistedTransparentUdpSessionRestore {
    pub(super) session_id: u64,
    #[cfg(unix)]
    pub(super) fd: i32,
    #[cfg(windows)]
    pub(super) socket: Vec<u8>,
    pub(super) upstream_local_addr: SocketAddr,
    pub(super) upstream_peer_addr: SocketAddr,
    pub(super) client_addr: SocketAddr,
    pub(super) target_key: String,
    pub(super) last_seen_ms: u64,
    pub(super) client_cid_len: Option<u8>,
    pub(super) server_cid_len: Option<u8>,
    pub(super) cids: Vec<ExportedQuicConnectionId>,
    pub(super) matched_rule: Option<String>,
    pub(super) rate_limit_profile: Option<String>,
    pub(super) rate_limit_ctx: RateLimitContext,
}

impl PersistedTransparentUdpSessionRestore {
    pub(super) fn into_restore(self, socket: std::net::UdpSocket) -> TransparentUdpSessionRestore {
        TransparentUdpSessionRestore {
            session_id: self.session_id,
            socket,
            upstream_local_addr: self.upstream_local_addr,
            upstream_peer_addr: self.upstream_peer_addr,
            client_addr: self.client_addr,
            target_key: self.target_key,
            last_seen_ms: self.last_seen_ms,
            client_cid_len: self.client_cid_len,
            server_cid_len: self.server_cid_len,
            cids: self.cids,
            matched_rule: self.matched_rule,
            rate_limit_profile: self.rate_limit_profile,
            rate_limit_ctx: self.rate_limit_ctx,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PersistedReversePassthroughListenerRestore {
    pub(super) name: String,
    pub(super) listen: String,
    pub(super) exported_elapsed_ms: u64,
    pub(super) sessions: Vec<PersistedReversePassthroughSessionRestore>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PersistedReversePassthroughSessionRestore {
    pub(super) session_id: u64,
    #[cfg(unix)]
    pub(super) fd: i32,
    #[cfg(windows)]
    pub(super) socket: Vec<u8>,
    pub(super) upstream_local_addr: SocketAddr,
    pub(super) upstream_peer_addr: SocketAddr,
    pub(super) client_addr: SocketAddr,
    pub(super) last_seen_ms: u64,
    pub(super) bytes_in: u64,
    pub(super) bytes_out: u64,
    pub(super) client_cid_len: Option<u8>,
    pub(super) server_cid_len: Option<u8>,
    pub(super) cids: Vec<ExportedQuicConnectionId>,
}

impl PersistedReversePassthroughSessionRestore {
    pub(super) fn into_restore(
        self,
        socket: std::net::UdpSocket,
    ) -> ReversePassthroughSessionRestore {
        ReversePassthroughSessionRestore {
            session_id: self.session_id,
            socket,
            upstream_local_addr: self.upstream_local_addr,
            upstream_peer_addr: self.upstream_peer_addr,
            client_addr: self.client_addr,
            last_seen_ms: self.last_seen_ms,
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
            client_cid_len: self.client_cid_len,
            server_cid_len: self.server_cid_len,
            cids: self.cids,
        }
    }
}

#[cfg(windows)]
#[derive(Debug)]
pub(super) struct WindowsUdpSessionPreparedHandoff {
    pub(super) transparent: Vec<WindowsTransparentUdpListenerRestore>,
    pub(super) reverse_passthrough: Vec<WindowsReversePassthroughListenerRestore>,
}

#[cfg(windows)]
#[derive(Debug)]
pub(super) struct WindowsTransparentUdpListenerRestore {
    pub(super) name: String,
    pub(super) listen: String,
    pub(super) exported_elapsed_ms: u64,
    pub(super) sessions: Vec<WindowsTransparentUdpSessionRestore>,
}

#[cfg(windows)]
#[derive(Debug)]
pub(super) struct WindowsTransparentUdpSessionRestore {
    pub(super) session_id: u64,
    pub(super) socket: std::net::UdpSocket,
    pub(super) upstream_local_addr: SocketAddr,
    pub(super) upstream_peer_addr: SocketAddr,
    pub(super) client_addr: SocketAddr,
    pub(super) target_key: String,
    pub(super) last_seen_ms: u64,
    pub(super) client_cid_len: Option<u8>,
    pub(super) server_cid_len: Option<u8>,
    pub(super) cids: Vec<ExportedQuicConnectionId>,
    pub(super) matched_rule: Option<String>,
    pub(super) rate_limit_profile: Option<String>,
    pub(super) rate_limit_ctx: RateLimitContext,
}

#[cfg(windows)]
#[derive(Debug)]
pub(super) struct WindowsReversePassthroughListenerRestore {
    pub(super) name: String,
    pub(super) listen: String,
    pub(super) exported_elapsed_ms: u64,
    pub(super) sessions: Vec<WindowsReversePassthroughSessionRestore>,
}

#[cfg(windows)]
#[derive(Debug)]
pub(super) struct WindowsReversePassthroughSessionRestore {
    pub(super) session_id: u64,
    pub(super) socket: std::net::UdpSocket,
    pub(super) upstream_local_addr: SocketAddr,
    pub(super) upstream_peer_addr: SocketAddr,
    pub(super) client_addr: SocketAddr,
    pub(super) last_seen_ms: u64,
    pub(super) bytes_in: u64,
    pub(super) bytes_out: u64,
    pub(super) client_cid_len: Option<u8>,
    pub(super) server_cid_len: Option<u8>,
    pub(super) cids: Vec<ExportedQuicConnectionId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn reverse_passthrough_persisted_fields_map_to_restore() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket_addr = socket.local_addr().unwrap();
        let cid = ExportedQuicConnectionId {
            len: 3,
            bytes: [7; 20],
        };
        let restored = PersistedReversePassthroughSessionRestore {
            session_id: 42,
            #[cfg(unix)]
            fd: 8,
            #[cfg(windows)]
            socket: vec![1, 2],
            upstream_local_addr: "127.0.0.1:5001".parse().unwrap(),
            upstream_peer_addr: "127.0.0.1:5002".parse().unwrap(),
            client_addr: "127.0.0.1:5003".parse().unwrap(),
            last_seen_ms: 987,
            bytes_in: 1234,
            bytes_out: 5678,
            client_cid_len: Some(3),
            server_cid_len: Some(4),
            cids: vec![cid],
        }
        .into_restore(socket);

        assert_eq!(restored.session_id, 42);
        assert_eq!(restored.socket.local_addr().unwrap(), socket_addr);
        assert_eq!(
            restored.upstream_local_addr,
            "127.0.0.1:5001".parse().unwrap()
        );
        assert_eq!(
            restored.upstream_peer_addr,
            "127.0.0.1:5002".parse().unwrap()
        );
        assert_eq!(restored.client_addr, "127.0.0.1:5003".parse().unwrap());
        assert_eq!(restored.last_seen_ms, 987);
        assert_eq!(restored.bytes_in, 1234);
        assert_eq!(restored.bytes_out, 5678);
        assert_eq!(restored.client_cid_len, Some(3));
        assert_eq!(restored.server_cid_len, Some(4));
        assert_eq!(restored.cids, vec![cid]);
    }
}
