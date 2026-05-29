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
