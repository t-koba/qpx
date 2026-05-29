use anyhow::{Result, anyhow};
use qpx_core::config::Config;

const ENV_INHERITED_UDP_SESSIONS: &str = "QPX_INHERITED_UDP_SESSIONS";

mod types;
#[cfg(unix)]
mod unix;
#[cfg(not(any(unix, windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use self::unix as platform;
#[cfg(not(any(unix, windows)))]
use self::unsupported as platform;
#[cfg(windows)]
use self::windows as platform;

#[cfg(any(feature = "http3", test))]
pub(crate) use self::types::ExportedQuicConnectionId;
#[cfg(feature = "http3")]
pub(crate) use self::types::ReversePassthroughSessionRestore;
#[cfg(any(feature = "http3", test))]
pub(crate) use self::types::TransparentUdpSessionRestore;
use self::types::*;
pub(crate) use self::types::{
    ReversePassthroughListenerRestore, TransparentUdpListenerRestore, UdpSessionPreparedHandoff,
    UdpSessionRestoreState,
};

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
                "reverse_edge HTTP/3 passthrough handoff for {} expected listen {}, got {}",
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
        platform::prepare_handoff(self, config)
    }

    pub(crate) fn take_from_env() -> Result<Option<Self>> {
        let Some(raw) = std::env::var_os(ENV_INHERITED_UDP_SESSIONS) else {
            return Ok(None);
        };
        unsafe {
            std::env::remove_var(ENV_INHERITED_UDP_SESSIONS);
        }

        platform::take_from_env(raw)
    }

    pub(crate) fn handoff_env_key() -> &'static str {
        ENV_INHERITED_UDP_SESSIONS
    }

    pub(crate) fn finalize_handoff_for_child(
        handoff: &UdpSessionPreparedHandoff,
        child_pid: u32,
    ) -> Result<()> {
        platform::finalize_handoff_for_child(handoff, child_pid)
    }

    pub(crate) fn cleanup_handoff_file(handoff: &UdpSessionPreparedHandoff) {
        platform::cleanup_handoff_file(handoff);
    }
}

#[cfg(unix)]
mod file;
#[cfg(all(test, unix))]
mod tests;
