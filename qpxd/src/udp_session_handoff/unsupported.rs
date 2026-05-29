use super::types::{UdpSessionPreparedHandoff, UdpSessionRestoreState};
use anyhow::{Result, anyhow};
use qpx_core::config::Config;
use std::ffi::OsString;

pub(super) fn prepare_handoff(
    state: &UdpSessionRestoreState,
    config: &Config,
) -> Result<Option<UdpSessionPreparedHandoff>> {
    let _ = state;
    let _ = config;
    Err(anyhow!(
        "UDP session handoff is only supported on unix and windows"
    ))
}

pub(super) fn take_from_env(raw: OsString) -> Result<Option<UdpSessionRestoreState>> {
    let _ = raw;
    Err(anyhow!(
        "UDP session handoff is only supported on unix and windows"
    ))
}

pub(super) fn finalize_handoff_for_child(
    handoff: &UdpSessionPreparedHandoff,
    child_pid: u32,
) -> Result<()> {
    let _ = handoff;
    let _ = child_pid;
    Err(anyhow!(
        "UDP session handoff is only supported on unix and windows"
    ))
}

pub(super) fn cleanup_handoff_file(handoff: &UdpSessionPreparedHandoff) {
    let _ = handoff;
}
