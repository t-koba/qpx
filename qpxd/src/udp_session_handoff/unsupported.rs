use super::types::{UdpSessionPreparedHandoff, UdpSessionRestoreState};
use anyhow::{Result, anyhow};
use qpx_core::config::Config;
use std::ffi::OsString;

pub(super) fn prepare_handoff(
    _state: &UdpSessionRestoreState,
    _config: &Config,
) -> Result<Option<UdpSessionPreparedHandoff>> {
    Err(anyhow!(
        "UDP session handoff is only supported on unix and windows"
    ))
}

pub(super) fn take_from_env(_raw: OsString) -> Result<Option<UdpSessionRestoreState>> {
    Err(anyhow!(
        "UDP session handoff is only supported on unix and windows"
    ))
}

pub(super) fn finalize_handoff_for_child(
    _handoff: &UdpSessionPreparedHandoff,
    _child_pid: u32,
) -> Result<()> {
    Err(anyhow!(
        "UDP session handoff is only supported on unix and windows"
    ))
}

pub(super) fn cleanup_handoff_file(_handoff: &UdpSessionPreparedHandoff) {}
