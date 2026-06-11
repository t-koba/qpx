use anyhow::{Result, anyhow};

pub(crate) struct UpgradeTrigger;
pub(crate) struct ReadyNotifier;

pub(crate) fn install_upgrade_trigger() -> Result<Option<UpgradeTrigger>> {
    Ok(None)
}

impl UpgradeTrigger {
    pub(crate) async fn recv(&mut self) -> Result<()> {
        Ok(())
    }

    pub(crate) fn acknowledge(&self) -> Result<()> {
        Ok(())
    }
}

pub(crate) fn request_upgrade(_pid: u32) -> Result<()> {
    Err(anyhow!(
        "binary upgrade requests are unsupported on this platform"
    ))
}

pub(crate) async fn spawn_upgraded_child(
    _tcp_bindings: &crate::tcp_bindings::TcpBindings,
    _udp_bindings: &crate::udp_bindings::UdpBindings,
    _udp_sessions: Option<&crate::udp_session_handoff::UdpSessionRestoreState>,
    #[cfg(feature = "http3")] _quic_brokers: Option<
        &crate::http3::quinn_socket::QuinnBrokerPreparedHandoff,
    >,
    _config: &qpx_core::config::Config,
) -> Result<()> {
    Err(anyhow!("binary upgrade is unsupported on this platform"))
}

pub(crate) fn take_ready_notifier_from_env() -> Result<Option<ReadyNotifier>> {
    Ok(None)
}

impl ReadyNotifier {
    pub(crate) fn notify(self) -> Result<()> {
        Ok(())
    }
}
