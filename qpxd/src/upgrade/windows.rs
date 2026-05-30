use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;

const ENV_READY_ADDR: &str = "QPX_UPGRADE_READY_ADDR";
const ENV_READY_TOKEN: &str = "QPX_UPGRADE_READY_TOKEN";
const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) enum UpgradeTrigger {
    Event(crate::windows_handoff::EventHandle),
}

pub(crate) struct ReadyNotifier {
    addr: SocketAddr,
    token: String,
}

struct TcpReadyListener {
    listener: tokio::net::TcpListener,
    token: String,
}

pub(crate) fn install_upgrade_trigger() -> Result<Option<UpgradeTrigger>> {
    let event = crate::windows_handoff::create_upgrade_event(std::process::id())?;
    Ok(Some(UpgradeTrigger::Event(event)))
}

impl UpgradeTrigger {
    pub(crate) async fn recv(&mut self) -> Result<()> {
        match self {
            Self::Event(event) => loop {
                let fired = tokio::task::spawn_blocking({
                    let raw = event.raw() as usize;
                    move || {
                        crate::windows_handoff::wait_for_event_raw(
                            raw as windows_sys::Win32::Foundation::HANDLE,
                            READY_TIMEOUT,
                        )
                    }
                })
                .await
                .context("upgrade event wait join failed")??;
                if fired {
                    return Ok(());
                }
            },
        }
    }

    pub(crate) fn acknowledge(&self) -> Result<()> {
        match self {
            Self::Event(event) => crate::windows_handoff::reset_event(event),
        }
    }
}

pub(crate) fn request_upgrade(pid: u32) -> Result<()> {
    let event = crate::windows_handoff::open_upgrade_event(pid)?;
    crate::windows_handoff::signal_event(&event)
}

pub(crate) async fn spawn_upgraded_child(
    tcp_bindings: &crate::tcp_bindings::TcpBindings,
    udp_bindings: &crate::udp_bindings::UdpBindings,
    udp_sessions: Option<&crate::udp_session_handoff::UdpSessionRestoreState>,
    #[cfg(feature = "http3")] quic_brokers: Option<
        &crate::http3::quinn_socket::QuinnBrokerPreparedHandoff,
    >,
    config: &qpx_core::config::Config,
) -> Result<()> {
    let tcp_handoff = tcp_bindings.prepare_handoff(config)?;
    let udp_handoff = udp_bindings.prepare_handoff(config)?;
    let udp_session_handoff = match udp_sessions {
        Some(sessions) => sessions.prepare_handoff(config)?,
        None => None,
    };
    let ready_listener = TcpReadyListener::bind()?;

    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let mut child_cmd = std::process::Command::new(current_exe);
    child_cmd.args(std::env::args_os().skip(1));
    child_cmd.env(
        crate::tcp_bindings::TcpBindings::handoff_env_key(),
        &tcp_handoff.env_value,
    );
    child_cmd.env(
        crate::udp_bindings::UdpBindings::handoff_env_key(),
        &udp_handoff.env_value,
    );
    if let Some(handoff) = &udp_session_handoff {
        child_cmd.env(
            crate::udp_session_handoff::UdpSessionRestoreState::handoff_env_key(),
            &handoff.env_value,
        );
    }
    #[cfg(feature = "http3")]
    if let Some(quic_brokers) = quic_brokers {
        child_cmd.env(
            crate::http3::quinn_socket::QuinnBrokerRestoreSet::handoff_env_key(),
            &quic_brokers.env_value,
        );
    }
    child_cmd.env(ENV_READY_ADDR, ready_listener.addr()?.to_string());
    child_cmd.env(ENV_READY_TOKEN, ready_listener.token.as_str());

    let mut child = child_cmd
        .spawn()
        .context("failed to spawn upgraded child")?;
    let child_pid = child.id();

    let finalize = (|| -> Result<()> {
        crate::tcp_bindings::TcpBindings::finalize_handoff_for_child(&tcp_handoff, child_pid)?;
        crate::udp_bindings::UdpBindings::finalize_handoff_for_child(&udp_handoff, child_pid)?;
        if let Some(handoff) = &udp_session_handoff {
            crate::udp_session_handoff::UdpSessionRestoreState::finalize_handoff_for_child(
                handoff, child_pid,
            )?;
        }
        Ok(())
    })();

    if let Err(err) = finalize {
        let _ = child.kill();
        crate::tcp_bindings::TcpBindings::cleanup_handoff_file(&tcp_handoff);
        crate::udp_bindings::UdpBindings::cleanup_handoff_file(&udp_handoff);
        if let Some(handoff) = &udp_session_handoff {
            crate::udp_session_handoff::UdpSessionRestoreState::cleanup_handoff_file(handoff);
        }
        #[cfg(feature = "http3")]
        if let Some(quic_brokers) = quic_brokers {
            quic_brokers.cleanup_pending();
        }
        return Err(err).context("failed to finalize upgrade handoff for child");
    }

    let readiness = ready_listener.wait().await;
    crate::tcp_bindings::TcpBindings::cleanup_handoff_file(&tcp_handoff);
    crate::udp_bindings::UdpBindings::cleanup_handoff_file(&udp_handoff);
    if let Some(handoff) = &udp_session_handoff {
        crate::udp_session_handoff::UdpSessionRestoreState::cleanup_handoff_file(handoff);
    }
    if let Err(err) = readiness {
        let _ = child.kill();
        #[cfg(feature = "http3")]
        if let Some(quic_brokers) = quic_brokers {
            quic_brokers.cleanup_pending();
        }
        return Err(err);
    }
    Ok(())
}

pub(crate) fn take_ready_notifier_from_env() -> Result<Option<ReadyNotifier>> {
    let Some(addr_raw) = std::env::var_os(ENV_READY_ADDR) else {
        return Ok(None);
    };
    let Some(token_raw) = std::env::var_os(ENV_READY_TOKEN) else {
        return Err(anyhow!(
            "upgrade ready token missing while ready address is present"
        ));
    };
    unsafe {
        std::env::remove_var(ENV_READY_ADDR);
        std::env::remove_var(ENV_READY_TOKEN);
    }
    let addr: SocketAddr = addr_raw
        .to_string_lossy()
        .parse()
        .context("invalid upgrade ready address")?;
    Ok(Some(ReadyNotifier {
        addr,
        token: token_raw.to_string_lossy().into_owned(),
    }))
}

impl ReadyNotifier {
    pub(crate) fn notify(self) -> Result<()> {
        use std::io::Write;

        let mut stream = std::net::TcpStream::connect(self.addr)
            .with_context(|| format!("failed to connect readiness socket {}", self.addr))?;
        let token = self.token.as_bytes();
        let len = u16::try_from(token.len()).context("upgrade readiness token too long")?;
        stream
            .write_all(&len.to_be_bytes())
            .context("failed to write readiness token length")?;
        stream
            .write_all(token)
            .context("failed to write readiness token")?;
        stream.flush().ok();
        Ok(())
    }
}

impl TcpReadyListener {
    fn bind() -> Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .context("failed to bind upgrade readiness listener")?;
        listener
            .set_nonblocking(true)
            .context("failed to set upgrade readiness listener nonblocking")?;
        Ok(Self {
            listener: tokio::net::TcpListener::from_std(listener)
                .context("failed to adopt upgrade readiness listener")?,
            token: uuid::Uuid::new_v4().to_string(),
        })
    }

    fn addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .context("failed to read upgrade readiness listener local address")
    }

    async fn wait(self) -> Result<()> {
        let token = self.token;
        let deadline = std::time::Instant::now() + READY_TIMEOUT;
        loop {
            let remaining = readiness_remaining(deadline)?;
            let accept = tokio::time::timeout(remaining, self.listener.accept())
                .await
                .context("upgrade child readiness timed out")?
                .context("failed to accept upgrade readiness connection")?;
            let (mut stream, _) = accept;
            let remaining = readiness_remaining(deadline)?;
            let token_result = tokio::time::timeout(remaining, read_ready_token(&mut stream)).await;
            let received = match token_result {
                Ok(Ok(received)) => received,
                Ok(Err(_)) => continue,
                Err(_) => return Err(anyhow!("upgrade child readiness timed out")),
            };
            if received == token.as_bytes() {
                return Ok(());
            }
        }
    }
}

fn readiness_remaining(deadline: std::time::Instant) -> Result<std::time::Duration> {
    deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| anyhow!("upgrade child readiness timed out"))
}

async fn read_ready_token(stream: &mut tokio::net::TcpStream) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    const MAX_READY_TOKEN_LEN: usize = 512;
    let len = stream
        .read_u16()
        .await
        .context("failed to read readiness token length")? as usize;
    if len > MAX_READY_TOKEN_LEN {
        return Err(anyhow!("upgrade readiness token is too long"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .context("failed to read readiness token")?;
    Ok(buf)
}
