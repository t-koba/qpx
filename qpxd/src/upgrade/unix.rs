use anyhow::{Context, Result, anyhow};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const ENV_READY_FD: &str = "QPX_UPGRADE_READY_FD";
const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) enum UpgradeTrigger {
    Signal(tokio::signal::unix::Signal),
}

pub(crate) struct ReadyNotifier {
    fd: OwnedFd,
}

pub(crate) fn install_upgrade_trigger() -> Result<Option<UpgradeTrigger>> {
    let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())?;
    Ok(Some(UpgradeTrigger::Signal(signal)))
}

impl UpgradeTrigger {
    pub(crate) async fn recv(&mut self) -> Result<()> {
        match self {
            Self::Signal(signal) => {
                signal.recv().await;
                Ok(())
            }
        }
    }

    pub(crate) fn acknowledge(&self) -> Result<()> {
        Ok(())
    }
}

pub(crate) fn request_upgrade(pid: u32) -> Result<()> {
    let rc = unsafe { libc::kill(pid as i32, libc::SIGUSR2) };
    if rc != 0 {
        return Err(anyhow!(
            "failed to signal process {} for binary upgrade: {}",
            pid,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
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
    use std::io::Read;

    let tcp_handoff = tcp_bindings.prepare_handoff(config)?;
    let udp_handoff = udp_bindings.prepare_handoff(config)?;
    let crate::tcp_bindings::TcpBindingHandoff {
        env_value: tcp_env_value,
        mut kept_fds,
    } = tcp_handoff;
    let crate::udp_bindings::UdpBindingHandoff {
        env_value: udp_env_value,
        kept_fds: udp_kept_fds,
    } = udp_handoff;
    kept_fds.extend(udp_kept_fds);

    let mut udp_session_handoff = match udp_sessions {
        Some(sessions) => sessions.prepare_handoff(config)?,
        None => None,
    };
    if let Some(handoff) = udp_session_handoff.as_mut() {
        kept_fds.append(&mut handoff.kept_fds);
    }

    #[cfg(feature = "http3")]
    if let Some(brokers) = quic_brokers {
        kept_fds.extend(
            brokers
                .kept_fds
                .iter()
                .map(|fd| fd.try_clone())
                .collect::<std::io::Result<Vec<_>>>()
                .context("failed to clone QUIC broker handoff fds")?,
        );
    }

    let mut pipe_fds = [0; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(anyhow!(
            "failed to create upgrade readiness pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    let read_fd = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };
    set_cloexec(write_fd.as_raw_fd(), false)?;

    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let mut child = std::process::Command::new(current_exe);
    child.args(std::env::args_os().skip(1));
    child.env(
        crate::tcp_bindings::TcpBindings::handoff_env_key(),
        tcp_env_value,
    );
    child.env(
        crate::udp_bindings::UdpBindings::handoff_env_key(),
        udp_env_value,
    );
    if let Some(handoff) = &udp_session_handoff {
        child.env(
            crate::udp_session_handoff::UdpSessionRestoreState::handoff_env_key(),
            &handoff.env_value,
        );
    }
    #[cfg(feature = "http3")]
    if let Some(quic_brokers) = quic_brokers {
        child.env(
            crate::http3::quinn_socket::QuinnBrokerRestoreSet::handoff_env_key(),
            &quic_brokers.env_value,
        );
    }
    child.env(ENV_READY_FD, write_fd.as_raw_fd().to_string());

    let _keep_pipe_alive = write_fd;
    let _keep_socket_fds = kept_fds;
    let child = match child.spawn() {
        Ok(child) => child,
        Err(err) => {
            if let Some(handoff) = &udp_session_handoff {
                crate::udp_session_handoff::UdpSessionRestoreState::cleanup_handoff_file(handoff);
            }
            return Err(err).context("failed to spawn upgraded child");
        }
    };
    if let Some(handoff) = &udp_session_handoff {
        crate::udp_session_handoff::UdpSessionRestoreState::finalize_handoff_for_child(
            handoff,
            child.id(),
        )?;
    }

    let readiness = tokio::time::timeout(
        READY_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            let mut file = std::fs::File::from(read_fd);
            let mut buf = [0u8; 1];
            let n = file.read(&mut buf)?;
            if n == 1 && buf[0] == b'1' {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "upgrade child exited before signaling readiness",
                ))
            }
        }),
    )
    .await;
    if let Some(handoff) = &udp_session_handoff {
        crate::udp_session_handoff::UdpSessionRestoreState::cleanup_handoff_file(handoff);
    }
    readiness
        .context("upgrade child readiness timed out")?
        .context("upgrade child readiness failed")?
        .context("upgrade child readiness failed")?;
    Ok(())
}

pub(crate) fn take_ready_notifier_from_env() -> Result<Option<ReadyNotifier>> {
    use std::os::fd::FromRawFd;

    let Some(raw) = std::env::var_os(ENV_READY_FD) else {
        return Ok(None);
    };
    unsafe {
        std::env::remove_var(ENV_READY_FD);
    }
    let fd: i32 = raw
        .to_string_lossy()
        .parse()
        .context("invalid upgrade ready fd")?;
    set_cloexec(fd, true)?;
    Ok(Some(ReadyNotifier {
        fd: unsafe { OwnedFd::from_raw_fd(fd) },
    }))
}

impl ReadyNotifier {
    pub(crate) fn notify(self) -> Result<()> {
        use std::io::Write;

        let mut file = std::fs::File::from(self.fd);
        file.write_all(b"1")
            .context("failed to signal upgrade readiness")?;
        file.flush().ok();
        Ok(())
    }
}

fn set_cloexec(fd: i32, enabled: bool) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(anyhow!(
            "failed to read fd flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    let next = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, next) } < 0 {
        return Err(anyhow!(
            "failed to set fd flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ready_notifier_from_env_writes_readiness_byte() {
        use std::io::Read;
        use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};

        let (notifier, read_fd) = {
            let _guard = crate::test_env_lock().lock().expect("env lock");

            let mut pipe_fds = [0; 2];
            assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
            let read_fd = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
            let write_fd = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };
            let write_raw = write_fd.into_raw_fd();

            unsafe {
                std::env::set_var(ENV_READY_FD, write_raw.to_string());
            }
            let notifier = take_ready_notifier_from_env()
                .expect("take notifier")
                .expect("ready notifier");
            (notifier, read_fd)
        };

        let read_task = tokio::task::spawn_blocking(move || -> std::io::Result<u8> {
            let mut file = std::fs::File::from(read_fd);
            let mut buf = [0u8; 1];
            file.read_exact(&mut buf)?;
            Ok(buf[0])
        });

        notifier.notify().expect("notify");
        assert_eq!(
            read_task.await.expect("join").expect("read"),
            b'1',
            "parent should observe child readiness byte"
        );
    }
}
