use anyhow::{anyhow, Context, Result};
#[cfg(windows)]
use std::net::SocketAddr;

#[cfg(unix)]
const ENV_READY_FD: &str = "QPX_UPGRADE_READY_FD";
#[cfg(windows)]
const ENV_READY_ADDR: &str = "QPX_UPGRADE_READY_ADDR";
#[cfg(windows)]
const ENV_READY_TOKEN: &str = "QPX_UPGRADE_READY_TOKEN";
const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) enum UpgradeTrigger {
    #[cfg(unix)]
    Signal(tokio::signal::unix::Signal),
    #[cfg(windows)]
    Event(crate::windows_handoff::EventHandle),
}

pub(crate) struct ReadyNotifier {
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
    #[cfg(windows)]
    addr: SocketAddr,
    #[cfg(windows)]
    token: String,
}

#[cfg(windows)]
struct TcpReadyListener {
    listener: tokio::net::TcpListener,
    token: String,
}

pub(crate) fn install_upgrade_trigger() -> Result<Option<UpgradeTrigger>> {
    #[cfg(unix)]
    {
        let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())?;
        Ok(Some(UpgradeTrigger::Signal(signal)))
    }

    #[cfg(windows)]
    {
        let event = crate::windows_handoff::create_upgrade_event(std::process::id())?;
        return Ok(Some(UpgradeTrigger::Event(event)));
    }

    #[cfg(not(any(unix, windows)))]
    {
        Ok(None)
    }
}

impl UpgradeTrigger {
    pub(crate) async fn recv(&mut self) -> Result<()> {
        match self {
            #[cfg(unix)]
            Self::Signal(signal) => {
                signal.recv().await;
                Ok(())
            }
            #[cfg(windows)]
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
}

pub(crate) fn request_upgrade(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
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

    #[cfg(windows)]
    {
        let event = crate::windows_handoff::open_upgrade_event(pid)?;
        return crate::windows_handoff::signal_event(&event);
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        Err(anyhow!(
            "binary upgrade requests are unsupported on this platform"
        ))
    }
}

#[cfg(unix)]
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
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

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
    let (udp_session_env, udp_session_kept_fds, udp_session_cleanup) = match udp_sessions {
        Some(sessions) => match sessions.prepare_handoff(config)? {
            Some(handoff) => (
                Some(handoff.env_value),
                handoff.kept_fds,
                Some(handoff.cleanup_path),
            ),
            None => (None, Vec::new(), None),
        },
        None => (None, Vec::new(), None),
    };
    kept_fds.extend(udp_session_kept_fds);
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
    if let Some(env_value) = &udp_session_env {
        child.env(
            crate::udp_session_handoff::UdpSessionRestoreState::handoff_env_key(),
            env_value,
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
    if let Err(err) = child.spawn() {
        if let Some(path) = &udp_session_cleanup {
            let _ = std::fs::remove_file(path);
        }
        return Err(err).context("failed to spawn upgraded child");
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
    if let Some(path) = udp_session_cleanup {
        let _ = std::fs::remove_file(path);
    }
    readiness
        .context("upgrade child readiness timed out")?
        .context("upgrade child readiness failed")?
        .context("upgrade child readiness failed")?;
    Ok(())
}

#[cfg(windows)]
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
    child_cmd.env(ENV_READY_ADDR, ready_listener.addr().to_string());
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
        #[cfg(all(feature = "http3", windows))]
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
        #[cfg(all(feature = "http3", windows))]
        if let Some(quic_brokers) = quic_brokers {
            quic_brokers.cleanup_pending();
        }
        return Err(err);
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
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
    #[cfg(unix)]
    {
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
            fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
        }))
    }

    #[cfg(windows)]
    {
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
        return Ok(Some(ReadyNotifier {
            addr,
            token: token_raw.to_string_lossy().into_owned(),
        }));
    }

    #[cfg(not(any(unix, windows)))]
    {
        Ok(None)
    }
}

impl ReadyNotifier {
    pub(crate) fn notify(self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::io::Write;

            let mut file = std::fs::File::from(self.fd);
            file.write_all(b"1")
                .context("failed to signal upgrade readiness")?;
            file.flush().ok();
            Ok(())
        }

        #[cfg(windows)]
        {
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
            return Ok(());
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = self;
            Ok(())
        }
    }
}

#[cfg(windows)]
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

    fn addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("readiness listener should have local addr")
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

#[cfg(windows)]
fn readiness_remaining(deadline: std::time::Instant) -> Result<std::time::Duration> {
    deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| anyhow!("upgrade child readiness timed out"))
}

#[cfg(windows)]
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

#[cfg(unix)]
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
    use std::sync::{Mutex, OnceLock};

    #[cfg(unix)]
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ready_notifier_from_env_writes_readiness_byte() {
        use std::io::Read;
        use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};

        let (notifier, read_fd) = {
            let _guard = env_lock().lock().expect("env lock");

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
