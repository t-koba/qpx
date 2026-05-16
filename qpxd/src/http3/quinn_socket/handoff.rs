use super::broker::{LocalQuinnBrokerHandle, QuinnBrokerKind};
#[cfg(not(unix))]
use super::stream::QuinnBrokerStream;
#[cfg(unix)]
use super::stream::{QuinnBrokerStream, adopt_unix_stream, unix_stream_into_owned_fd};
#[cfg(windows)]
use super::stream::{
    TokioQuinnBrokerStream, connect_windows_broker, read_broker_token, remaining_handoff_wait,
};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[cfg(windows)]
use std::net::TcpListener as StdTcpListener;
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream as StdUnixStream;
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use tokio::net::TcpListener as TokioTcpListener;

const ENV_INHERITED_QUIC_BROKERS: &str = "QPX_INHERITED_QUIC_BROKERS";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InheritedQuicBrokers {
    forward: Vec<InheritedQuicBroker>,
    reverse_edges: Vec<InheritedQuicBroker>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InheritedQuicBroker {
    name: String,
    #[cfg(unix)]
    fd: i32,
    #[cfg(windows)]
    addr: String,
    #[cfg(windows)]
    token: String,
}

pub(crate) struct QuinnBrokerPreparedHandoff {
    pub(crate) env_value: String,
    #[cfg(unix)]
    pub(crate) kept_fds: Vec<OwnedFd>,
    #[cfg(windows)]
    cleanup_path: PathBuf,
    #[cfg(windows)]
    accept_tasks: Vec<tokio::task::JoinHandle<()>>,
}

#[derive(Default)]
pub(crate) struct QuinnBrokerRestoreSet {
    #[cfg(any(unix, windows))]
    forward: HashMap<String, QuinnBrokerStream>,
    #[cfg(any(unix, windows))]
    reverse_edges: HashMap<String, QuinnBrokerStream>,
}

impl QuinnBrokerRestoreSet {
    pub(crate) fn take_from_env() -> Result<Option<Self>> {
        let Some(raw) = std::env::var_os(ENV_INHERITED_QUIC_BROKERS) else {
            return Ok(None);
        };
        unsafe {
            std::env::remove_var(ENV_INHERITED_QUIC_BROKERS);
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = raw;
            Err(anyhow!(
                "QUIC broker handoff is only supported on unix and windows"
            ))
        }

        #[cfg(unix)]
        {
            let inherited: InheritedQuicBrokers =
                serde_json::from_str(raw.to_string_lossy().as_ref())
                    .context("invalid inherited QUIC broker manifest")?;
            let mut restore = Self::default();
            for entry in inherited.forward {
                restore
                    .forward
                    .insert(entry.name, adopt_unix_stream(entry.fd)?);
            }
            for entry in inherited.reverse_edges {
                restore
                    .reverse_edges
                    .insert(entry.name, adopt_unix_stream(entry.fd)?);
            }
            Ok(Some(restore))
        }

        #[cfg(windows)]
        {
            let path = PathBuf::from(raw);
            let inherited: InheritedQuicBrokers =
                crate::windows_handoff::read_json_wait(path.as_path())
                    .context("invalid inherited QUIC broker manifest")?;
            let _ = std::fs::remove_file(&path);
            let mut restore = Self::default();
            for entry in inherited.forward {
                restore.forward.insert(
                    entry.name,
                    connect_windows_broker(entry.addr.as_str(), entry.token.as_str())?,
                );
            }
            for entry in inherited.reverse_edges {
                restore.reverse_edges.insert(
                    entry.name,
                    connect_windows_broker(entry.addr.as_str(), entry.token.as_str())?,
                );
            }
            Ok(Some(restore))
        }
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn take_forward(&mut self, name: &str) -> Option<QuinnBrokerStream> {
        self.forward.remove(name)
    }

    #[cfg(not(any(unix, windows)))]
    pub(crate) fn take_forward(&mut self, _name: &str) -> Option<QuinnBrokerStream> {
        None
    }

    #[cfg(any(unix, windows))]
    pub(crate) fn take_reverse(&mut self, name: &str) -> Option<QuinnBrokerStream> {
        self.reverse_edges.remove(name)
    }

    #[cfg(not(any(unix, windows)))]
    pub(crate) fn take_reverse(&mut self, _name: &str) -> Option<QuinnBrokerStream> {
        None
    }

    pub(crate) fn ensure_consumed(&self) -> Result<()> {
        #[cfg(not(any(unix, windows)))]
        {
            Ok(())
        }

        #[cfg(any(unix, windows))]
        {
            if self.forward.is_empty() && self.reverse_edges.is_empty() {
                return Ok(());
            }
            Err(anyhow!(
                "unused inherited QUIC brokers remain: forward={:?}, reverse_edges={:?}",
                self.forward.keys().collect::<Vec<_>>(),
                self.reverse_edges.keys().collect::<Vec<_>>(),
            ))
        }
    }

    pub(crate) fn handoff_env_key() -> &'static str {
        ENV_INHERITED_QUIC_BROKERS
    }
}

#[cfg(windows)]
impl QuinnBrokerPreparedHandoff {
    pub(crate) fn cleanup_pending(&self) {
        for task in &self.accept_tasks {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.cleanup_path);
    }
}

impl LocalQuinnBrokerHandle {
    #[cfg(unix)]
    fn prepare_remote_handoff(
        &self,
        inherited: &mut InheritedQuicBrokers,
        kept_fds: &mut Vec<OwnedFd>,
    ) -> Result<()> {
        let (parent, child) =
            StdUnixStream::pair().context("failed to create QUIC broker socketpair")?;
        parent
            .set_nonblocking(true)
            .context("failed to set QUIC broker parent socket nonblocking")?;
        child
            .set_nonblocking(true)
            .context("failed to set QUIC broker child socket nonblocking")?;
        self.socket.attach_remote(parent)?;
        let owned = unix_stream_into_owned_fd(child);
        let raw = owned.as_raw_fd();
        kept_fds.push(owned);
        let entry = InheritedQuicBroker {
            name: self.name.clone(),
            fd: raw,
        };
        match self.kind {
            QuinnBrokerKind::Forward => inherited.forward.push(entry),
            QuinnBrokerKind::ReverseTerminate => inherited.reverse_edges.push(entry),
        }
        Ok(())
    }

    #[cfg(windows)]
    fn prepare_remote_handoff(
        &self,
        inherited: &mut InheritedQuicBrokers,
        accept_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    ) -> Result<()> {
        let listener = StdTcpListener::bind("127.0.0.1:0")
            .context("failed to bind QUIC broker rendezvous listener")?;
        listener
            .set_nonblocking(true)
            .context("failed to set QUIC broker rendezvous listener nonblocking")?;
        let addr = listener
            .local_addr()
            .context("failed to resolve QUIC broker rendezvous listener addr")?;
        let token = uuid::Uuid::new_v4().to_string();
        let socket = self.socket.clone();
        let expected = token.clone();
        let task = tokio::spawn(async move {
            let listener = match TokioTcpListener::from_std(listener) {
                Ok(listener) => listener,
                Err(_) => return,
            };
            let deadline = std::time::Instant::now() + crate::windows_handoff::HANDOFF_WAIT_TIMEOUT;
            loop {
                let Ok(remaining) = remaining_handoff_wait(deadline) else {
                    return;
                };
                let accepted = tokio::time::timeout(remaining, listener.accept()).await;
                let Ok(Ok((mut stream, _))) = accepted else {
                    return;
                };
                let Ok(remaining) = remaining_handoff_wait(deadline) else {
                    return;
                };
                match tokio::time::timeout(
                    remaining,
                    read_broker_token(&mut stream, expected.as_str()),
                )
                .await
                {
                    Ok(Ok(())) => {
                        let _ = socket.attach_remote_tokio(TokioQuinnBrokerStream::Tcp(stream));
                        return;
                    }
                    Ok(Err(_)) => continue,
                    Err(_) => return,
                }
            }
        });
        let entry = InheritedQuicBroker {
            name: self.name.clone(),
            addr: addr.to_string(),
            token,
        };
        accept_tasks.push(task);
        match self.kind {
            QuinnBrokerKind::Forward => inherited.forward.push(entry),
            QuinnBrokerKind::ReverseTerminate => inherited.reverse_edges.push(entry),
        }
        Ok(())
    }
}

pub(crate) fn prepare_quic_broker_handoff(
    handles: &[LocalQuinnBrokerHandle],
    _config: &qpx_core::config::Config,
) -> Result<Option<QuinnBrokerPreparedHandoff>> {
    #[cfg(not(any(unix, windows)))]
    {
        let _ = handles;
        let _ = _config;
        Err(anyhow!(
            "QUIC broker handoff is only supported on unix and windows"
        ))
    }

    #[cfg(unix)]
    {
        if handles.is_empty() {
            return Ok(None);
        }
        let mut inherited = InheritedQuicBrokers {
            forward: Vec::new(),
            reverse_edges: Vec::new(),
        };
        let mut kept_fds = Vec::new();
        let mut attached: Vec<LocalQuinnBrokerHandle> = Vec::new();
        for handle in handles {
            if let Err(err) = handle.prepare_remote_handoff(&mut inherited, &mut kept_fds) {
                for attached_handle in &attached {
                    attached_handle.detach_remote();
                }
                return Err(err);
            }
            attached.push(handle.clone());
        }
        let env_value = match serde_json::to_string(&inherited) {
            Ok(value) => value,
            Err(err) => {
                for handle in handles {
                    handle.detach_remote();
                }
                return Err(err).context("failed to serialize inherited QUIC brokers");
            }
        };
        Ok(Some(QuinnBrokerPreparedHandoff {
            env_value,
            kept_fds,
        }))
    }

    #[cfg(windows)]
    {
        if handles.is_empty() {
            return Ok(None);
        }
        let mut inherited = InheritedQuicBrokers {
            forward: Vec::new(),
            reverse_edges: Vec::new(),
        };
        let mut accept_tasks = Vec::new();
        for handle in handles {
            if let Err(err) = handle.prepare_remote_handoff(&mut inherited, &mut accept_tasks) {
                for task in &accept_tasks {
                    task.abort();
                }
                return Err(err);
            }
        }
        let path = crate::windows_handoff::create_handoff_path(_config, "quic-brokers")?;
        if let Err(err) = crate::windows_handoff::write_json_file(path.as_path(), &inherited) {
            for task in &accept_tasks {
                task.abort();
            }
            return Err(err).context("failed to serialize inherited QUIC brokers");
        }
        Ok(Some(QuinnBrokerPreparedHandoff {
            env_value: path.display().to_string(),
            cleanup_path: path,
            accept_tasks,
        }))
    }
}

pub(crate) fn detach_quic_broker_handoff(handles: &[LocalQuinnBrokerHandle]) {
    for handle in handles {
        handle.detach_remote();
    }
}
