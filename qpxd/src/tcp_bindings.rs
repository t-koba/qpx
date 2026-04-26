use anyhow::{anyhow, Context, Result};
use qpx_core::config::{Config, ReverseConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::TcpListener;
#[cfg(windows)]
use std::path::PathBuf;

const ENV_INHERITED_TCP_BINDINGS: &str = "QPX_INHERITED_TCP_BINDINGS";

pub(crate) struct TcpBindings {
    listener_tcp: HashMap<String, Vec<TcpListener>>,
    reverse_tcp: HashMap<String, Vec<TcpListener>>,
    metrics: Option<TcpListener>,
    #[cfg(feature = "acme")]
    acme_http01: Option<TcpListener>,
}

pub(crate) struct TcpBindingHandoff {
    pub(crate) env_value: String,
    #[cfg(unix)]
    pub(crate) kept_fds: Vec<std::os::fd::OwnedFd>,
    #[cfg(windows)]
    pending: WindowsTcpBindingHandoff,
    #[cfg(windows)]
    cleanup_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InheritedTcpBindings {
    listeners: Vec<InheritedTcpGroup>,
    reverses: Vec<InheritedTcpGroup>,
    metrics: Option<InheritedSingleTcp>,
    #[cfg(feature = "acme")]
    acme_http01: Option<InheritedSingleTcp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InheritedTcpGroup {
    name: String,
    listen: String,
    #[cfg(unix)]
    fds: Vec<i32>,
    #[cfg(windows)]
    sockets: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InheritedSingleTcp {
    listen: String,
    #[cfg(unix)]
    fd: i32,
    #[cfg(windows)]
    socket: Vec<u8>,
}

#[cfg(windows)]
struct WindowsTcpBindingHandoff {
    listeners: Vec<WindowsTcpGroup>,
    reverses: Vec<WindowsTcpGroup>,
    metrics: Option<WindowsSingleTcp>,
    #[cfg(feature = "acme")]
    acme_http01: Option<WindowsSingleTcp>,
}

#[cfg(windows)]
struct WindowsTcpGroup {
    name: String,
    listen: String,
    listeners: Vec<TcpListener>,
}

#[cfg(windows)]
struct WindowsSingleTcp {
    listen: String,
    listener: TcpListener,
}

impl TcpBindings {
    pub(crate) fn bind(config: &Config) -> Result<Self> {
        let mut listener_tcp = HashMap::new();
        let mut reverse_tcp = HashMap::new();

        for listener in &config.listeners {
            let addr = listener
                .listen
                .parse()
                .with_context(|| format!("listener {} listen is invalid", listener.name))?;
            let listeners = crate::net::bind_tcp_std_listeners(addr, &config.runtime)?;
            listener_tcp.insert(listener.name.clone(), listeners);
        }

        for reverse in &config.reverse {
            if !reverse_requires_tcp(reverse) {
                continue;
            }
            let addr = reverse
                .listen
                .parse()
                .with_context(|| format!("reverse {} listen is invalid", reverse.name))?;
            let listeners = crate::net::bind_tcp_std_listeners(addr, &config.runtime)?;
            reverse_tcp.insert(reverse.name.clone(), listeners);
        }

        let metrics = config
            .metrics
            .as_ref()
            .map(|metrics| bind_admin_listener(metrics.listen.as_str(), "metrics.listen"))
            .transpose()?;

        #[cfg(feature = "acme")]
        let acme_http01 = if config.acme.as_ref().is_some_and(|acme| acme.enabled) {
            let listen = config
                .acme
                .as_ref()
                .and_then(|acme| acme.http01_listen.as_deref())
                .ok_or_else(|| anyhow!("acme.http01_listen missing"))?;
            Some(bind_admin_listener(listen, "acme.http01_listen")?)
        } else {
            None
        };

        Ok(Self {
            listener_tcp,
            reverse_tcp,
            metrics,
            #[cfg(feature = "acme")]
            acme_http01,
        })
    }

    pub(crate) fn bind_for_hot_reload(
        config: &Config,
        previous_config: &Config,
        previous: &Self,
    ) -> Result<Self> {
        let mut listener_tcp = HashMap::new();
        let mut reverse_tcp = HashMap::new();

        for listener in &config.listeners {
            let listeners = previous
                .tcp_group_for_listen(previous_config, listener.listen.as_str())
                .map(|group| clone_std_tcp_group(group, "listener", listener.name.as_str()))
                .unwrap_or_else(|| bind_tcp_group(listener.listen.as_str(), config, "listener"))?;
            listener_tcp.insert(listener.name.clone(), listeners);
        }

        for reverse in &config.reverse {
            if !reverse_requires_tcp(reverse) {
                continue;
            }
            let listeners = previous
                .tcp_group_for_listen(previous_config, reverse.listen.as_str())
                .map(|group| clone_std_tcp_group(group, "reverse", reverse.name.as_str()))
                .unwrap_or_else(|| bind_tcp_group(reverse.listen.as_str(), config, "reverse"))?;
            reverse_tcp.insert(reverse.name.clone(), listeners);
        }

        let metrics = config
            .metrics
            .as_ref()
            .map(|metrics| {
                previous
                    .metrics_for_listen(previous_config, metrics.listen.as_str())
                    .map(|listener| {
                        listener
                            .try_clone()
                            .context("failed to clone metrics binding")
                    })
                    .unwrap_or_else(|| {
                        bind_admin_listener(metrics.listen.as_str(), "metrics.listen")
                    })
            })
            .transpose()?;

        #[cfg(feature = "acme")]
        let acme_http01 = if config.acme.as_ref().is_some_and(|acme| acme.enabled) {
            let listen = config
                .acme
                .as_ref()
                .and_then(|acme| acme.http01_listen.as_deref())
                .ok_or_else(|| anyhow!("acme.http01_listen missing"))?;
            Some(
                previous
                    .acme_for_listen(previous_config, listen)
                    .map(|listener| {
                        listener
                            .try_clone()
                            .context("failed to clone acme http-01 binding")
                    })
                    .unwrap_or_else(|| bind_admin_listener(listen, "acme.http01_listen"))?,
            )
        } else {
            None
        };

        Ok(Self {
            listener_tcp,
            reverse_tcp,
            metrics,
            #[cfg(feature = "acme")]
            acme_http01,
        })
    }

    fn tcp_group_for_listen<'a>(
        &'a self,
        config: &Config,
        listen: &str,
    ) -> Option<&'a Vec<TcpListener>> {
        for listener in &config.listeners {
            if listener.listen == listen {
                if let Some(group) = self.listener_tcp.get(&listener.name) {
                    return Some(group);
                }
            }
        }
        for reverse in &config.reverse {
            if reverse_requires_tcp(reverse) && reverse.listen == listen {
                if let Some(group) = self.reverse_tcp.get(&reverse.name) {
                    return Some(group);
                }
            }
        }
        None
    }

    fn metrics_for_listen<'a>(&'a self, config: &Config, listen: &str) -> Option<&'a TcpListener> {
        config
            .metrics
            .as_ref()
            .filter(|metrics| metrics.listen == listen)
            .and(self.metrics.as_ref())
    }

    #[cfg(feature = "acme")]
    fn acme_for_listen<'a>(&'a self, config: &Config, listen: &str) -> Option<&'a TcpListener> {
        config
            .acme
            .as_ref()
            .filter(|acme| acme.enabled)
            .and_then(|acme| acme.http01_listen.as_deref())
            .filter(|old_listen| *old_listen == listen)
            .and(self.acme_http01.as_ref())
    }

    pub(crate) fn from_env(config: &Config) -> Result<Option<Self>> {
        let Some(raw) = std::env::var_os(ENV_INHERITED_TCP_BINDINGS) else {
            return Ok(None);
        };
        unsafe {
            std::env::remove_var(ENV_INHERITED_TCP_BINDINGS);
        }
        #[cfg(unix)]
        let inherited: InheritedTcpBindings = serde_json::from_str(raw.to_string_lossy().as_ref())
            .context("invalid inherited tcp bindings")?;
        #[cfg(windows)]
        let inherited: InheritedTcpBindings = {
            let path = PathBuf::from(raw);
            let inherited = crate::windows_handoff::read_json_wait(path.as_path())?;
            let _ = std::fs::remove_file(&path);
            inherited
        };

        let mut listener_tcp = HashMap::new();
        let mut reverse_tcp = HashMap::new();

        for listener in &config.listeners {
            let group = inherited
                .listeners
                .iter()
                .find(|group| group.name == listener.name)
                .ok_or_else(|| {
                    anyhow!("missing inherited listener binding for {}", listener.name)
                })?;
            if group.listen != listener.listen {
                return Err(anyhow!(
                    "inherited listener binding for {} does not match listen {}",
                    listener.name,
                    listener.listen
                ));
            }
            listener_tcp.insert(listener.name.clone(), adopt_tcp_group(group)?);
        }
        for group in &inherited.listeners {
            if !config
                .listeners
                .iter()
                .any(|listener| listener.name == group.name)
            {
                return Err(anyhow!(
                    "unexpected inherited listener binding {}",
                    group.name
                ));
            }
        }

        for reverse in &config.reverse {
            let maybe_group = inherited
                .reverses
                .iter()
                .find(|group| group.name == reverse.name);
            if reverse_requires_tcp(reverse) {
                let group = maybe_group.ok_or_else(|| {
                    anyhow!("missing inherited reverse binding for {}", reverse.name)
                })?;
                if group.listen != reverse.listen {
                    return Err(anyhow!(
                        "inherited reverse binding for {} does not match listen {}",
                        reverse.name,
                        reverse.listen
                    ));
                }
                reverse_tcp.insert(reverse.name.clone(), adopt_tcp_group(group)?);
            } else if maybe_group.is_some() {
                return Err(anyhow!(
                    "unexpected inherited reverse binding for passthrough-only reverse {}",
                    reverse.name
                ));
            }
        }
        for group in &inherited.reverses {
            if !config
                .reverse
                .iter()
                .any(|reverse| reverse.name == group.name)
            {
                return Err(anyhow!(
                    "unexpected inherited reverse binding {}",
                    group.name
                ));
            }
        }

        let metrics = match (&config.metrics, inherited.metrics.as_ref()) {
            (Some(metrics), Some(inherited)) => {
                if inherited.listen != metrics.listen {
                    return Err(anyhow!(
                        "inherited metrics binding does not match metrics.listen={}",
                        metrics.listen
                    ));
                }
                #[cfg(unix)]
                let listener = adopt_tcp_listener(inherited.fd)?;
                #[cfg(windows)]
                let listener = adopt_tcp_listener_windows(inherited.socket.as_slice())?;
                Some(listener)
            }
            (None, None) => None,
            (Some(_), None) => return Err(anyhow!("missing inherited metrics binding")),
            (None, Some(_)) => return Err(anyhow!("unexpected inherited metrics binding")),
        };

        #[cfg(feature = "acme")]
        let acme_http01 = match (
            config.acme.as_ref().filter(|acme| acme.enabled),
            inherited.acme_http01.as_ref(),
        ) {
            (Some(acme), Some(inherited)) => {
                let listen = acme
                    .http01_listen
                    .as_deref()
                    .ok_or_else(|| anyhow!("acme.http01_listen missing"))?;
                if inherited.listen != listen {
                    return Err(anyhow!(
                        "inherited acme binding does not match acme.http01_listen={listen}"
                    ));
                }
                #[cfg(unix)]
                let listener = adopt_tcp_listener(inherited.fd)?;
                #[cfg(windows)]
                let listener = adopt_tcp_listener_windows(inherited.socket.as_slice())?;
                Some(listener)
            }
            (None, None) => None,
            (Some(_), None) => return Err(anyhow!("missing inherited acme http-01 binding")),
            (None, Some(_)) => return Err(anyhow!("unexpected inherited acme http-01 binding")),
        };

        Ok(Some(Self {
            listener_tcp,
            reverse_tcp,
            metrics,
            #[cfg(feature = "acme")]
            acme_http01,
        }))
    }

    pub(crate) fn clone_listener(&self, name: &str) -> Result<Vec<tokio::net::TcpListener>> {
        self.listener_tcp
            .get(name)
            .ok_or_else(|| anyhow!("listener binding not found for {}", name))?
            .iter()
            .map(|listener| {
                let cloned = listener
                    .try_clone()
                    .with_context(|| format!("failed to clone listener binding for {}", name))?;
                crate::net::tokio_listener_from_std(cloned)
            })
            .collect()
    }

    pub(crate) fn clone_reverse(&self, name: &str) -> Result<Vec<tokio::net::TcpListener>> {
        self.reverse_tcp
            .get(name)
            .ok_or_else(|| anyhow!("reverse binding not found for {}", name))?
            .iter()
            .map(|listener| {
                let cloned = listener
                    .try_clone()
                    .with_context(|| format!("failed to clone reverse binding for {}", name))?;
                crate::net::tokio_listener_from_std(cloned)
            })
            .collect()
    }

    pub(crate) fn clone_metrics(&self) -> Result<Option<TcpListener>> {
        self.metrics
            .as_ref()
            .map(|listener| {
                listener
                    .try_clone()
                    .context("failed to clone metrics binding")
            })
            .transpose()
    }

    #[cfg(feature = "acme")]
    pub(crate) fn clone_acme_http01(&self) -> Result<Option<TcpListener>> {
        self.acme_http01
            .as_ref()
            .map(|listener| {
                listener
                    .try_clone()
                    .context("failed to clone acme http-01 binding")
            })
            .transpose()
    }

    pub(crate) fn prepare_handoff(&self, config: &Config) -> Result<TcpBindingHandoff> {
        #[cfg(not(any(unix, windows)))]
        {
            let _ = config;
            return Err(anyhow!(
                "binary upgrade handoff is only supported on unix and windows"
            ));
        }

        #[cfg(unix)]
        {
            let mut kept_fds = Vec::new();
            let mut inherited = InheritedTcpBindings {
                listeners: Vec::new(),
                reverses: Vec::new(),
                metrics: None,
                #[cfg(feature = "acme")]
                acme_http01: None,
            };

            for listener in &config.listeners {
                let sockets = self
                    .listener_tcp
                    .get(&listener.name)
                    .ok_or_else(|| anyhow!("listener binding not found for {}", listener.name))?;
                inherited.listeners.push(InheritedTcpGroup {
                    name: listener.name.clone(),
                    listen: listener.listen.clone(),
                    fds: duplicate_listeners_for_handoff(sockets, &mut kept_fds)?,
                });
            }

            for reverse in &config.reverse {
                if !reverse_requires_tcp(reverse) {
                    continue;
                }
                let sockets = self
                    .reverse_tcp
                    .get(&reverse.name)
                    .ok_or_else(|| anyhow!("reverse binding not found for {}", reverse.name))?;
                inherited.reverses.push(InheritedTcpGroup {
                    name: reverse.name.clone(),
                    listen: reverse.listen.clone(),
                    fds: duplicate_listeners_for_handoff(sockets, &mut kept_fds)?,
                });
            }

            if let Some(metrics) = config.metrics.as_ref() {
                let listener = self
                    .metrics
                    .as_ref()
                    .ok_or_else(|| anyhow!("metrics binding not found"))?;
                inherited.metrics = Some(InheritedSingleTcp {
                    listen: metrics.listen.clone(),
                    fd: duplicate_listener_for_handoff(listener, &mut kept_fds)?,
                });
            }

            #[cfg(feature = "acme")]
            if let Some(acme) = config.acme.as_ref().filter(|acme| acme.enabled) {
                let listen = acme
                    .http01_listen
                    .as_ref()
                    .ok_or_else(|| anyhow!("acme.http01_listen missing"))?;
                let listener = self
                    .acme_http01
                    .as_ref()
                    .ok_or_else(|| anyhow!("acme http-01 binding not found"))?;
                inherited.acme_http01 = Some(InheritedSingleTcp {
                    listen: listen.clone(),
                    fd: duplicate_listener_for_handoff(listener, &mut kept_fds)?,
                });
            }

            Ok(TcpBindingHandoff {
                env_value: serde_json::to_string(&inherited)
                    .context("failed to serialize inherited tcp bindings")?,
                kept_fds,
            })
        }

        #[cfg(windows)]
        {
            let path = crate::windows_handoff::create_handoff_path(config, "tcp-bindings")?;
            let listeners = config
                .listeners
                .iter()
                .map(|listener| {
                    let sockets = self.listener_tcp.get(&listener.name).ok_or_else(|| {
                        anyhow!("listener binding not found for {}", listener.name)
                    })?;
                    Ok(WindowsTcpGroup {
                        name: listener.name.clone(),
                        listen: listener.listen.clone(),
                        listeners: sockets
                            .iter()
                            .map(|listener| {
                                listener.try_clone().context("failed to clone listener")
                            })
                            .collect::<Result<Vec<_>>>()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            let reverses = config
                .reverse
                .iter()
                .filter(|reverse| reverse_requires_tcp(reverse))
                .map(|reverse| {
                    let sockets = self
                        .reverse_tcp
                        .get(&reverse.name)
                        .ok_or_else(|| anyhow!("reverse binding not found for {}", reverse.name))?;
                    Ok(WindowsTcpGroup {
                        name: reverse.name.clone(),
                        listen: reverse.listen.clone(),
                        listeners: sockets
                            .iter()
                            .map(|listener| {
                                listener
                                    .try_clone()
                                    .context("failed to clone reverse listener")
                            })
                            .collect::<Result<Vec<_>>>()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            let metrics = match config.metrics.as_ref() {
                Some(metrics) => {
                    let listener = self
                        .metrics
                        .as_ref()
                        .ok_or_else(|| anyhow!("metrics binding not found"))?;
                    Some(WindowsSingleTcp {
                        listen: metrics.listen.clone(),
                        listener: listener
                            .try_clone()
                            .context("failed to clone metrics listener")?,
                    })
                }
                None => None,
            };

            #[cfg(feature = "acme")]
            let acme_http01 = match config.acme.as_ref().filter(|acme| acme.enabled) {
                Some(acme) => {
                    let listen = acme
                        .http01_listen
                        .as_ref()
                        .ok_or_else(|| anyhow!("acme.http01_listen missing"))?;
                    let listener = self
                        .acme_http01
                        .as_ref()
                        .ok_or_else(|| anyhow!("acme http-01 binding not found"))?;
                    Some(WindowsSingleTcp {
                        listen: listen.clone(),
                        listener: listener
                            .try_clone()
                            .context("failed to clone acme listener")?,
                    })
                }
                None => None,
            };

            Ok(TcpBindingHandoff {
                env_value: path.display().to_string(),
                pending: WindowsTcpBindingHandoff {
                    listeners,
                    reverses,
                    metrics,
                    #[cfg(feature = "acme")]
                    acme_http01,
                },
                cleanup_path: path,
            })
        }
    }

    pub(crate) fn handoff_env_key() -> &'static str {
        ENV_INHERITED_TCP_BINDINGS
    }

    #[cfg(windows)]
    pub(crate) fn finalize_handoff_for_child(
        handoff: &TcpBindingHandoff,
        child_pid: u32,
    ) -> Result<()> {
        let inherited = InheritedTcpBindings {
            listeners: handoff
                .pending
                .listeners
                .iter()
                .map(|group| {
                    Ok(InheritedTcpGroup {
                        name: group.name.clone(),
                        listen: group.listen.clone(),
                        sockets: group
                            .listeners
                            .iter()
                            .map(|listener| {
                                crate::windows_handoff::duplicate_socket_for_child(
                                    listener, child_pid,
                                )
                            })
                            .collect::<Result<Vec<_>>>()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            reverses: handoff
                .pending
                .reverses
                .iter()
                .map(|group| {
                    Ok(InheritedTcpGroup {
                        name: group.name.clone(),
                        listen: group.listen.clone(),
                        sockets: group
                            .listeners
                            .iter()
                            .map(|listener| {
                                crate::windows_handoff::duplicate_socket_for_child(
                                    listener, child_pid,
                                )
                            })
                            .collect::<Result<Vec<_>>>()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            metrics: handoff
                .pending
                .metrics
                .as_ref()
                .map(|single| {
                    Ok(InheritedSingleTcp {
                        listen: single.listen.clone(),
                        socket: crate::windows_handoff::duplicate_socket_for_child(
                            &single.listener,
                            child_pid,
                        )?,
                    })
                })
                .transpose()?,
            #[cfg(feature = "acme")]
            acme_http01: handoff
                .pending
                .acme_http01
                .as_ref()
                .map(|single| {
                    Ok(InheritedSingleTcp {
                        listen: single.listen.clone(),
                        socket: crate::windows_handoff::duplicate_socket_for_child(
                            &single.listener,
                            child_pid,
                        )?,
                    })
                })
                .transpose()?,
        };
        crate::windows_handoff::write_json_file(handoff.cleanup_path.as_path(), &inherited)
    }

    #[cfg(windows)]
    pub(crate) fn cleanup_handoff_file(handoff: &TcpBindingHandoff) {
        let _ = std::fs::remove_file(&handoff.cleanup_path);
    }
}

fn bind_tcp_group(listen: &str, config: &Config, kind: &str) -> Result<Vec<TcpListener>> {
    let addr = listen
        .parse()
        .with_context(|| format!("{kind} listen is invalid: {listen}"))?;
    crate::net::bind_tcp_std_listeners(addr, &config.runtime)
        .with_context(|| format!("failed to bind {kind} listen={listen}"))
}

fn clone_std_tcp_group(group: &[TcpListener], kind: &str, name: &str) -> Result<Vec<TcpListener>> {
    group
        .iter()
        .map(|listener| {
            listener
                .try_clone()
                .with_context(|| format!("failed to clone {kind} binding for {name}"))
        })
        .collect()
}

fn reverse_requires_tcp(reverse: &ReverseConfig) -> bool {
    !(reverse
        .http3
        .as_ref()
        .map(|http3| {
            http3.enabled
                && !http3.passthrough_upstreams.is_empty()
                && reverse.routes.is_empty()
                && reverse.tls_passthrough_routes.is_empty()
        })
        .unwrap_or(false))
}

fn bind_admin_listener(listen: &str, field: &str) -> Result<TcpListener> {
    let addr: std::net::SocketAddr = listen
        .parse()
        .with_context(|| format!("{field} is invalid"))?;
    let listener =
        TcpListener::bind(addr).with_context(|| format!("failed to bind {field}={listen}"))?;
    listener
        .set_nonblocking(true)
        .with_context(|| format!("failed to set {field} nonblocking"))?;
    Ok(listener)
}

fn adopt_tcp_group(group: &InheritedTcpGroup) -> Result<Vec<TcpListener>> {
    #[cfg(unix)]
    {
        group.fds.iter().copied().map(adopt_tcp_listener).collect()
    }
    #[cfg(windows)]
    {
        group
            .sockets
            .iter()
            .map(|socket| adopt_tcp_listener_windows(socket.as_slice()))
            .collect()
    }
}

fn adopt_tcp_listener(fd: i32) -> Result<TcpListener> {
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};

        let listener = unsafe { TcpListener::from_raw_fd(fd) };
        listener
            .set_nonblocking(true)
            .context("failed to set inherited listener nonblocking")?;
        set_cloexec(listener.as_raw_fd(), true)?;
        Ok(listener)
    }
    #[cfg(not(unix))]
    {
        let _ = fd;
        Err(anyhow!("inherited tcp bindings are only supported on unix"))
    }
}

#[cfg(windows)]
fn adopt_tcp_listener_windows(socket: &[u8]) -> Result<TcpListener> {
    crate::windows_handoff::adopt_tcp_listener(socket)
}

#[cfg(unix)]
fn duplicate_listeners_for_handoff(
    listeners: &[TcpListener],
    kept_fds: &mut Vec<std::os::fd::OwnedFd>,
) -> Result<Vec<i32>> {
    listeners
        .iter()
        .map(|listener| duplicate_listener_for_handoff(listener, kept_fds))
        .collect()
}

#[cfg(unix)]
fn duplicate_listener_for_handoff(
    listener: &TcpListener,
    kept_fds: &mut Vec<std::os::fd::OwnedFd>,
) -> Result<i32> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let fd = unsafe { libc::dup(listener.as_raw_fd()) };
    if fd < 0 {
        return Err(anyhow!(
            "failed to duplicate inherited listener fd: {}",
            std::io::Error::last_os_error()
        ));
    }
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let raw = owned.as_raw_fd();
    kept_fds.push(owned);
    Ok(raw)
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
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CacheConfig, Config,
        IdentityConfig, ListenerConfig, ListenerMode, MessagesConfig, RuntimeConfig,
        SystemLogConfig,
    };
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn test_config() -> Config {
        let runtime = RuntimeConfig {
            acceptor_tasks_per_listener: Some(1),
            reuse_port: false,
            ..RuntimeConfig::default()
        };
        Config {
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime,
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            acme: None,
            exporter: None,
            auth: AuthConfig::default(),
            identity_sources: Vec::new(),
            ext_authz: Vec::new(),
            destination_resolution: Default::default(),
            listeners: vec![ListenerConfig {
                name: "forward".to_string(),
                mode: ListenerMode::Forward,
                listen: "127.0.0.1:0".to_string(),
                default_action: ActionConfig {
                    kind: ActionKind::Direct,
                    upstream: None,
                    local_response: None,
                },
                tls_inspection: None,
                rules: Vec::new(),
                connection_filter: Vec::new(),
                upstream_proxy: None,
                http3: None,
                ftp: Default::default(),
                xdp: None,
                cache: None,
                rate_limit: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                http_modules: Vec::new(),
            }],
            named_sets: Vec::new(),
            http_guard_profiles: Vec::new(),
            rate_limit_profiles: Vec::new(),
            upstream_trust_profiles: Vec::new(),
            reverse: Vec::new(),
            upstreams: Vec::new(),
            cache: CacheConfig::default(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn inherited_bindings_round_trip() {
        let _guard = env_lock().lock().expect("env lock");
        let config = test_config();
        let bindings = TcpBindings::bind(&config).expect("bind");
        let handoff = bindings.prepare_handoff(&config).expect("handoff");
        let TcpBindingHandoff {
            env_value,
            kept_fds,
        } = handoff;
        assert_eq!(kept_fds.len(), 1);
        unsafe {
            std::env::set_var(TcpBindings::handoff_env_key(), env_value);
        }
        std::mem::forget(kept_fds);
        let inherited = TcpBindings::from_env(&config)
            .expect("from env")
            .expect("bindings");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let listeners = inherited.clone_listener("forward").expect("listener clone");
            assert_eq!(listeners.len(), 1);
        });
    }
}
