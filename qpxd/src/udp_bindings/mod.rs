#[cfg(feature = "http3")]
use anyhow::Context;
use anyhow::Result;
#[cfg(feature = "http3")]
use anyhow::anyhow;
use qpx_core::config::Config;
#[cfg(feature = "http3")]
use qpx_core::config::IngressEdgeMode;
use serde::{Deserialize, Serialize};
#[cfg(feature = "http3")]
use std::collections::HashMap;
#[cfg(feature = "http3")]
use std::net::{SocketAddr, UdpSocket};
#[cfg(windows)]
use std::path::PathBuf;

#[cfg(all(feature = "http3", unix))]
use crate::udp_socket_handoff::adopt_inherited_udp_socket;
#[cfg(all(feature = "http3", windows))]
use crate::udp_socket_handoff::adopt_inherited_udp_socket_windows;

const ENV_INHERITED_UDP_BINDINGS: &str = "QPX_INHERITED_UDP_BINDINGS";

mod handoff;

pub(crate) struct UdpBindings {
    #[cfg(feature = "http3")]
    listener_udp: HashMap<String, UdpSocket>,
    #[cfg(feature = "http3")]
    reverse_udp: HashMap<String, UdpSocket>,
}

pub(crate) struct UdpBindingHandoff {
    pub(crate) env_value: String,
    #[cfg(unix)]
    pub(crate) kept_fds: Vec<std::os::fd::OwnedFd>,
    #[cfg(all(feature = "http3", windows))]
    pending: WindowsUdpBindingHandoff,
    #[cfg(windows)]
    cleanup_path: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct InheritedUdpBindings {
    forward_edges: Vec<InheritedUdpSocket>,
    reverse_edge: Vec<InheritedUdpSocket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InheritedUdpSocket {
    name: String,
    listen: String,
    #[cfg(unix)]
    fd: i32,
    #[cfg(windows)]
    socket: Vec<u8>,
}

#[cfg(all(feature = "http3", windows))]
struct WindowsUdpBindingHandoff {
    forward_edges: Vec<WindowsInheritedUdpSocket>,
    reverse_edge: Vec<WindowsInheritedUdpSocket>,
}

#[cfg(all(feature = "http3", windows))]
struct WindowsInheritedUdpSocket {
    name: String,
    listen: String,
    socket: UdpSocket,
}

impl UdpBindings {
    pub(crate) fn bind(config: &Config) -> Result<Self> {
        #[cfg(feature = "http3")]
        {
            let mut listener_udp = HashMap::new();
            let mut reverse_udp = HashMap::new();

            for listener in config.ingress_edges() {
                let Some(http3) = listener.http3.as_ref().filter(|cfg| cfg.enabled) else {
                    continue;
                };
                let listen = http3
                    .listen
                    .clone()
                    .unwrap_or_else(|| listener.listen.clone());
                let addr: SocketAddr = listen.parse().with_context(|| {
                    format!("listener {} http3.listen is invalid", listener.name)
                })?;
                let socket = match listener.mode {
                    IngressEdgeMode::Forward => {
                        crate::tcp_bindings::net::bind_udp_std_socket(addr, &config.runtime)?
                    }
                    IngressEdgeMode::Transparent => {
                        crate::transparent::udp_socket::bind_udp_std_listener(
                            addr,
                            config.runtime.reuse_port,
                        )?
                    }
                };
                listener_udp.insert(listener.name.clone(), socket);
            }

            for reverse_edge in config.reverse_edge_configs() {
                let Some(http3) = reverse_edge.http3.as_ref().filter(|cfg| cfg.enabled) else {
                    continue;
                };
                let listen = http3
                    .listen
                    .clone()
                    .unwrap_or_else(|| reverse_edge.listen.clone());
                let addr: SocketAddr = listen.parse().with_context(|| {
                    format!("reverse_edge {} http3.listen is invalid", reverse_edge.name)
                })?;
                let socket = crate::tcp_bindings::net::bind_udp_std_socket(addr, &config.runtime)?;
                reverse_udp.insert(reverse_edge.name.clone(), socket);
            }

            Ok(Self {
                listener_udp,
                reverse_udp,
            })
        }

        #[cfg(not(feature = "http3"))]
        {
            let _ = config;
            Ok(Self {})
        }
    }

    pub(crate) fn bind_for_hot_reload(
        config: &Config,
        previous_config: &Config,
        previous: &Self,
    ) -> Result<Self> {
        #[cfg(feature = "http3")]
        {
            let mut listener_udp = HashMap::new();
            let mut reverse_udp = HashMap::new();

            for listener in config.ingress_edges() {
                let Some(http3) = listener.http3.as_ref().filter(|cfg| cfg.enabled) else {
                    continue;
                };
                let listen = http3
                    .listen
                    .clone()
                    .unwrap_or_else(|| listener.listen.clone());
                let socket = previous
                    .udp_socket_for_listen(previous_config, listen.as_str())
                    .map(|socket| {
                        socket.with_context(|| {
                            format!("failed to clone udp listener binding for {}", listener.name)
                        })
                    })
                    .unwrap_or_else(|| bind_udp_for_listener(listener, config, listen.as_str()))?;
                listener_udp.insert(listener.name.clone(), socket);
            }

            for reverse_edge in config.reverse_edge_configs() {
                let Some(http3) = reverse_edge.http3.as_ref().filter(|cfg| cfg.enabled) else {
                    continue;
                };
                let listen = http3
                    .listen
                    .clone()
                    .unwrap_or_else(|| reverse_edge.listen.clone());
                let socket = previous
                    .udp_socket_for_listen(previous_config, listen.as_str())
                    .map(|socket| {
                        socket.with_context(|| {
                            format!(
                                "failed to clone udp reverse_edge binding for {}",
                                reverse_edge.name
                            )
                        })
                    })
                    .unwrap_or_else(|| {
                        bind_udp_for_reverse(reverse_edge, config, listen.as_str())
                    })?;
                reverse_udp.insert(reverse_edge.name.clone(), socket);
            }

            Ok(Self {
                listener_udp,
                reverse_udp,
            })
        }

        #[cfg(not(feature = "http3"))]
        {
            let _ = config;
            let _ = previous_config;
            let _ = previous;
            Ok(Self {})
        }
    }

    #[cfg(feature = "http3")]
    fn udp_socket_for_listen(&self, config: &Config, listen: &str) -> Option<Result<UdpSocket>> {
        for listener in config.ingress_edges() {
            let old_listen = listener
                .http3
                .as_ref()
                .filter(|cfg| cfg.enabled)
                .map(|cfg| {
                    cfg.listen
                        .clone()
                        .unwrap_or_else(|| listener.listen.clone())
                });
            if old_listen.as_deref() == Some(listen)
                && let Some(socket) = self.listener_udp.get(&listener.name)
            {
                return Some(socket.try_clone().context("failed to clone udp listener"));
            }
        }
        for reverse_edge in config.reverse_edge_configs() {
            let old_listen = reverse_edge
                .http3
                .as_ref()
                .filter(|cfg| cfg.enabled)
                .map(|cfg| {
                    cfg.listen
                        .clone()
                        .unwrap_or_else(|| reverse_edge.listen.clone())
                });
            if old_listen.as_deref() == Some(listen)
                && let Some(socket) = self.reverse_udp.get(&reverse_edge.name)
            {
                return Some(
                    socket
                        .try_clone()
                        .context("failed to clone udp reverse_edge"),
                );
            }
        }
        None
    }

    pub(crate) fn from_env(config: &Config) -> Result<Option<Self>> {
        let Some(raw) = std::env::var_os(ENV_INHERITED_UDP_BINDINGS) else {
            return Ok(None);
        };
        unsafe {
            std::env::remove_var(ENV_INHERITED_UDP_BINDINGS);
        }

        #[cfg(feature = "http3")]
        {
            #[cfg(unix)]
            let inherited: InheritedUdpBindings =
                serde_json::from_str(raw.to_string_lossy().as_ref())
                    .context("invalid inherited udp bindings")?;
            #[cfg(windows)]
            let inherited: InheritedUdpBindings = {
                let path = PathBuf::from(raw);
                let inherited = crate::windows_handoff::read_json_wait(path.as_path())?;
                let _ = std::fs::remove_file(&path);
                inherited
            };
            let mut listener_udp = HashMap::new();
            let mut reverse_udp = HashMap::new();

            for listener in config.ingress_edges() {
                let maybe = inherited
                    .forward_edges
                    .iter()
                    .find(|entry| entry.name == listener.name);
                let expect_socket = listener
                    .http3
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false);
                if expect_socket {
                    let listen = listener
                        .http3
                        .as_ref()
                        .and_then(|cfg| cfg.listen.clone())
                        .unwrap_or_else(|| listener.listen.clone());
                    let entry = maybe.ok_or_else(|| {
                        anyhow!(
                            "missing inherited udp listener binding for {}",
                            listener.name
                        )
                    })?;
                    if entry.listen != listen {
                        return Err(anyhow!(
                            "inherited udp listener binding for {} does not match listen {}",
                            listener.name,
                            listen
                        ));
                    }
                    listener_udp.insert(
                        listener.name.clone(),
                        #[cfg(unix)]
                        adopt_inherited_udp_socket(entry.fd)?,
                        #[cfg(windows)]
                        adopt_inherited_udp_socket_windows(entry.socket.as_slice())?,
                    );
                } else if maybe.is_some() {
                    return Err(anyhow!(
                        "unexpected inherited udp listener binding for {}",
                        listener.name
                    ));
                }
            }

            for reverse_edge in config.reverse_edge_configs() {
                let maybe = inherited
                    .reverse_edge
                    .iter()
                    .find(|entry| entry.name == reverse_edge.name);
                let expect_socket = reverse_edge
                    .http3
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false);
                if expect_socket {
                    let listen = reverse_edge
                        .http3
                        .as_ref()
                        .and_then(|cfg| cfg.listen.clone())
                        .unwrap_or_else(|| reverse_edge.listen.clone());
                    let entry = maybe.ok_or_else(|| {
                        anyhow!(
                            "missing inherited udp reverse_edge binding for {}",
                            reverse_edge.name
                        )
                    })?;
                    if entry.listen != listen {
                        return Err(anyhow!(
                            "inherited udp reverse_edge binding for {} does not match listen {}",
                            reverse_edge.name,
                            listen
                        ));
                    }
                    reverse_udp.insert(
                        reverse_edge.name.clone(),
                        #[cfg(unix)]
                        adopt_inherited_udp_socket(entry.fd)?,
                        #[cfg(windows)]
                        adopt_inherited_udp_socket_windows(entry.socket.as_slice())?,
                    );
                } else if maybe.is_some() {
                    return Err(anyhow!(
                        "unexpected inherited udp reverse_edge binding for {}",
                        reverse_edge.name
                    ));
                }
            }

            Ok(Some(Self {
                listener_udp,
                reverse_udp,
            }))
        }

        #[cfg(not(feature = "http3"))]
        {
            let _ = config;
            let _ = raw;
            Ok(Some(Self {}))
        }
    }

    #[cfg(feature = "http3")]
    pub(crate) fn clone_listener(&self, name: &str) -> Result<Option<UdpSocket>> {
        self.listener_udp
            .get(name)
            .map(|socket| {
                socket
                    .try_clone()
                    .with_context(|| format!("failed to clone udp listener binding for {name}"))
            })
            .transpose()
    }

    #[cfg(feature = "http3")]
    pub(crate) fn clone_reverse(&self, name: &str) -> Result<Option<UdpSocket>> {
        self.reverse_udp
            .get(name)
            .map(|socket| {
                socket
                    .try_clone()
                    .with_context(|| format!("failed to clone udp reverse_edge binding for {name}"))
            })
            .transpose()
    }
}

#[cfg(feature = "http3")]
fn bind_udp_for_listener(
    listener: &qpx_core::config::IngressEdgeConfig,
    config: &Config,
    listen: &str,
) -> Result<UdpSocket> {
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("listener {} http3.listen is invalid", listener.name))?;
    match listener.mode {
        IngressEdgeMode::Forward => {
            crate::tcp_bindings::net::bind_udp_std_socket(addr, &config.runtime)
        }
        IngressEdgeMode::Transparent => {
            crate::transparent::udp_socket::bind_udp_std_listener(addr, config.runtime.reuse_port)
        }
    }
}

#[cfg(feature = "http3")]
fn bind_udp_for_reverse(
    reverse_edge: &qpx_core::config::ReverseEdgeConfig,
    config: &Config,
    listen: &str,
) -> Result<UdpSocket> {
    let addr = listen
        .parse()
        .with_context(|| format!("reverse_edge {} http3.listen is invalid", reverse_edge.name))?;
    crate::tcp_bindings::net::bind_udp_std_socket(addr, &config.runtime)
}
