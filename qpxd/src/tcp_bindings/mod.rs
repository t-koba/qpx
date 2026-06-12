use anyhow::{Context, Result, anyhow};
use qpx_core::config::{Config, ReverseEdgeConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::TcpListener;
#[cfg(windows)]
use std::path::PathBuf;

const ENV_INHERITED_TCP_BINDINGS: &str = "QPX_INHERITED_TCP_BINDINGS";

pub(crate) mod filter;
mod handoff;
pub(crate) mod net;

use handoff::adopt_tcp_group;
#[cfg(unix)]
use handoff::adopt_tcp_listener;
#[cfg(windows)]
use handoff::adopt_tcp_listener_windows;

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
    forward_edges: Vec<InheritedTcpGroup>,
    reverse_edge: Vec<InheritedTcpGroup>,
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
    forward_edges: Vec<WindowsTcpGroup>,
    reverse_edge: Vec<WindowsTcpGroup>,
    metrics: Option<WindowsSingleTcp>,
    #[cfg(feature = "acme")]
    acme_http01: Option<WindowsSingleTcp>,
}

#[cfg(windows)]
struct WindowsTcpGroup {
    name: String,
    listen: String,
    forward_edges: Vec<TcpListener>,
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

        for listener in config.ingress_edges() {
            let addr = listener
                .listen
                .parse()
                .with_context(|| format!("listener {} listen is invalid", listener.name))?;
            let forward_edges =
                crate::tcp_bindings::net::bind_tcp_std_listeners(addr, &config.runtime)?;
            listener_tcp.insert(listener.name.clone(), forward_edges);
        }

        for reverse_edge in config.reverse_edge_configs() {
            if !reverse_requires_tcp(reverse_edge) {
                continue;
            }
            let addr = reverse_edge
                .listen
                .parse()
                .with_context(|| format!("reverse_edge {} listen is invalid", reverse_edge.name))?;
            let forward_edges =
                crate::tcp_bindings::net::bind_tcp_std_listeners(addr, &config.runtime)?;
            reverse_tcp.insert(reverse_edge.name.clone(), forward_edges);
        }

        let metrics = config
            .telemetry
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

        for listener in config.ingress_edges() {
            let forward_edges = previous
                .tcp_group_for_listen(previous_config, listener.listen.as_str())
                .map(|group| clone_std_tcp_group(group, "listener", listener.name.as_str()))
                .unwrap_or_else(|| bind_tcp_group(listener.listen.as_str(), config, "listener"))?;
            listener_tcp.insert(listener.name.clone(), forward_edges);
        }

        for reverse_edge in config.reverse_edge_configs() {
            if !reverse_requires_tcp(reverse_edge) {
                continue;
            }
            let forward_edges = previous
                .tcp_group_for_listen(previous_config, reverse_edge.listen.as_str())
                .map(|group| clone_std_tcp_group(group, "reverse_edge", reverse_edge.name.as_str()))
                .unwrap_or_else(|| {
                    bind_tcp_group(reverse_edge.listen.as_str(), config, "reverse_edge")
                })?;
            reverse_tcp.insert(reverse_edge.name.clone(), forward_edges);
        }

        let metrics = config
            .telemetry
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
        for listener in config.ingress_edges() {
            if listener.listen == listen
                && let Some(group) = self.listener_tcp.get(&listener.name)
            {
                return Some(group);
            }
        }
        for reverse_edge in config.reverse_edge_configs() {
            if reverse_requires_tcp(reverse_edge)
                && reverse_edge.listen == listen
                && let Some(group) = self.reverse_tcp.get(&reverse_edge.name)
            {
                return Some(group);
            }
        }
        None
    }

    fn metrics_for_listen<'a>(&'a self, config: &Config, listen: &str) -> Option<&'a TcpListener> {
        config
            .telemetry
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
        // SAFETY: inherited binding env is consumed during startup before concurrent env access.
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

        for listener in config.ingress_edges() {
            let group = inherited
                .forward_edges
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
        for group in &inherited.forward_edges {
            if !config
                .ingress_edge_configs()
                .iter()
                .any(|listener| listener.name == group.name)
            {
                return Err(anyhow!(
                    "unexpected inherited listener binding {}",
                    group.name
                ));
            }
        }

        for reverse_edge in config.reverse_edge_configs() {
            let maybe_group = inherited
                .reverse_edge
                .iter()
                .find(|group| group.name == reverse_edge.name);
            if reverse_requires_tcp(reverse_edge) {
                let group = maybe_group.ok_or_else(|| {
                    anyhow!(
                        "missing inherited reverse_edge binding for {}",
                        reverse_edge.name
                    )
                })?;
                if group.listen != reverse_edge.listen {
                    return Err(anyhow!(
                        "inherited reverse_edge binding for {} does not match listen {}",
                        reverse_edge.name,
                        reverse_edge.listen
                    ));
                }
                reverse_tcp.insert(reverse_edge.name.clone(), adopt_tcp_group(group)?);
            } else if maybe_group.is_some() {
                return Err(anyhow!(
                    "unexpected inherited reverse_edge binding for passthrough-only reverse_edge {}",
                    reverse_edge.name
                ));
            }
        }
        for group in &inherited.reverse_edge {
            if !config
                .reverse_edge_configs()
                .iter()
                .any(|reverse_edge| reverse_edge.name == group.name)
            {
                return Err(anyhow!(
                    "unexpected inherited reverse_edge binding {}",
                    group.name
                ));
            }
        }

        let metrics = match (&config.telemetry.metrics, inherited.metrics.as_ref()) {
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
                crate::tcp_bindings::net::tokio_listener_from_std(cloned)
            })
            .collect()
    }

    pub(crate) fn clone_reverse(&self, name: &str) -> Result<Vec<tokio::net::TcpListener>> {
        self.reverse_tcp
            .get(name)
            .ok_or_else(|| anyhow!("reverse_edge binding not found for {}", name))?
            .iter()
            .map(|listener| {
                let cloned = listener.try_clone().with_context(|| {
                    format!("failed to clone reverse_edge binding for {}", name)
                })?;
                crate::tcp_bindings::net::tokio_listener_from_std(cloned)
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
}

fn bind_tcp_group(listen: &str, config: &Config, kind: &str) -> Result<Vec<TcpListener>> {
    let addr = listen
        .parse()
        .with_context(|| format!("{kind} listen is invalid: {listen}"))?;
    crate::tcp_bindings::net::bind_tcp_std_listeners(addr, &config.runtime)
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

fn reverse_requires_tcp(reverse_edge: &ReverseEdgeConfig) -> bool {
    !(reverse_edge
        .http3
        .as_ref()
        .map(|http3| {
            http3.enabled
                && !http3.passthrough_upstreams.is_empty()
                && reverse_edge.routes.is_empty()
                && reverse_edge.tls_passthrough_routes.is_empty()
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
