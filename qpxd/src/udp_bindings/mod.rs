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
                let listen = effective_http3_listen(http3.listen.as_deref(), &listener.listen);
                let socket = bind_udp_for_listener(listener, config, listen)?;
                listener_udp.insert(listener.name.clone(), socket);
            }

            for reverse_edge in config.reverse_edge_configs() {
                let Some(http3) = reverse_edge.http3.as_ref().filter(|cfg| cfg.enabled) else {
                    continue;
                };
                let listen = effective_http3_listen(http3.listen.as_deref(), &reverse_edge.listen);
                let socket = bind_udp_for_reverse(reverse_edge, config, listen)?;
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
                let listen = effective_http3_listen(http3.listen.as_deref(), &listener.listen);
                let socket = previous
                    .udp_socket_for_listen(previous_config, listen)
                    .map(|socket| {
                        socket.with_context(|| {
                            format!("failed to clone udp listener binding for {}", listener.name)
                        })
                    })
                    .unwrap_or_else(|| bind_udp_for_listener(listener, config, listen))?;
                listener_udp.insert(listener.name.clone(), socket);
            }

            for reverse_edge in config.reverse_edge_configs() {
                let Some(http3) = reverse_edge.http3.as_ref().filter(|cfg| cfg.enabled) else {
                    continue;
                };
                let listen = effective_http3_listen(http3.listen.as_deref(), &reverse_edge.listen);
                let socket = previous
                    .udp_socket_for_listen(previous_config, listen)
                    .map(|socket| {
                        socket.with_context(|| {
                            format!(
                                "failed to clone udp reverse_edge binding for {}",
                                reverse_edge.name
                            )
                        })
                    })
                    .unwrap_or_else(|| bind_udp_for_reverse(reverse_edge, config, listen))?;
                reverse_udp.insert(reverse_edge.name.clone(), socket);
            }

            Ok(Self {
                listener_udp,
                reverse_udp,
            })
        }

        #[cfg(not(feature = "http3"))]
        {
            let _ = (config, previous_config, previous);
            Ok(Self {})
        }
    }

    #[cfg(feature = "http3")]
    fn udp_socket_for_listen(&self, config: &Config, listen: &str) -> Option<Result<UdpSocket>> {
        // A configured port 0 is an instruction to allocate a fresh port, not an
        // endpoint identity; reusing the old socket would give two edges one port.
        if listen
            .parse::<SocketAddr>()
            .is_ok_and(|addr| addr.port() == 0)
        {
            return None;
        }
        for listener in config.ingress_edges() {
            let old_listen = listener
                .http3
                .as_ref()
                .filter(|cfg| cfg.enabled)
                .map(|cfg| effective_http3_listen(cfg.listen.as_deref(), &listener.listen));
            if old_listen == Some(listen)
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
                .map(|cfg| effective_http3_listen(cfg.listen.as_deref(), &reverse_edge.listen));
            if old_listen == Some(listen)
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
        // SAFETY: the process environment is mutated only during controlled handoff bootstrap.
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
            let inherited: InheritedUdpBindings =
                crate::windows_handoff::read_json_wait_and_remove(PathBuf::from(raw))?;
            let mut listener_udp = HashMap::new();
            let mut reverse_udp = HashMap::new();

            for listener in config.ingress_edges() {
                let maybe = inherited
                    .forward_edges
                    .iter()
                    .find(|entry| entry.name == listener.name);
                let listen = listener
                    .http3
                    .as_ref()
                    .filter(|cfg| cfg.enabled)
                    .map(|cfg| effective_http3_listen(cfg.listen.as_deref(), &listener.listen));
                if let Some(socket) =
                    inherited_udp_socket(maybe, &listener.name, "listener", listen)?
                {
                    listener_udp.insert(listener.name.clone(), socket);
                }
            }

            for reverse_edge in config.reverse_edge_configs() {
                let maybe = inherited
                    .reverse_edge
                    .iter()
                    .find(|entry| entry.name == reverse_edge.name);
                let listen = reverse_edge
                    .http3
                    .as_ref()
                    .filter(|cfg| cfg.enabled)
                    .map(|cfg| effective_http3_listen(cfg.listen.as_deref(), &reverse_edge.listen));
                if let Some(socket) =
                    inherited_udp_socket(maybe, &reverse_edge.name, "reverse_edge", listen)?
                {
                    reverse_udp.insert(reverse_edge.name.clone(), socket);
                }
            }

            Ok(Some(Self {
                listener_udp,
                reverse_udp,
            }))
        }

        #[cfg(not(feature = "http3"))]
        {
            let _ = (config, raw);
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
fn effective_http3_listen<'a>(configured: Option<&'a str>, fallback: &'a str) -> &'a str {
    configured.unwrap_or(fallback)
}

#[cfg(feature = "http3")]
fn inherited_udp_socket(
    inherited: Option<&InheritedUdpSocket>,
    name: &str,
    kind: &str,
    listen: Option<&str>,
) -> Result<Option<UdpSocket>> {
    let Some(listen) = listen else {
        if inherited.is_some() {
            return Err(anyhow!(
                "unexpected inherited udp {kind} binding for {name}"
            ));
        }
        return Ok(None);
    };
    let entry =
        inherited.ok_or_else(|| anyhow!("missing inherited udp {kind} binding for {name}"))?;
    if entry.listen != listen {
        return Err(anyhow!(
            "inherited udp {kind} binding for {name} does not match listen {listen}"
        ));
    }
    #[cfg(unix)]
    let socket = adopt_inherited_udp_socket(entry.fd)?;
    #[cfg(windows)]
    let socket = adopt_inherited_udp_socket_windows(entry.socket.as_slice())?;
    Ok(Some(socket))
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

#[cfg(all(test, feature = "http3"))]
mod listen_tests {
    use super::effective_http3_listen;

    #[test]
    fn configured_h3_listen_overrides_edge_listen() {
        assert_eq!(
            effective_http3_listen(Some("127.0.0.1:8443"), "0.0.0.0:443"),
            "127.0.0.1:8443"
        );
        assert_eq!(effective_http3_listen(None, "0.0.0.0:443"), "0.0.0.0:443");
    }
}

#[cfg(all(test, feature = "http3"))]
mod tests {
    use super::*;
    use qpx_core::config::{
        ActionConfig, ActionKind, EdgeConfig, Http3IngressEdgeConfig, IngressEdgeConfig,
        IngressEdgeMode,
    };

    fn config(names: &[&str]) -> Config {
        Config {
            state_dir: None,
            identity: Default::default(),
            messages: Default::default(),
            runtime: Default::default(),
            telemetry: qpx_core::config::TelemetryConfig {
                system_log: Default::default(),
                access_log: Default::default(),
                audit_log: Default::default(),
                metrics: None,
                otel: None,
                exporter: None,
            },
            security: qpx_core::config::SecurityConfig {
                auth: Default::default(),
                identity_sources: Vec::new(),
                decisions: qpx_core::config::DecisionConfig {
                    services: Vec::new(),
                },
                destination: Default::default(),
                named_sets: Vec::new(),
                upstream_trust_profiles: Vec::new(),
            },
            http: Default::default(),
            traffic: Default::default(),
            acme: None,
            edges: names
                .iter()
                .map(|name| {
                    EdgeConfig::Forward(IngressEdgeConfig {
                        name: (*name).to_string(),
                        mode: IngressEdgeMode::Forward,
                        listen: "127.0.0.1:0".to_string(),
                        default_action: ActionConfig {
                            kind: ActionKind::Direct,
                            upstream: None,
                            local_response: None,
                        },
                        original_dst: None,
                        tls_inspection: None,
                        rules: Vec::new(),
                        connection_filter: Vec::new(),
                        streaming: None,
                        grpc: None,
                        sse: None,
                        streaming_requirement: None,
                        upstream_proxy: None,
                        http3: Some(Http3IngressEdgeConfig {
                            enabled: true,
                            listen: Some("127.0.0.1:0".to_string()),
                            connect_udp: None,
                            connect_ip: None,
                        }),
                        ftp: Default::default(),
                        xdp: None,
                        cache: None,
                        capture: None,
                        rate_limit: None,
                        policy_context: None,
                        http: None,
                        http_guard_profile: None,
                        destination_resolution: None,
                        http_modules: Vec::new(),
                    })
                })
                .collect(),
            upstreams: Vec::new(),
            caches: Vec::new(),
        }
    }

    #[test]
    fn ephemeral_hot_reload_binds_distinct_udp_sockets() {
        let previous_config = config(&["a"]);
        let previous = UdpBindings::bind(&previous_config).expect("initial bind");
        let reloaded_config = config(&["a", "b"]);
        let reloaded =
            UdpBindings::bind_for_hot_reload(&reloaded_config, &previous_config, &previous)
                .expect("hot reload bind");
        let a = reloaded
            .clone_listener("a")
            .expect("clone a")
            .expect("a socket");
        let b = reloaded
            .clone_listener("b")
            .expect("clone b")
            .expect("b socket");
        assert_ne!(
            a.local_addr().expect("a addr"),
            b.local_addr().expect("b addr")
        );
    }
}
