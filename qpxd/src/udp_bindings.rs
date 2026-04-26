#[cfg(feature = "http3")]
use anyhow::anyhow;
use anyhow::{Context, Result};
use qpx_core::config::Config;
#[cfg(feature = "http3")]
use qpx_core::config::ListenerMode;
use serde::{Deserialize, Serialize};
#[cfg(feature = "http3")]
use std::collections::HashMap;
#[cfg(feature = "http3")]
use std::net::{SocketAddr, UdpSocket};
#[cfg(windows)]
use std::path::PathBuf;

#[cfg(all(feature = "http3", unix))]
use crate::udp_socket_handoff::{adopt_inherited_udp_socket, duplicate_std_udp_socket_for_handoff};
#[cfg(windows)]
use crate::udp_socket_handoff::{
    adopt_inherited_udp_socket_windows, duplicate_std_udp_socket_for_child,
};

const ENV_INHERITED_UDP_BINDINGS: &str = "QPX_INHERITED_UDP_BINDINGS";

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
    #[cfg(windows)]
    pending: WindowsUdpBindingHandoff,
    #[cfg(windows)]
    cleanup_path: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct InheritedUdpBindings {
    listeners: Vec<InheritedUdpSocket>,
    reverses: Vec<InheritedUdpSocket>,
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
    listeners: Vec<WindowsInheritedUdpSocket>,
    reverses: Vec<WindowsInheritedUdpSocket>,
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

            for listener in &config.listeners {
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
                    ListenerMode::Forward => {
                        crate::net::bind_udp_std_socket(addr, &config.runtime)?
                    }
                    ListenerMode::Transparent => {
                        crate::transparent::udp_socket::bind_udp_std_listener(
                            addr,
                            &config.runtime,
                        )?
                    }
                };
                listener_udp.insert(listener.name.clone(), socket);
            }

            for reverse in &config.reverse {
                let Some(http3) = reverse.http3.as_ref().filter(|cfg| cfg.enabled) else {
                    continue;
                };
                let listen = http3
                    .listen
                    .clone()
                    .unwrap_or_else(|| reverse.listen.clone());
                let addr: SocketAddr = listen
                    .parse()
                    .with_context(|| format!("reverse {} http3.listen is invalid", reverse.name))?;
                let socket = crate::net::bind_udp_std_socket(addr, &config.runtime)?;
                reverse_udp.insert(reverse.name.clone(), socket);
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

            for listener in &config.listeners {
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

            for reverse in &config.reverse {
                let Some(http3) = reverse.http3.as_ref().filter(|cfg| cfg.enabled) else {
                    continue;
                };
                let listen = http3
                    .listen
                    .clone()
                    .unwrap_or_else(|| reverse.listen.clone());
                let socket = previous
                    .udp_socket_for_listen(previous_config, listen.as_str())
                    .map(|socket| {
                        socket.with_context(|| {
                            format!("failed to clone udp reverse binding for {}", reverse.name)
                        })
                    })
                    .unwrap_or_else(|| bind_udp_for_reverse(reverse, config, listen.as_str()))?;
                reverse_udp.insert(reverse.name.clone(), socket);
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
        for listener in &config.listeners {
            let old_listen = listener
                .http3
                .as_ref()
                .filter(|cfg| cfg.enabled)
                .map(|cfg| {
                    cfg.listen
                        .clone()
                        .unwrap_or_else(|| listener.listen.clone())
                });
            if old_listen.as_deref() == Some(listen) {
                if let Some(socket) = self.listener_udp.get(&listener.name) {
                    return Some(socket.try_clone().context("failed to clone udp listener"));
                }
            }
        }
        for reverse in &config.reverse {
            let old_listen = reverse
                .http3
                .as_ref()
                .filter(|cfg| cfg.enabled)
                .map(|cfg| cfg.listen.clone().unwrap_or_else(|| reverse.listen.clone()));
            if old_listen.as_deref() == Some(listen) {
                if let Some(socket) = self.reverse_udp.get(&reverse.name) {
                    return Some(socket.try_clone().context("failed to clone udp reverse"));
                }
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

            for listener in &config.listeners {
                let maybe = inherited
                    .listeners
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

            for reverse in &config.reverse {
                let maybe = inherited
                    .reverses
                    .iter()
                    .find(|entry| entry.name == reverse.name);
                let expect_socket = reverse
                    .http3
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false);
                if expect_socket {
                    let listen = reverse
                        .http3
                        .as_ref()
                        .and_then(|cfg| cfg.listen.clone())
                        .unwrap_or_else(|| reverse.listen.clone());
                    let entry = maybe.ok_or_else(|| {
                        anyhow!("missing inherited udp reverse binding for {}", reverse.name)
                    })?;
                    if entry.listen != listen {
                        return Err(anyhow!(
                            "inherited udp reverse binding for {} does not match listen {}",
                            reverse.name,
                            listen
                        ));
                    }
                    reverse_udp.insert(
                        reverse.name.clone(),
                        #[cfg(unix)]
                        adopt_inherited_udp_socket(entry.fd)?,
                        #[cfg(windows)]
                        adopt_inherited_udp_socket_windows(entry.socket.as_slice())?,
                    );
                } else if maybe.is_some() {
                    return Err(anyhow!(
                        "unexpected inherited udp reverse binding for {}",
                        reverse.name
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
                    .with_context(|| format!("failed to clone udp reverse binding for {name}"))
            })
            .transpose()
    }

    pub(crate) fn prepare_handoff(&self, config: &Config) -> Result<UdpBindingHandoff> {
        #[cfg(not(any(unix, windows)))]
        {
            let _ = self;
            let _ = config;
            return Err(anyhow!(
                "binary upgrade handoff is only supported on unix and windows"
            ));
        }

        #[cfg(unix)]
        {
            #[cfg(feature = "http3")]
            {
                let mut kept_fds = Vec::new();
                let mut inherited = InheritedUdpBindings::default();

                for listener in &config.listeners {
                    if !listener
                        .http3
                        .as_ref()
                        .map(|cfg| cfg.enabled)
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    let listen = listener
                        .http3
                        .as_ref()
                        .and_then(|cfg| cfg.listen.clone())
                        .unwrap_or_else(|| listener.listen.clone());
                    let socket = self.listener_udp.get(&listener.name).ok_or_else(|| {
                        anyhow!("udp listener binding not found for {}", listener.name)
                    })?;
                    inherited.listeners.push(InheritedUdpSocket {
                        name: listener.name.clone(),
                        listen,
                        fd: duplicate_std_udp_socket_for_handoff(socket, &mut kept_fds)?,
                    });
                }

                for reverse in &config.reverse {
                    if !reverse
                        .http3
                        .as_ref()
                        .map(|cfg| cfg.enabled)
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    let listen = reverse
                        .http3
                        .as_ref()
                        .and_then(|cfg| cfg.listen.clone())
                        .unwrap_or_else(|| reverse.listen.clone());
                    let socket = self.reverse_udp.get(&reverse.name).ok_or_else(|| {
                        anyhow!("udp reverse binding not found for {}", reverse.name)
                    })?;
                    inherited.reverses.push(InheritedUdpSocket {
                        name: reverse.name.clone(),
                        listen,
                        fd: duplicate_std_udp_socket_for_handoff(socket, &mut kept_fds)?,
                    });
                }

                Ok(UdpBindingHandoff {
                    env_value: serde_json::to_string(&inherited)
                        .context("failed to serialize inherited udp bindings")?,
                    kept_fds,
                })
            }

            #[cfg(not(feature = "http3"))]
            {
                let _ = self;
                let _ = config;
                Ok(UdpBindingHandoff {
                    env_value: serde_json::to_string(&InheritedUdpBindings::default())
                        .context("failed to serialize inherited udp bindings")?,
                    kept_fds: Vec::new(),
                })
            }
        }

        #[cfg(windows)]
        {
            #[cfg(feature = "http3")]
            {
                let path = crate::windows_handoff::create_handoff_path(config, "udp-bindings")?;
                let listeners = config
                    .listeners
                    .iter()
                    .filter(|listener| {
                        listener
                            .http3
                            .as_ref()
                            .map(|cfg| cfg.enabled)
                            .unwrap_or(false)
                    })
                    .map(|listener| {
                        let listen = listener
                            .http3
                            .as_ref()
                            .and_then(|cfg| cfg.listen.clone())
                            .unwrap_or_else(|| listener.listen.clone());
                        let socket = self
                            .listener_udp
                            .get(&listener.name)
                            .ok_or_else(|| {
                                anyhow!("udp listener binding not found for {}", listener.name)
                            })?
                            .try_clone()
                            .with_context(|| {
                                format!(
                                    "failed to clone udp listener binding for {}",
                                    listener.name
                                )
                            })?;
                        Ok(WindowsInheritedUdpSocket {
                            name: listener.name.clone(),
                            listen,
                            socket,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;

                let reverses = config
                    .reverse
                    .iter()
                    .filter(|reverse| {
                        reverse
                            .http3
                            .as_ref()
                            .map(|cfg| cfg.enabled)
                            .unwrap_or(false)
                    })
                    .map(|reverse| {
                        let listen = reverse
                            .http3
                            .as_ref()
                            .and_then(|cfg| cfg.listen.clone())
                            .unwrap_or_else(|| reverse.listen.clone());
                        let socket = self
                            .reverse_udp
                            .get(&reverse.name)
                            .ok_or_else(|| {
                                anyhow!("udp reverse binding not found for {}", reverse.name)
                            })?
                            .try_clone()
                            .with_context(|| {
                                format!("failed to clone udp reverse binding for {}", reverse.name)
                            })?;
                        Ok(WindowsInheritedUdpSocket {
                            name: reverse.name.clone(),
                            listen,
                            socket,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;

                Ok(UdpBindingHandoff {
                    env_value: path.display().to_string(),
                    pending: WindowsUdpBindingHandoff {
                        listeners,
                        reverses,
                    },
                    cleanup_path: path,
                })
            }

            #[cfg(not(feature = "http3"))]
            {
                let _ = self;
                let path = crate::windows_handoff::create_handoff_path(config, "udp-bindings")?;
                crate::windows_handoff::write_json_file(
                    path.as_path(),
                    &InheritedUdpBindings::default(),
                )?;
                Ok(UdpBindingHandoff {
                    env_value: path.display().to_string(),
                    pending: WindowsUdpBindingHandoff {
                        listeners: Vec::new(),
                        reverses: Vec::new(),
                    },
                    cleanup_path: path,
                })
            }
        }
    }

    pub(crate) fn handoff_env_key() -> &'static str {
        ENV_INHERITED_UDP_BINDINGS
    }

    #[cfg(windows)]
    pub(crate) fn finalize_handoff_for_child(
        handoff: &UdpBindingHandoff,
        child_pid: u32,
    ) -> Result<()> {
        let inherited = InheritedUdpBindings {
            listeners: handoff
                .pending
                .listeners
                .iter()
                .map(|entry| {
                    Ok(InheritedUdpSocket {
                        name: entry.name.clone(),
                        listen: entry.listen.clone(),
                        socket: duplicate_std_udp_socket_for_child(&entry.socket, child_pid)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            reverses: handoff
                .pending
                .reverses
                .iter()
                .map(|entry| {
                    Ok(InheritedUdpSocket {
                        name: entry.name.clone(),
                        listen: entry.listen.clone(),
                        socket: duplicate_std_udp_socket_for_child(&entry.socket, child_pid)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        };
        crate::windows_handoff::write_json_file(handoff.cleanup_path.as_path(), &inherited)
    }

    #[cfg(windows)]
    pub(crate) fn cleanup_handoff_file(handoff: &UdpBindingHandoff) {
        let _ = std::fs::remove_file(&handoff.cleanup_path);
    }
}

#[cfg(feature = "http3")]
fn bind_udp_for_listener(
    listener: &qpx_core::config::ListenerConfig,
    config: &Config,
    listen: &str,
) -> Result<UdpSocket> {
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("listener {} http3.listen is invalid", listener.name))?;
    match listener.mode {
        ListenerMode::Forward => crate::net::bind_udp_std_socket(addr, &config.runtime),
        ListenerMode::Transparent => {
            crate::transparent::udp_socket::bind_udp_std_listener(addr, &config.runtime)
        }
    }
}

#[cfg(feature = "http3")]
fn bind_udp_for_reverse(
    reverse: &qpx_core::config::ReverseConfig,
    config: &Config,
    listen: &str,
) -> Result<UdpSocket> {
    let addr = listen
        .parse()
        .with_context(|| format!("reverse {} http3.listen is invalid", reverse.name))?;
    crate::net::bind_udp_std_socket(addr, &config.runtime)
}

#[cfg(all(test, feature = "http3"))]
mod tests {
    use super::*;
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CacheConfig, Config,
        Http3ListenerConfig, IdentityConfig, ListenerConfig, ListenerMode, MessagesConfig,
        RuntimeConfig, SystemLogConfig,
    };
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn test_config() -> Config {
        Config {
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig {
                reuse_port: false,
                ..RuntimeConfig::default()
            },
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
                http3: Some(Http3ListenerConfig {
                    enabled: true,
                    listen: Some("127.0.0.1:0".to_string()),
                    connect_udp: None,
                }),
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
    fn inherited_udp_bindings_round_trip() {
        let _guard = env_lock().lock().expect("env lock");
        let config = test_config();
        let bindings = UdpBindings::bind(&config).expect("bind");
        let handoff = bindings.prepare_handoff(&config).expect("handoff");
        let UdpBindingHandoff {
            env_value,
            kept_fds,
        } = handoff;
        assert_eq!(kept_fds.len(), 1);
        unsafe {
            std::env::set_var(UdpBindings::handoff_env_key(), env_value);
        }
        std::mem::forget(kept_fds);

        let inherited = UdpBindings::from_env(&config)
            .expect("from env")
            .expect("bindings");
        let socket = inherited
            .clone_listener("forward")
            .expect("clone")
            .expect("socket");
        assert!(socket.local_addr().expect("local addr").port() > 0);
    }
}
