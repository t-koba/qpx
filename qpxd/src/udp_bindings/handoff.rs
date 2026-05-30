#[cfg(feature = "http3")]
use super::InheritedUdpSocket;
use super::{ENV_INHERITED_UDP_BINDINGS, InheritedUdpBindings, UdpBindingHandoff, UdpBindings};
#[cfg(all(feature = "http3", windows))]
use super::{WindowsInheritedUdpSocket, WindowsUdpBindingHandoff};
#[cfg(all(feature = "http3", windows))]
use crate::udp_socket_handoff::duplicate_std_udp_socket_for_child;
#[cfg(all(feature = "http3", unix))]
use crate::udp_socket_handoff::duplicate_std_udp_socket_for_handoff;
#[cfg(any(unix, all(windows, feature = "http3")))]
use anyhow::Context;
use anyhow::Result;
#[cfg(any(feature = "http3", not(any(unix, windows))))]
use anyhow::anyhow;
use qpx_core::config::Config;

impl UdpBindings {
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

                for listener in config.ingress_edges() {
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
                    inherited.forward_edges.push(InheritedUdpSocket {
                        name: listener.name.clone(),
                        listen,
                        fd: duplicate_std_udp_socket_for_handoff(socket, &mut kept_fds)?,
                    });
                }

                for reverse_edge in config.reverse_edge_configs() {
                    if !reverse_edge
                        .http3
                        .as_ref()
                        .map(|cfg| cfg.enabled)
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    let listen = reverse_edge
                        .http3
                        .as_ref()
                        .and_then(|cfg| cfg.listen.clone())
                        .unwrap_or_else(|| reverse_edge.listen.clone());
                    let socket = self.reverse_udp.get(&reverse_edge.name).ok_or_else(|| {
                        anyhow!(
                            "udp reverse_edge binding not found for {}",
                            reverse_edge.name
                        )
                    })?;
                    inherited.reverse_edge.push(InheritedUdpSocket {
                        name: reverse_edge.name.clone(),
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
                let forward_edges = config
                    .ingress_edge_configs()
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

                let reverse_edge = config
                    .reverse_edge_configs()
                    .iter()
                    .filter(|reverse_edge| {
                        reverse_edge
                            .http3
                            .as_ref()
                            .map(|cfg| cfg.enabled)
                            .unwrap_or(false)
                    })
                    .map(|reverse_edge| {
                        let listen = reverse_edge
                            .http3
                            .as_ref()
                            .and_then(|cfg| cfg.listen.clone())
                            .unwrap_or_else(|| reverse_edge.listen.clone());
                        let socket = self
                            .reverse_udp
                            .get(&reverse_edge.name)
                            .ok_or_else(|| {
                                anyhow!(
                                    "udp reverse_edge binding not found for {}",
                                    reverse_edge.name
                                )
                            })?
                            .try_clone()
                            .with_context(|| {
                                format!(
                                    "failed to clone udp reverse_edge binding for {}",
                                    reverse_edge.name
                                )
                            })?;
                        Ok(WindowsInheritedUdpSocket {
                            name: reverse_edge.name.clone(),
                            listen,
                            socket,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;

                Ok(UdpBindingHandoff {
                    env_value: path.display().to_string(),
                    pending: WindowsUdpBindingHandoff {
                        forward_edges,
                        reverse_edge,
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
        #[cfg(feature = "http3")]
        let inherited = {
            InheritedUdpBindings {
                forward_edges: handoff
                    .pending
                    .forward_edges
                    .iter()
                    .map(|entry| {
                        Ok(InheritedUdpSocket {
                            name: entry.name.clone(),
                            listen: entry.listen.clone(),
                            socket: duplicate_std_udp_socket_for_child(&entry.socket, child_pid)?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
                reverse_edge: handoff
                    .pending
                    .reverse_edge
                    .iter()
                    .map(|entry| {
                        Ok(InheritedUdpSocket {
                            name: entry.name.clone(),
                            listen: entry.listen.clone(),
                            socket: duplicate_std_udp_socket_for_child(&entry.socket, child_pid)?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            }
        };
        #[cfg(not(feature = "http3"))]
        let inherited = {
            let _ = child_pid;
            InheritedUdpBindings::default()
        };
        crate::windows_handoff::write_json_file(handoff.cleanup_path.as_path(), &inherited)
    }

    #[cfg(windows)]
    pub(crate) fn cleanup_handoff_file(handoff: &UdpBindingHandoff) {
        let _ = std::fs::remove_file(&handoff.cleanup_path);
    }
}

#[cfg(all(test, feature = "http3", unix))]
mod tests {
    use crate::udp_bindings::handoff::*;
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config,
        Http3IngressEdgeConfig, IdentityConfig, IngressEdgeConfig, IngressEdgeMode, MessagesConfig,
        RuntimeConfig, SystemLogConfig,
    };

    fn test_config() -> Config {
        Config {
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig {
                reuse_port: false,
                ..RuntimeConfig::default()
            },
            telemetry: qpx_core::config::TelemetryConfig {
                system_log: SystemLogConfig::default(),
                access_log: AccessLogConfig::default(),
                audit_log: AuditLogConfig::default(),
                metrics: None,
                otel: None,
                exporter: None,
            },
            security: qpx_core::config::SecurityConfig {
                auth: AuthConfig::default(),
                identity_sources: Vec::new(),
                decisions: qpx_core::config::DecisionConfig {
                    ext_authz: Vec::new(),
                },
                destination: Default::default(),
                named_sets: Vec::new(),
                upstream_trust_profiles: Vec::new(),
            },
            http: qpx_core::config::HttpGlobalConfig::default(),
            traffic: qpx_core::config::TrafficConfig::default(),
            acme: None,
            edges: vec![qpx_core::config::EdgeConfig::Forward(IngressEdgeConfig {
                name: "forward".to_string(),
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
            })],
            upstreams: Vec::new(),
            caches: Vec::new(),
        }
    }

    #[test]
    fn inherited_udp_bindings_round_trip() {
        let _guard = crate::test_env_lock().lock().expect("env lock");
        let config = test_config();
        let bindings = UdpBindings::bind(&config).expect("bind");
        let handoff = bindings.prepare_handoff(&config).expect("handoff");
        let UdpBindingHandoff {
            env_value,
            kept_fds,
        } = handoff;
        assert_eq!(kept_fds.len(), 1);
        // SAFETY: test holds the global environment lock.
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
