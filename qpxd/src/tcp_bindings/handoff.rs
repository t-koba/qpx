use super::*;

impl TcpBindings {
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
                forward_edges: Vec::new(),
                reverse_edge: Vec::new(),
                metrics: None,
                #[cfg(feature = "acme")]
                acme_http01: None,
            };

            for listener in config.ingress_edges() {
                let sockets = self
                    .listener_tcp
                    .get(&listener.name)
                    .ok_or_else(|| anyhow!("listener binding not found for {}", listener.name))?;
                inherited.forward_edges.push(InheritedTcpGroup {
                    name: listener.name.clone(),
                    listen: listener.listen.clone(),
                    fds: duplicate_listeners_for_handoff(sockets, &mut kept_fds)?,
                });
            }

            for reverse_edge in config.reverse_edge_configs() {
                if !reverse_requires_tcp(reverse_edge) {
                    continue;
                }
                let sockets = self.reverse_tcp.get(&reverse_edge.name).ok_or_else(|| {
                    anyhow!("reverse_edge binding not found for {}", reverse_edge.name)
                })?;
                inherited.reverse_edge.push(InheritedTcpGroup {
                    name: reverse_edge.name.clone(),
                    listen: reverse_edge.listen.clone(),
                    fds: duplicate_listeners_for_handoff(sockets, &mut kept_fds)?,
                });
            }

            if let Some(metrics) = config.telemetry.metrics.as_ref() {
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
            let forward_edges = config
                .ingress_edge_configs()
                .iter()
                .map(|listener| {
                    let sockets = self.listener_tcp.get(&listener.name).ok_or_else(|| {
                        anyhow!("listener binding not found for {}", listener.name)
                    })?;
                    Ok(WindowsTcpGroup {
                        name: listener.name.clone(),
                        listen: listener.listen.clone(),
                        forward_edges: sockets
                            .iter()
                            .map(|listener| {
                                listener.try_clone().context("failed to clone listener")
                            })
                            .collect::<Result<Vec<_>>>()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            let reverse_edge = config
                .reverse_edge_configs()
                .iter()
                .filter(|reverse_edge| reverse_requires_tcp(reverse_edge))
                .map(|reverse_edge| {
                    let sockets = self.reverse_tcp.get(&reverse_edge.name).ok_or_else(|| {
                        anyhow!("reverse_edge binding not found for {}", reverse_edge.name)
                    })?;
                    Ok(WindowsTcpGroup {
                        name: reverse_edge.name.clone(),
                        listen: reverse_edge.listen.clone(),
                        forward_edges: sockets
                            .iter()
                            .map(|listener| {
                                listener
                                    .try_clone()
                                    .context("failed to clone reverse_edge listener")
                            })
                            .collect::<Result<Vec<_>>>()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            let metrics = match config.telemetry.metrics.as_ref() {
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
                    forward_edges,
                    reverse_edge,
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
            forward_edges: handoff
                .pending
                .forward_edges
                .iter()
                .map(|group| {
                    Ok(InheritedTcpGroup {
                        name: group.name.clone(),
                        listen: group.listen.clone(),
                        sockets: group
                            .forward_edges
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
            reverse_edge: handoff
                .pending
                .reverse_edge
                .iter()
                .map(|group| {
                    Ok(InheritedTcpGroup {
                        name: group.name.clone(),
                        listen: group.listen.clone(),
                        sockets: group
                            .forward_edges
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
                    Ok::<InheritedSingleTcp, anyhow::Error>(InheritedSingleTcp {
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
                    Ok::<InheritedSingleTcp, anyhow::Error>(InheritedSingleTcp {
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

pub(super) fn adopt_tcp_group(group: &InheritedTcpGroup) -> Result<Vec<TcpListener>> {
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

#[cfg(unix)]
pub(super) fn adopt_tcp_listener(fd: i32) -> Result<TcpListener> {
    use std::os::fd::{AsRawFd, FromRawFd};

    // SAFETY: the inherited fd is transferred to this process by the parent handoff manifest.
    // `from_raw_fd` takes ownership exactly once when reconstructing the listener.
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    listener
        .set_nonblocking(true)
        .context("failed to set inherited listener nonblocking")?;
    set_cloexec(listener.as_raw_fd(), true)?;
    Ok(listener)
}

#[cfg(windows)]
pub(super) fn adopt_tcp_listener_windows(socket: &[u8]) -> Result<TcpListener> {
    crate::windows_handoff::adopt_tcp_listener(socket)
}

#[cfg(unix)]
fn duplicate_listeners_for_handoff(
    forward_edges: &[TcpListener],
    kept_fds: &mut Vec<std::os::fd::OwnedFd>,
) -> Result<Vec<i32>> {
    forward_edges
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

    // SAFETY: `listener.as_raw_fd()` is a valid listener fd. `dup` returns a new fd owned by this
    // function; `OwnedFd::from_raw_fd` assumes ownership of that duplicate exactly once.
    let fd = unsafe { libc::dup(listener.as_raw_fd()) };
    if fd < 0 {
        return Err(anyhow!(
            "failed to duplicate inherited listener fd: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `fd` was just returned by `dup` and is uniquely owned here.
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let raw = owned.as_raw_fd();
    kept_fds.push(owned);
    Ok(raw)
}

#[cfg(unix)]
fn set_cloexec(fd: i32, enabled: bool) -> Result<()> {
    // SAFETY: `fd` is an open file descriptor owned by a reconstructed or duplicated listener.
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
    // SAFETY: `fd` is valid and `next` is derived from existing fd flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, next) } < 0 {
        return Err(anyhow!(
            "failed to set fd flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config,
        IdentityConfig, IngressEdgeConfig, IngressEdgeMode, MessagesConfig, RuntimeConfig,
        SystemLogConfig,
    };

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
                upstream_proxy: None,
                http3: None,
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
    fn inherited_bindings_round_trip() {
        let _guard = crate::test_env_lock().lock().expect("env lock");
        let config = test_config();
        let bindings = TcpBindings::bind(&config).expect("bind");
        let handoff = bindings.prepare_handoff(&config).expect("handoff");
        let TcpBindingHandoff {
            env_value,
            kept_fds,
        } = handoff;
        assert_eq!(kept_fds.len(), 1);
        // SAFETY: test holds the global environment lock.
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
            let forward_edges = inherited.clone_listener("forward").expect("listener clone");
            assert_eq!(forward_edges.len(), 1);
        });
    }
}
