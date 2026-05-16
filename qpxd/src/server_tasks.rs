use super::*;
#[cfg(feature = "http3")]
use crate::server_sets::spawn_brokered_h3_server_set;
#[cfg(not(feature = "http3"))]
use crate::server_sets::spawn_empty_sidecar_server_set;
use crate::server_sets::{
    ExportableSidecarServerSet, run_tcp_server_set, spawn_exportable_sidecar_server_set,
};
use qpx_observability::start_metrics;

pub(super) struct PreparedBinaryUpgradeSidecars {
    pub(super) udp_sessions: udp_session_handoff::UdpSessionRestoreState,
    #[cfg(feature = "http3")]
    pub(super) quic_brokers: Option<crate::http3::quinn_socket::QuinnBrokerPreparedHandoff>,
}

pub(super) struct ProxyTasks {
    pub(super) tcp_bindings: tcp_bindings::TcpBindings,
    pub(super) udp_bindings: udp_bindings::UdpBindings,
    pub(super) reverse_runtimes: std::collections::HashMap<String, reverse::ReloadableReverse>,
    pub(super) tcp_shutdown_tx: watch::Sender<bool>,
    pub(super) tcp_task: tokio::task::JoinHandle<Result<()>>,
    pub(super) exportable_sidecar_control_tx: watch::Sender<sidecar_control::SidecarControl>,
    pub(super) exportable_sidecar_export:
        std::sync::Arc<std::sync::Mutex<udp_session_handoff::UdpSessionRestoreState>>,
    pub(super) exportable_sidecar_task: Option<tokio::task::JoinHandle<Result<()>>>,
    pub(super) brokered_h3_control_tx: watch::Sender<sidecar_control::SidecarControl>,
    pub(super) brokered_h3_task: tokio::task::JoinHandle<Result<()>>,
    #[cfg(feature = "http3")]
    pub(super) quic_broker_handles: Vec<crate::http3::quinn_socket::LocalQuinnBrokerHandle>,
}

impl ProxyTasks {
    pub(super) fn start(
        config: &ProxyConfig,
        runtime: runtime::Runtime,
        tcp_bindings: tcp_bindings::TcpBindings,
        udp_bindings: udp_bindings::UdpBindings,
        sidecar_restore: Option<udp_session_handoff::UdpSessionRestoreState>,
        #[cfg(feature = "http3")] quic_broker_restore: Option<
            crate::http3::quinn_socket::QuinnBrokerRestoreSet,
        >,
    ) -> Result<Self> {
        let reverse_runtimes = config
            .reverse_edge_configs()
            .iter()
            .map(|reverse| {
                reverse::build_reloadable_reverse(reverse, &runtime)
                    .map(|compiled| (reverse.name.clone(), compiled))
            })
            .collect::<Result<std::collections::HashMap<_, _>>>()?;
        let listener_bindings = config
            .ingress_edge_configs()
            .iter()
            .map(|listener| {
                tcp_bindings
                    .clone_listener(listener.name.as_str())
                    .map(|bindings| (listener.name.clone(), bindings))
            })
            .collect::<Result<std::collections::HashMap<_, _>>>()?;
        let reverse_bindings = config
            .reverse_edge_configs()
            .iter()
            .filter(|reverse| reverse::requires_tcp_listener(reverse))
            .map(|reverse| {
                tcp_bindings
                    .clone_reverse(reverse.name.as_str())
                    .map(|bindings| (reverse.name.clone(), bindings))
            })
            .collect::<Result<std::collections::HashMap<_, _>>>()?;
        let exportable_listener_udp_bindings =
            exportable_listener_udp_bindings(config, &udp_bindings)?;
        let exportable_reverse_udp_bindings =
            exportable_reverse_udp_bindings(config, &udp_bindings)?;
        #[cfg(feature = "http3")]
        let mut quic_broker_restore = quic_broker_restore.unwrap_or_default();
        #[cfg(feature = "http3")]
        let mut quic_broker_handles = Vec::new();
        #[cfg(feature = "http3")]
        let brokered_forward_h3_sockets = brokered_forward_h3_sockets(
            config,
            &udp_bindings,
            &mut quic_broker_restore,
            &mut quic_broker_handles,
        )?;
        #[cfg(feature = "http3")]
        let brokered_reverse_h3_sockets = brokered_reverse_h3_sockets(
            config,
            &udp_bindings,
            &reverse_runtimes,
            &mut quic_broker_restore,
            &mut quic_broker_handles,
        )?;
        #[cfg(feature = "http3")]
        quic_broker_restore.ensure_consumed()?;

        let ingress_edge_configs = config.ingress_edges().cloned().collect();
        let reverse_edge_configs = config.reverse_edges().cloned().collect();
        let (tcp_shutdown_tx, tcp_shutdown_rx) = watch::channel(false);
        let tcp_runtime = runtime.clone();
        let tcp_reverse_runtimes = reverse_runtimes.clone();
        let tcp_task = tokio::spawn(async move {
            run_tcp_server_set(
                ingress_edge_configs,
                reverse_edge_configs,
                tcp_runtime,
                listener_bindings,
                reverse_bindings,
                tcp_reverse_runtimes,
                tcp_shutdown_rx,
            )
            .await
        });

        let (exportable_sidecar_control_tx, exportable_sidecar_control_rx) =
            watch::channel(sidecar_control::SidecarControl::Running);
        let exportable_sidecar_export = std::sync::Arc::new(std::sync::Mutex::new(
            udp_session_handoff::UdpSessionRestoreState::default(),
        ));
        let exportable_sidecar_task = Some(spawn_exportable_sidecar_server_set(
            ExportableSidecarServerSet {
                ingress_edge_configs: config.ingress_edges().cloned().collect(),
                reverse_edge_configs: config.reverse_edges().cloned().collect(),
                runtime: runtime.clone(),
                reverse_runtimes: reverse_runtimes.clone(),
                listener_udp_bindings: exportable_listener_udp_bindings,
                reverse_udp_bindings: exportable_reverse_udp_bindings,
                control: exportable_sidecar_control_rx,
                sidecar_restore,
                sidecar_export: exportable_sidecar_export.clone(),
            },
        ));

        let (brokered_h3_control_tx, brokered_h3_control_rx) =
            watch::channel(sidecar_control::SidecarControl::Running);
        #[cfg(feature = "http3")]
        let brokered_h3_task = spawn_brokered_h3_server_set(
            config.ingress_edges().cloned().collect(),
            config.reverse_edges().cloned().collect(),
            runtime,
            reverse_runtimes.clone(),
            brokered_forward_h3_sockets,
            brokered_reverse_h3_sockets,
            brokered_h3_control_rx,
        );
        #[cfg(not(feature = "http3"))]
        let brokered_h3_task = spawn_empty_sidecar_server_set(brokered_h3_control_rx);

        Ok(Self {
            tcp_bindings,
            udp_bindings,
            reverse_runtimes,
            tcp_shutdown_tx,
            tcp_task,
            exportable_sidecar_control_tx,
            exportable_sidecar_export,
            exportable_sidecar_task,
            brokered_h3_control_tx,
            brokered_h3_task,
            #[cfg(feature = "http3")]
            quic_broker_handles,
        })
    }

    pub(super) fn tcp_bindings(&self) -> &tcp_bindings::TcpBindings {
        &self.tcp_bindings
    }

    pub(super) fn udp_bindings(&self) -> &udp_bindings::UdpBindings {
        &self.udp_bindings
    }

    pub(super) async fn stop_all(self) -> Result<()> {
        let _ = self
            .exportable_sidecar_control_tx
            .send(sidecar_control::SidecarControl::Stop);
        let _ = self
            .brokered_h3_control_tx
            .send(sidecar_control::SidecarControl::Stop);
        let _ = self.tcp_shutdown_tx.send(true);
        if let Some(exportable_sidecar_task) = self.exportable_sidecar_task {
            match exportable_sidecar_task.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    return Err(err).context("exportable UDP sidecar set failed while stopping");
                }
                Err(err) => {
                    return Err(anyhow::anyhow!(
                        "exportable UDP sidecar join failed while stopping: {err}"
                    ));
                }
            }
        }
        match self.brokered_h3_task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                return Err(err).context("brokered HTTP/3 sidecar set failed while stopping");
            }
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "brokered HTTP/3 sidecar join failed while stopping: {err}"
                ));
            }
        }
        match self.tcp_task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err).context("tcp listener/reverse set failed while stopping"),
            Err(err) => Err(anyhow::anyhow!(
                "tcp listener/reverse join failed while stopping: {err}"
            )),
        }
    }

    pub(super) async fn prepare_binary_upgrade(
        &mut self,
        config: &ProxyConfig,
    ) -> Result<PreparedBinaryUpgradeSidecars> {
        let udp_sessions = self.export_exportable_sidecars().await?;
        #[cfg(not(feature = "http3"))]
        let _ = config;
        #[cfg(feature = "http3")]
        let quic_brokers = crate::http3::quinn_socket::prepare_quic_broker_handoff(
            self.quic_broker_handles.as_slice(),
            config,
        )?;
        Ok(PreparedBinaryUpgradeSidecars {
            udp_sessions,
            #[cfg(feature = "http3")]
            quic_brokers,
        })
    }

    pub(super) fn rollback_failed_upgrade(
        &mut self,
        config: &ProxyConfig,
        runtime: runtime::Runtime,
        sidecar_restore: udp_session_handoff::UdpSessionRestoreState,
    ) -> Result<()> {
        #[cfg(feature = "http3")]
        crate::http3::quinn_socket::detach_quic_broker_handoff(self.quic_broker_handles.as_slice());
        self.restart_exportable_sidecars(config, runtime, Some(sidecar_restore))
    }

    async fn export_exportable_sidecars(
        &mut self,
    ) -> Result<udp_session_handoff::UdpSessionRestoreState> {
        let Some(task) = self.exportable_sidecar_task.take() else {
            return Ok(udp_session_handoff::UdpSessionRestoreState::default());
        };
        let _ = self
            .exportable_sidecar_control_tx
            .send(sidecar_control::SidecarControl::ExportForUpgrade);
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                return Err(err).context("exportable UDP sidecar set failed while exporting");
            }
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "exportable UDP sidecar join failed while exporting: {err}"
                ));
            }
        }
        let exported = std::mem::take(
            &mut *self
                .exportable_sidecar_export
                .lock()
                .map_err(|_| anyhow::anyhow!("exportable sidecar export lock poisoned"))?,
        );
        self.reset_exportable_sidecar_control();
        Ok(exported)
    }

    fn restart_exportable_sidecars(
        &mut self,
        config: &ProxyConfig,
        runtime: runtime::Runtime,
        sidecar_restore: Option<udp_session_handoff::UdpSessionRestoreState>,
    ) -> Result<()> {
        if self.exportable_sidecar_task.is_some() {
            return Err(anyhow::anyhow!(
                "exportable UDP sidecars are already running"
            ));
        }
        let (control_tx, control_rx) = watch::channel(sidecar_control::SidecarControl::Running);
        self.exportable_sidecar_control_tx = control_tx;
        self.exportable_sidecar_export = std::sync::Arc::new(std::sync::Mutex::new(
            udp_session_handoff::UdpSessionRestoreState::default(),
        ));
        self.exportable_sidecar_task = Some(spawn_exportable_sidecar_server_set(
            ExportableSidecarServerSet {
                ingress_edge_configs: config.ingress_edges().cloned().collect(),
                reverse_edge_configs: config.reverse_edges().cloned().collect(),
                runtime,
                reverse_runtimes: self.reverse_runtimes.clone(),
                listener_udp_bindings: exportable_listener_udp_bindings(
                    config,
                    &self.udp_bindings,
                )?,
                reverse_udp_bindings: exportable_reverse_udp_bindings(config, &self.udp_bindings)?,
                control: control_rx,
                sidecar_restore,
                sidecar_export: self.exportable_sidecar_export.clone(),
            },
        ));
        Ok(())
    }

    fn reset_exportable_sidecar_control(&mut self) {
        let (control_tx, _control_rx) = watch::channel(sidecar_control::SidecarControl::Running);
        self.exportable_sidecar_control_tx = control_tx;
        self.exportable_sidecar_export = std::sync::Arc::new(std::sync::Mutex::new(
            udp_session_handoff::UdpSessionRestoreState::default(),
        ));
    }

    pub(super) async fn shutdown_tcp(self) -> Result<()> {
        let _ = self.tcp_shutdown_tx.send(true);
        match self.tcp_task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err).context("tcp listener/reverse set failed while draining"),
            Err(err) => Err(anyhow::anyhow!(
                "tcp listener/reverse join failed while draining: {err}"
            )),
        }
    }
}

pub(super) struct AdminTasks {
    metrics_task: Option<tokio::task::JoinHandle<()>>,
    http01_task: Option<tokio::task::JoinHandle<Result<()>>>,
    manager_task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl AdminTasks {
    pub(super) fn start(
        config: &ProxyConfig,
        runtime: runtime::Runtime,
        tcp_bindings: &tcp_bindings::TcpBindings,
    ) -> Result<Self> {
        let metrics_task = config
            .telemetry
            .metrics
            .as_ref()
            .map(|metrics| start_metrics(metrics, tcp_bindings.clone_metrics()?))
            .transpose()?;

        #[cfg(feature = "acme")]
        let (http01_task, manager_task) =
            if let Some(acme_state) = qpx_acme::init(config, std::sync::Arc::new(runtime))? {
                let http_listener = tcp_bindings.clone_acme_http01()?.ok_or_else(|| {
                    anyhow::anyhow!("acme http-01 binding missing while ACME is enabled")
                })?;
                let http_state = acme_state.clone();
                let http01_task = tokio::spawn(async move {
                    qpx_acme::run_http01_server_with_std_listener(http_listener, http_state).await
                });
                let manager_state = acme_state.clone();
                let manager_task =
                    tokio::spawn(async move { qpx_acme::run_manager(manager_state).await });
                (Some(http01_task), Some(manager_task))
            } else {
                (None, None)
            };

        #[cfg(not(feature = "acme"))]
        let (http01_task, manager_task) = {
            let _ = runtime;
            (None, None)
        };

        Ok(Self {
            metrics_task,
            http01_task,
            manager_task,
        })
    }

    pub(super) fn abort_all(&mut self) {
        if let Some(task) = self.metrics_task.take() {
            task.abort();
        }
        if let Some(task) = self.http01_task.take() {
            task.abort();
        }
        if let Some(task) = self.manager_task.take() {
            task.abort();
        }
    }
}

fn exportable_listener_udp_bindings(
    config: &ProxyConfig,
    udp_bindings: &udp_bindings::UdpBindings,
) -> Result<std::collections::HashMap<String, std::net::UdpSocket>> {
    #[cfg(feature = "http3")]
    {
        config
            .ingress_edge_configs()
            .iter()
            .filter(|listener| {
                matches!(
                    listener.mode,
                    qpx_core::config::IngressEdgeMode::Transparent
                ) && listener
                    .http3
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false)
            })
            .map(|listener| {
                udp_bindings
                    .clone_listener(listener.name.as_str())?
                    .ok_or_else(|| {
                        anyhow::anyhow!("udp listener binding missing for {}", listener.name)
                    })
                    .map(|socket| (listener.name.clone(), socket))
            })
            .collect::<Result<std::collections::HashMap<_, _>>>()
    }

    #[cfg(not(feature = "http3"))]
    {
        let _ = config;
        let _ = udp_bindings;
        Ok(std::collections::HashMap::new())
    }
}

fn exportable_reverse_udp_bindings(
    config: &ProxyConfig,
    udp_bindings: &udp_bindings::UdpBindings,
) -> Result<std::collections::HashMap<String, std::net::UdpSocket>> {
    #[cfg(feature = "http3")]
    {
        config
            .reverse_edge_configs()
            .iter()
            .filter(|reverse| {
                reverse
                    .http3
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false)
                    && !reverse::requires_tcp_listener(reverse)
            })
            .map(|reverse| {
                udp_bindings
                    .clone_reverse(reverse.name.as_str())?
                    .ok_or_else(|| {
                        anyhow::anyhow!("udp reverse binding missing for {}", reverse.name)
                    })
                    .map(|socket| (reverse.name.clone(), socket))
            })
            .collect::<Result<std::collections::HashMap<_, _>>>()
    }

    #[cfg(not(feature = "http3"))]
    {
        let _ = config;
        let _ = udp_bindings;
        Ok(std::collections::HashMap::new())
    }
}

#[cfg(feature = "http3")]
fn brokered_forward_h3_sockets(
    config: &ProxyConfig,
    udp_bindings: &udp_bindings::UdpBindings,
    quic_broker_restore: &mut crate::http3::quinn_socket::QuinnBrokerRestoreSet,
    quic_broker_handles: &mut Vec<crate::http3::quinn_socket::LocalQuinnBrokerHandle>,
) -> Result<std::collections::HashMap<String, crate::http3::quinn_socket::QuinnEndpointSocket>> {
    config
        .ingress_edge_configs()
        .iter()
        .filter(|listener| {
            matches!(listener.mode, qpx_core::config::IngressEdgeMode::Forward)
                && listener
                    .http3
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false)
        })
        .map(|listener| {
            let udp_socket = udp_bindings
                .clone_listener(listener.name.as_str())?
                .ok_or_else(|| {
                    anyhow::anyhow!("udp listener binding missing for {}", listener.name)
                })?;
            let prepared = crate::forward::h3::prepare_http3_listener_socket(
                listener.name.as_str(),
                udp_socket,
                quic_broker_restore.take_forward(listener.name.as_str()),
            )?;
            if let Some(handle) = prepared.local_broker_handle {
                quic_broker_handles.push(handle);
            }
            Ok((listener.name.clone(), prepared.endpoint_socket))
        })
        .collect::<Result<std::collections::HashMap<_, _>>>()
}

#[cfg(feature = "http3")]
fn brokered_reverse_h3_sockets(
    config: &ProxyConfig,
    udp_bindings: &udp_bindings::UdpBindings,
    reverse_runtimes: &std::collections::HashMap<String, reverse::ReloadableReverse>,
    quic_broker_restore: &mut crate::http3::quinn_socket::QuinnBrokerRestoreSet,
    quic_broker_handles: &mut Vec<crate::http3::quinn_socket::LocalQuinnBrokerHandle>,
) -> Result<std::collections::HashMap<String, crate::http3::quinn_socket::QuinnEndpointSocket>> {
    config
        .reverse_edge_configs()
        .iter()
        .filter(|reverse| {
            reverse
                .http3
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false)
                && reverse::requires_tcp_listener(reverse)
        })
        .map(|reverse| {
            let reverse_rt = reverse_runtimes
                .get(reverse.name.as_str())
                .cloned()
                .ok_or_else(|| {
                    anyhow::anyhow!("reloadable reverse missing for {}", reverse.name)
                })?;
            let udp_socket = udp_bindings
                .clone_reverse(reverse.name.as_str())?
                .ok_or_else(|| {
                    anyhow::anyhow!("udp reverse binding missing for {}", reverse.name)
                })?;
            let prepared = crate::reverse::h3_terminate::prepare_reverse_terminate_socket(
                reverse.name.as_str(),
                reverse_rt,
                udp_socket,
                quic_broker_restore.take_reverse(reverse.name.as_str()),
            )?;
            if let Some(handle) = prepared.local_broker_handle {
                quic_broker_handles.push(handle);
            }
            Ok((reverse.name.clone(), prepared.endpoint_socket))
        })
        .collect::<Result<std::collections::HashMap<_, _>>>()
}
