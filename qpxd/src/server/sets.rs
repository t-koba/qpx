use super::control::SidecarControl;
use crate::{forward, reverse, runtime, transparent, udp_session_handoff};
use anyhow::{Context, Result};
use tokio::sync::watch;
use tokio::task::JoinSet;

pub(super) struct ExportableSidecarServerSet {
    pub(super) ingress_edge_configs: Vec<qpx_core::config::IngressEdgeConfig>,
    pub(super) reverse_edge_configs: Vec<qpx_core::config::ReverseEdgeConfig>,
    pub(super) runtime: runtime::Runtime,
    pub(super) reverse_runtimes: std::collections::HashMap<String, reverse::ReloadableReverse>,
    pub(super) listener_udp_bindings: std::collections::HashMap<String, std::net::UdpSocket>,
    pub(super) reverse_udp_bindings: std::collections::HashMap<String, std::net::UdpSocket>,
    pub(super) control: watch::Receiver<SidecarControl>,
    pub(super) sidecar_restore: Option<udp_session_handoff::UdpSessionRestoreState>,
    pub(super) sidecar_export:
        std::sync::Arc<std::sync::Mutex<udp_session_handoff::UdpSessionRestoreState>>,
}

pub(super) fn spawn_exportable_sidecar_server_set(
    args: ExportableSidecarServerSet,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move { run_exportable_sidecar_server_set(args).await })
}

#[cfg(feature = "http3")]
pub(super) fn spawn_brokered_h3_server_set(
    ingress_edge_configs: Vec<qpx_core::config::IngressEdgeConfig>,
    reverse_edge_configs: Vec<qpx_core::config::ReverseEdgeConfig>,
    runtime: runtime::Runtime,
    reverse_runtimes: std::collections::HashMap<String, reverse::ReloadableReverse>,
    listener_h3_sockets: std::collections::HashMap<
        String,
        crate::http3::quinn_socket::QuinnEndpointSocket,
    >,
    reverse_h3_sockets: std::collections::HashMap<
        String,
        crate::http3::quinn_socket::QuinnEndpointSocket,
    >,
    control: watch::Receiver<SidecarControl>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        run_brokered_h3_server_set(
            ingress_edge_configs,
            reverse_edge_configs,
            runtime,
            reverse_runtimes,
            listener_h3_sockets,
            reverse_h3_sockets,
            control,
        )
        .await
    })
}

#[cfg(not(feature = "http3"))]
pub(super) fn spawn_empty_sidecar_server_set(
    mut control: watch::Receiver<SidecarControl>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            if control.changed().await.is_err() || control.borrow().should_stop() {
                return Ok(());
            }
        }
    })
}

pub(super) async fn run_tcp_server_set(
    ingress_edge_configs: Vec<qpx_core::config::IngressEdgeConfig>,
    reverse_edge_configs: Vec<qpx_core::config::ReverseEdgeConfig>,
    runtime: runtime::Runtime,
    mut listener_bindings: std::collections::HashMap<String, Vec<tokio::net::TcpListener>>,
    mut reverse_bindings: std::collections::HashMap<String, Vec<tokio::net::TcpListener>>,
    reverse_runtimes: std::collections::HashMap<String, reverse::ReloadableReverse>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut tasks: JoinSet<(String, Result<()>)> = JoinSet::new();

    for listener in ingress_edge_configs {
        let rt = runtime.clone();
        let name = listener.name.clone();
        let tcp_listeners = listener_bindings
            .remove(name.as_str())
            .ok_or_else(|| anyhow::anyhow!("listener binding missing for {}", name))?;
        let task_shutdown = shutdown.clone();
        tasks.spawn(async move {
            let res = match listener.mode {
                qpx_core::config::IngressEdgeMode::Forward => {
                    forward::run_tcp(listener, rt, task_shutdown, tcp_listeners).await
                }
                qpx_core::config::IngressEdgeMode::Transparent => {
                    transparent::run_tcp(listener, rt, task_shutdown, tcp_listeners).await
                }
            };
            (format!("listener {}", name), res)
        });
    }

    for reverse_cfg in reverse_edge_configs {
        if !reverse::requires_tcp_listener(&reverse_cfg) {
            continue;
        }
        let rt = reverse_runtimes
            .get(reverse_cfg.name.as_str())
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("reloadable reverse missing for {}", reverse_cfg.name)
            })?;
        let tcp_listeners = reverse_bindings
            .remove(reverse_cfg.name.as_str())
            .ok_or_else(|| anyhow::anyhow!("reverse binding missing for {}", reverse_cfg.name))?;
        let name = reverse_cfg.name.clone();
        let task_shutdown = shutdown.clone();
        tasks.spawn(async move {
            (
                format!("reverse {}", name),
                reverse::run_tcp(reverse_cfg, rt, task_shutdown, tcp_listeners).await,
            )
        });
    }

    if tasks.is_empty() {
        loop {
            if shutdown.changed().await.is_err() || *shutdown.borrow() {
                return Ok(());
            }
        }
    }

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            joined = tasks.join_next() => {
                match joined {
                    Some(Ok((label, Ok(())))) => {
                        tasks.abort_all();
                        return Err(anyhow::anyhow!("{label} exited"));
                    }
                    Some(Ok((label, Err(err)))) => {
                        tasks.abort_all();
                        return Err(err).with_context(|| format!("{label} failed"));
                    }
                    Some(Err(err)) => {
                        tasks.abort_all();
                        return Err(anyhow::anyhow!("task join failed: {err}"));
                    }
                    None => return Err(anyhow::anyhow!("no tcp listener/reverse tasks running")),
                }
            }
        }
    }

    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((_label, Ok(()))) => {}
            Ok((label, Err(err))) => return Err(err).with_context(|| format!("{label} failed")),
            Err(err) => return Err(anyhow::anyhow!("task join failed: {err}")),
        }
    }
    Ok(())
}

async fn run_exportable_sidecar_server_set(args: ExportableSidecarServerSet) -> Result<()> {
    let ExportableSidecarServerSet {
        ingress_edge_configs,
        reverse_edge_configs,
        runtime,
        reverse_runtimes,
        mut listener_udp_bindings,
        mut reverse_udp_bindings,
        mut control,
        sidecar_restore,
        sidecar_export,
    } = args;
    let mut tasks: JoinSet<(String, Result<()>)> = JoinSet::new();
    let mut restore = sidecar_restore.unwrap_or_default();

    for listener in ingress_edge_configs {
        if !matches!(
            listener.mode,
            qpx_core::config::IngressEdgeMode::Transparent
        ) || !listener
            .http3
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false)
        {
            continue;
        }
        let rt = runtime.clone();
        let name = listener.name.clone();
        let listen = listener
            .http3
            .as_ref()
            .and_then(|cfg| cfg.listen.clone())
            .unwrap_or_else(|| listener.listen.clone());
        let udp_socket = listener_udp_bindings
            .remove(name.as_str())
            .ok_or_else(|| anyhow::anyhow!("udp listener binding missing for {}", name))?;
        let task_control = control.clone();
        let transparent_restore = if matches!(
            listener.mode,
            qpx_core::config::IngressEdgeMode::Transparent
        ) {
            restore.take_transparent(name.as_str(), listen.as_str())?
        } else {
            None
        };
        let export_sink = sidecar_export.clone();
        tasks.spawn(async move {
            let res = {
                #[cfg(feature = "http3")]
                {
                    transparent::run_udp(
                        listener,
                        rt,
                        task_control,
                        udp_socket,
                        transparent_restore,
                        export_sink,
                    )
                    .await
                }
                #[cfg(not(feature = "http3"))]
                {
                    let _ = rt;
                    let _ = task_control;
                    let _ = transparent_restore;
                    let _ = export_sink;
                    let _ = udp_socket;
                    let _ = listener;
                    Err(anyhow::anyhow!(
                        "transparent UDP sidecar requires http3 feature"
                    ))
                }
            };
            (format!("transparent-sidecar {}", name), res)
        });
    }

    for reverse_cfg in reverse_edge_configs {
        if !reverse_cfg
            .http3
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false)
            || reverse::requires_tcp_listener(&reverse_cfg)
        {
            continue;
        }
        let reverse_rt = reverse_runtimes
            .get(reverse_cfg.name.as_str())
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("reloadable reverse missing for {}", reverse_cfg.name)
            })?;
        let name = reverse_cfg.name.clone();
        let h3_cfg = reverse_cfg.http3.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "reverse {} enables http3 sidecar without http3 config",
                reverse_cfg.name
            )
        })?;
        let listen = reverse_cfg
            .http3
            .as_ref()
            .and_then(|cfg| cfg.listen.clone())
            .unwrap_or_else(|| reverse_cfg.listen.clone());
        let listen_addr: std::net::SocketAddr = listen.parse()?;
        let resolve_timeout = std::time::Duration::from_millis(
            runtime
                .state()
                .plan
                .limits
                .timeouts
                .upstream_http_timeout_ms,
        );
        let udp_socket = reverse_udp_bindings
            .remove(reverse_cfg.name.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!("udp reverse binding missing for {}", reverse_cfg.name)
            })?;
        let task_control = control.clone();
        let passthrough_restore = if !reverse::requires_tcp_listener(&reverse_cfg) {
            restore.take_reverse_passthrough(name.as_str(), listen.as_str())?
        } else {
            None
        };
        let export_sink = sidecar_export.clone();
        tasks.spawn(async move {
            let res = {
                #[cfg(feature = "http3")]
                {
                    let passthrough_targets = h3_cfg.passthrough_upstreams.clone();
                    reverse::h3::passthrough::run_http3_passthrough(
                        listen_addr,
                        passthrough_targets,
                        &h3_cfg,
                        reverse::h3::passthrough::Http3PassthroughRuntime {
                            reverse: reverse_rt,
                            upstream_resolve_timeout: resolve_timeout,
                            shutdown: task_control,
                            listener_socket: udp_socket,
                            restore: passthrough_restore,
                            export_sink,
                        },
                    )
                    .await
                }
                #[cfg(not(feature = "http3"))]
                {
                    let _ = h3_cfg;
                    let _ = listen_addr;
                    let _ = resolve_timeout;
                    let _ = passthrough_restore;
                    let _ = export_sink;
                    let _ = reverse_rt;
                    let _ = task_control;
                    let _ = udp_socket;
                    Err(anyhow::anyhow!(
                        "reverse HTTP/3 sidecar requires http3 feature"
                    ))
                }
            };
            (format!("reverse-passthrough-sidecar {}", name), res)
        });
    }

    restore.ensure_consumed()?;

    if tasks.is_empty() {
        loop {
            if control.changed().await.is_err() || control.borrow().should_stop() {
                return Ok(());
            }
        }
    }

    let mut stop_mode = SidecarControl::Running;
    loop {
        tokio::select! {
            changed = control.changed(), if !stop_mode.should_stop() => {
                if changed.is_err() {
                    stop_mode = SidecarControl::Stop;
                } else {
                    stop_mode = *control.borrow();
                }
                if tasks.is_empty() {
                    return Ok(());
                }
            }
            joined = tasks.join_next() => {
                match joined {
                    Some(Ok((label, Ok(())))) => {
                        if stop_mode.should_stop() {
                            if tasks.is_empty() {
                                return Ok(());
                            }
                        } else {
                            return Err(anyhow::anyhow!("{label} exited"));
                        }
                    }
                    Some(Ok((label, Err(err)))) => {
                        return Err(err).with_context(|| format!("{label} failed"));
                    }
                    Some(Err(err)) => {
                        return Err(anyhow::anyhow!("task join failed: {err}"));
                    }
                    None => {
                        if stop_mode.should_stop() {
                            return Ok(());
                        }
                        return Err(anyhow::anyhow!("no udp/http3 sidecar tasks running"));
                    }
                }
            }
        }
    }
}

#[cfg(feature = "http3")]
async fn run_brokered_h3_server_set(
    ingress_edge_configs: Vec<qpx_core::config::IngressEdgeConfig>,
    reverse_edge_configs: Vec<qpx_core::config::ReverseEdgeConfig>,
    runtime: runtime::Runtime,
    reverse_runtimes: std::collections::HashMap<String, reverse::ReloadableReverse>,
    mut listener_h3_sockets: std::collections::HashMap<
        String,
        crate::http3::quinn_socket::QuinnEndpointSocket,
    >,
    mut reverse_h3_sockets: std::collections::HashMap<
        String,
        crate::http3::quinn_socket::QuinnEndpointSocket,
    >,
    mut control: watch::Receiver<SidecarControl>,
) -> Result<()> {
    let mut tasks: JoinSet<(String, Result<()>)> = JoinSet::new();

    for listener in ingress_edge_configs {
        if !matches!(listener.mode, qpx_core::config::IngressEdgeMode::Forward)
            || !listener
                .http3
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false)
        {
            continue;
        }
        let rt = runtime.clone();
        let name = listener.name.clone();
        let endpoint_socket = listener_h3_sockets
            .remove(name.as_str())
            .ok_or_else(|| anyhow::anyhow!("forward HTTP/3 endpoint missing for {}", name))?;
        let task_control = control.clone();
        tasks.spawn(async move {
            (
                format!("forward-h3-sidecar {}", name),
                forward::run_h3(listener, rt, task_control, endpoint_socket).await,
            )
        });
    }

    for reverse_cfg in reverse_edge_configs {
        if !reverse_cfg
            .http3
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false)
            || !reverse::requires_tcp_listener(&reverse_cfg)
        {
            continue;
        }
        let reverse_rt = reverse_runtimes
            .get(reverse_cfg.name.as_str())
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("reloadable reverse missing for {}", reverse_cfg.name)
            })?;
        let name = reverse_cfg.name.clone();
        let listen_addr: std::net::SocketAddr = reverse_cfg
            .http3
            .as_ref()
            .and_then(|cfg| cfg.listen.clone())
            .unwrap_or_else(|| reverse_cfg.listen.clone())
            .parse()?;
        let endpoint_socket = reverse_h3_sockets
            .remove(name.as_str())
            .ok_or_else(|| anyhow::anyhow!("reverse HTTP/3 endpoint missing for {}", name))?;
        let task_control = control.clone();
        tasks.spawn(async move {
            (
                format!("reverse-terminate-h3-sidecar {}", name),
                reverse::h3::terminate::run_http3_terminate(
                    reverse_cfg,
                    listen_addr,
                    reverse_rt,
                    task_control,
                    endpoint_socket,
                )
                .await,
            )
        });
    }

    if tasks.is_empty() {
        loop {
            if control.changed().await.is_err() || control.borrow().should_stop() {
                return Ok(());
            }
        }
    }

    loop {
        tokio::select! {
            changed = control.changed() => {
                if changed.is_err() || control.borrow().should_stop() {
                    break;
                }
            }
            joined = tasks.join_next() => {
                match joined {
                    Some(Ok((label, Ok(())))) => {
                        tasks.abort_all();
                        return Err(anyhow::anyhow!("{label} exited"));
                    }
                    Some(Ok((label, Err(err)))) => {
                        tasks.abort_all();
                        return Err(err).with_context(|| format!("{label} failed"));
                    }
                    Some(Err(err)) => {
                        tasks.abort_all();
                        return Err(anyhow::anyhow!("task join failed: {err}"));
                    }
                    None => return Err(anyhow::anyhow!("no brokered HTTP/3 sidecar tasks running")),
                }
            }
        }
    }

    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((_label, Ok(()))) => {}
            Ok((label, Err(err))) => return Err(err).with_context(|| format!("{label} failed")),
            Err(err) => return Err(anyhow::anyhow!("task join failed: {err}")),
        }
    }
    Ok(())
}

pub(crate) async fn wait_for_connection_drain(runtime: &runtime::Runtime) {
    let semaphore = runtime.state().resources.connection_semaphore.clone();
    let target = runtime
        .state()
        .plan
        .limits
        .general
        .max_concurrent_connections;
    while semaphore.available_permits() < target {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
