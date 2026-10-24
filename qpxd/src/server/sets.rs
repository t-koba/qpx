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
        wait_for_empty_server_set_stop(&mut control, |mode| mode.should_stop()).await;
        Ok(())
    })
}

pub(super) async fn run_tcp_server_set(
    ingress_edge_configs: Vec<qpx_core::config::IngressEdgeConfig>,
    reverse_edge_configs: Vec<qpx_core::config::ReverseEdgeConfig>,
    runtime: runtime::Runtime,
    mut listener_bindings: std::collections::HashMap<String, Vec<tokio::net::TcpListener>>,
    mut reverse_bindings: std::collections::HashMap<String, Vec<tokio::net::TcpListener>>,
    reverse_runtimes: std::collections::HashMap<String, reverse::ReloadableReverse>,
    shutdown: watch::Receiver<bool>,
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

    await_server_tasks(
        tasks,
        shutdown,
        |stop| *stop,
        "no tcp listener/reverse tasks running",
    )
    .await
}

async fn run_exportable_sidecar_server_set(args: ExportableSidecarServerSet) -> Result<()> {
    let ExportableSidecarServerSet {
        ingress_edge_configs,
        reverse_edge_configs,
        runtime,
        reverse_runtimes,
        mut listener_udp_bindings,
        mut reverse_udp_bindings,
        control,
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
        let transparent_restore = restore.take_transparent(name.as_str(), listen.as_str())?;
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
        let passthrough_restore =
            restore.take_reverse_passthrough(name.as_str(), listen.as_str())?;
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
    await_exportable_sidecar_tasks(tasks, control).await
}

async fn await_exportable_sidecar_tasks(
    mut tasks: JoinSet<(String, Result<()>)>,
    mut control: watch::Receiver<SidecarControl>,
) -> Result<()> {
    if tasks.is_empty() {
        wait_for_empty_server_set_stop(&mut control, |mode| mode.should_stop()).await;
        return Ok(());
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
                        return finish_server_tasks_after_success(
                            tasks, &label, &control,
                            |mode| stop_mode.should_stop() || mode.should_stop(),
                        ).await;
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
    control: watch::Receiver<SidecarControl>,
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

    await_server_tasks(
        tasks,
        control,
        |mode| mode.should_stop(),
        "no brokered HTTP/3 sidecar tasks running",
    )
    .await
}

// TCP and brokered HTTP/3 share stop-and-drain supervision. Exportable
// sidecars keep their separate lifecycle in await_exportable_sidecar_tasks.
async fn await_server_tasks<T>(
    mut tasks: JoinSet<(String, Result<()>)>,
    mut control: watch::Receiver<T>,
    should_stop: impl Fn(&T) -> bool,
    no_tasks_error: &str,
) -> Result<()> {
    if tasks.is_empty() {
        wait_for_empty_server_set_stop(&mut control, should_stop).await;
        return Ok(());
    }

    loop {
        tokio::select! {
            changed = control.changed() => {
                if changed.is_err() || should_stop(&control.borrow()) {
                    break;
                }
            }
            joined = tasks.join_next() => {
                match joined {
                    Some(Ok((label, Ok(())))) => {
                        return finish_server_tasks_after_success(
                            tasks, &label, &control, should_stop,
                        ).await;
                    }
                    Some(Ok((label, Err(err)))) => {
                        tasks.abort_all();
                        return Err(err).with_context(|| format!("{label} failed"));
                    }
                    Some(Err(err)) => {
                        tasks.abort_all();
                        return Err(anyhow::anyhow!("task join failed: {err}"));
                    }
                    None => return Err(anyhow::anyhow!("{no_tasks_error}")),
                }
            }
        }
    }

    drain_server_tasks(tasks).await
}

/// Wait for stop when a server set has no tasks to supervise.
///
/// Returns once the watch sender closes or the caller-provided stop
/// predicate observes the current value.
async fn wait_for_empty_server_set_stop<T>(
    control: &mut watch::Receiver<T>,
    should_stop: impl Fn(&T) -> bool,
) {
    loop {
        if control.changed().await.is_err() || should_stop(&control.borrow()) {
            return;
        }
    }
}

// A child can observe stop and finish before the supervisor selects changed().
// Inspect the current request (or sender closure), not just the selected branch.
async fn finish_server_tasks_after_success<T>(
    mut tasks: JoinSet<(String, Result<()>)>,
    label: &str,
    control: &watch::Receiver<T>,
    should_stop: impl FnOnce(&T) -> bool,
) -> Result<()> {
    let stopping = should_stop(&control.borrow()) || control.has_changed().is_err();
    if !stopping {
        tasks.abort_all();
        return Err(anyhow::anyhow!("{label} exited"));
    }
    drain_server_tasks(tasks).await
}

async fn drain_server_tasks(mut tasks: JoinSet<(String, Result<()>)>) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::oneshot;

    async fn ready_success() -> JoinSet<(String, Result<()>)> {
        let mut tasks = JoinSet::new();
        let child = tasks.spawn(async { ("completed".to_owned(), Ok(())) });
        // Wait for actual task completion, not just a notification before return.
        tokio::time::timeout(Duration::from_secs(5), async {
            while !child.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("child completed");
        tasks
    }

    async fn select_success_first<T>(
        tasks: &mut JoinSet<(String, Result<()>)>,
        control: &mut watch::Receiver<T>,
    ) -> String {
        assert!(control.has_changed().unwrap_or(true));
        // Both branches are ready. Deliberately take the ordering that caused the
        // race, then exercise the same completion helper as the production arms.
        tokio::select! {
            biased;
            joined = tasks.join_next() => {
                let (label, result) = joined.expect("child").expect("join");
                result.expect("success");
                label
            }
            _ = control.changed() => panic!("completed child was not ready"),
        }
    }

    async fn assert_orderly_completion<T>(
        mut tasks: JoinSet<(String, Result<()>)>,
        control: &mut watch::Receiver<T>,
        should_stop: impl FnOnce(&T) -> bool,
    ) {
        let (release, wait) = oneshot::channel();
        let (finished, did_finish) = oneshot::channel();
        tasks.spawn(async move {
            wait.await.expect("release sibling");
            finished.send(()).expect("report sibling completion");
            ("sibling".to_owned(), Ok(()))
        });
        let label = select_success_first(&mut tasks, control).await;
        let completion = finish_server_tasks_after_success(tasks, &label, control, should_stop);
        tokio::pin!(completion);
        // Poll once while the sibling is gated: success must wait, not abort it.
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(std::future::Future::poll(completion.as_mut(), cx))
            })
            .await
            .is_pending()
        );
        release.send(()).expect("sibling not aborted");
        tokio::time::timeout(Duration::from_secs(5), completion)
            .await
            .expect("drain completed")
            .expect("orderly completion");
        did_finish.await.expect("sibling finished normally");
    }

    async fn assert_pending<F: std::future::Future>(mut future: std::pin::Pin<&mut F>) {
        assert!(
            std::future::poll_fn(|cx| { std::task::Poll::Ready(future.as_mut().poll(cx)) })
                .await
                .is_pending()
        );
    }

    async fn assert_supervisor_stop<T: Clone>(running: T, stop: T, should_stop: fn(&T) -> bool) {
        for empty in [false, true] {
            for close_sender in [false, true] {
                let (sender, control) = watch::channel(running.clone());
                let mut tasks = JoinSet::new();
                let (release, wait) = oneshot::channel();
                let (finished, did_finish) = oneshot::channel();
                if !empty {
                    tasks.spawn(async move {
                        wait.await.expect("release child");
                        finished.send(()).expect("report completion");
                        ("gated".to_owned(), Ok(()))
                    });
                }
                let supervision = await_server_tasks(tasks, control, should_stop, "no tasks");
                tokio::pin!(supervision);
                assert_pending(supervision.as_mut()).await;
                assert!(sender.send(running.clone()).is_ok(), "still supervising");
                assert_pending(supervision.as_mut()).await;
                if close_sender {
                    drop(sender);
                } else {
                    assert!(sender.send(stop.clone()).is_ok(), "request stop");
                }
                if !empty {
                    // Stop must drain the gated child, not cancel it or return early.
                    assert_pending(supervision.as_mut()).await;
                    release.send(()).expect("child not aborted");
                }
                tokio::time::timeout(Duration::from_secs(5), supervision)
                    .await
                    .expect("supervisor completed")
                    .expect("orderly stop");
                if !empty {
                    did_finish.await.expect("child finished normally");
                }
            }
        }
    }

    #[tokio::test]
    async fn supervisor_waits_and_drains_for_both_control_types() {
        assert_supervisor_stop(false, true, |stop| *stop).await;
        for stop in [SidecarControl::Stop, SidecarControl::ExportForUpgrade] {
            assert_supervisor_stop(SidecarControl::Running, stop, |mode| mode.should_stop()).await;
        }
    }

    async fn assert_supervisor_success_race<T>(stop: T, should_stop: fn(&T) -> bool) {
        let mut tasks = ready_success().await;
        let (release, wait) = oneshot::channel();
        tasks.spawn(async move {
            wait.await.expect("release sibling");
            ("sibling".to_owned(), Ok(()))
        });
        let (_sender, control) = watch::channel(stop);
        // No changed() notification: only the completed child is ready. The
        // supervisor must inspect the current control value and drain its sibling.
        let supervision = await_server_tasks(tasks, control, should_stop, "no tasks");
        tokio::pin!(supervision);
        assert_pending(supervision.as_mut()).await;
        release.send(()).expect("sibling not aborted");
        tokio::time::timeout(Duration::from_secs(5), supervision)
            .await
            .expect("drain completed")
            .expect("current stop permits success");
    }

    #[tokio::test]
    async fn supervisor_success_checks_current_stop_for_both_control_types() {
        assert_supervisor_success_race(true, |stop| *stop).await;
        for stop in [SidecarControl::Stop, SidecarControl::ExportForUpgrade] {
            assert_supervisor_success_race(stop, |mode| mode.should_stop()).await;
        }
    }

    async fn assert_supervisor_errors<T: Clone>(running: T, stop: T, should_stop: fn(&T) -> bool) {
        for stopping in [false, true] {
            for failure in 0..3 {
                if stopping && failure == 0 {
                    continue; // Successful exits during stop are tested above.
                }
                let (sender, mut control) = watch::channel(running.clone());
                if stopping {
                    assert!(sender.send(stop.clone()).is_ok(), "request stop");
                    control.borrow_and_update(); // Force the join/completion path.
                }
                let mut tasks = JoinSet::new();
                let (guard, dropped) = oneshot::channel::<()>();
                tasks.spawn(async move {
                    let _guard = guard;
                    std::future::pending::<()>().await;
                    ("pending sibling".to_owned(), Ok(()))
                });
                tasks.spawn(async move {
                    assert_ne!(failure, 2, "child panic");
                    let result = if failure == 1 {
                        Err(anyhow::anyhow!("child failure"))
                    } else {
                        Ok(())
                    };
                    ("child".to_owned(), result)
                });
                let err = tokio::time::timeout(
                    Duration::from_secs(5),
                    await_server_tasks(tasks, control, should_stop, "no tasks"),
                )
                .await
                .expect("supervisor completed")
                .expect_err("unexpected success or failure is fatal");
                match failure {
                    0 => assert_eq!(err.to_string(), "child exited"),
                    1 => assert_eq!(format!("{err:#}"), "child failed: child failure"),
                    _ => {
                        assert!(err.to_string().starts_with("task join failed:"));
                        assert!(err.to_string().contains("child panic"));
                    }
                }
                tokio::time::timeout(Duration::from_secs(5), dropped)
                    .await
                    .expect("sibling aborted")
                    .expect_err("sibling guard dropped without completion");
            }
        }
    }

    #[tokio::test]
    async fn supervisor_preserves_errors_and_aborts_siblings_for_both_control_types() {
        assert_supervisor_errors(false, true, |stop| *stop).await;
        assert_supervisor_errors(SidecarControl::Running, SidecarControl::Stop, |mode| {
            mode.should_stop()
        })
        .await;
    }

    #[tokio::test]
    async fn empty_server_set_wait_exits_on_stop_request() {
        let (sender, mut shutdown) = watch::channel(false);
        sender.send(true).expect("request shutdown");
        tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_empty_server_set_stop(&mut shutdown, |stop| *stop),
        )
        .await
        .expect("TCP stop request exits");

        let (sender, mut control) = watch::channel(SidecarControl::Running);
        sender
            .send(SidecarControl::Stop)
            .expect("request sidecar stop");
        tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_empty_server_set_stop(&mut control, |mode| mode.should_stop()),
        )
        .await
        .expect("sidecar stop request exits");
    }

    #[tokio::test]
    async fn empty_server_set_wait_exits_on_sender_closure() {
        let (sender, mut shutdown) = watch::channel(false);
        drop(sender);
        tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_empty_server_set_stop(&mut shutdown, |stop| *stop),
        )
        .await
        .expect("closed TCP sender exits");

        let (sender, mut control) = watch::channel(SidecarControl::Running);
        drop(sender);
        tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_empty_server_set_stop(&mut control, |mode| mode.should_stop()),
        )
        .await
        .expect("closed sidecar sender exits");
    }

    #[tokio::test]
    async fn tcp_success_with_ready_shutdown_or_closed_sender_drains() {
        for close_sender in [false, true] {
            let tasks = ready_success().await;
            let (sender, mut shutdown) = watch::channel(false);
            if close_sender {
                drop(sender);
            } else {
                sender.send(true).expect("request shutdown");
            }
            assert_orderly_completion(tasks, &mut shutdown, |stop| *stop).await;
        }
    }

    #[tokio::test]
    async fn sidecar_success_with_ready_stop_export_or_closed_sender_drains() {
        for mode in [
            Some(SidecarControl::Stop),
            Some(SidecarControl::ExportForUpgrade),
            None,
        ] {
            let tasks = ready_success().await;
            let (sender, mut control) = watch::channel(SidecarControl::Running);
            if let Some(mode) = mode {
                sender.send(mode).expect("request stop/export");
            } else {
                drop(sender);
            }
            assert_orderly_completion(tasks, &mut control, |mode| mode.should_stop()).await;
        }
    }

    #[tokio::test]
    async fn successful_exit_while_running_is_unexpected() {
        let mut tasks = ready_success().await;
        let (_sender, control) = watch::channel(false);
        let (label, result) = tasks.join_next().await.unwrap().unwrap();
        result.unwrap();
        let err = finish_server_tasks_after_success(tasks, &label, &control, |stop| *stop)
            .await
            .expect_err("TCP exit while running");
        assert_eq!(err.to_string(), "completed exited");

        let tasks = ready_success().await;
        let (_sender, control) = watch::channel(SidecarControl::Running);
        let err = await_exportable_sidecar_tasks(tasks, control)
            .await
            .expect_err("sidecar exit while running");
        assert_eq!(err.to_string(), "completed exited");
    }

    #[tokio::test]
    async fn exportable_sidecar_success_checks_current_stop_not_local_mode() {
        for mode in [SidecarControl::Stop, SidecarControl::ExportForUpgrade] {
            let tasks = ready_success().await;
            let (sender, mut control) = watch::channel(SidecarControl::Running);
            sender.send(mode).expect("request stop/export");
            // Make changed() pending so the real supervisor must process the
            // successful join while its local stop_mode is still Running.
            assert_eq!(*control.borrow_and_update(), mode);
            tokio::time::timeout(
                Duration::from_secs(5),
                await_exportable_sidecar_tasks(tasks, control),
            )
            .await
            .expect("supervisor completed")
            .expect("current stop request permits success");
        }
    }

    #[tokio::test]
    async fn drain_preserves_child_and_join_errors_during_stop() {
        let (sender, control) = watch::channel(false);
        sender.send(true).unwrap();
        let mut tasks = JoinSet::new();
        tasks.spawn(async { ("failing".to_owned(), Err(anyhow::anyhow!("child failure"))) });
        let err = finish_server_tasks_after_success(tasks, "completed", &control, |stop| *stop)
            .await
            .expect_err("child error remains fatal");
        assert_eq!(format!("{err:#}"), "failing failed: child failure");

        let mut tasks = JoinSet::new();
        tasks.spawn(async { panic!("child panic") });
        let err = finish_server_tasks_after_success(tasks, "completed", &control, |stop| *stop)
            .await
            .expect_err("join error remains fatal");
        assert!(err.to_string().starts_with("task join failed:"));
        assert!(err.to_string().contains("child panic"));
    }

    #[tokio::test]
    async fn exportable_sidecar_errors_remain_fatal_with_stop_ready() {
        for panic in [false, true] {
            let (sender, control) = watch::channel(SidecarControl::Running);
            sender.send(SidecarControl::Stop).unwrap();
            let mut tasks = JoinSet::new();
            tasks.spawn(async move {
                assert!(!panic, "sidecar panic");
                ("sidecar".to_owned(), Err(anyhow::anyhow!("child failure")))
            });
            let err = await_exportable_sidecar_tasks(tasks, control)
                .await
                .expect_err("errors remain fatal during stop");
            if panic {
                assert!(err.to_string().starts_with("task join failed:"));
            } else {
                assert_eq!(format!("{err:#}"), "sidecar failed: child failure");
            }
        }
    }
}
