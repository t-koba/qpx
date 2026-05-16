use crate::runtime::Runtime;
#[cfg(feature = "http3")]
use crate::sidecar_control::SidecarControl;
use crate::tls::{
    extract_client_hello_info, looks_like_tls_client_hello, read_client_hello_with_timeout,
};
use crate::{
    connection_filter::{
        ConnectionFilterStage, emit_connection_filter_audit, evaluate_connection_filter,
    },
    runtime::metric_names,
};
use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use metrics::{counter, histogram};
use qpx_core::config::IngressEdgeConfig;
use qpx_core::rules::RuleMatchContext;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::Duration;
use tracing::{info, warn};

mod destination;
mod http_path;
#[cfg(feature = "http3")]
pub(crate) mod quic;
mod tls_path;
#[cfg(feature = "http3")]
mod udp_path;
#[cfg(feature = "http3")]
pub(crate) mod udp_socket;

use self::destination::{DestinationResolver, destination_resolver_for_listener};

pub async fn run_tcp(
    listener: IngressEdgeConfig,
    runtime: Runtime,
    shutdown: watch::Receiver<bool>,
    forward_edges: Vec<TcpListener>,
) -> Result<()> {
    let addr: SocketAddr = listener.listen.parse()?;
    let listener_name = listener.name.clone();
    let resolver = destination_resolver_for_listener(&listener)?;
    info!(
        addr = %addr,
        listener = %listener.name,
        acceptors = forward_edges.len(),
        "transparent listener starting"
    );

    let mut accept_tasks = Vec::with_capacity(forward_edges.len() + 1);
    for tcp_listener in forward_edges {
        let runtime = runtime.clone();
        let listener_name = listener_name.clone();
        let resolver = resolver.clone();
        let acceptor_shutdown = shutdown.clone();
        accept_tasks.push(tokio::spawn(async move {
            run_transparent_acceptor(
                tcp_listener,
                listener_name,
                runtime,
                resolver,
                acceptor_shutdown,
            )
            .await
        }));
    }

    for task in accept_tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(err) => return Err(anyhow!("transparent acceptor task failed: {}", err)),
        }
    }
    Ok(())
}

#[cfg(feature = "http3")]
pub async fn run_udp(
    listener: IngressEdgeConfig,
    runtime: Runtime,
    shutdown: watch::Receiver<SidecarControl>,
    udp_socket: std::net::UdpSocket,
    restore: Option<crate::udp_session_handoff::TransparentUdpListenerRestore>,
    export_sink: std::sync::Arc<
        std::sync::Mutex<crate::udp_session_handoff::UdpSessionRestoreState>,
    >,
) -> Result<()> {
    udp_path::run_transparent_udp_listener(
        listener,
        runtime,
        shutdown,
        Some(udp_socket),
        restore,
        export_sink,
    )
    .await
}

async fn run_transparent_acceptor(
    tcp_listener: TcpListener,
    listener_name: String,
    runtime: Runtime,
    resolver: DestinationResolver,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let semaphore = runtime.state().connection_semaphore.clone();
    loop {
        let permit = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            permit = semaphore.clone().acquire_owned() => Some(permit?),
        };
        let Some(permit) = permit else {
            break;
        };
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            accepted = tcp_listener.accept() => match accepted {
                Ok(accepted) => Some(accepted),
                Err(err) => {
                    warn!(error = ?err, "transparent accept failed");
                    continue;
                }
            }
        };
        let Some((stream, remote_addr)) = accepted else {
            break;
        };
        let local_port = match stream.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => {
                warn!(error = ?err, "failed to resolve transparent local addr");
                continue;
            }
        };
        let runtime = runtime.clone();
        let listener_name = listener_name.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = handle_connection(
                stream,
                remote_addr,
                local_port,
                &listener_name,
                runtime,
                resolver,
            )
            .await
            {
                warn!(error = ?err, "transparent connection failed");
            }
        });
    }
    Ok(())
}

async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    local_port: u16,
    listener_name: &str,
    runtime: Runtime,
    resolver: DestinationResolver,
) -> Result<()> {
    let started = Instant::now();
    let _ = stream.set_nodelay(true);
    let metadata_timeout =
        Duration::from_millis(runtime.state().plan.limits.http_header_read_timeout_ms);
    let (mut stream, remote_addr, original_target) = resolver
        .resolve_original_target(stream, remote_addr, metadata_timeout)
        .await?;
    let accept_stage_block = {
        let state = runtime.state();
        evaluate_connection_filter(
            state
                .policy
                .connection_filters_by_listener
                .get(listener_name),
            &RuleMatchContext {
                src_ip: Some(remote_addr.ip()),
                dst_port: Some(local_port),
                ..Default::default()
            },
        )
        .map(str::to_string)
    };
    if let Some(matched_rule) = accept_stage_block {
        counter!(metric_names().transparent_requests_total.clone(), "result" => "blocked")
            .increment(1);
        histogram!(metric_names().transparent_latency_ms.clone())
            .record(started.elapsed().as_secs_f64() * 1000.0);
        emit_connection_filter_audit(
            "listener",
            listener_name,
            remote_addr,
            local_port,
            ConnectionFilterStage::Accept,
            matched_rule.as_str(),
            None,
        );
        return Ok(());
    }
    let state = runtime.state();
    let peek_timeout = Duration::from_millis(state.plan.limits.tls_peek_timeout_ms);
    let sniff = read_client_hello_with_timeout(&mut stream, peek_timeout)
        .await
        .context("transparent TLS peek timed out")?;
    let is_tls = looks_like_tls_client_hello(&sniff);
    let client_hello = is_tls.then(|| extract_client_hello_info(&sniff)).flatten();
    if let Some(client_hello) = client_hello.as_ref() {
        let client_hello_stage_block = {
            let state = runtime.state();
            evaluate_connection_filter(
                state
                    .policy
                    .connection_filters_by_listener
                    .get(listener_name),
                &RuleMatchContext {
                    src_ip: Some(remote_addr.ip()),
                    dst_port: Some(local_port),
                    sni: client_hello.sni.as_deref(),
                    alpn: client_hello.alpn.as_deref(),
                    tls_version: client_hello.tls_version.as_deref(),
                    ja3: client_hello.ja3.as_deref(),
                    ja4: client_hello.ja4.as_deref(),
                    ..Default::default()
                },
            )
            .map(str::to_string)
        };
        if let Some(matched_rule) = client_hello_stage_block {
            counter!(metric_names().transparent_requests_total.clone(), "result" => "blocked")
                .increment(1);
            histogram!(metric_names().transparent_latency_ms.clone())
                .record(started.elapsed().as_secs_f64() * 1000.0);
            emit_connection_filter_audit(
                "listener",
                listener_name,
                remote_addr,
                local_port,
                ConnectionFilterStage::ClientHello,
                matched_rule.as_str(),
                client_hello.sni.as_deref(),
            );
            return Ok(());
        }
    }
    let stream = crate::io_prefix::PrefixedIo::new(stream, Bytes::from(sniff));

    if is_tls {
        let result = tls_path::handle_tls_connection(
            stream,
            remote_addr,
            original_target,
            listener_name,
            runtime.clone(),
            client_hello,
        )
        .await;
        match result {
            Ok(outcome) => {
                let state = runtime.state();
                counter!(
                    state.observability.metric_names.transparent_requests_total.clone(),
                    "result" => outcome.metric_result()
                )
                .increment(1);
                histogram!(
                    state
                        .observability
                        .metric_names
                        .transparent_latency_ms
                        .clone()
                )
                .record(started.elapsed().as_secs_f64() * 1000.0);
                return Ok(());
            }
            Err(err) => {
                let state = runtime.state();
                counter!(
                    state.observability.metric_names.transparent_requests_total.clone(),
                    "result" => "error"
                )
                .increment(1);
                return Err(err);
            }
        }
    }

    let result = http_path::handle_http_connection(
        stream,
        remote_addr,
        original_target,
        listener_name,
        runtime.clone(),
    )
    .await;
    if result.is_ok() {
        let state = runtime.state();
        counter!(
            state.observability.metric_names.transparent_requests_total.clone(),
            "result" => "ok"
        )
        .increment(1);
        histogram!(
            state
                .observability
                .metric_names
                .transparent_latency_ms
                .clone()
        )
        .record(started.elapsed().as_secs_f64() * 1000.0);
    } else {
        let state = runtime.state();
        counter!(
            state.observability.metric_names.transparent_requests_total.clone(),
            "result" => "error"
        )
        .increment(1);
    }
    result
}
