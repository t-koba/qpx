use crate::runtime::Runtime;
use crate::tls::{extract_sni, looks_like_tls_client_hello, peek_client_hello_with_timeout};
use anyhow::{anyhow, Context, Result};
use metrics::{counter, histogram};
use qpx_core::config::ListenerConfig;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;
use tracing::{info, warn};

mod destination;
mod http_path;
mod tls_path;

use self::destination::{destination_resolver_for_listener, DestinationResolver};

pub async fn run(listener: ListenerConfig, runtime: Runtime) -> Result<()> {
    let addr: SocketAddr = listener.listen.parse()?;
    let runtime_cfg = runtime.state().config.runtime.clone();
    let listeners = crate::net::bind_tcp_listeners(addr, &runtime_cfg)?;
    let listener_name = listener.name.clone();
    let resolver = destination_resolver_for_listener(&listener)?;
    info!(
        addr = %addr,
        listener = %listener.name,
        acceptors = listeners.len(),
        "transparent listener starting"
    );

    let mut accept_tasks = Vec::with_capacity(listeners.len());
    for tcp_listener in listeners {
        let runtime = runtime.clone();
        let listener_name = listener_name.clone();
        let resolver = resolver.clone();
        accept_tasks.push(tokio::spawn(async move {
            run_transparent_acceptor(tcp_listener, listener_name, runtime, resolver).await
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

async fn run_transparent_acceptor(
    tcp_listener: TcpListener,
    listener_name: String,
    runtime: Runtime,
    resolver: DestinationResolver,
) -> Result<()> {
    loop {
        let (stream, remote_addr) = match tcp_listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(error = ?err, "transparent accept failed");
                continue;
            }
        };
        let runtime = runtime.clone();
        let listener_name = listener_name.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(err) =
                handle_connection(stream, remote_addr, &listener_name, runtime, resolver).await
            {
                warn!(error = ?err, "transparent connection failed");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    listener_name: &str,
    runtime: Runtime,
    resolver: DestinationResolver,
) -> Result<()> {
    let started = Instant::now();
    let mut stream = stream;
    let metadata_timeout =
        Duration::from_millis(runtime.state().config.runtime.http_header_read_timeout_ms);
    let original_target = resolver
        .resolve_original_target(&mut stream, remote_addr, metadata_timeout)
        .await?;
    let state = runtime.state();
    let peek_timeout = Duration::from_millis(state.config.runtime.tls_peek_timeout_ms);
    let sniff = peek_client_hello_with_timeout(&stream, peek_timeout)
        .await
        .context("transparent TLS peek timed out")?;

    if looks_like_tls_client_hello(&sniff) {
        let sni = extract_sni(&sniff);
        let result = tls_path::handle_tls_connection(
            stream,
            remote_addr,
            original_target,
            listener_name,
            runtime.clone(),
            sni,
        )
        .await;
        match result {
            Ok(outcome) => {
                let state = runtime.state();
                counter!(
                    state.metric_names.transparent_requests_total.clone(),
                    "result" => outcome.metric_result()
                )
                .increment(1);
                histogram!(state.metric_names.transparent_latency_ms.clone())
                    .record(started.elapsed().as_secs_f64() * 1000.0);
                return Ok(());
            }
            Err(err) => {
                let state = runtime.state();
                counter!(
                    state.metric_names.transparent_requests_total.clone(),
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
            state.metric_names.transparent_requests_total.clone(),
            "result" => "ok"
        )
        .increment(1);
        histogram!(state.metric_names.transparent_latency_ms.clone())
            .record(started.elapsed().as_secs_f64() * 1000.0);
    } else {
        let state = runtime.state();
        counter!(
            state.metric_names.transparent_requests_total.clone(),
            "result" => "error"
        )
        .increment(1);
    }
    result
}
