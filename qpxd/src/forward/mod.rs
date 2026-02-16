use crate::http::l7::finalize_response_for_request;
use crate::http::server::serve_http1_with_upgrades;
use crate::runtime::Runtime;
use crate::xdp::remote::resolve_remote_addr_with_xdp;
use anyhow::{anyhow, Result};
use hyper::service::service_fn;
use hyper::{Body, Request, Response, StatusCode};
use metrics::{counter, histogram};
use qpx_core::config::ListenerConfig;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};
use tracing::{error, info, warn};

mod connect;
#[cfg(feature = "http3")]
mod h3;
#[cfg(feature = "http3")]
mod h3_connect;
#[cfg(feature = "http3")]
mod h3_connect_udp;
mod policy;
mod request;

#[cfg(feature = "http3")]
pub(crate) use policy::{evaluate_forward_policy, ForwardPolicyDecision};
pub(crate) use request::handle_request_inner;

pub async fn run(listener: ListenerConfig, runtime: Runtime) -> Result<()> {
    let addr: SocketAddr = listener.listen.parse()?;
    let h3_task: Option<tokio::task::JoinHandle<Result<()>>> = if listener
        .http3
        .as_ref()
        .map(|cfg| cfg.enabled)
        .unwrap_or(false)
    {
        #[cfg(feature = "http3")]
        {
            let http3 = listener.http3.clone().expect("enabled config");
            let listener_h3 = listener.clone();
            let runtime_h3 = runtime.clone();
            Some(tokio::spawn(async move {
                crate::forward::h3::run_http3_listener(listener_h3, runtime_h3, http3).await
            }))
        }
        #[cfg(not(feature = "http3"))]
        {
            return Err(anyhow!(
                "listener {} enables http3, but this build was compiled without feature http3",
                listener.name
            ));
        }
    } else {
        None
    };

    let runtime_cfg = runtime.state().config.runtime.clone();
    let tcp_listeners = crate::net::bind_tcp_listeners(addr, &runtime_cfg)?;
    info!(
        listener = %listener.name,
        addr = %addr,
        acceptors = tcp_listeners.len(),
        "forward listener starting"
    );
    let listener_name = listener.name.clone();
    let xdp_cfg = crate::xdp::compile_xdp_config(listener.xdp.as_ref())?;

    let mut accept_tasks = Vec::with_capacity(tcp_listeners.len());
    for tcp_listener in tcp_listeners {
        let runtime = runtime.clone();
        let listener_name = listener_name.clone();
        let xdp_cfg = xdp_cfg.clone();
        accept_tasks.push(tokio::spawn(async move {
            run_forward_acceptor(tcp_listener, runtime, listener_name, xdp_cfg).await
        }));
    }
    let http_server = async move {
        for task in accept_tasks {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err),
                Err(err) => return Err(anyhow!("forward acceptor task failed: {}", err)),
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    if let Some(task) = h3_task {
        tokio::select! {
            res = http_server => {
                res?;
            }
            res = task => {
                res??;
            }
        }
    } else {
        http_server.await?;
    }
    Ok(())
}

async fn run_forward_acceptor(
    tcp_listener: TcpListener,
    runtime: Runtime,
    listener_name: String,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
) -> Result<()> {
    loop {
        let (mut stream, remote_addr) = match tcp_listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(error = ?err, "forward accept failed");
                continue;
            }
        };
        let runtime = runtime.clone();
        let listener_name = listener_name.clone();
        let xdp_cfg = xdp_cfg.clone();
        tokio::spawn(async move {
            let header_read_timeout =
                Duration::from_millis(runtime.state().config.runtime.http_header_read_timeout_ms);
            let metadata_timeout = header_read_timeout;
            let effective_remote_addr = match resolve_remote_addr_with_xdp(
                &mut stream,
                remote_addr,
                xdp_cfg.as_ref(),
                metadata_timeout,
            )
            .await
            {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(error = ?err, "failed to resolve xdp remote metadata");
                    return;
                }
            };
            let service = service_fn(move |req| {
                handle_request(
                    req,
                    runtime.clone(),
                    listener_name.clone(),
                    effective_remote_addr,
                )
            });
            if let Err(err) =
                serve_http1_with_upgrades(stream, service, header_read_timeout, true).await
            {
                warn!(error = ?err, "forward connection failed");
            }
        });
    }
}

async fn handle_request(
    req: Request<Body>,
    runtime: Runtime,
    listener_name: String,
    remote_addr: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    let started = Instant::now();
    let state = runtime.state();
    let request_method = req.method().clone();
    let request_version = req.version();
    let result = handle_request_inner(req, runtime, &listener_name, remote_addr).await;
    match result {
        Ok(response) => {
            counter!(state.metric_names.forward_requests_total.clone(), "result" => "ok")
                .increment(1);
            histogram!(state.metric_names.forward_latency_ms.clone())
                .record(started.elapsed().as_secs_f64() * 1000.0);
            Ok(response)
        }
        Err(err) => {
            counter!(state.metric_names.forward_requests_total.clone(), "result" => "error")
                .increment(1);
            error!(error = ?err, "request handling failed");
            Ok(finalize_response_for_request(
                &request_method,
                request_version,
                state.config.identity.proxy_name.as_str(),
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from(state.messages.proxy_error.clone()))
                    .unwrap(),
                false,
            ))
        }
    }
}

// HTTP/3 integration lives in `forward/h3*.rs`, protocol mechanics in `http3/*`.
