use crate::http::codec::h1::serve_http1_with_interim_and_capacity;
use crate::http::codec::interim::{
    H2_PREFACE, serve_h2_with_interim_and_capacity, sniff_h2_preface,
};
use crate::http::metrics as http_metrics;
use crate::http::protocol::l7::finalize_response_for_request;
use crate::runtime::Runtime;
#[cfg(feature = "http3")]
use crate::server::control::SidecarControl;
use crate::tcp_bindings::filter::{
    ConnectionFilterStage, emit_connection_filter_audit, evaluate_connection_filter,
};
use crate::xdp::remote::resolve_remote_addr_with_xdp;
use anyhow::{Result, anyhow};
use hyper::{Request, Response, StatusCode};
use qpx_core::config::IngressEdgeConfig;
use qpx_core::rules::RuleMatchContext;
use qpx_http::body::Body;
use qpx_observability::access_log::{AccessLogContext, AccessLogService};
use qpx_observability::handler_fn;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::{Duration, Instant};
use tracing::{error, info, warn};

mod connect;
#[cfg(feature = "http3")]
pub(crate) mod h3;
mod policy;
mod request;

#[cfg(feature = "mitm")]
pub(crate) use policy::evaluate_forward_policy_staged;
#[cfg(any(feature = "mitm", all(feature = "http3", feature = "http3-backend-h3")))]
pub(crate) use policy::{ForwardPolicyDecision, evaluate_forward_policy};
pub(crate) use request::handle_request_inner;
#[cfg(feature = "mitm")]
#[cfg(feature = "auth-basic")]
pub(crate) use request::proxy_auth_required;

pub(crate) async fn run_tcp(
    listener: IngressEdgeConfig,
    runtime: Runtime,
    shutdown: watch::Receiver<bool>,
    tcp_listeners: Vec<TcpListener>,
) -> Result<()> {
    let addr: SocketAddr = listener.listen.parse()?;
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
        let acceptor_shutdown = shutdown.clone();
        accept_tasks.push(tokio::spawn(async move {
            run_forward_acceptor(
                tcp_listener,
                runtime,
                listener_name,
                xdp_cfg,
                acceptor_shutdown,
            )
            .await
        }));
    }
    for task in accept_tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(err) => return Err(anyhow!("forward acceptor task failed: {}", err)),
        }
    }
    Ok(())
}

#[cfg(feature = "http3")]
pub(crate) async fn run_h3(
    listener: IngressEdgeConfig,
    runtime: Runtime,
    shutdown: watch::Receiver<SidecarControl>,
    endpoint_socket: crate::http3::quinn_socket::QuinnEndpointSocket,
) -> Result<()> {
    let http3 = listener.http3.clone().ok_or_else(|| {
        anyhow!(
            "listener {} enables http3 sidecar without http3 config",
            listener.name
        )
    })?;
    crate::forward::h3::run_http3_listener(listener, runtime, http3, shutdown, endpoint_socket)
        .await
}

async fn run_forward_acceptor(
    tcp_listener: TcpListener,
    runtime: Runtime,
    listener_name: String,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
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
                    warn!(error = ?err, "forward accept failed");
                    continue;
                }
            }
        };
        let Some((stream, remote_addr)) = accepted else {
            break;
        };
        let _ = stream.set_nodelay(true);
        let local_port = match stream.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => {
                warn!(error = ?err, "failed to resolve forward local addr");
                continue;
            }
        };
        let runtime = runtime.clone();
        let listener_name = listener_name.clone();
        let xdp_cfg = xdp_cfg.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let header_read_timeout = Duration::from_millis(
                runtime
                    .state()
                    .plan
                    .limits
                    .timeouts
                    .http_header_read_timeout_ms,
            );
            let (stream, effective_remote_addr) = match resolve_remote_addr_with_xdp(
                stream,
                remote_addr,
                xdp_cfg.as_ref(),
                header_read_timeout,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(err) => {
                    warn!(error = ?err, "failed to resolve xdp remote metadata");
                    return;
                }
            };
            let block_rule = {
                let state = runtime.state();
                evaluate_connection_filter(
                    state
                        .policy
                        .connection_filters_by_listener
                        .get(listener_name.as_str()),
                    &RuleMatchContext {
                        src_ip: Some(effective_remote_addr.ip()),
                        dst_port: Some(local_port),
                        ..Default::default()
                    },
                )
                .map(str::to_string)
            };
            if let Some(matched_rule) = block_rule {
                http_metrics::forward_request(crate::runtime::metric_names(), "blocked");
                emit_connection_filter_audit(
                    "listener",
                    listener_name.as_str(),
                    effective_remote_addr,
                    local_port,
                    ConnectionFilterStage::Accept,
                    matched_rule.as_str(),
                    None,
                );
                return;
            }
            let mut stream = stream;
            let preface = match sniff_h2_preface(&mut stream, header_read_timeout).await {
                Ok(preface) => preface,
                Err(err) => {
                    warn!(error = ?err, "forward protocol sniff failed");
                    return;
                }
            };
            let stream = crate::http::protocol::io_prefix::PrefixedIo::new(stream, preface.clone());
            let access_cfg = runtime.state().resources.access_log.clone();
            let body_channel_capacity = runtime.state().plan.limits.body.body_channel_capacity;
            let access_name = Arc::<str>::from(listener_name.as_str());
            let request_runtime = runtime.clone();
            let service = handler_fn(move |req| {
                handle_request(
                    req,
                    request_runtime.clone(),
                    listener_name.clone(),
                    effective_remote_addr,
                )
            });
            let service = AccessLogService::new(
                service,
                effective_remote_addr,
                AccessLogContext {
                    kind: crate::http::dispatch::ProxyKind::Forward.as_str(),
                    name: access_name,
                },
                &access_cfg,
            );
            let result = if preface.as_ref() == H2_PREFACE {
                serve_h2_with_interim_and_capacity(
                    stream,
                    service,
                    true,
                    header_read_timeout,
                    body_channel_capacity,
                )
                .await
            } else {
                serve_http1_with_interim_and_capacity(
                    stream,
                    service,
                    header_read_timeout,
                    body_channel_capacity,
                )
                .await
            };
            if let Err(err) = result {
                warn!(error = ?err, "forward connection failed");
            }
        });
    }
    Ok(())
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
            http_metrics::forward_request_with_latency(
                &state.observability.metric_names,
                "ok",
                started.elapsed(),
            );
            Ok(response)
        }
        Err(err) => {
            http_metrics::forward_request(&state.observability.metric_names, "error");
            error!(error = ?err, "request handling failed");
            Ok(finalize_response_for_request(
                &request_method,
                request_version,
                state.plan.identity.proxy_name.as_ref(),
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from(state.messages.proxy_error.clone()))
                    .unwrap_or_else(|_| Response::new(Body::empty())),
                false,
            ))
        }
    }
}

// HTTP/3 integration lives in `forward/h3*.rs`, protocol mechanics in `http3/*`.
