use crate::http::body::Body;
use crate::http::http1_codec::serve_http1_with_interim;
use crate::http::interim::{serve_h2_with_interim, sniff_h2_preface, H2_PREFACE};
use crate::http::l7::finalize_response_for_request;
use crate::runtime::Runtime;
#[cfg(feature = "http3")]
use crate::sidecar_control::SidecarControl;
use crate::xdp::remote::resolve_remote_addr_with_xdp;
use crate::{
    connection_filter::{
        emit_connection_filter_audit, evaluate_connection_filter, ConnectionFilterStage,
    },
    runtime::metric_names,
};
use anyhow::{anyhow, Result};
use hyper::{Request, Response, StatusCode};
use metrics::{counter, histogram};
use qpx_core::config::ListenerConfig;
use qpx_core::rules::RuleMatchContext;
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
mod connect_udp_upstream;
#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(crate) mod h3;
#[cfg(all(
    feature = "http3",
    feature = "http3-backend-qpx",
    not(feature = "http3-backend-h3")
))]
#[path = "h3_qpx.rs"]
pub(crate) mod h3;
#[cfg(all(
    feature = "http3",
    not(any(
        all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")),
        all(feature = "http3-backend-qpx", not(feature = "http3-backend-h3"))
    ))
))]
#[path = "h3_invalid.rs"]
pub(crate) mod h3;
#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
mod h3_connect;
#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
mod h3_connect_udp;
mod policy;
mod request;

#[cfg(any(feature = "mitm", all(feature = "http3", feature = "http3-backend-h3")))]
pub(crate) use policy::{evaluate_forward_policy, ForwardPolicyDecision};
pub(crate) use request::handle_request_inner;
#[cfg(feature = "mitm")]
pub(crate) use request::proxy_auth_required;

pub async fn run_tcp(
    listener: ListenerConfig,
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
pub async fn run_h3(
    listener: ListenerConfig,
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
        if permit.is_none() {
            break;
        }
        let permit = permit.expect("checked permit");
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
        if accepted.is_none() {
            break;
        }
        let (stream, remote_addr) = accepted.expect("checked accept");
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
            let header_read_timeout =
                Duration::from_millis(runtime.state().config.runtime.http_header_read_timeout_ms);
            let metadata_timeout = header_read_timeout;
            let (stream, effective_remote_addr) = match resolve_remote_addr_with_xdp(
                stream,
                remote_addr,
                xdp_cfg.as_ref(),
                metadata_timeout,
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
                counter!(metric_names().forward_requests_total.clone(), "result" => "blocked")
                    .increment(1);
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
            let stream = crate::io_prefix::PrefixedIo::new(stream, preface.clone());
            let access_cfg = runtime.state().config.access_log.clone();
            let access_name = Arc::<str>::from(listener_name.as_str());
            let service = handler_fn(move |req| {
                handle_request(
                    req,
                    runtime.clone(),
                    listener_name.clone(),
                    effective_remote_addr,
                )
            });
            let service = AccessLogService::new(
                service,
                effective_remote_addr,
                AccessLogContext {
                    kind: "forward",
                    name: access_name,
                },
                &access_cfg,
            );
            let result = if preface.as_ref() == H2_PREFACE {
                serve_h2_with_interim(stream, service, true, header_read_timeout).await
            } else {
                serve_http1_with_interim(stream, service, header_read_timeout).await
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
            counter!(state.observability.metric_names.forward_requests_total.clone(), "result" => "ok")
                .increment(1);
            histogram!(state.observability.metric_names.forward_latency_ms.clone())
                .record(started.elapsed().as_secs_f64() * 1000.0);
            Ok(response)
        }
        Err(err) => {
            counter!(state.observability.metric_names.forward_requests_total.clone(), "result" => "error")
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
