use super::super::destination::{ConnectTarget, connect_target_stream};
use crate::http::body::Body;
use crate::http::codec::h1::serve_http1_with_interim_and_capacity;
use crate::http::mitm::{MitmRouteContext, proxy_mitm_request};
use crate::runtime::Runtime;
use crate::tls::CompiledUpstreamTlsTrust;
use crate::tls::mitm::{accept_mitm_client, connect_mitm_upstream, prewarm_mitm_cert};
use anyhow::{Context, Result};
use hyper::Request;
use qpx_observability::access_log::{AccessLogContext, AccessLogService};
use qpx_observability::handler_fn;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use tracing::warn;

#[cfg(feature = "mitm")]
pub(super) struct TransparentMitmContext {
    pub(super) connect_target: ConnectTarget,
    pub(super) upstream_proxy: Option<crate::upstream::pool::ResolvedUpstreamProxy>,
    pub(super) runtime: Runtime,
    pub(super) listener_name: String,
    pub(super) remote_addr: SocketAddr,
    pub(super) sni: String,
    pub(super) mitm: qpx_core::tls::MitmConfig,
    pub(super) verify_upstream: bool,
    pub(super) trust: Option<Arc<CompiledUpstreamTlsTrust>>,
}

#[cfg(feature = "mitm")]
pub(super) async fn transparent_mitm<I>(stream: I, ctx: TransparentMitmContext) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let TransparentMitmContext {
        connect_target,
        upstream_proxy,
        runtime,
        listener_name,
        remote_addr,
        sni,
        mitm,
        verify_upstream,
        trust,
    } = ctx;
    let upstream_timeout = Duration::from_millis(
        runtime
            .state()
            .plan
            .limits
            .timeouts
            .upstream_http_timeout_ms,
    );

    let upstream_connected = timeout(
        upstream_timeout,
        connect_target_stream(
            &connect_target,
            upstream_proxy.as_ref(),
            runtime.state().plan.identity.proxy_name.as_ref(),
            upstream_timeout,
        ),
    )
    .await??;
    prewarm_mitm_cert(&mitm, sni.as_str(), upstream_timeout).await?;
    let client_tls = accept_mitm_client(stream, &mitm, upstream_timeout).await?;
    let (sender, upstream_cert) = connect_mitm_upstream(
        upstream_connected.io,
        sni.as_str(),
        verify_upstream,
        trust.as_deref(),
        upstream_timeout,
        "transparent MITM upstream conn",
    )
    .await?;
    let upstream_cert = Arc::new(upstream_cert);
    let runtime_for_service = runtime.clone();
    let listener_for_service = listener_name.clone();
    let sni_for_service = sni.clone();
    let connect_target_for_service = connect_target.clone();
    let access_cfg = runtime.state().resources.access_log.clone();
    let access_name = Arc::<str>::from(listener_name.as_str());

    let service = handler_fn(move |req: Request<Body>| {
        let sender = sender.clone();
        let runtime = runtime_for_service.clone();
        let listener_name = listener_for_service.clone();
        let sni = sni_for_service.clone();
        let connect_target = connect_target_for_service.clone();
        let upstream_cert = upstream_cert.clone();

        async move {
            let proxy_name = runtime.state().plan.identity.proxy_name.to_string();
            let proxy_error = runtime.state().messages.proxy_error.clone();
            let request_method = req.method().clone();
            let request_version = req.version();
            let target_host = connect_target.host_for_connect();
            let route = MitmRouteContext {
                listener_name: listener_name.as_str(),
                src_addr: remote_addr,
                dst_port: connect_target.port(),
                host: target_host.as_str(),
                sni: sni.as_str(),
                upstream_cert: Some(upstream_cert),
            };
            match proxy_mitm_request(req, runtime, sender, route).await {
                Ok(response) => Ok::<_, Infallible>(response),
                Err(err) => {
                    warn!(error = ?err, "transparent MITM request failed");
                    Ok(crate::http::protocol::l7::finalize_response_for_request(
                        &request_method,
                        request_version,
                        proxy_name.as_str(),
                        hyper::Response::builder()
                            .status(hyper::StatusCode::BAD_GATEWAY)
                            .body(Body::from(proxy_error))
                            .unwrap_or_else(|_| hyper::Response::new(Body::from("proxy error"))),
                        false,
                    ))
                }
            }
        }
    });
    let service = AccessLogService::new(
        service,
        remote_addr,
        AccessLogContext {
            kind: crate::http::dispatch::ProxyKind::Transparent.as_str(),
            name: access_name,
        },
        &access_cfg,
    );

    let header_read_timeout = Duration::from_millis(
        runtime
            .state()
            .plan
            .limits
            .timeouts
            .http_header_read_timeout_ms,
    );
    serve_http1_with_interim_and_capacity(
        client_tls,
        service,
        header_read_timeout,
        runtime.state().plan.limits.body.body_channel_capacity,
    )
    .await
    .context("transparent MITM serve_connection failed")?;

    Ok(())
}
