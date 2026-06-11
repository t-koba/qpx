use super::destination::{ConnectTarget, resolve_http_target, resolve_upstream};
use crate::http::codec::h1::serve_http1_with_interim_and_capacity;
use crate::http::codec::interim::{
    H2_PREFACE, serve_h2_with_interim_and_capacity, sniff_h2_preface,
};
use crate::http::protocol::common::bad_request_response as bad_request;
use crate::http::protocol::l7::finalize_response_for_request;
use crate::runtime::Runtime;
use anyhow::{Context, Result};
use hyper::{Request, StatusCode};
use qpx_http::body::Body;
use qpx_observability::access_log::{AccessLogContext, AccessLogService};
use qpx_observability::handler_fn;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::error;

mod dispatch;

use self::dispatch::dispatch_transparent_request;

pub(super) async fn handle_http_connection<I>(
    stream: I,
    remote_addr: SocketAddr,
    original_target: Option<ConnectTarget>,
    listener_name: &str,
    runtime: Runtime,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let listener_name = listener_name.to_string();
    let dispatch_view = runtime.dispatch_view();
    let header_read_timeout = Duration::from_millis(
        dispatch_view
            .plan
            .limits
            .timeouts
            .http_header_read_timeout_ms,
    );
    let body_channel_capacity = dispatch_view.plan.limits.body.body_channel_capacity;
    let access_cfg = dispatch_view.resources.access_log.clone();
    let access_name = Arc::<str>::from(listener_name.as_str());

    let request_runtime = runtime.clone();
    let service = handler_fn(move |req: Request<Body>| {
        let runtime = request_runtime.clone();
        let listener_name = listener_name.clone();
        let original_target = original_target.clone();

        async move {
            let error_state = runtime.state();
            let request_method = req.method().clone();
            let request_version = req.version();

            match dispatch_transparent_request(
                req,
                runtime,
                remote_addr,
                original_target,
                listener_name.as_str(),
            )
            .await
            {
                Ok(response) => Ok::<_, Infallible>(response),
                Err(err) => {
                    error!(error = ?err, "transparent request handling failed");
                    Ok(finalize_response_for_request(
                        &request_method,
                        request_version,
                        error_state.plan.identity.proxy_name.as_ref(),
                        hyper::Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Body::from(error_state.messages.proxy_error.clone()))
                            .unwrap_or_else(|_| bad_request("proxy error")),
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

    let mut stream = stream;
    let preface = sniff_h2_preface(&mut stream, header_read_timeout).await?;
    let stream = crate::http::protocol::io_prefix::PrefixedIo::new(stream, preface.clone());
    if preface.as_ref() == H2_PREFACE {
        serve_h2_with_interim_and_capacity(
            stream,
            service,
            false,
            header_read_timeout,
            body_channel_capacity,
        )
        .await
        .context("transparent HTTP/2 serve_connection failed")?;
    } else {
        serve_http1_with_interim_and_capacity(
            stream,
            service,
            header_read_timeout,
            body_channel_capacity,
        )
        .await
        .context("transparent HTTP/1 serve_connection failed")?;
    }

    Ok(())
}
