use super::destination::{resolve_http_target, resolve_upstream, ConnectTarget};
use crate::destination::DestinationInputs;
use crate::http::base_fields::{extract_base_request_fields, BaseRequestContext};
use crate::http::body::Body;
use crate::http::body_size::observed_request_size;
use crate::http::common::{
    bad_request_response as bad_request, forbidden_response as forbidden,
    too_many_requests_response as too_many_requests,
};
use crate::http::http1_codec::serve_http1_with_interim;
use crate::http::interim::{serve_h2_with_interim, sniff_h2_preface, H2_PREFACE};
use crate::http::l7::{
    finalize_response_for_request, finalize_response_with_headers_in_place,
    handle_max_forwards_in_place, prepare_request_with_headers_in_place,
};
use crate::http::policy::{evaluate_listener_policy, ListenerPolicyDecision};
use crate::http::preflight::{preflight_validate, PreflightOptions, PreflightOutcome};
use crate::http::response_policy::{
    apply_listener_response_policy, ListenerResponsePolicyDecision, ResponseBodyObservationLimits,
};
use crate::http::websocket::is_websocket_upgrade;
use crate::policy_context::{
    apply_ext_authz_action_overrides, attach_log_context, emit_audit_log, enforce_ext_authz,
    merge_header_controls, merge_policy_tags, resolve_identity, sanitize_headers_for_policy,
    strip_untrusted_identity_headers, validate_ext_authz_allow_mode, AuditRecord,
    EffectivePolicyContext, ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode,
};
use crate::rate_limit::RateLimitContext;
use crate::runtime::Runtime;
use crate::upstream::http1::{
    proxy_http1_request_with_interim, proxy_websocket_http1, WebsocketProxyConfig,
};
use anyhow::{anyhow, Context, Result};
use hyper::{Request, StatusCode};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_observability::access_log::{AccessLogContext, AccessLogService};
use qpx_observability::handler_fn;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::error;

#[path = "http_dispatch.rs"]
mod http_dispatch;

use self::http_dispatch::dispatch_transparent_request;

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
    let header_read_timeout =
        Duration::from_millis(runtime.state().config.runtime.http_header_read_timeout_ms);
    let access_cfg = runtime.state().config.access_log.clone();
    let access_name = Arc::<str>::from(listener_name.as_str());

    let service = handler_fn(move |req: Request<Body>| {
        let runtime = runtime.clone();
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
                        error_state.config.identity.proxy_name.as_str(),
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
            kind: "transparent",
            name: access_name,
        },
        &access_cfg,
    );

    let mut stream = stream;
    let preface = sniff_h2_preface(&mut stream, header_read_timeout).await?;
    let stream = crate::io_prefix::PrefixedIo::new(stream, preface.clone());
    if preface.as_ref() == H2_PREFACE {
        serve_h2_with_interim(stream, service, false, header_read_timeout)
            .await
            .context("transparent HTTP/2 serve_connection failed")?;
    } else {
        serve_http1_with_interim(stream, service, header_read_timeout)
            .await
            .context("transparent HTTP/1 serve_connection failed")?;
    }

    Ok(())
}
