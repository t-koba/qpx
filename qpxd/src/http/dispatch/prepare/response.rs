use crate::http::dispatch::audit::DispatchAuditContext;
use crate::http::dispatch::audit::annotate_dispatch_response;
use crate::http::dispatch::outcome::DispatchOutcome;
use crate::http::modules::HttpModuleExecution;
use crate::http::protocol::l7::{
    finalize_response_for_request, finalize_response_with_headers_in_place,
    handle_max_forwards_in_place,
};
use anyhow::Result;
use hyper::{Method, Request, Response, StatusCode};
use qpx_core::config::LocalResponseConfig;
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use std::time::Duration;

pub(crate) fn request_body_too_large_response(
    method: &Method,
    version: http::Version,
    proxy_name: &str,
    audit: Option<&DispatchAuditContext>,
) -> Result<Response<Body>> {
    let mut response = finalize_response_for_request(
        method,
        version,
        proxy_name,
        Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(Body::from("request body too large"))?,
        false,
    );
    if let Some(audit) = audit {
        annotate_dispatch_response(&mut response, audit, DispatchOutcome::Error, &[]);
    }
    Ok(response)
}

pub(crate) async fn annotated_max_forwards_response(
    req: &mut Request<Body>,
    proxy_name: &str,
    trace_reflect_all_headers: bool,
    max_observed_request_body_bytes: usize,
    read_timeout: Duration,
    audit: &DispatchAuditContext,
) -> Option<Response<Body>> {
    let mut response = handle_max_forwards_in_place(
        req,
        proxy_name,
        trace_reflect_all_headers,
        max_observed_request_body_bytes,
        read_timeout,
    )
    .await?;
    annotate_dispatch_response(&mut response, audit, DispatchOutcome::MaxForwards, &[]);
    Some(response)
}

pub(crate) async fn prepare_http_module_local_response(
    http_modules: &mut HttpModuleExecution,
    response: Response<Body>,
    request_method: &Method,
    proxy_name: &str,
    headers: Option<&CompiledHeaderControl>,
    audit: &DispatchAuditContext,
) -> Result<Response<Body>> {
    let mut response = http_modules.prepare_downstream_response(response).await?;
    finalize_response_with_headers_in_place(
        request_method,
        response.version(),
        proxy_name,
        &mut response,
        headers,
        false,
    );
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_dispatch_response(
        &mut response,
        audit,
        DispatchOutcome::HttpModuleLocalResponse,
        &[],
    );
    Ok(response)
}

pub(crate) fn annotated_local_response(
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    local: &LocalResponseConfig,
    headers: Option<&CompiledHeaderControl>,
    audit: &DispatchAuditContext,
    outcome: DispatchOutcome,
) -> Result<Response<Body>> {
    let mut response = crate::http::local_response::finalized_local_response(
        request_method,
        request_version,
        proxy_name,
        local,
        headers,
    )?;
    annotate_dispatch_response(&mut response, audit, outcome, &[]);
    Ok(response)
}
