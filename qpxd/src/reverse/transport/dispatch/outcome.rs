use super::super::mirrors::{record_reverse_upstream_error, record_reverse_upstream_timeout};
use super::super::{ReverseInterimResponses, empty_interim_response};
use crate::http::body::Body;
use crate::http::dispatch::{
    DispatchAuditContext, finalize_dispatch_stale_if_error_response,
    record_upstream_request_duration,
};
use crate::reverse::health::UpstreamEndpoint;
use crate::reverse::router::HttpRoute;
use crate::runtime;
use anyhow::{Result, anyhow};
use hyper::{Method, Response};
use metrics::{counter, histogram};
use qpx_core::rules::CompiledHeaderControl;
use std::sync::Arc;
use tokio::time::{Duration, Instant, sleep};

pub(super) fn consume_reverse_retry_budget(
    state: &runtime::RuntimeState,
    route: &HttpRoute,
) -> bool {
    if route.policy.retry_budget.try_consume_retry() {
        return true;
    }
    counter!(
        state
            .observability
            .metric_names
            .reverse_retry_budget_exhausted_total
            .clone()
    )
    .increment(1);
    false
}

pub(super) async fn reverse_retry_backoff(route: &HttpRoute) {
    if route.policy.retry_backoff > Duration::ZERO {
        sleep(route.policy.retry_backoff).await;
    }
}

pub(super) fn record_reverse_success_metrics(state: &runtime::RuntimeState, started: Instant) {
    record_upstream_request_duration(crate::http::dispatch::ProxyKind::Reverse, started.elapsed());
    histogram!(
        state
            .observability
            .metric_names
            .reverse_upstream_latency_ms
            .clone()
    )
    .record(started.elapsed().as_secs_f64() * 1000.0);
    counter!(
        state.observability.metric_names.reverse_requests_total.clone(),
        "result" => "ok"
    )
    .increment(1);
}

pub(super) async fn record_reverse_loop_error(
    state: &runtime::RuntimeState,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    err: anyhow::Error,
    result: &'static str,
) -> anyhow::Error {
    http_modules.on_error(&err).await;
    counter!(
        state.observability.metric_names.reverse_requests_total.clone(),
        "result" => result
    )
    .increment(1);
    err
}

pub(super) async fn record_reverse_http_loop_error(
    state: &runtime::RuntimeState,
    route: &HttpRoute,
    selected_upstream: Option<&Arc<UpstreamEndpoint>>,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    err: anyhow::Error,
) -> anyhow::Error {
    http_modules.on_error(&err).await;
    if let Some(upstream) = selected_upstream {
        record_reverse_upstream_error(upstream, &route.policy, &err);
    }
    counter!(
        state.observability.metric_names.reverse_requests_total.clone(),
        "result" => "error"
    )
    .increment(1);
    err
}

pub(super) async fn record_reverse_http_loop_timeout(
    state: &runtime::RuntimeState,
    route: &HttpRoute,
    selected_upstream: Option<&Arc<UpstreamEndpoint>>,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
) -> anyhow::Error {
    let err = anyhow!("upstream timeout");
    http_modules.on_error(&err).await;
    if let Some(upstream) = selected_upstream {
        record_reverse_upstream_timeout(upstream, &route.policy);
    }
    counter!(
        state.observability.metric_names.reverse_requests_total.clone(),
        "result" => "timeout"
    )
    .increment(1);
    err
}

pub(super) async fn finish_reverse_upstream_failure(
    revalidation_state: Option<&crate::cache::RevalidationState>,
    request_method: &Method,
    proxy_name: &str,
    route_headers: Option<&CompiledHeaderControl>,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &DispatchAuditContext,
    last_err: Option<anyhow::Error>,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    if let Some(stale) = finalize_dispatch_stale_if_error_response(
        revalidation_state,
        request_method,
        proxy_name,
        route_headers,
        http_modules,
        audit_ctx,
    )
    .await?
    {
        return Ok(empty_interim_response(stale));
    }
    if let Some(err) = last_err.as_ref() {
        http_modules.on_error(err).await;
    }
    Err(last_err.unwrap_or_else(|| anyhow!("upstream request failed")))
}
