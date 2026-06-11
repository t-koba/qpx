use super::super::mirrors::{record_reverse_upstream_error, record_reverse_upstream_timeout};
use super::super::{InterimList, empty_interim_response};
use crate::http::dispatch::{
    DispatchAuditContext, ProxyKind, finalize_dispatch_stale_if_error_response,
    record_upstream_request_duration,
};
use crate::reverse::health::UpstreamEndpoint;
use crate::reverse::router::HttpRoute;
use crate::runtime;
use anyhow::{Result, anyhow};
use hyper::{Method, Response};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use std::sync::Arc;
use tokio::time::{Duration, Instant, sleep};

pub(super) fn consume_reverse_retry_budget(
    state: &runtime::RuntimeState,
    route: &HttpRoute,
) -> bool {
    if route.policy.retry_budget.try_consume_retry() {
        return true;
    }
    super::super::metrics::retry_budget_exhausted(state);
    false
}

pub(super) async fn reverse_retry_backoff(route: &HttpRoute) {
    if route.policy.retry_backoff > Duration::ZERO {
        sleep(route.policy.retry_backoff).await;
    }
}

pub(super) async fn prepare_reverse_http_retry(
    state: &runtime::RuntimeState,
    route: &HttpRoute,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    attempt_idx: usize,
    attempts: usize,
    last_err: Option<&anyhow::Error>,
) -> Result<bool> {
    if attempt_idx + 1 >= attempts || !consume_reverse_retry_budget(state, route) {
        return Ok(false);
    }
    if let Some(err) = last_err {
        let retry_reason = err.to_string();
        http_modules
            .on_retry(attempt_idx + 2, retry_reason.as_str())
            .await?;
    }
    reverse_retry_backoff(route).await;
    Ok(true)
}

pub(super) fn record_reverse_success_metrics(state: &runtime::RuntimeState, started: Instant) {
    let elapsed = started.elapsed();
    record_upstream_request_duration(ProxyKind::Reverse, elapsed);
    super::super::metrics::upstream_latency(state, elapsed);
    super::super::metrics::reverse_result(state, "ok");
}

pub(super) fn acquire_reverse_upstream_concurrency(
    request_limits: &mut crate::rate_limit::AppliedRateLimits,
    request_limit_ctx: &crate::rate_limit::RateLimitContext,
    selected_upstream: Option<&Arc<UpstreamEndpoint>>,
) -> Option<crate::rate_limit::ConcurrencyPermits> {
    let mut concurrency_ctx = request_limit_ctx.clone();
    if concurrency_ctx.upstream.is_none() {
        concurrency_ctx.upstream = selected_upstream.map(|upstream| upstream.target.clone());
    }
    request_limits.acquire_concurrency(&concurrency_ctx)
}

pub(super) async fn capture_reverse_response_outcome(
    outcome: super::ReverseAttemptOutcome,
    route: &HttpRoute,
    export_session: Option<&crate::exporter::ExportSession>,
) -> super::ReverseAttemptOutcome {
    match outcome {
        super::ReverseAttemptOutcome::Response(response) => {
            let (interim, response) = *response;
            let response = match export_session {
                Some(session) => {
                    crate::http::capture::stream::emit_response_for_export(
                        response,
                        &route.plan,
                        session,
                    )
                    .await
                }
                None => crate::http::capture::stream::limit_response_body_for_plan(
                    response,
                    &route.plan,
                ),
            };
            super::ReverseAttemptOutcome::Response(Box::new((interim, response)))
        }
        outcome => outcome,
    }
}

pub(super) async fn record_reverse_loop_error(
    state: &runtime::RuntimeState,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    err: anyhow::Error,
    result: &'static str,
) -> anyhow::Error {
    http_modules.on_error(&err).await;
    super::super::metrics::reverse_result(state, result);
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
    super::super::metrics::reverse_result(state, "error");
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
    super::super::metrics::reverse_result(state, "timeout");
    err
}

pub(super) struct ReverseUpstreamFailureInput<'a> {
    pub(super) revalidation_state: Option<&'a qpxd_cache::RevalidationState>,
    pub(super) plan: &'a crate::runtime::ExecutionPlan,
    pub(super) request_method: &'a Method,
    pub(super) proxy_name: &'a str,
    pub(super) route_headers: Option<&'a CompiledHeaderControl>,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) audit_ctx: &'a DispatchAuditContext,
    pub(super) last_err: Option<anyhow::Error>,
}

pub(super) async fn finish_reverse_upstream_failure(
    input: ReverseUpstreamFailureInput<'_>,
) -> Result<(InterimList, Response<Body>)> {
    if let Some(stale) = finalize_dispatch_stale_if_error_response(
        input.revalidation_state,
        input.plan,
        input.request_method,
        input.proxy_name,
        input.route_headers,
        input.http_modules,
        input.audit_ctx,
    )
    .await?
    {
        return Ok(empty_interim_response(stale));
    }
    if let Some(err) = input.last_err.as_ref() {
        input.http_modules.on_error(err).await;
    }
    Err(input
        .last_err
        .unwrap_or_else(|| anyhow!("upstream request failed")))
}
