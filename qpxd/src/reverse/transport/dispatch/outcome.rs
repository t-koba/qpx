use super::super::InterimList;
use super::super::ReverseTerminalResponse;
use super::super::mirrors::{record_reverse_upstream_error, record_reverse_upstream_timeout};
use crate::http::dispatch::{
    DispatchAuditContext, ProxyKind, finalize_dispatch_stale_if_error_response,
    record_upstream_request_duration,
};
use crate::reverse::health::UpstreamEndpoint;
use crate::reverse::router::HttpRoute;
use crate::runtime;
use anyhow::{Result, anyhow};
use hyper::Method;
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

pub(super) fn record_reverse_success_metrics(
    state: &runtime::RuntimeState,
    started: Option<Instant>,
) {
    if !qpx_observability::metrics_enabled() {
        return;
    }
    let Some(started) = started else {
        return;
    };
    let elapsed = started.elapsed();
    record_upstream_request_duration(ProxyKind::Reverse, elapsed);
    super::super::metrics::upstream_latency(state, elapsed);
    super::super::metrics::reverse_result(state, super::super::metrics::ReverseResult::Ok);
}

pub(super) fn acquire_reverse_upstream_concurrency(
    request_limits: &mut crate::rate_limit::AppliedRateLimits,
    request_limit_ctx: &crate::rate_limit::RateLimitContext,
    selected_upstream: Option<&Arc<UpstreamEndpoint>>,
) -> crate::rate_limit::ConcurrencyAcquire {
    let mut concurrency_ctx = request_limit_ctx.clone();
    if request_limits.has_concurrency_controls() && concurrency_ctx.upstream.is_none() {
        concurrency_ctx.upstream = selected_upstream.map(|upstream| upstream.target.clone());
    }
    request_limits.acquire_concurrency_with_retry(&concurrency_ctx)
}

pub(super) async fn capture_reverse_response_outcome<R: ReverseTerminalResponse>(
    outcome: super::ReverseAttemptOutcome<qpx_core::http_message::Response<qpx_http::body::Body>>,
    route: &HttpRoute,
    export_session: Option<&crate::exporter::ExportSession>,
) -> super::ReverseAttemptOutcome<R> {
    match outcome {
        super::ReverseAttemptOutcome::Response(response) => {
            let (interim, response) = *response;
            let response = R::from_finalized_owner(response);
            let response = crate::http::capture::stream::emit_optional_response_for_export(
                response,
                &route.plan,
                export_session,
            )
            .await;
            super::ReverseAttemptOutcome::Response(Box::new((interim, response)))
        }
        super::ReverseAttemptOutcome::Retry(err) => super::ReverseAttemptOutcome::Retry(err),
        super::ReverseAttemptOutcome::Stop(err) => super::ReverseAttemptOutcome::Stop(err),
    }
}

pub(super) async fn record_reverse_loop_error(
    state: &runtime::RuntimeState,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    err: anyhow::Error,
    result: super::super::metrics::ReverseResult,
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
    super::super::metrics::reverse_result(state, super::super::metrics::ReverseResult::Error);
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
    super::super::metrics::reverse_result(state, super::super::metrics::ReverseResult::Timeout);
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

pub(super) async fn finish_reverse_upstream_failure<R: ReverseTerminalResponse>(
    input: ReverseUpstreamFailureInput<'_>,
) -> Result<(InterimList, R)> {
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
        return Ok((Vec::new(), R::from_finalized_owner(stale)));
    }
    if let Some(err) = input.last_err.as_ref() {
        input.http_modules.on_error(err).await;
    }
    Err(input
        .last_err
        .unwrap_or_else(|| anyhow!("upstream request failed")))
}
