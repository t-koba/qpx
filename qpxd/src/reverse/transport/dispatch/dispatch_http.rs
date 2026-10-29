use super::super::InterimList;
use super::super::ReverseTerminalResponse;
use super::super::destination::classify_reverse_destination;
use super::success::handle_reverse_success;
use super::{
    ReverseAttemptOutcome, ReverseHttpDispatchInput, ReverseSuccessInput,
    ReverseUpstreamFailureInput, acquire_reverse_upstream_concurrency,
    build_reverse_attempt_request, finish_reverse_upstream_failure, prepare_reverse_http_retry,
    proxy_reverse_http_attempt, record_reverse_http_loop_error, record_reverse_http_loop_timeout,
};
use crate::http::dispatch::concurrency_limited_response_for_parts_with_limits;
use crate::upstream::origin::OriginEndpoint;
use anyhow::{Result, anyhow};
use tokio::time::Instant;

pub(super) async fn dispatch_reverse_http_route<R: ReverseTerminalResponse>(
    input: ReverseHttpDispatchInput<'_>,
) -> Result<(InterimList, R)> {
    let ReverseHttpDispatchInput {
        base,
        state,
        conn,
        host,
        route,
        resolution_override,
        request_method,
        request_version,
        request_rpc,
        request_destination,
        identity,
        route_headers,
        cache_policy,
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        mut revalidation_state,
        mut cache_collapse_guard,
        mut first_request,
        template,
        replay_recorder,
        mut mirror_upstreams,
        attempts,
        override_upstream,
        seed,
        sticky_seed,
        route_timeout,
        proxy_name,
        http_modules,
        request_limits,
        request_limit_ctx,
        audit_ctx,
        connection_pool,
    } = input;
    let mut last_err = None;
    for attempt_idx in 0..attempts {
        let selected_upstream = override_upstream
            .is_none()
            .then(|| {
                route
                    .select_upstream(seed, sticky_seed)
                    .ok_or_else(|| anyhow!("no upstream"))
            })
            .transpose()?;
        let override_origin = override_upstream.map(OriginEndpoint::direct);
        let upstream_origin = override_origin
            .as_ref()
            .or_else(|| selected_upstream.as_ref().map(|upstream| &upstream.origin))
            .ok_or_else(|| anyhow!("no upstream"))?;
        let export_session = state.export_session_for_plan(
            &route.plan,
            conn.remote_addr,
            upstream_origin.upstream.as_str(),
        );
        let concurrency = acquire_reverse_upstream_concurrency(
            request_limits,
            request_limit_ctx,
            selected_upstream.as_ref(),
        );
        let Some(_concurrency_permits) = concurrency.permits else {
            let response = concurrency_limited_response_for_parts_with_limits(
                request_method,
                request_version,
                proxy_name,
                request_limits,
                concurrency.retry_after,
                audit_ctx.clone(),
            );
            return Ok((Vec::new(), R::from_finalized_http(response)));
        };
        let inflight_guard = selected_upstream
            .as_ref()
            .map(|upstream| upstream.hold_inflight());
        let started = (qpx_observability::metrics_enabled()
            || cache_policy.is_some()
            || route
                .policy
                .passive_health
                .as_ref()
                .is_some_and(|policy| policy.latency_threshold.is_some()))
        .then(Instant::now);
        let mut req_for_upstream = match build_reverse_attempt_request(
            attempt_idx,
            &mut first_request,
            template.as_ref(),
            replay_recorder.as_ref(),
        )
        .await
        {
            Ok(req) => req,
            Err(err) => {
                last_err = Some(err);
                break;
            }
        };
        http_modules
            .on_upstream_request(&mut req_for_upstream)
            .await?;
        req_for_upstream = crate::http::capture::stream::emit_request_for_export(
            req_for_upstream,
            &route.plan,
            export_session.as_ref(),
            true,
        )
        .await;
        let response = proxy_reverse_http_attempt(
            &state.pools,
            req_for_upstream,
            upstream_origin,
            request_version,
            proxy_name,
            route,
            super::ReverseHttpAttemptTransport {
                timeout: route_timeout,
                connection_pool,
            },
        )
        .await;
        if let Some(guard) = inflight_guard {
            guard.release();
        }
        match response {
            Ok(Ok((interim, resp, upstream_cert))) => {
                let resp = http_modules
                    .on_upstream_response(qpx_core::http_message::Response::from_http(resp))
                    .await?;
                let classified_response_destination;
                let response_destination = if upstream_cert.is_some()
                    && (route.requires_destination_after_selection()
                        || state.destination_trace_enabled())
                {
                    classified_response_destination = classify_reverse_destination(
                        state,
                        conn,
                        host,
                        upstream_cert.as_ref(),
                        resolution_override,
                    );
                    &classified_response_destination
                } else {
                    request_destination
                };
                match handle_reverse_success::<R>(ReverseSuccessInput {
                    base,
                    state,
                    conn,
                    route,
                    request_method,
                    request_version,
                    request_rpc,
                    response_destination,
                    identity,
                    route_headers: route_headers.clone(),
                    cache_policy,
                    request_headers_snapshot,
                    cache_lookup_key,
                    cache_target_key,
                    revalidation_state: &mut revalidation_state,
                    cache_collapse_guard: &mut cache_collapse_guard,
                    template: template.as_ref(),
                    replay_recorder: replay_recorder.clone(),
                    mirror_upstreams: &mut mirror_upstreams,
                    attempts,
                    route_timeout,
                    proxy_name,
                    http_modules,
                    audit_ctx,
                    attempt_idx,
                    selected_upstream: selected_upstream.as_ref(),
                    started,
                    interim,
                    response: resp,
                    upstream_cert: upstream_cert.as_ref(),
                    export_session: export_session.as_ref(),
                })
                .await?
                {
                    ReverseAttemptOutcome::Response(response) => return Ok(*response),
                    ReverseAttemptOutcome::Retry(err) => {
                        last_err = Some(err);
                        continue;
                    }
                    ReverseAttemptOutcome::Stop(err) => {
                        last_err = Some(err);
                        break;
                    }
                }
            }
            Ok(Err(err)) => {
                last_err = Some(
                    record_reverse_http_loop_error(
                        state,
                        route,
                        selected_upstream.as_ref(),
                        http_modules,
                        err,
                    )
                    .await,
                );
            }
            Err(_) => {
                last_err = Some(
                    record_reverse_http_loop_timeout(
                        state,
                        route,
                        selected_upstream.as_ref(),
                        http_modules,
                    )
                    .await,
                );
            }
        }
        if !prepare_reverse_http_retry(
            state,
            route,
            http_modules,
            attempt_idx,
            attempts,
            last_err.as_ref(),
        )
        .await?
        {
            break;
        }
    }
    finish_reverse_upstream_failure::<R>(ReverseUpstreamFailureInput {
        revalidation_state: revalidation_state.as_ref(),
        plan: &route.plan,
        request_method,
        proxy_name,
        route_headers: route_headers.as_deref(),
        http_modules,
        audit_ctx,
        last_err,
    })
    .await
}
