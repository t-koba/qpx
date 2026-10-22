use super::super::destination::classify_reverse_destination;
use super::super::mirrors::record_reverse_upstream_status;
use super::super::response_rules::{
    DispatchResponseRuleInput, ResponseRuleInput, apply_dispatch_response_rules,
};
use super::super::{InterimList, empty_interim_response};
use super::finalize::{ReverseFinalizeResponseInput, finalize_reverse_dispatch_response};
use super::record_reverse_success_metrics;
use super::{
    ReverseAttemptOutcome, ReverseHttpDispatchInput, ReverseHttpSuccessInput,
    ReverseResponseRuleInput, ReverseUpstreamFailureInput, acquire_reverse_upstream_concurrency,
    build_reverse_attempt_request, capture_reverse_response_outcome,
    finish_reverse_upstream_failure, prepare_reverse_http_retry, proxy_reverse_http_attempt,
    record_reverse_http_loop_error, record_reverse_http_loop_timeout,
    reverse_continue_response_rule,
};
use crate::http::dispatch::{
    concurrency_limited_response_for_parts_with_limits, finalize_dispatch_stale_if_error_response,
};
use crate::upstream::origin::OriginEndpoint;
use anyhow::{Result, anyhow};
use hyper::Response;
use qpx_http::body::Body;
use tokio::time::{Duration, Instant};

pub(super) async fn dispatch_reverse_http_route(
    input: ReverseHttpDispatchInput<'_>,
) -> Result<(InterimList, Response<Body>)> {
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
            return Ok(empty_interim_response(response));
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
                match handle_reverse_http_success(ReverseHttpSuccessInput {
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
                    upstream_cert,
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
    finish_reverse_upstream_failure(ReverseUpstreamFailureInput {
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

async fn handle_reverse_http_success(
    input: ReverseHttpSuccessInput<'_>,
) -> Result<ReverseAttemptOutcome> {
    let ReverseHttpSuccessInput {
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
        revalidation_state,
        cache_collapse_guard,
        template,
        replay_recorder,
        mirror_upstreams,
        attempts,
        route_timeout,
        proxy_name,
        http_modules,
        audit_ctx,
        attempt_idx,
        selected_upstream,
        started,
        interim,
        response,
        upstream_cert,
        export_session,
    } = input;
    let resp = http_modules.on_upstream_response(response).await?;
    let classified_response_destination;
    let response_destination = if upstream_cert.is_some()
        && (route.requires_destination_after_selection() || state.destination_trace_enabled())
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
    let response_rule = apply_dispatch_response_rules(DispatchResponseRuleInput {
        rule: ResponseRuleInput {
            route,
            base,
            conn,
            destination: response_destination,
            upstream_cert: upstream_cert.as_ref(),
            identity,
            request_rpc,
            route_headers: route_headers.clone(),
            response: resp,
            max_observed_response_body_bytes: route.plan.response_body_observation_limit(
                state.plan.limits.body.max_observed_response_body_bytes,
            ),
            response_body_read_timeout: Duration::from_millis(
                state.plan.limits.timeouts.upstream_http_timeout_ms.max(1),
            ),
            force_response_body_observation: false,
        },
        http_modules,
        audit: audit_ctx,
        request_method,
        request_version,
        proxy_name,
    })
    .await?;
    let (resp, route_headers_for_response, response_cache_bypass, policy_tags, mirror) =
        match reverse_continue_response_rule(ReverseResponseRuleInput {
            response_rule,
            http_modules,
            state,
            route,
            selected_upstream,
            attempt_idx,
            attempts,
            started,
        })
        .await?
        {
            Ok(values) => values,
            Err(outcome) => {
                return Ok(capture_reverse_response_outcome(outcome, route, export_session).await);
            }
        };
    if resp.status().is_server_error()
        && let Some(stale) = finalize_dispatch_stale_if_error_response(
            revalidation_state.as_ref(),
            &route.plan,
            request_method,
            proxy_name,
            route_headers.as_deref(),
            http_modules,
            audit_ctx,
        )
        .await?
    {
        if let Some(upstream) = selected_upstream {
            record_reverse_upstream_status(upstream, &route.policy, resp.status(), started);
        }
        return Ok(capture_reverse_response_outcome(
            ReverseAttemptOutcome::Response(Box::new(empty_interim_response(stale))),
            route,
            export_session,
        )
        .await);
    }
    if let Some(upstream) = selected_upstream {
        record_reverse_upstream_status(upstream, &route.policy, resp.status(), started);
    }
    record_reverse_success_metrics(state, started);
    let resp = finalize_reverse_dispatch_response(ReverseFinalizeResponseInput {
        response: resp,
        state,
        route,
        request_method,
        cache_policy,
        response_cache_bypass,
        request_headers_snapshot,
        cache_target_key,
        cache_lookup_key,
        revalidation_state,
        cache_collapse_guard,
        started,
        route_headers_for_response,
        export_session,
        template,
        replay_recorder: replay_recorder.as_ref(),
        mirror_upstreams,
        mirror,
        route_timeout,
        proxy_name,
        http_modules,
        audit_ctx,
        policy_tags: policy_tags.as_slice(),
    })
    .await?;
    Ok(ReverseAttemptOutcome::Response(Box::new((interim, resp))))
}
