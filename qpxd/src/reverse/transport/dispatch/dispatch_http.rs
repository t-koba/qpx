use super::super::destination::classify_reverse_destination;
use super::super::mirrors::{dispatch_mirrors, record_reverse_upstream_status};
use super::super::response_rules::{
    DispatchResponseRuleInput, ResponseRuleInput, apply_dispatch_response_rules,
};
use super::super::{InterimList, empty_interim_response};
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
    DispatchCacheWriteInput, DispatchOutcome, annotate_dispatch_response,
    concurrency_limited_response_for_parts, finalize_dispatch_stale_if_error_response,
    write_dispatch_cache_result,
};
use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use crate::upstream::origin::OriginEndpoint;
use anyhow::{Result, anyhow};
use hyper::Response;
use qpx_http::body::Body;
use std::sync::atomic::Ordering;
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
        let Some(_concurrency_permits) = acquire_reverse_upstream_concurrency(
            request_limits,
            request_limit_ctx,
            selected_upstream.as_ref(),
        ) else {
            let response = concurrency_limited_response_for_parts(
                request_method,
                request_version,
                proxy_name,
                audit_ctx.clone(),
            );
            return Ok(empty_interim_response(response));
        };
        if let Some(upstream) = selected_upstream.as_ref() {
            upstream.inflight.fetch_add(1, Ordering::Relaxed);
        }
        let started = Instant::now();
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
            route_timeout,
        )
        .await;
        if let Some(upstream) = selected_upstream.as_ref() {
            upstream.inflight.fetch_sub(1, Ordering::Relaxed);
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
    let response_destination = classify_reverse_destination(
        state,
        conn,
        host,
        upstream_cert.as_ref(),
        resolution_override,
    );
    let response_rule = apply_dispatch_response_rules(DispatchResponseRuleInput {
        rule: ResponseRuleInput {
            route,
            base,
            conn,
            destination: &response_destination,
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
    let (mut resp, route_headers_for_response, response_cache_bypass, policy_tags, mirror) =
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
            record_reverse_upstream_status(
                upstream,
                &route.policy,
                resp.status(),
                started.elapsed(),
            );
        }
        return Ok(capture_reverse_response_outcome(
            ReverseAttemptOutcome::Response(Box::new(empty_interim_response(stale))),
            route,
            export_session,
        )
        .await);
    }
    if let Some(upstream) = selected_upstream {
        record_reverse_upstream_status(upstream, &route.policy, resp.status(), started.elapsed());
    }
    record_reverse_success_metrics(state, started);
    resp = write_dispatch_cache_result(DispatchCacheWriteInput {
        response: resp,
        cache_policy,
        response_cache_bypass,
        request_headers_snapshot,
        cache_target_key,
        cache_lookup_key,
        revalidation_state: revalidation_state.take(),
        request_collapse_guard: cache_collapse_guard.take(),
        request_method,
        response_delay_secs: started.elapsed().as_secs(),
        state,
    })
    .await?;
    resp = http_modules.prepare_downstream_response(resp).await?;
    finalize_response_with_headers_in_place(
        request_method,
        resp.version(),
        proxy_name,
        &mut resp,
        route_headers_for_response.as_deref(),
        false,
    );
    resp = crate::http::capture::stream::emit_optional_response_for_export(
        resp,
        &route.plan,
        export_session,
    )
    .await;
    if mirror.unwrap_or(true) && !mirror_upstreams.is_empty() {
        if let Some(template) = template {
            dispatch_mirrors(
                state.pools.clone(),
                template,
                std::mem::take(mirror_upstreams),
                route_timeout,
                route.policy.health.clone(),
                route.policy.lifecycle.clone(),
                route.upstream_trust.clone(),
                proxy_name,
            );
        } else if let Some(recorder) = replay_recorder.as_ref()
            && let Some(template) = recorder.template().await
        {
            dispatch_mirrors(
                state.pools.clone(),
                template.as_ref(),
                std::mem::take(mirror_upstreams),
                route_timeout,
                route.policy.health.clone(),
                route.policy.lifecycle.clone(),
                route.upstream_trust.clone(),
                proxy_name,
            );
        }
    }
    http_modules.on_logging(Some(resp.status()), None).await;
    annotate_dispatch_response(
        &mut resp,
        audit_ctx,
        DispatchOutcome::Allow,
        policy_tags.as_ref(),
    );
    Ok(ReverseAttemptOutcome::Response(Box::new((interim, resp))))
}
