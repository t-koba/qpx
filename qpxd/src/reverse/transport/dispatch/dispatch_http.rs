use super::super::destination::classify_reverse_destination;
use super::super::mirrors::{dispatch_mirrors, record_reverse_upstream_status};
use super::super::response_rules::ResponseRuleInput;
use super::super::{ReverseInterimResponses, empty_interim_response};
use super::record_reverse_success_metrics;
use super::{
    ReverseAttemptOutcome, ReverseHttpDispatchInput, ReverseHttpSuccessInput,
    ReverseResponseRuleInput, apply_response_rules, build_reverse_attempt_request,
    consume_reverse_retry_budget, finish_reverse_upstream_failure, proxy_reverse_http_attempt,
    record_reverse_http_loop_error, record_reverse_http_loop_timeout,
    reverse_continue_response_rule, reverse_retry_backoff,
};
use crate::http::body::Body;
use crate::http::dispatch::{
    DispatchCacheWriteInput, annotate_dispatch_response, finalize_dispatch_stale_if_error_response,
    write_dispatch_cache_result,
};
use crate::http::protocol::common::too_many_requests_response as too_many_requests;
use crate::http::protocol::l7::{
    finalize_response_for_request, finalize_response_with_headers_in_place,
};
use crate::upstream::origin::OriginEndpoint;
use anyhow::{Result, anyhow};
use hyper::Response;
use std::sync::atomic::Ordering;
use tokio::time::{Duration, Instant};

pub(super) async fn dispatch_reverse_http_route(
    input: ReverseHttpDispatchInput<'_>,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
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
        let selected_upstream = if override_upstream.is_none() {
            Some(
                route
                    .select_upstream(seed, sticky_seed)
                    .ok_or_else(|| anyhow!("no upstream"))?,
            )
        } else {
            None
        };
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
        let mut concurrency_ctx = request_limit_ctx.clone();
        if concurrency_ctx.upstream.is_none() {
            concurrency_ctx.upstream = selected_upstream
                .as_ref()
                .map(|upstream| upstream.target.clone());
        }
        let _concurrency_permits = match request_limits.acquire_concurrency(&concurrency_ctx) {
            Some(permits) => permits,
            None => {
                let mut response = finalize_response_for_request(
                    request_method,
                    request_version,
                    proxy_name,
                    too_many_requests(None),
                    false,
                );
                annotate_dispatch_response(
                    &mut response,
                    audit_ctx,
                    crate::http::dispatch::DispatchOutcome::ConcurrencyLimited,
                    &[],
                );
                return Ok(empty_interim_response(response));
            }
        };
        if let Some(upstream) = selected_upstream.as_ref() {
            upstream.inflight.fetch_add(1, Ordering::Relaxed);
        }
        let started = Instant::now();
        let mut req_for_upstream =
            build_reverse_attempt_request(attempt_idx, &mut first_request, template.as_ref())?;
        http_modules
            .on_upstream_request(&mut req_for_upstream)
            .await?;
        if let Some(session) = export_session.as_ref() {
            let preview = crate::exporter::serialize_request_preview_async(&req_for_upstream).await;
            session.emit_plaintext(true, &preview);
            if let Some(sample_bytes) = route.plan.capture_stream_sample_bytes() {
                req_for_upstream = crate::http::capture::stream::sample_request_body_for_export(
                    req_for_upstream,
                    sample_bytes,
                    route.plan.streaming.body_channel_capacity,
                    Duration::from_millis(route.plan.streaming.body_read_timeout_ms),
                    session.clone(),
                    true,
                );
            } else if let Some(max_capture_bytes) = route.plan.capture_full_body_bytes() {
                req_for_upstream = crate::http::capture::stream::capture_request_body_for_export(
                    req_for_upstream,
                    max_capture_bytes,
                    route.plan.streaming.body_channel_capacity,
                    Duration::from_millis(route.plan.streaming.body_read_timeout_ms),
                    session.clone(),
                    true,
                );
            }
        }
        let response = proxy_reverse_http_attempt(
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
        if attempt_idx + 1 < attempts {
            if !consume_reverse_retry_budget(state, route) {
                break;
            }
            if let Some(err) = last_err.as_ref() {
                let retry_reason = err.to_string();
                http_modules
                    .on_retry(attempt_idx + 2, retry_reason.as_str())
                    .await?;
            }
            reverse_retry_backoff(route).await;
        }
    }
    finish_reverse_upstream_failure(
        revalidation_state.as_ref(),
        request_method,
        proxy_name,
        route_headers.as_deref(),
        http_modules,
        audit_ctx,
        last_err,
    )
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
    let response_rule = apply_response_rules(ResponseRuleInput {
        route,
        base,
        conn,
        destination: &response_destination,
        upstream_cert: upstream_cert.as_ref(),
        identity,
        request_rpc,
        route_headers: route_headers.clone(),
        response: resp,
        max_observed_response_body_bytes: route
            .plan
            .body_observation_limit(state.plan.limits.body.max_observed_response_body_bytes),
        response_body_read_timeout: Duration::from_millis(
            state.plan.limits.timeouts.upstream_http_timeout_ms.max(1),
        ),
        force_response_body_observation: false,
    })
    .await?;
    let (mut resp, route_headers_for_response, response_cache_bypass, policy_tags, mirror) =
        match reverse_continue_response_rule(ReverseResponseRuleInput {
            response_rule,
            request_method,
            request_version,
            proxy_name,
            http_modules,
            audit_ctx,
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
            Err(outcome) => return Ok(outcome),
        };
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_response_preview_async(&resp).await;
        session.emit_plaintext(false, &preview);
    }
    if resp.status().is_server_error()
        && let Some(stale) = finalize_dispatch_stale_if_error_response(
            revalidation_state.as_ref(),
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
        return Ok(ReverseAttemptOutcome::Response(Box::new(
            empty_interim_response(stale),
        )));
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
    let resp_version = resp.version();
    finalize_response_with_headers_in_place(
        request_method,
        resp_version,
        proxy_name,
        &mut resp,
        route_headers_for_response.as_deref(),
        false,
    );
    if let Some(session) = export_session
        && let Some(sample_bytes) = route.plan.capture_stream_sample_bytes()
    {
        resp = crate::http::capture::stream::sample_response_body_for_export(
            resp,
            sample_bytes,
            route.plan.streaming.body_channel_capacity,
            Duration::from_millis(route.plan.streaming.body_read_timeout_ms),
            session.clone(),
        );
    } else if let Some(session) = export_session
        && let Some(max_capture_bytes) = route.plan.capture_full_body_bytes()
    {
        resp = crate::http::capture::stream::capture_response_body_for_export(
            resp,
            max_capture_bytes,
            route.plan.streaming.body_channel_capacity,
            Duration::from_millis(route.plan.streaming.body_read_timeout_ms),
            session.clone(),
        );
    }
    if mirror.unwrap_or(true)
        && !mirror_upstreams.is_empty()
        && let Some(template) = template
    {
        dispatch_mirrors(
            template,
            std::mem::take(mirror_upstreams),
            route_timeout,
            route.policy.health.clone(),
            route.policy.lifecycle.clone(),
            route.upstream_trust.clone(),
            proxy_name,
        );
    }
    http_modules.on_logging(Some(resp.status()), None).await;
    annotate_dispatch_response(
        &mut resp,
        audit_ctx,
        crate::http::dispatch::DispatchOutcome::Allow,
        policy_tags.as_ref(),
    );
    Ok(ReverseAttemptOutcome::Response(Box::new((interim, resp))))
}
