use super::super::mirrors::{
    dispatch_mirrors, record_reverse_upstream_error, record_reverse_upstream_status,
    record_reverse_upstream_timeout,
};
use super::super::response_rules::{
    DispatchResponseRuleInput, ResponseRuleInput, apply_dispatch_response_rules,
};
use super::super::{InterimList, empty_interim_response};
use super::record_reverse_success_metrics;
use super::{
    ReverseAttemptOutcome, ReverseIpcDispatchInput, ReverseIpcSuccessInput,
    ReverseResponseRuleInput, ReverseWebsocketDispatch, acquire_reverse_upstream_concurrency,
    build_reverse_attempt_request, capture_reverse_response_outcome, consume_reverse_retry_budget,
    record_reverse_loop_error, reverse_continue_response_rule, reverse_retry_backoff,
};
use crate::http::dispatch::{
    DispatchCacheWriteInput, DispatchOutcome, annotate_dispatch_response,
    concurrency_limited_response_for_parts, finalize_dispatch_stale_if_error_response,
    write_dispatch_cache_result,
};
use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use crate::ipc_client::{ClientConnInfo, proxy_ipc_upstream};
use crate::upstream::origin::{OriginEndpoint, proxy_websocket};
use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use qpx_http::body::Body;
use std::sync::atomic::Ordering;
use tokio::time::{Duration, Instant, timeout};

pub(super) async fn dispatch_reverse_ipc_route(
    input: ReverseIpcDispatchInput<'_>,
) -> Result<(InterimList, Response<Body>)> {
    let ReverseIpcDispatchInput {
        base,
        state,
        conn,
        route,
        request_destination,
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
        route_timeout,
        proxy_name,
        http_modules,
        request_limits,
        request_limit_ctx,
        audit_ctx,
    } = input;
    let ipc = route
        .ipc
        .as_ref()
        .ok_or_else(|| anyhow!("reverse IPC route missing"))?;
    let _concurrency_permits = match request_limits.acquire_concurrency(request_limit_ctx) {
        Some(permits) => permits,
        None => {
            let response = concurrency_limited_response_for_parts(
                request_method,
                request_version,
                proxy_name,
                audit_ctx.clone(),
            );
            return Ok(empty_interim_response(response));
        }
    };
    let ipc_conn = ClientConnInfo {
        remote_addr: Some(conn.remote_addr),
    };
    let timeout_dur = std::cmp::min(route_timeout, ipc.timeout());
    let mut last_err = None;
    for attempt_idx in 0..attempts {
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
        let export_session =
            state.export_session_for_plan(&route.plan, conn.remote_addr, ipc.endpoint_label());
        req_for_upstream = crate::http::capture::stream::emit_request_for_export(
            req_for_upstream,
            &route.plan,
            export_session.as_ref(),
            true,
        )
        .await;
        let response = timeout(
            timeout_dur,
            proxy_ipc_upstream(
                &state.pools,
                req_for_upstream,
                ipc,
                proxy_name,
                ipc_conn,
                route_timeout,
            ),
        )
        .await;
        match response {
            Ok(Ok(resp)) => {
                match handle_reverse_ipc_success(ReverseIpcSuccessInput {
                    base,
                    state,
                    conn,
                    route,
                    request_destination,
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
                    started,
                    response: resp,
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
                last_err = Some(record_reverse_loop_error(state, http_modules, err, "error").await);
            }
            Err(_) => {
                let err = anyhow!("upstream timeout");
                last_err =
                    Some(record_reverse_loop_error(state, http_modules, err, "timeout").await);
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
    if let Some(stale) = finalize_dispatch_stale_if_error_response(
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
        return Ok(empty_interim_response(stale));
    }
    if let Some(err) = last_err.as_ref() {
        http_modules.on_error(err).await;
    }
    Err(last_err.unwrap_or_else(|| anyhow!("upstream request failed")))
}

async fn handle_reverse_ipc_success(
    input: ReverseIpcSuccessInput<'_>,
) -> Result<ReverseAttemptOutcome> {
    let ReverseIpcSuccessInput {
        base,
        state,
        conn,
        route,
        request_destination,
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
        started,
        response,
        export_session,
    } = input;
    let resp = http_modules.on_upstream_response(response).await?;
    let response_rule = apply_dispatch_response_rules(DispatchResponseRuleInput {
        rule: ResponseRuleInput {
            route,
            base,
            conn,
            destination: request_destination,
            upstream_cert: None,
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
            selected_upstream: None,
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
        return Ok(capture_reverse_response_outcome(
            ReverseAttemptOutcome::Response(Box::new(empty_interim_response(stale))),
            route,
            export_session,
        )
        .await);
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
    Ok(ReverseAttemptOutcome::Response(Box::new(
        empty_interim_response(resp),
    )))
}

pub(super) async fn handle_reverse_websocket_upgrade(
    ctx: ReverseWebsocketDispatch<'_>,
) -> Result<(InterimList, Response<Body>)> {
    let ReverseWebsocketDispatch {
        req,
        state,
        route,
        conn,
        override_upstream,
        seed,
        sticky_seed,
        request_limit_ctx,
        request_limits,
        route_timeout,
        proxy_name,
        route_headers,
        request_method,
        http_modules,
        audit_ctx,
    } = ctx;
    let upgrade_wait_timeout =
        Duration::from_millis(state.plan.limits.timeouts.upgrade_wait_timeout_ms);
    let tunnel_idle_timeout =
        Duration::from_millis(state.plan.limits.timeouts.tunnel_idle_timeout_ms);
    let selected_upstream = if override_upstream.is_none() {
        Some(
            route
                .select_upstream(seed, sticky_seed)
                .ok_or_else(|| anyhow!("no healthy upstream"))?,
        )
    } else {
        None
    };
    let override_origin = override_upstream.map(OriginEndpoint::direct);
    let upstream_origin = override_origin
        .as_ref()
        .or_else(|| selected_upstream.as_ref().map(|upstream| &upstream.origin))
        .ok_or_else(|| anyhow!("no healthy upstream"))?;
    let export_session = state.export_session_for_plan(
        &route.plan,
        conn.remote_addr,
        upstream_origin.upstream.as_str(),
    );
    let _concurrency_permits = match acquire_reverse_upstream_concurrency(
        request_limits,
        request_limit_ctx,
        selected_upstream.as_ref(),
    ) {
        Some(permits) => permits,
        None => {
            let response = concurrency_limited_response_for_parts(
                request_method,
                req.version(),
                proxy_name,
                audit_ctx.clone(),
            );
            return Ok(empty_interim_response(response));
        }
    };
    if let Some(upstream) = selected_upstream.as_ref() {
        upstream.inflight.fetch_add(1, Ordering::Relaxed);
    }
    let started = Instant::now();
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_request_preview_async(&req).await;
        session.emit_plaintext(true, &preview);
    }
    let response = timeout(
        route_timeout,
        proxy_websocket(
            req,
            upstream_origin,
            proxy_name,
            route_timeout,
            upgrade_wait_timeout,
            tunnel_idle_timeout,
            route.upstream_trust.as_deref(),
        ),
    )
    .await;
    if let Some(upstream) = selected_upstream.as_ref() {
        upstream.inflight.fetch_sub(1, Ordering::Relaxed);
    }
    match response {
        Ok(Ok(mut resp)) => {
            if let Some(upstream) = selected_upstream.as_ref() {
                record_reverse_upstream_status(
                    upstream,
                    &route.policy,
                    resp.status(),
                    started.elapsed(),
                );
            }
            super::super::metrics::upstream_latency(state, started.elapsed());
            super::super::metrics::reverse_result(state, "ok");
            resp = http_modules.on_upstream_response(resp).await?;
            resp = http_modules.prepare_downstream_response(resp).await?;
            let keep_upgrade = resp.status() == StatusCode::SWITCHING_PROTOCOLS;
            finalize_response_with_headers_in_place(
                request_method,
                resp.version(),
                proxy_name,
                &mut resp,
                route_headers,
                keep_upgrade,
            );
            resp = crate::http::capture::stream::emit_optional_response_for_export(
                resp,
                &route.plan,
                export_session.as_ref(),
            )
            .await;
            http_modules.on_logging(Some(resp.status()), None).await;
            annotate_dispatch_response(&mut resp, audit_ctx, DispatchOutcome::Allow, &[]);
            Ok(empty_interim_response(resp))
        }
        Ok(Err(err)) => {
            http_modules.on_error(&err).await;
            if let Some(upstream) = selected_upstream.as_ref() {
                record_reverse_upstream_error(upstream, &route.policy, &err);
            }
            super::super::metrics::reverse_result(state, "error");
            Err(err)
        }
        Err(_) => {
            let err = anyhow!("upstream timeout");
            http_modules.on_error(&err).await;
            if let Some(upstream) = selected_upstream.as_ref() {
                record_reverse_upstream_timeout(upstream, &route.policy);
            }
            super::super::metrics::reverse_result(state, "timeout");
            Err(err)
        }
    }
}
