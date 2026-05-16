use super::*;

pub(super) async fn dispatch_reverse_ipc_route(
    input: ReverseIpcDispatchInput<'_>,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
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
        mut first_request,
        template,
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
    let ipc_conn = ClientConnInfo {
        remote_addr: Some(conn.remote_addr),
    };
    let timeout_dur = std::cmp::min(route_timeout, ipc.timeout());
    let mut last_err = None;
    for attempt_idx in 0..attempts {
        let started = Instant::now();
        let mut req_for_upstream =
            build_reverse_attempt_request(attempt_idx, &mut first_request, template.as_ref())?;
        http_modules
            .on_upstream_request(&mut req_for_upstream)
            .await?;
        let export_session =
            state.export_session_for_plan(&route.plan, conn.remote_addr, ipc.endpoint_label());
        if let Some(session) = export_session.as_ref() {
            let preview = crate::exporter::serialize_request_preview(&req_for_upstream);
            session.emit_plaintext(true, &preview);
        }
        let response = timeout(
            timeout_dur,
            proxy_ipc_upstream(req_for_upstream, ipc, proxy_name, ipc_conn, route_timeout),
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
                    template: template.as_ref(),
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
        template,
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
    let response_rule = apply_response_rules(ResponseRuleInput {
        route,
        base,
        conn,
        destination: request_destination,
        upstream_cert: None,
        identity,
        request_rpc,
        route_headers: route_headers.clone(),
        response: resp,
        max_observed_response_body_bytes: route
            .plan
            .body_observation_limit(state.plan.limits.max_observed_response_body_bytes),
        response_body_read_timeout: Duration::from_millis(
            state.plan.limits.upstream_http_timeout_ms.max(1),
        ),
        force_response_body_observation: route
            .plan
            .flags
            .contains(crate::runtime::PlanFlags::CAPTURE_BODY),
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
            selected_upstream: None,
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
        let preview = crate::exporter::serialize_response_preview(&resp);
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
        return Ok(ReverseAttemptOutcome::Response(Box::new(
            empty_interim_response(stale),
        )));
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
    Ok(ReverseAttemptOutcome::Response(Box::new(
        empty_interim_response(resp),
    )))
}

pub(super) async fn handle_reverse_websocket_upgrade(
    ctx: ReverseWebsocketDispatch<'_>,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
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
    let upgrade_wait_timeout = Duration::from_millis(state.plan.limits.upgrade_wait_timeout_ms);
    let tunnel_idle_timeout = Duration::from_millis(state.plan.limits.tunnel_idle_timeout_ms);
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
                req.version(),
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
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_request_preview(&req);
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
            resp = http_modules.on_upstream_response(resp).await?;
            resp = http_modules.prepare_downstream_response(resp).await?;
            if let Some(session) = export_session.as_ref() {
                let preview = crate::exporter::serialize_response_preview(&resp);
                session.emit_plaintext(false, &preview);
            }
            let keep_upgrade = resp.status() == StatusCode::SWITCHING_PROTOCOLS;
            let resp_version = resp.version();
            finalize_response_with_headers_in_place(
                request_method,
                resp_version,
                proxy_name,
                &mut resp,
                route_headers,
                keep_upgrade,
            );
            http_modules.on_logging(Some(resp.status()), None).await;
            annotate_dispatch_response(
                &mut resp,
                audit_ctx,
                crate::http::dispatch::DispatchOutcome::Allow,
                &[],
            );
            Ok(empty_interim_response(resp))
        }
        Ok(Err(err)) => {
            http_modules.on_error(&err).await;
            if let Some(upstream) = selected_upstream.as_ref() {
                record_reverse_upstream_error(upstream, &route.policy, &err);
            }
            counter!(
                state.observability.metric_names.reverse_requests_total.clone(),
                "result" => "error"
            )
            .increment(1);
            Err(err)
        }
        Err(_) => {
            let err = anyhow!("upstream timeout");
            http_modules.on_error(&err).await;
            if let Some(upstream) = selected_upstream.as_ref() {
                record_reverse_upstream_timeout(upstream, &route.policy);
            }
            counter!(
                state.observability.metric_names.reverse_requests_total.clone(),
                "result" => "timeout"
            )
            .increment(1);
            Err(err)
        }
    }
}
