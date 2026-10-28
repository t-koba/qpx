use super::super::InterimList;
use super::super::ReverseTerminalResponse;
use super::super::mirrors::{
    record_reverse_upstream_error, record_reverse_upstream_status, record_reverse_upstream_timeout,
};
use super::success::handle_reverse_success;
use super::{
    ReverseAttemptOutcome, ReverseIpcDispatchInput, ReverseSuccessInput, ReverseWebsocketDispatch,
    acquire_reverse_upstream_concurrency, build_reverse_attempt_request,
    consume_reverse_retry_budget, record_reverse_loop_error, reverse_retry_backoff,
};
use crate::http::dispatch::{
    DispatchOutcome, annotate_dispatch_response,
    concurrency_limited_response_for_parts_with_limits, finalize_dispatch_stale_if_error_response,
};
use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use crate::ipc_client::{ClientConnInfo, IpcUpstreamRequestContext, proxy_ipc_upstream};
use crate::upstream::origin::{OriginEndpoint, proxy_websocket};
use anyhow::{Result, anyhow};
use hyper::StatusCode;
use tokio::time::{Duration, Instant, timeout};

pub(super) async fn dispatch_reverse_ipc_route<R: ReverseTerminalResponse>(
    input: ReverseIpcDispatchInput<'_>,
) -> Result<(InterimList, R)> {
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
        authorization_decision,
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
    let concurrency = request_limits.acquire_concurrency_with_retry(request_limit_ctx);
    let _concurrency_permits = match concurrency.permits {
        Some(permits) => permits,
        None => {
            let response = concurrency_limited_response_for_parts_with_limits(
                request_method,
                request_version,
                proxy_name,
                request_limits,
                concurrency.retry_after,
                audit_ctx.clone(),
            );
            return Ok((Vec::new(), R::from_finalized_http(response)));
        }
    };
    let ipc_conn = ClientConnInfo {
        remote_addr: Some(conn.remote_addr),
    };
    let verified_identity = qpx_core::ipc::meta::VerifiedIdentityContext {
        subject: identity.user.clone(),
        issuer: identity.idp.clone(),
        tenant: identity.tenant.clone(),
        groups: identity.groups.clone(),
        roles: identity.roles.clone(),
        entitlements: identity.entitlements.clone(),
        assurance: identity.auth_strength.clone(),
    };
    let verified_identity = (!verified_identity.is_empty()).then_some(verified_identity);
    let timeout_dur = std::cmp::min(route_timeout, ipc.timeout());
    let mut last_err = None;
    for attempt_idx in 0..attempts {
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
        let export_session =
            state.export_session_for_plan(&route.plan, conn.remote_addr, ipc.endpoint_label());
        req_for_upstream = crate::http::capture::stream::emit_request_for_export(
            req_for_upstream,
            &route.plan,
            export_session.as_ref(),
            true,
        )
        .await;
        let hyper_req_for_upstream = req_for_upstream
            .into_http_for_codec()
            .map_err(|err| anyhow!("{err}"))?;
        let response = timeout(
            timeout_dur,
            proxy_ipc_upstream(
                &state.pools,
                hyper_req_for_upstream,
                ipc,
                proxy_name,
                IpcUpstreamRequestContext {
                    conn: ipc_conn,
                    verified_identity: verified_identity.clone(),
                    authorization_decision: authorization_decision.cloned(),
                    route_timeout,
                },
            ),
        )
        .await;
        match response {
            Ok(Ok(resp)) => {
                let resp = http_modules.on_upstream_response(resp).await?;
                match handle_reverse_success::<R>(ReverseSuccessInput {
                    base,
                    state,
                    conn,
                    route,
                    response_destination: request_destination,
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
                    selected_upstream: None,
                    upstream_cert: None,
                    interim: InterimList::new(),
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
                last_err = Some(
                    record_reverse_loop_error(
                        state,
                        http_modules,
                        err,
                        super::super::metrics::ReverseResult::Error,
                    )
                    .await,
                );
            }
            Err(_) => {
                let err = anyhow!("upstream timeout");
                last_err = Some(
                    record_reverse_loop_error(
                        state,
                        http_modules,
                        err,
                        super::super::metrics::ReverseResult::Timeout,
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
        return Ok((Vec::new(), R::from_finalized_http(stale)));
    }
    if let Some(err) = last_err.as_ref() {
        http_modules.on_error(err).await;
    }
    Err(last_err.unwrap_or_else(|| anyhow!("upstream request failed")))
}

pub(super) async fn handle_reverse_websocket_upgrade<R: ReverseTerminalResponse>(
    ctx: ReverseWebsocketDispatch<'_>,
) -> Result<(InterimList, R)> {
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
    let concurrency = acquire_reverse_upstream_concurrency(
        request_limits,
        request_limit_ctx,
        selected_upstream.as_ref(),
    );
    let _concurrency_permits = match concurrency.permits {
        None => {
            let response = concurrency_limited_response_for_parts_with_limits(
                request_method,
                req.version(),
                proxy_name,
                request_limits,
                concurrency.retry_after,
                audit_ctx.clone(),
            );
            return Ok((Vec::new(), R::from_finalized_http(response)));
        }
        Some(permits) => permits,
    };
    let inflight_guard = selected_upstream
        .as_ref()
        .map(|upstream| upstream.hold_inflight());
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
    if let Some(guard) = inflight_guard {
        guard.release();
    }
    match response {
        Ok(Ok(mut resp)) => {
            if let Some(upstream) = selected_upstream.as_ref() {
                record_reverse_upstream_status(
                    upstream,
                    &route.policy,
                    resp.status(),
                    Some(started),
                );
            }
            if qpx_observability::metrics_enabled() {
                super::super::metrics::upstream_latency(state, started.elapsed());
                super::super::metrics::reverse_result(
                    state,
                    super::super::metrics::ReverseResult::Ok,
                );
            }
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
            let mut resp = crate::http::capture::stream::emit_optional_response_for_export(
                R::from_finalized_http(resp),
                &route.plan,
                export_session.as_ref(),
            )
            .await;
            http_modules.on_logging(Some(resp.status()), None).await;
            annotate_dispatch_response(&mut resp, audit_ctx, DispatchOutcome::Allow, &[]);
            Ok((Vec::new(), resp))
        }
        Ok(Err(err)) => {
            http_modules.on_error(&err).await;
            if let Some(upstream) = selected_upstream.as_ref() {
                record_reverse_upstream_error(upstream, &route.policy, &err);
            }
            super::super::metrics::reverse_result(
                state,
                super::super::metrics::ReverseResult::Error,
            );
            Err(err)
        }
        Err(_) => {
            let err = anyhow!("upstream timeout");
            http_modules.on_error(&err).await;
            if let Some(upstream) = selected_upstream.as_ref() {
                record_reverse_upstream_timeout(upstream, &route.policy);
            }
            super::super::metrics::reverse_result(
                state,
                super::super::metrics::ReverseResult::Timeout,
            );
            Err(err)
        }
    }
}
