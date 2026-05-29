use super::destination::classify_reverse_destination;
use super::mirrors::{record_reverse_upstream_status, request_seed};
use super::request_template::ReverseRequestTemplate;
use super::response_rules::apply_response_rules;
use super::{
    ResponseRuleDecision, ReverseConnInfo, ReverseInterimResponses, empty_interim_response,
};
use crate::http::body::Body;
use crate::http::dispatch::{
    DispatchAuditContext, annotate_dispatch_response, record_response_policy_action,
};
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::l7::{finalize_response_with_headers, handle_max_forwards_in_place};
use crate::http::protocol::websocket::is_websocket_upgrade;
use crate::ipc_client::proxy_ipc;
use crate::reverse::ReloadableReverse;
use crate::reverse::router::HttpRoute;
use crate::runtime::Runtime;
use crate::upstream::origin::{OriginEndpoint, proxy_http, proxy_http_with_interim};
use anyhow::{Result, anyhow};
use hyper::{Request, Response};
use tokio::time::{Duration, timeout};
use url::Url;

mod access;
mod dispatch_cache;
mod dispatch_http;
mod dispatch_ipc;
mod modules;
mod outcome;
mod prepare;
mod types;

use self::access::enforce_reverse_access_control;
use self::dispatch_cache::prepare_reverse_cache;
use self::dispatch_http::dispatch_reverse_http_route;
use self::dispatch_ipc::{dispatch_reverse_ipc_route, handle_reverse_websocket_upgrade};
use self::modules::prepare_reverse_modules;
use self::outcome::{
    consume_reverse_retry_budget, finish_reverse_upstream_failure, record_reverse_http_loop_error,
    record_reverse_http_loop_timeout, record_reverse_loop_error, record_reverse_success_metrics,
    reverse_retry_backoff,
};
use self::prepare::{
    attach_streaming_limits, buffer_reverse_guarded_request, prepare_reverse_request,
    prepare_reverse_retry_dispatch,
};
use self::types::*;

#[tracing::instrument(
    skip_all,
    fields(kind = "reverse", host = %base.host.as_deref().unwrap_or(""), method = %base.method)
)]
pub(super) async fn dispatch_reverse_request(
    req: Request<Body>,
    base: BaseRequestFields,
    reverse: ReloadableReverse,
    runtime: Runtime,
    conn: ReverseConnInfo,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    let compiled = reverse.compiled().await;
    let prepared = match prepare_reverse_request(req, &base, &runtime, &conn, compiled).await? {
        Ok(prepared) => prepared,
        Err(response) => return Ok(response),
    };
    execute_reverse_request(prepared, base, reverse, runtime, conn).await
}

async fn execute_reverse_request(
    prepared: PreparedReverseRequest,
    base: BaseRequestFields,
    reverse: ReloadableReverse,
    runtime: Runtime,
    conn: ReverseConnInfo,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    let PreparedReverseRequest {
        mut req,
        context,
        route: prepared_route,
        observation,
    } = prepared;
    let router = context.router;
    let state = context.state;
    let proxy_name = context.proxy_name;
    let host = prepared_route.host;
    let request_method = prepared_route.request_method;
    let request_version = prepared_route.request_version;
    let path_owned = prepared_route.path_owned;
    let request_uri = prepared_route.request_uri;
    let route_idx = prepared_route.route_idx;
    let selected_policy = prepared_route.selected_policy;
    let identity = prepared_route.identity;
    let sanitized_headers = prepared_route.sanitized_headers;
    let request_destination_cache = prepared_route.request_destination_cache;
    let max_observed_request_body_bytes = prepared_route.max_observed_request_body_bytes;
    let request_rpc = observation.request_rpc;
    let route = Some(route_idx)
        .and_then(|idx| router.route_at(idx))
        .ok_or_else(|| anyhow!("no route matched"))?;
    let streaming = route.plan.streaming;
    debug_assert!(match &route.target {
        crate::runtime::CompiledReverseRouteTarget::Upstream { .. }
        | crate::runtime::CompiledReverseRouteTarget::Weighted { .. } =>
            route.local_response.is_none() && route.ipc.is_none(),
        crate::runtime::CompiledReverseRouteTarget::Ipc { .. } =>
            route.local_response.is_none() && route.ipc.is_some(),
        crate::runtime::CompiledReverseRouteTarget::LocalResponse { .. } =>
            route.local_response.is_some() && route.ipc.is_none(),
        crate::runtime::CompiledReverseRouteTarget::TlsPassthrough { .. } => false,
    });
    let resolution_override = route.plan.destination_resolution.as_ref();
    let route_http_guard = route.plan.guard.as_deref();
    let route_max_observed_request_body_bytes = route_http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(max_observed_request_body_bytes))
        .unwrap_or(max_observed_request_body_bytes);
    let request_destination = request_destination_cache
        .get(&format!("{:?}", resolution_override))
        .cloned()
        .unwrap_or_else(|| {
            classify_reverse_destination(&state, &conn, host.as_str(), None, resolution_override)
        });
    req = match buffer_reverse_guarded_request(
        req,
        route_http_guard,
        route_max_observed_request_body_bytes,
        Duration::from_millis(streaming.body_read_timeout_ms),
        &request_method,
        request_version,
        proxy_name.as_ref(),
    )
    .await?
    {
        Ok(req) => req,
        Err(response) => return Ok(empty_interim_response(response)),
    };
    let seed = request_seed(&conn, host.as_str(), &req);
    let sticky_seed = route.affinity_seed(&conn, host.as_str(), &req, &identity);
    let access = match enforce_reverse_access_control(ReverseAccessInput {
        state: &state,
        reverse_name: reverse.name.as_ref(),
        proxy_name: proxy_name.as_ref(),
        conn: &conn,
        host: host.as_str(),
        request_method: &request_method,
        path: path_owned.as_deref(),
        request_uri: request_uri.as_str(),
        req,
        route,
        selected_policy: &selected_policy,
        identity: &identity,
        sanitized_headers: &sanitized_headers,
        request_destination: &request_destination,
    })
    .await?
    {
        ReverseAccessOutcome::Response(response) => {
            return Ok(attach_streaming_limits(
                empty_interim_response(*response),
                streaming,
            ));
        }
        ReverseAccessOutcome::Continue(access) => *access,
    };
    let ReverseAccessControl {
        mut req,
        log_context,
        ext_authz_policy_id,
        route_headers,
        override_upstream,
        route_timeout,
        cache_bypass,
        ext_authz_mirror_upstreams,
        request_limit_ctx,
        mut request_limits,
    } = access;
    let audit_ctx = DispatchAuditContext::new(
        state.clone(),
        crate::http::dispatch::ProxyKind::Reverse,
        reverse.name.as_ref(),
        conn.remote_addr,
        request_method.clone(),
        path_owned.clone(),
        log_context,
    )
    .with_host((!host.is_empty()).then_some(host.clone()))
    .with_sni(conn.tls_sni.as_deref().map(ToOwned::to_owned))
    .with_matched_route(route.name.as_deref().map(ToOwned::to_owned))
    .with_ext_authz_policy_id(ext_authz_policy_id);

    if let Some(response) = handle_max_forwards_in_place(
        &mut req,
        proxy_name.as_str(),
        state.plan.limits.general.trace_reflect_all_headers,
        state.plan.limits.body.max_observed_request_body_bytes,
        std::time::Duration::from_millis(streaming.body_read_timeout_ms),
    )
    .await
    {
        let mut response = response;
        annotate_dispatch_response(
            &mut response,
            &audit_ctx,
            crate::http::dispatch::DispatchOutcome::MaxForwards,
            &[],
        );
        return Ok(attach_streaming_limits(
            empty_interim_response(response),
            streaming,
        ));
    }

    let module_dispatch = match prepare_reverse_modules(ReverseModuleInput {
        req,
        state: &state,
        selected_policy: &selected_policy,
        conn: &conn,
        route,
        reverse_name: reverse.name.as_ref(),
        proxy_name: proxy_name.as_ref(),
        identity: &identity,
        route_headers: route_headers.as_deref(),
        cache_bypass,
        audit_ctx: &audit_ctx,
    })
    .await?
    {
        ReverseModuleOutcome::Response(response) => {
            return Ok(attach_streaming_limits(
                empty_interim_response(*response),
                streaming,
            ));
        }
        ReverseModuleOutcome::Continue(dispatch) => *dispatch,
    };
    let ReverseModuleDispatch {
        req,
        http_modules,
        request_cache_policy,
    } = module_dispatch;
    let result = complete_reverse_after_modules(ReversePostModuleInput {
        req,
        http_modules,
        request_cache_policy,
        base: &base,
        runtime: &runtime,
        state: &state,
        conn: &conn,
        host: host.as_str(),
        route,
        resolution_override,
        request_destination: &request_destination,
        request_method: &request_method,
        request_version,
        request_rpc: request_rpc.as_ref(),
        identity: &identity,
        route_headers,
        override_upstream: override_upstream.as_deref(),
        ext_authz_mirror_upstreams,
        seed,
        sticky_seed,
        route_timeout,
        proxy_name: proxy_name.as_str(),
        request_limits: &mut request_limits,
        request_limit_ctx: &request_limit_ctx,
        audit_ctx: &audit_ctx,
    })
    .await?;
    Ok(attach_streaming_limits(result, streaming))
}

async fn complete_reverse_after_modules(
    input: ReversePostModuleInput<'_>,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    let ReversePostModuleInput {
        req,
        mut http_modules,
        request_cache_policy,
        base,
        runtime,
        state,
        conn,
        host,
        route,
        resolution_override,
        request_destination,
        request_method,
        request_version,
        request_rpc,
        identity,
        route_headers,
        override_upstream,
        ext_authz_mirror_upstreams,
        seed,
        sticky_seed,
        route_timeout,
        proxy_name,
        request_limits,
        request_limit_ctx,
        audit_ctx,
    } = input;
    if is_websocket_upgrade(req.headers()) {
        return handle_reverse_websocket_upgrade(ReverseWebsocketDispatch {
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
            route_headers: route_headers.as_deref(),
            request_method,
            http_modules: &mut http_modules,
            audit_ctx,
        })
        .await;
    }
    let cache_state = match prepare_reverse_cache(ReverseCacheInput {
        req,
        runtime,
        state,
        route,
        conn,
        request_method,
        request_version,
        proxy_name,
        route_headers: route_headers.as_deref(),
        request_cache_policy: request_cache_policy.as_ref(),
        override_upstream,
        seed,
        sticky_seed,
        route_timeout,
        http_modules: &mut http_modules,
        audit_ctx,
    })
    .await?
    {
        ReverseCacheOutcome::Response(response) => return Ok(empty_interim_response(*response)),
        ReverseCacheOutcome::Continue(state) => *state,
    };
    let ReverseCacheState {
        req,
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        revalidation_state,
        cache_collapse_guard,
    } = cache_state;
    let cache_policy = request_cache_policy.as_ref();
    let ReverseRetryDispatch {
        attempts,
        first_request,
        template,
        mirror_upstreams,
    } = prepare_reverse_retry_dispatch(ReverseRetryPrepareInput {
        req,
        route,
        state,
        request_method,
        seed,
        sticky_seed,
        ext_authz_mirror_upstreams,
        route_timeout,
        proxy_name,
    })
    .await?;
    if override_upstream.is_none() && route.ipc.is_some() {
        return dispatch_reverse_ipc_route(ReverseIpcDispatchInput {
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
            request_headers_snapshot: request_headers_snapshot.as_ref(),
            cache_lookup_key: cache_lookup_key.as_ref(),
            cache_target_key: cache_target_key.as_ref(),
            revalidation_state,
            cache_collapse_guard,
            first_request,
            template,
            mirror_upstreams,
            attempts,
            route_timeout,
            proxy_name,
            http_modules: &mut http_modules,
            request_limits,
            request_limit_ctx,
            audit_ctx,
        })
        .await;
    }
    dispatch_reverse_http_route(ReverseHttpDispatchInput {
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
        request_headers_snapshot: request_headers_snapshot.as_ref(),
        cache_lookup_key: cache_lookup_key.as_ref(),
        cache_target_key: cache_target_key.as_ref(),
        revalidation_state,
        cache_collapse_guard,
        first_request,
        template,
        mirror_upstreams,
        attempts,
        override_upstream,
        seed,
        sticky_seed,
        route_timeout,
        proxy_name,
        http_modules: &mut http_modules,
        request_limits,
        request_limit_ctx,
        audit_ctx,
    })
    .await
}

async fn reverse_continue_response_rule(
    input: ReverseResponseRuleInput<'_>,
) -> Result<std::result::Result<ReverseResponseRuleContinue, ReverseAttemptOutcome>> {
    let ReverseResponseRuleInput {
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
    } = input;
    match response_rule {
        ResponseRuleDecision::Continue {
            response,
            route_headers,
            cache_bypass,
            policy_tags,
            suppress_retry,
            mirror,
        } => {
            record_response_policy_action(audit_ctx.kind, "continue");
            if response.status().is_server_error() && attempt_idx + 1 < attempts && !suppress_retry
            {
                if let Some(upstream) = selected_upstream {
                    record_reverse_upstream_status(
                        upstream,
                        &route.policy,
                        response.status(),
                        started.elapsed(),
                    );
                }
                let retry_reason = format!("upstream returned {}", response.status());
                let err = anyhow!(retry_reason.clone());
                if !consume_reverse_retry_budget(state, route) {
                    return Ok(Err(ReverseAttemptOutcome::Stop(err)));
                }
                http_modules
                    .on_retry(attempt_idx + 2, retry_reason.as_str())
                    .await?;
                reverse_retry_backoff(route).await;
                return Ok(Err(ReverseAttemptOutcome::Retry(err)));
            }
            Ok(Ok((
                response,
                route_headers,
                cache_bypass,
                policy_tags,
                mirror,
            )))
        }
        ResponseRuleDecision::LocalResponse {
            response,
            route_headers,
            policy_tags,
        } => {
            let response = http_modules.prepare_downstream_response(response).await?;
            let mut response = finalize_response_with_headers(
                request_method,
                request_version,
                proxy_name,
                response,
                route_headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(response.status()), None).await;
            annotate_dispatch_response(
                &mut response,
                audit_ctx,
                crate::http::dispatch::DispatchOutcome::ResponseRuleLocalResponse,
                policy_tags.as_ref(),
            );
            Ok(Err(ReverseAttemptOutcome::Response(Box::new(
                empty_interim_response(response),
            ))))
        }
    }
}

fn build_reverse_attempt_request(
    attempt_idx: usize,
    first_request: &mut Option<Request<Body>>,
    template: Option<&ReverseRequestTemplate>,
) -> Result<Request<Body>> {
    if attempt_idx == 0 {
        return match (template, first_request.take()) {
            (Some(template), _) => template.build(),
            (None, Some(req)) => Ok(req),
            (None, None) => Err(anyhow!("missing reverse request for first attempt")),
        };
    }
    template
        .ok_or_else(|| anyhow!("reverse retry template missing"))?
        .build()
}

async fn proxy_reverse_http_attempt(
    req_for_upstream: Request<Body>,
    upstream_origin: &OriginEndpoint,
    request_version: http::Version,
    proxy_name: &str,
    route: &HttpRoute,
    route_timeout: Duration,
) -> std::result::Result<
    Result<(
        ReverseInterimResponses,
        Response<Body>,
        Option<crate::tls::cert_info::UpstreamCertificateInfo>,
    )>,
    tokio::time::error::Elapsed,
> {
    timeout(route_timeout, async {
        if upstream_origin.upstream.starts_with("ipc://")
            || upstream_origin.upstream.starts_with("ipc+unix://")
        {
            let url = Url::parse(upstream_origin.upstream.as_str())
                .map_err(|err| anyhow!("invalid ipc upstream url: {}", err))?;
            return Ok((
                Vec::new(),
                proxy_ipc(req_for_upstream, &url, proxy_name).await?,
                None,
            ));
        }
        if matches!(
            request_version,
            http::Version::HTTP_10
                | http::Version::HTTP_11
                | http::Version::HTTP_2
                | http::Version::HTTP_3
        ) {
            let proxied = proxy_http_with_interim(
                req_for_upstream,
                upstream_origin,
                proxy_name,
                route.upstream_trust.as_deref(),
            )
            .await?;
            return Ok((proxied.interim, proxied.response, proxied.upstream_cert));
        }
        Ok((
            Vec::new(),
            proxy_http(
                req_for_upstream,
                upstream_origin,
                proxy_name,
                route.upstream_trust.as_deref(),
            )
            .await?,
            None,
        ))
    })
    .await
}
