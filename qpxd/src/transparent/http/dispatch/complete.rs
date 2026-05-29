use super::super::{ConnectTarget, resolve_upstream};
use super::access::{TransparentAccessInput, enforce_transparent_access_control};
use super::local::{TransparentWebsocketInput, proxy_transparent_websocket};
use super::types::{TransparentAccessOutcome, TransparentPreparedRequest};
use crate::http::body::Body;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchResponsePolicyInput, DispatchResponsePolicyOutcome,
    annotate_dispatch_response, apply_dispatch_response_policy, record_upstream_request_duration,
};
use crate::http::policy::response_policy::ResponseBodyObservationLimits;
use crate::http::policy::rule_context::{
    ResponseRuleContextInput, build_response_rule_match_context,
};
use crate::http::protocol::common::too_many_requests_response as too_many_requests;
use crate::http::protocol::l7::{
    finalize_response_for_request, finalize_response_with_headers_in_place,
    handle_max_forwards_in_place, prepare_request_with_headers_in_place,
};
use crate::http::protocol::websocket::is_websocket_upgrade;
use crate::policy_context::strip_untrusted_identity_headers;
use crate::rate_limit::RateLimitContext;
use crate::upstream::http1::proxy_http1_request_with_interim;
use anyhow::Result;
use hyper::{Request, Response, StatusCode};
use qpx_core::prefilter::MatchPrefilterContext;
use std::sync::Arc;
use tokio::time::Duration;

pub(super) async fn complete_transparent_request(
    prepared: TransparentPreparedRequest,
) -> Result<hyper::Response<Body>> {
    let TransparentPreparedRequest {
        mut req,
        context,
        policy: prepared_policy,
        limits,
        observation,
        mode,
        base,
    } = prepared;
    let state = context.state;
    let proxy_name = context.proxy_name;
    let listener_name = context.listener_name;
    let listener_cfg = context.listener_cfg;
    let remote_addr = context.remote_addr;
    let connect_target = mode.connect_target;
    let host_for_match = mode.host_for_match;
    let effective_policy = prepared_policy.effective_policy;
    let destination = prepared_policy.destination;
    let identity = prepared_policy.identity;
    let sanitized_headers = prepared_policy.sanitized_headers;
    let response_engine = prepared_policy.response_engine;
    let selected_plan = prepared_policy.selected_plan;
    let policy = prepared_policy.policy;
    let early_response = prepared_policy.early_response;
    let matched_rule = prepared_policy.matched_rule;
    let mut request_limits = limits.request_limits;
    let request_limit_ctx = limits.request_limit_ctx;
    let max_observed_request_body_bytes = limits.max_observed_request_body_bytes;
    let body_read_timeout = limits.body_read_timeout;
    let mut request_rpc = observation.request_rpc;
    let response_request_observation = observation.response_request_observation;
    let request_body_observed = observation.request_body_observed;
    let request_rpc_observed = observation.request_rpc_observed;
    let proxy_name = proxy_name.as_str();
    let listener_name = listener_name.as_str();
    let request_method = req.method().clone();
    let request_version = req.version();
    let access = match enforce_transparent_access_control(TransparentAccessInput {
        state: state.clone(),
        proxy_name,
        listener_name,
        remote_addr,
        connect_target: &connect_target,
        host_for_match: &host_for_match,
        base: &base,
        effective_policy: &effective_policy,
        destination: &destination,
        identity: &identity,
        sanitized_headers: &sanitized_headers,
        request_method: request_method.clone(),
        request_version,
        request_uri: base.request_uri.clone(),
        policy,
        early_response,
        matched_rule: matched_rule.clone(),
        request_limits: &mut request_limits,
        request_limit_ctx: &request_limit_ctx,
    })
    .await?
    {
        TransparentAccessOutcome::Response(response) => return Ok(*response),
        TransparentAccessOutcome::Continue(access) => *access,
    };
    let mut policy = access.policy;
    let timeout_override = access.timeout_override;
    let audit = access.audit;

    if !response_request_observation.is_empty()
        && ((response_request_observation.needs_body && !request_body_observed)
            || (response_request_observation.needs_rpc && !request_rpc_observed))
    {
        let observation_plan =
            crate::http::body::observation::RequestObservationPlan::from_requirements(
                response_request_observation,
            );
        req = match observation_plan
            .observe_request(req, max_observed_request_body_bytes, body_read_timeout)
            .await
        {
            Ok(req) => req,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                let mut response = finalize_response_for_request(
                    &base.method,
                    request_version,
                    proxy_name,
                    Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Body::from("request body too large"))?,
                    false,
                );
                annotate_dispatch_response(
                    &mut response,
                    &audit,
                    crate::http::dispatch::DispatchOutcome::Error,
                    &[],
                );
                return Ok(response);
            }
            Err(err) => return Err(err),
        };
        if observation_plan.needs_rpc {
            request_rpc = Some(crate::http::rpc::inspect_request(&req).await);
        }
    }

    if let Some(response) = handle_max_forwards_in_place(
        &mut req,
        proxy_name,
        state.plan.limits.general.trace_reflect_all_headers,
        state.plan.limits.body.max_observed_request_body_bytes,
        std::time::Duration::from_millis(selected_plan.streaming.body_read_timeout_ms),
    )
    .await
    {
        let mut response = response;
        annotate_dispatch_response(
            &mut response,
            &audit,
            crate::http::dispatch::DispatchOutcome::MaxForwards,
            &[],
        );
        return Ok(response);
    }
    strip_untrusted_identity_headers(
        &state,
        &effective_policy,
        remote_addr.ip(),
        req.headers_mut(),
    )?;
    let websocket = is_websocket_upgrade(req.headers());
    prepare_request_with_headers_in_place(
        &mut req,
        proxy_name,
        policy.headers.as_deref(),
        websocket,
    );
    let mut http_modules = selected_plan.modules.start(
        state.clone(),
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: crate::http::dispatch::ProxyKind::Transparent,
            proxy_name,
            scope_name: listener_name,
            route_name: None,
            remote_ip: remote_addr.ip(),
            sni: None,
            identity_user: identity.user.as_deref(),
            cache_policy: None,
            cache_default_scheme: None,
        },
    );
    match http_modules.on_request_headers(&mut req).await? {
        crate::http::modules::RequestHeadersOutcome::Continue => {}
        crate::http::modules::RequestHeadersOutcome::Respond(response) => {
            let mut response = http_modules.prepare_downstream_response(*response).await?;
            let response_version = response.version();
            finalize_response_with_headers_in_place(
                &request_method,
                response_version,
                proxy_name,
                &mut response,
                policy.headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(response.status()), None).await;
            annotate_dispatch_response(
                &mut response,
                &audit,
                crate::http::dispatch::DispatchOutcome::HttpModuleLocalResponse,
                &[],
            );
            return Ok(response);
        }
    }

    let upstream = resolve_upstream(&policy.action, &state, &listener_cfg)?;
    let rate_limit_ctx = RateLimitContext::from_identity(
        remote_addr.ip(),
        &identity,
        matched_rule.as_deref(),
        upstream.as_ref().map(|upstream| upstream.key()),
    );
    let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_ctx) {
        Some(permits) => permits,
        None => {
            let mut response = finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                too_many_requests(None),
                false,
            );
            annotate_dispatch_response(
                &mut response,
                &audit,
                crate::http::dispatch::DispatchOutcome::ConcurrencyLimited,
                &[],
            );
            return Ok(response);
        }
    };
    let upstream_timeout = timeout_override.unwrap_or_else(|| {
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms)
    });
    let upgrade_wait_timeout =
        Duration::from_millis(state.plan.limits.timeouts.upgrade_wait_timeout_ms);
    let tunnel_idle_timeout =
        Duration::from_millis(state.plan.limits.timeouts.tunnel_idle_timeout_ms);
    let authority = connect_target.authority();
    let export_session =
        state.export_session_for_plan(&selected_plan, remote_addr, authority.as_str());
    if websocket {
        return proxy_transparent_websocket(TransparentWebsocketInput {
            req,
            upstream: upstream.as_ref(),
            authority: authority.as_str(),
            upstream_timeout,
            upgrade_wait_timeout,
            tunnel_idle_timeout,
            http_modules: &mut http_modules,
            export_session: export_session.as_ref(),
            request_method: &request_method,
            proxy_name,
            policy_headers: policy.headers.as_deref(),
            audit: &audit,
        })
        .await;
    }

    proxy_transparent_http1(
        req,
        upstream.as_ref(),
        authority.as_str(),
        upstream_timeout,
        &mut http_modules,
        export_session.as_ref(),
        TransparentResponsePolicyInput {
            state: &state,
            response_engine: response_engine.as_deref(),
            selected_plan: &selected_plan,
            base: &base,
            destination: &destination,
            identity: &identity,
            connect_target: &connect_target,
            host_for_match: &host_for_match,
            request_method: &request_method,
            request_version,
            proxy_name,
            request_rpc: request_rpc.as_ref(),
            headers: &mut policy.headers,
            audit: &audit,
        },
    )
    .await
}

pub(super) struct TransparentResponsePolicyInput<'a> {
    pub(super) state: &'a Arc<crate::runtime::RuntimeState>,
    pub(super) response_engine:
        Option<&'a crate::http::policy::response_policy::HttpResponseRuleEngine>,
    pub(super) selected_plan: &'a crate::runtime::ExecutionPlan,
    pub(super) base: &'a crate::http::protocol::base_fields::BaseRequestFields,
    pub(super) destination: &'a crate::destination::DestinationMetadata,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) connect_target: &'a ConnectTarget,
    pub(super) host_for_match: &'a Option<String>,
    pub(super) request_method: &'a hyper::Method,
    pub(super) request_version: hyper::Version,
    pub(super) proxy_name: &'a str,
    pub(super) request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    pub(super) headers: &'a mut Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    pub(super) audit: &'a DispatchAuditContext,
}

pub(super) async fn proxy_transparent_http1(
    mut req: Request<Body>,
    upstream: Option<&crate::upstream::pool::ResolvedUpstreamProxy>,
    authority: &str,
    upstream_timeout: Duration,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    export_session: Option<&crate::exporter::ExportSession>,
    input: TransparentResponsePolicyInput<'_>,
) -> Result<hyper::Response<Body>> {
    let upstream_started = std::time::Instant::now();
    http_modules.on_upstream_request(&mut req).await?;
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_request_preview_async(&req).await;
        session.emit_plaintext(true, &preview);
        if let Some(sample_bytes) = input.selected_plan.capture_stream_sample_bytes() {
            req = crate::http::capture::stream::sample_request_body_for_export(
                req,
                sample_bytes,
                input.selected_plan.streaming.body_channel_capacity,
                std::time::Duration::from_millis(
                    input.selected_plan.streaming.body_read_timeout_ms,
                ),
                session.clone(),
                true,
            );
        } else if let Some(max_capture_bytes) = input.selected_plan.capture_full_body_bytes() {
            req = crate::http::capture::stream::capture_request_body_for_export(
                req,
                max_capture_bytes,
                input.selected_plan.streaming.body_channel_capacity,
                std::time::Duration::from_millis(
                    input.selected_plan.streaming.body_read_timeout_ms,
                ),
                session.clone(),
                true,
            );
        }
    }
    let proxied_result =
        proxy_http1_request_with_interim(req, upstream, authority, upstream_timeout).await;
    record_upstream_request_duration(input.audit.kind, upstream_started.elapsed());
    let proxied = match proxied_result {
        Ok(proxied) => proxied,
        Err(err) => {
            http_modules.on_error(&err).await;
            return Err(err);
        }
    };
    let mut response = proxied.response;
    if !proxied.interim.is_empty() {
        response.extensions_mut().insert(proxied.interim);
    }
    response = http_modules.on_upstream_response(response).await?;
    let response_candidates = input
        .response_engine
        .map(|engine| {
            engine.candidate_profile(MatchPrefilterContext {
                method: Some(input.request_method.as_str()),
                dst_port: Some(input.connect_target.port()),
                src_ip: Some(input.audit.remote_addr.ip()),
                host: input.host_for_match.as_deref(),
                sni: None,
                path: input.base.path.as_deref(),
            })
        })
        .unwrap_or_default();
    let response_status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let response_policy_tags = match apply_dispatch_response_policy(DispatchResponsePolicyInput {
        response,
        engine: input.response_engine,
        candidates: response_candidates,
        rule_context: build_response_rule_match_context(ResponseRuleContextInput {
            base: input.base,
            headers: &response_headers,
            destination: input.destination,
            identity: input.identity,
            response_status,
            response_size: None,
            rpc: None,
            client_cert: None,
            upstream_cert: None,
        }),
        headers: input.headers.as_ref().cloned(),
        request_rpc: input.request_rpc,
        body_observation: ResponseBodyObservationLimits {
            max_body_bytes: input.selected_plan.body_observation_limit(
                input
                    .state
                    .plan
                    .limits
                    .body
                    .max_observed_response_body_bytes,
            ),
            read_timeout: std::time::Duration::from_millis(
                input
                    .state
                    .plan
                    .limits
                    .timeouts
                    .upstream_http_timeout_ms
                    .max(1),
            ),
            force_body: false,
        },
        http_modules,
        audit: input.audit,
        request_method: input.request_method,
        request_version: input.request_version,
        proxy_name: input.proxy_name,
        pre_finalize_local_response: true,
    })
    .await?
    {
        DispatchResponsePolicyOutcome::Continue {
            response: updated,
            headers: updated_headers,
            cache_bypass: _cache_bypass,
            suppress_retry: _suppress_retry,
            mirror: _mirror,
            policy_tags,
        } => {
            response = updated;
            *input.headers = updated_headers;
            policy_tags
        }
        DispatchResponsePolicyOutcome::Response(response) => return Ok(response),
    };
    response = http_modules.prepare_downstream_response(response).await?;
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_response_preview_async(&response).await;
        session.emit_plaintext(false, &preview);
        if let Some(sample_bytes) = input.selected_plan.capture_stream_sample_bytes() {
            response = crate::http::capture::stream::sample_response_body_for_export(
                response,
                sample_bytes,
                input.selected_plan.streaming.body_channel_capacity,
                std::time::Duration::from_millis(
                    input.selected_plan.streaming.body_read_timeout_ms,
                ),
                session.clone(),
            );
        } else if let Some(max_capture_bytes) = input.selected_plan.capture_full_body_bytes() {
            response = crate::http::capture::stream::capture_response_body_for_export(
                response,
                max_capture_bytes,
                input.selected_plan.streaming.body_channel_capacity,
                std::time::Duration::from_millis(
                    input.selected_plan.streaming.body_read_timeout_ms,
                ),
                session.clone(),
            );
        }
    }
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        input.request_method,
        response_version,
        input.proxy_name,
        &mut response,
        input.headers.as_ref().map(|headers| headers.as_ref()),
        false,
    );
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_dispatch_response(
        &mut response,
        input.audit,
        crate::http::dispatch::DispatchOutcome::Allow,
        &response_policy_tags,
    );
    Ok(response)
}
