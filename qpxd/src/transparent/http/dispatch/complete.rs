use super::super::{ConnectTarget, resolve_upstream};
use super::local::{TransparentWebsocketInput, proxy_transparent_websocket};
use super::types::TransparentPreparedRequest;
use crate::http::body::size::limit_request_body;
use crate::http::capture::stream::emit_optional_response_for_export;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchOutcome, DispatchResponsePolicyInput,
    DispatchResponsePolicyOutcome, ProxyKind, annotate_dispatch_response,
    annotated_max_forwards_response, apply_dispatch_response_policy,
    concurrency_limited_response_for_parts as concurrency_limited_response,
    prepare_http_module_local_response, record_upstream_request_duration,
    request_body_too_large_response as body_too_large_response,
};
use crate::http::policy::response_policy::ResponseBodyObservationLimits;
use crate::http::policy::rule_context::{
    ResponseRuleContextInput, build_response_rule_match_context,
};
use crate::http::protocol::l7::{
    finalize_response_with_headers_in_place, prepare_request_with_headers_in_place,
};
use crate::http::protocol::websocket::is_websocket_upgrade;
use crate::policy_context::strip_untrusted_identity_headers;
use crate::rate_limit::RateLimitContext;
use crate::upstream::http1::proxy_http1_request_with_interim;
use anyhow::Result;
use hyper::Request;
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_http::body::Body;
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
    let mut request_rpc = observation.request_rpc;
    let proxy_name = proxy_name.as_str();
    let listener_name = listener_name.as_str();
    let request_method = req.method().clone();
    let request_version = req.version();
    let remote_ip = remote_addr.ip();
    // `policy` and `early_response` are mutually exclusive listener-policy
    // outcomes; ext_authz is enforced only when a policy proceeded.
    let mut policy = policy;
    let base_headers = policy.as_mut().and_then(|policy| policy.headers.take());
    let decision =
        crate::http::dispatch::enforce_http_access(crate::http::dispatch::HttpAccessInput {
            state: &state,
            policy: &effective_policy,
            kind: ProxyKind::Transparent,
            mode: crate::policy_context::ExtAuthzMode::TransparentHttp,
            enforce_ext_authz: policy.is_some(),
            proxy_name,
            scope_name: listener_name,
            remote_addr,
            dst_port: Some(connect_target.port()),
            host: host_for_match.as_deref(),
            sni: None,
            request_method: &request_method,
            request_version,
            path: base.path.as_deref(),
            uri: Some(base.request_uri.as_str()),
            matched_rule: matched_rule.as_deref(),
            matched_route: None,
            action: policy.as_ref().map(|policy| &policy.action),
            sanitized_headers: &sanitized_headers,
            identity: &identity,
            destination: &destination,
            base_headers,
            request_limit: Some((
                &mut request_limits,
                &request_limit_ctx,
                &state.policy.rate_limiters,
            )),
            default_deny_response: crate::http::protocol::common::forbidden_response(
                state.messages.forbidden.as_str(),
            ),
        })
        .await?;
    let (mut policy, audit, timeout_override) = match decision {
        crate::http::dispatch::HttpAccessDecision::Blocked { response, .. } => {
            return Ok(crate::http::capture::stream::limit_response_body_for_plan(
                *response,
                &selected_plan,
            ));
        }
        crate::http::dispatch::HttpAccessDecision::Allow(allowed) => {
            let crate::http::dispatch::HttpAccessAllowed { audit, controls } = *allowed;
            if let Some(mut response) = early_response {
                annotate_dispatch_response(
                    &mut response,
                    &audit,
                    DispatchOutcome::EarlyResponse,
                    &[],
                );
                return Ok(crate::http::capture::stream::limit_response_body_for_plan(
                    *response,
                    &selected_plan,
                ));
            }
            let Some(mut policy) = policy else {
                return Err(anyhow::anyhow!(
                    "transparent policy missing after early response handling"
                ));
            };
            let timeout_override = controls.as_ref().and_then(|allow| allow.timeout_override);
            if let Some(allow) = controls {
                policy.headers = allow.headers.clone();
                allow.apply_action_overrides(&mut policy.action);
            }
            (policy, audit, timeout_override)
        }
    };
    let (observed_req, needs_rpc) =
        match crate::http::body::observation::observe_missing_request_requirements(
            req,
            observation.response_request_observation,
            observation.request_body_observed,
            observation.request_rpc_observed,
            limits.max_observed_request_body_bytes,
            limits.body_read_timeout,
        )
        .await
        {
            Ok(observed) => observed,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                return body_too_large_response(
                    &request_method,
                    request_version,
                    proxy_name,
                    Some(&audit),
                );
            }
            Err(err) => return Err(err),
        };
    req = observed_req;
    if needs_rpc {
        request_rpc = Some(crate::http::rpc::inspect_request(&req).await);
    }
    req = match limit_request_body(req, selected_plan.streaming.max_request_body_bytes) {
        Ok(req) => req,
        Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
            return body_too_large_response(
                &request_method,
                request_version,
                proxy_name,
                Some(&audit),
            );
        }
        Err(err) => return Err(err),
    };
    if let Some(response) = annotated_max_forwards_response(
        &mut req,
        proxy_name,
        state.plan.limits.general.trace_reflect_all_headers,
        state.plan.limits.body.max_observed_request_body_bytes,
        std::time::Duration::from_millis(selected_plan.streaming.body_read_timeout_ms),
        &audit,
    )
    .await
    {
        return Ok(response);
    }
    strip_untrusted_identity_headers(&state, &effective_policy, remote_ip, req.headers_mut())?;
    let websocket = is_websocket_upgrade(req.headers());
    let policy_headers = policy.headers.as_deref();
    prepare_request_with_headers_in_place(&mut req, proxy_name, policy_headers, websocket);
    let module_init = transparent_module_init(proxy_name, listener_name, remote_ip, &identity);
    let mut http_modules = selected_plan.modules.start(state.clone(), module_init);
    match http_modules.on_request_headers(&mut req).await? {
        crate::http::modules::RequestHeadersOutcome::Continue => {}
        crate::http::modules::RequestHeadersOutcome::Respond(response) => {
            let response = prepare_http_module_local_response(
                &mut http_modules,
                *response,
                &request_method,
                proxy_name,
                policy_headers,
                &audit,
            )
            .await?;
            return Ok(crate::http::capture::stream::limit_response_body_for_plan(
                response,
                &selected_plan,
            ));
        }
    }
    let upstream = resolve_upstream(&policy.action, &state, &listener_cfg)?;
    let rate_limit_ctx = RateLimitContext::from_identity(
        remote_ip,
        &identity,
        matched_rule.as_deref(),
        upstream.as_ref().map(|upstream| upstream.key()),
    );
    let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_ctx) {
        Some(permits) => permits,
        None => {
            let response = concurrency_limited_response(
                req.method(),
                req.version(),
                proxy_name,
                audit.clone(),
            );
            return Ok(response);
        }
    };
    let ms = Duration::from_millis;
    let timeouts = &state.plan.limits.timeouts;
    let upstream_timeout =
        timeout_override.unwrap_or_else(|| ms(timeouts.upstream_http_timeout_ms));
    let upgrade_wait_timeout = ms(timeouts.upgrade_wait_timeout_ms);
    let tunnel_idle_timeout = ms(timeouts.tunnel_idle_timeout_ms);
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
            policy_headers,
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

fn transparent_module_init<'a>(
    proxy_name: &'a str,
    listener_name: &'a str,
    remote_ip: std::net::IpAddr,
    identity: &'a crate::policy_context::ResolvedIdentity,
) -> crate::http::modules::HttpModuleSessionInit<'a> {
    crate::http::modules::HttpModuleSessionInit {
        proxy_kind: ProxyKind::Transparent,
        proxy_name,
        scope_name: listener_name,
        route_name: None,
        remote_ip,
        sni: None,
        identity_user: identity.user.as_deref(),
        cache_policy: None,
        cache_default_scheme: None,
    }
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
    req = crate::http::capture::stream::emit_request_for_export(
        req,
        input.selected_plan,
        export_session,
        true,
    )
    .await;
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
            headers: Some(&response_headers),
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
            max_body_bytes: input.selected_plan.response_body_observation_limit(
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
        local_response_outcome: crate::http::dispatch::DispatchOutcome::ResponseLocalResponse,
        request_method: input.request_method,
        request_version: input.request_version,
        proxy_name: input.proxy_name,
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
        DispatchResponsePolicyOutcome::Response(response) => {
            return Ok(emit_optional_response_for_export(
                response,
                input.selected_plan,
                export_session,
            )
            .await);
        }
    };
    response = http_modules.prepare_downstream_response(response).await?;
    finalize_response_with_headers_in_place(
        input.request_method,
        response.version(),
        input.proxy_name,
        &mut response,
        input.headers.as_ref().map(|headers| headers.as_ref()),
        false,
    );
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_dispatch_response(
        &mut response,
        input.audit,
        DispatchOutcome::Allow,
        &response_policy_tags,
    );
    response =
        emit_optional_response_for_export(response, input.selected_plan, export_session).await;
    Ok(response)
}
