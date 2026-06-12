use super::MitmRouteContext;
use crate::destination::DestinationMetadata;
use crate::http::capture::stream::{emit_optional_response_for_export, emit_request_for_export};
use crate::http::dispatch::{
    DispatchAuditContext, DispatchOutcome, DispatchResponsePolicyInput,
    DispatchResponsePolicyOutcome, ProxyKind, annotate_dispatch_response,
    annotated_max_forwards_response, apply_dispatch_response_policy,
    concurrency_limited_response_for_parts as concurrency_limited_response,
    prepare_http_module_local_response, record_upstream_request_duration,
};
use crate::http::policy::response_policy::ResponseBodyObservationLimits;
use crate::http::policy::rule_context::{
    ResponseRuleContextInput, build_response_rule_match_context,
};
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::l7::{
    finalize_response_with_headers_in_place,
    prepare_request_with_headers_in_place as prepare_request,
};
use crate::http::protocol::upgrade::PendingDownstreamUpgrade;
use crate::http::protocol::websocket::spawn_upgrade_tunnel;
use crate::policy_context::{
    EffectivePolicyContext, ResolvedIdentity, strip_untrusted_identity_headers as strip_identity,
};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
use crate::runtime::{ExecutionPlan, Runtime};
use anyhow::Result;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_http::body::Body;
use qpx_http::protocol::address::format_authority_host_port;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};

pub(super) struct MitmDispatch<'a> {
    pub(super) req: Request<Body>,
    pub(super) base: &'a BaseRequestFields,
    pub(super) runtime: Runtime,
    pub(super) sender: Arc<Mutex<SendRequest<Body>>>,
    pub(super) route: MitmRouteContext<'a>,
    pub(super) selected_plan: &'a ExecutionPlan,
    pub(super) effective_policy: EffectivePolicyContext,
    pub(super) request_limits: AppliedRateLimits,
    pub(super) identity: ResolvedIdentity,
    pub(super) matched_rule: Option<String>,
    pub(super) headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    pub(super) timeout_override: Option<Duration>,
    pub(super) request_rpc: Option<crate::http::rpc::RpcMatchContext>,
    pub(super) destination: DestinationMetadata,
    pub(super) upstream_cert: Option<Arc<qpx_core::tls::UpstreamCertificateInfo>>,
    pub(super) audit: DispatchAuditContext,
    pub(super) websocket: bool,
    pub(super) client_upgrade: Option<PendingDownstreamUpgrade>,
    pub(super) req_method: http::Method,
    pub(super) req_version: http::Version,
}

pub(super) async fn dispatch_mitm_upstream(mut input: MitmDispatch<'_>) -> Result<Response<Body>> {
    let state = input.runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let selected_plan = input.selected_plan;
    let src_ip = input.route.src_addr.ip();
    let audit = &input.audit;
    let effective_policy = &input.effective_policy;
    let req_method = &input.req_method;
    let route_headers = input.headers.as_deref();
    let path = input.base.path.as_deref().unwrap_or("/");
    let export_server = format_authority_host_port(input.route.host, input.route.dst_port);
    let rate_ctx = RateLimitContext::from_identity(
        src_ip,
        &input.identity,
        input.matched_rule.as_deref(),
        Some(export_server.as_str()),
    );
    let _concurrency_permits = match input.request_limits.acquire_concurrency(&rate_ctx) {
        Some(permits) => permits,
        None => {
            let response = concurrency_limited_response(
                input.req.method(),
                input.req.version(),
                proxy_name,
                (*audit).clone(),
            );
            return Ok(response);
        }
    };
    let export_session =
        state.export_session_for_plan(selected_plan, input.route.src_addr, export_server);
    if let Some(response) = annotated_max_forwards_response(
        &mut input.req,
        proxy_name,
        state.plan.limits.general.trace_reflect_all_headers,
        state.plan.limits.body.max_observed_request_body_bytes,
        std::time::Duration::from_millis(selected_plan.streaming.body_read_timeout_ms),
        audit,
    )
    .await
    {
        return Ok(response);
    }
    strip_identity(&state, effective_policy, src_ip, input.req.headers_mut())?;
    prepare_request(&mut input.req, proxy_name, route_headers, input.websocket);
    *input.req.version_mut() = http::Version::HTTP_11;
    if !input.req.headers().contains_key(http::header::HOST) {
        let authority = format_authority_host_port(input.route.host, input.route.dst_port);
        input
            .req
            .headers_mut()
            .insert(http::header::HOST, http::HeaderValue::from_str(&authority)?);
    }
    let module_init = mitm_module_init(proxy_name, &input.route, &input.identity);
    let mut http_modules = selected_plan.modules.start(state.clone(), module_init);
    match http_modules.on_request_headers(&mut input.req).await? {
        crate::http::modules::RequestHeadersOutcome::Continue => {}
        crate::http::modules::RequestHeadersOutcome::Respond(response) => {
            let response = prepare_http_module_local_response(
                &mut http_modules,
                *response,
                req_method,
                proxy_name,
                route_headers,
                audit,
            )
            .await?;
            return Ok(crate::http::capture::stream::limit_response_body_for_plan(
                response,
                selected_plan,
            ));
        }
    }
    let ms = Duration::from_millis;
    let timeouts = &state.plan.limits.timeouts;
    let upstream_timeout = input
        .timeout_override
        .unwrap_or_else(|| ms(timeouts.upstream_http_timeout_ms));
    let upstream_started = std::time::Instant::now();
    http_modules.on_upstream_request(&mut input.req).await?;
    input.req =
        emit_request_for_export(input.req, selected_plan, export_session.as_ref(), true).await;
    let mut guard = input.sender.lock().await;
    let upstream_result = timeout(upstream_timeout, guard.send_request(input.req)).await;
    record_upstream_request_duration(input.audit.kind, upstream_started.elapsed());
    let mut response = match upstream_result {
        Ok(Ok(response)) => response.map(Body::from),
        Ok(Err(err)) => {
            let err = err.into();
            http_modules.on_error(&err).await;
            return Err(err);
        }
        Err(err) => {
            let err = err.into();
            http_modules.on_error(&err).await;
            return Err(err);
        }
    };
    response = http_modules.on_upstream_response(response).await?;
    let response_engine = selected_plan.response_rules.as_deref();
    let response_candidates = response_engine
        .map(|engine| {
            engine.candidate_profile(MatchPrefilterContext {
                method: Some(req_method.as_str()),
                dst_port: Some(input.route.dst_port),
                src_ip: Some(src_ip),
                host: Some(input.route.host),
                sni: Some(input.route.sni),
                path: Some(path),
            })
        })
        .unwrap_or_default();
    let response_status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let response_policy_tags = match apply_dispatch_response_policy(DispatchResponsePolicyInput {
        response,
        engine: response_engine,
        candidates: response_candidates,
        rule_context: build_response_rule_match_context(ResponseRuleContextInput {
            base: input.base,
            headers: Some(&response_headers),
            destination: &input.destination,
            identity: &input.identity,
            response_status,
            response_size: None,
            rpc: None,
            client_cert: None,
            upstream_cert: input.upstream_cert.as_deref(),
        }),
        headers: input.headers.clone(),
        request_rpc: input.request_rpc.as_ref(),
        body_observation: ResponseBodyObservationLimits {
            max_body_bytes: selected_plan.response_body_observation_limit(
                state.plan.limits.body.max_observed_response_body_bytes,
            ),
            read_timeout: std::time::Duration::from_millis(
                timeouts.upstream_http_timeout_ms.max(1),
            ),
            force_body: false,
        },
        http_modules: &mut http_modules,
        audit,
        local_response_outcome: crate::http::dispatch::DispatchOutcome::ResponseLocalResponse,
        request_method: req_method,
        request_version: input.req_version,
        proxy_name,
    })
    .await?
    {
        DispatchResponsePolicyOutcome::Continue {
            response: updated,
            headers: updated_headers,
            policy_tags,
            ..
        } => {
            response = updated;
            input.headers = updated_headers;
            policy_tags
        }
        DispatchResponsePolicyOutcome::Response(response) => {
            return Ok(emit_optional_response_for_export(
                response,
                selected_plan,
                export_session.as_ref(),
            )
            .await);
        }
    };
    let keep_upgrade =
        input.websocket && response.status() == http::StatusCode::SWITCHING_PROTOCOLS;
    if keep_upgrade && let Some(client_upgrade) = input.client_upgrade.take() {
        let upgrade_wait_timeout = ms(timeouts.upgrade_wait_timeout_ms);
        let tunnel_idle_timeout = ms(timeouts.tunnel_idle_timeout_ms);
        spawn_upgrade_tunnel(
            &mut response,
            client_upgrade,
            "mitm",
            upgrade_wait_timeout,
            tunnel_idle_timeout,
        );
    }
    response = http_modules.prepare_downstream_response(response).await?;
    finalize_response_with_headers_in_place(
        req_method,
        response.version(),
        proxy_name,
        &mut response,
        input.headers.as_deref(),
        keep_upgrade,
    );
    response =
        emit_optional_response_for_export(response, selected_plan, export_session.as_ref()).await;
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_dispatch_response(
        &mut response,
        audit,
        DispatchOutcome::Allow,
        &response_policy_tags,
    );
    Ok(response)
}

fn mitm_module_init<'a>(
    proxy_name: &'a str,
    route: &MitmRouteContext<'a>,
    identity: &'a ResolvedIdentity,
) -> crate::http::modules::HttpModuleSessionInit<'a> {
    crate::http::modules::HttpModuleSessionInit {
        proxy_kind: ProxyKind::Mitm,
        proxy_name,
        scope_name: route.listener_name,
        route_name: None,
        remote_ip: route.src_addr.ip(),
        sni: Some(route.host),
        identity_user: identity.user.as_deref(),
        cache_policy: None,
        cache_default_scheme: None,
    }
}
