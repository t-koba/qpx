use super::MitmRouteContext;
use crate::destination::DestinationMetadata;
use crate::http::body::Body;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchResponsePolicyInput, DispatchResponsePolicyOutcome,
    annotate_dispatch_response, apply_dispatch_response_policy, record_upstream_request_duration,
};
use crate::http::policy::response_policy::ResponseBodyObservationLimits;
use crate::http::policy::rule_context::{
    ResponseRuleContextInput, build_response_rule_match_context,
};
use crate::http::protocol::address::format_authority_host_port;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::l7::{
    finalize_response_with_headers_in_place, handle_max_forwards_in_place,
    prepare_request_with_headers_in_place,
};
use crate::http::protocol::upgrade::PendingDownstreamUpgrade;
use crate::http::protocol::websocket::spawn_upgrade_tunnel;
use crate::policy_context::{
    EffectivePolicyContext, ResolvedIdentity, strip_untrusted_identity_headers,
};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
use crate::runtime::{ExecutionPlan, Runtime};
use anyhow::Result;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response};
use qpx_core::prefilter::MatchPrefilterContext;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};

pub(super) struct MitmUpstreamDispatch<'a> {
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
    pub(super) upstream_cert: Option<Arc<crate::tls::UpstreamCertificateInfo>>,
    pub(super) audit: DispatchAuditContext,
    pub(super) websocket: bool,
    pub(super) client_upgrade: Option<PendingDownstreamUpgrade>,
    pub(super) req_method: http::Method,
    pub(super) req_version: http::Version,
}

pub(super) async fn dispatch_mitm_upstream(
    mut input: MitmUpstreamDispatch<'_>,
) -> Result<Response<Body>> {
    let state = input.runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let path = input.base.path.as_deref().unwrap_or("/");
    let export_server = format_authority_host_port(input.route.host, input.route.dst_port);
    let _concurrency_permits =
        match input
            .request_limits
            .acquire_concurrency(&RateLimitContext::from_identity(
                input.route.src_addr.ip(),
                &input.identity,
                input.matched_rule.as_deref(),
                Some(export_server.as_str()),
            )) {
            Some(permits) => permits,
            None => {
                let mut response = crate::http::protocol::l7::finalize_response_for_request(
                    input.req.method(),
                    input.req.version(),
                    proxy_name,
                    crate::http::protocol::common::too_many_requests_response(None),
                    false,
                );
                annotate_dispatch_response(
                    &mut response,
                    &input.audit,
                    crate::http::dispatch::DispatchOutcome::ConcurrencyLimited,
                    &[],
                );
                return Ok(response);
            }
        };
    let export_session =
        state.export_session_for_plan(input.selected_plan, input.route.src_addr, export_server);
    if let Some(response) = handle_max_forwards_in_place(
        &mut input.req,
        proxy_name,
        state.plan.limits.general.trace_reflect_all_headers,
        state.plan.limits.body.max_observed_request_body_bytes,
        std::time::Duration::from_millis(input.selected_plan.streaming.body_read_timeout_ms),
    )
    .await
    {
        let mut response = response;
        annotate_dispatch_response(
            &mut response,
            &input.audit,
            crate::http::dispatch::DispatchOutcome::MaxForwards,
            &[],
        );
        return Ok(response);
    }
    strip_untrusted_identity_headers(
        &state,
        &input.effective_policy,
        input.route.src_addr.ip(),
        input.req.headers_mut(),
    )?;
    prepare_request_with_headers_in_place(
        &mut input.req,
        proxy_name,
        input.headers.as_deref(),
        input.websocket,
    );
    *input.req.version_mut() = http::Version::HTTP_11;
    if !input.req.headers().contains_key(http::header::HOST) {
        let authority = format_authority_host_port(input.route.host, input.route.dst_port);
        input
            .req
            .headers_mut()
            .insert(http::header::HOST, http::HeaderValue::from_str(&authority)?);
    }
    let mut http_modules = input.selected_plan.modules.start(
        state.clone(),
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: crate::http::dispatch::ProxyKind::Mitm,
            proxy_name,
            scope_name: input.route.listener_name,
            route_name: None,
            remote_ip: input.route.src_addr.ip(),
            sni: Some(input.route.host),
            identity_user: input.identity.user.as_deref(),
            cache_policy: None,
            cache_default_scheme: None,
        },
    );
    match http_modules.on_request_headers(&mut input.req).await? {
        crate::http::modules::RequestHeadersOutcome::Continue => {}
        crate::http::modules::RequestHeadersOutcome::Respond(response) => {
            let mut response = http_modules.prepare_downstream_response(*response).await?;
            let response_version = response.version();
            finalize_response_with_headers_in_place(
                &input.req_method,
                response_version,
                proxy_name,
                &mut response,
                input.headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(response.status()), None).await;
            annotate_dispatch_response(
                &mut response,
                &input.audit,
                crate::http::dispatch::DispatchOutcome::HttpModuleLocalResponse,
                &[],
            );
            return Ok(response);
        }
    }
    let upstream_timeout = input.timeout_override.unwrap_or_else(|| {
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms)
    });
    let upstream_started = std::time::Instant::now();
    http_modules.on_upstream_request(&mut input.req).await?;
    input.req = emit_request_capture(input.req, input.selected_plan, export_session.as_ref()).await;
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
    let response_engine = input.selected_plan.response_rules.as_deref();
    let response_candidates = response_engine
        .map(|engine| {
            engine.candidate_profile(MatchPrefilterContext {
                method: Some(input.req_method.as_str()),
                dst_port: Some(input.route.dst_port),
                src_ip: Some(input.route.src_addr.ip()),
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
            headers: &response_headers,
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
            max_body_bytes: input
                .selected_plan
                .body_observation_limit(state.plan.limits.body.max_observed_response_body_bytes),
            read_timeout: std::time::Duration::from_millis(
                state.plan.limits.timeouts.upstream_http_timeout_ms.max(1),
            ),
            force_body: false,
        },
        http_modules: &mut http_modules,
        audit: &input.audit,
        request_method: &input.req_method,
        request_version: input.req_version,
        proxy_name,
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
            input.headers = updated_headers;
            policy_tags
        }
        DispatchResponsePolicyOutcome::Response(response) => return Ok(response),
    };
    response = http_modules.prepare_downstream_response(response).await?;
    response = emit_response_capture(response, input.selected_plan, export_session.as_ref()).await;
    let keep_upgrade =
        input.websocket && response.status() == http::StatusCode::SWITCHING_PROTOCOLS;
    if keep_upgrade {
        let upgrade_wait_timeout =
            Duration::from_millis(state.plan.limits.timeouts.upgrade_wait_timeout_ms);
        let tunnel_idle_timeout =
            Duration::from_millis(state.plan.limits.timeouts.tunnel_idle_timeout_ms);
        if let Some(client_upgrade) = input.client_upgrade {
            spawn_upgrade_tunnel(
                &mut response,
                client_upgrade,
                "mitm",
                upgrade_wait_timeout,
                tunnel_idle_timeout,
            );
        }
    }
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        &input.req_method,
        response_version,
        proxy_name,
        &mut response,
        input.headers.as_deref(),
        keep_upgrade,
    );
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_dispatch_response(
        &mut response,
        &input.audit,
        crate::http::dispatch::DispatchOutcome::Allow,
        &response_policy_tags,
    );
    Ok(response)
}

async fn emit_request_capture(
    mut req: Request<Body>,
    selected_plan: &ExecutionPlan,
    export_session: Option<&crate::exporter::ExportSession>,
) -> Request<Body> {
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_request_preview_async(&req).await;
        session.emit_plaintext(true, &preview);
        if let Some(sample_bytes) = selected_plan.capture_stream_sample_bytes() {
            req = crate::http::capture::stream::sample_request_body_for_export(
                req,
                sample_bytes,
                selected_plan.streaming.body_channel_capacity,
                std::time::Duration::from_millis(selected_plan.streaming.body_read_timeout_ms),
                session.clone(),
                true,
            );
        } else if let Some(max_capture_bytes) = selected_plan.capture_full_body_bytes() {
            req = crate::http::capture::stream::capture_request_body_for_export(
                req,
                max_capture_bytes,
                selected_plan.streaming.body_channel_capacity,
                std::time::Duration::from_millis(selected_plan.streaming.body_read_timeout_ms),
                session.clone(),
                true,
            );
        }
    }
    req
}

async fn emit_response_capture(
    mut response: Response<Body>,
    selected_plan: &ExecutionPlan,
    export_session: Option<&crate::exporter::ExportSession>,
) -> Response<Body> {
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_response_preview_async(&response).await;
        session.emit_plaintext(false, &preview);
        if let Some(sample_bytes) = selected_plan.capture_stream_sample_bytes() {
            response = crate::http::capture::stream::sample_response_body_for_export(
                response,
                sample_bytes,
                selected_plan.streaming.body_channel_capacity,
                std::time::Duration::from_millis(selected_plan.streaming.body_read_timeout_ms),
                session.clone(),
            );
        } else if let Some(max_capture_bytes) = selected_plan.capture_full_body_bytes() {
            response = crate::http::capture::stream::capture_response_body_for_export(
                response,
                max_capture_bytes,
                selected_plan.streaming.body_channel_capacity,
                std::time::Duration::from_millis(selected_plan.streaming.body_read_timeout_ms),
                session.clone(),
            );
        }
    }
    response
}
