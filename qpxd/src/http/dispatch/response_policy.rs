use super::{DispatchAuditContext, annotate_dispatch_response, record_response_policy_action};
use crate::http::policy::response_policy::{
    HttpResponseRuleEngine, ListenerResponsePolicyDecision, ResponseBodyObservationLimits,
    ResponseRuleCandidates, apply_listener_response_policy,
};
use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use anyhow::Result;
use hyper::{Method, Response};
use qpx_core::rules::{CompiledHeaderControl, RuleMatchContext};
use qpx_http::body::Body;
use std::sync::Arc;

pub(crate) struct DispatchResponsePolicyInput<'a> {
    pub(crate) response: Response<Body>,
    pub(crate) engine: Option<&'a HttpResponseRuleEngine>,
    pub(crate) candidates: ResponseRuleCandidates,
    pub(crate) rule_context: RuleMatchContext<'a>,
    pub(crate) headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    pub(crate) body_observation: ResponseBodyObservationLimits,
    pub(crate) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(crate) audit: &'a DispatchAuditContext,
    pub(crate) local_response_outcome: crate::http::dispatch::DispatchOutcome,
    pub(crate) request_method: &'a Method,
    pub(crate) request_version: http::Version,
    pub(crate) proxy_name: &'a str,
}

pub(crate) enum DispatchResponsePolicyOutcome {
    Continue {
        response: Response<Body>,
        headers: Option<Arc<CompiledHeaderControl>>,
        cache_bypass: bool,
        suppress_retry: bool,
        mirror: Option<bool>,
        policy_tags: Vec<String>,
    },
    Response(Response<Body>),
}

struct DispatchResponseTransformContext<'a> {
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit: &'a DispatchAuditContext,
    local_response_outcome: crate::http::dispatch::DispatchOutcome,
    request_method: &'a Method,
    request_version: http::Version,
    proxy_name: &'a str,
}

trait ResponseTransform {
    async fn apply_dispatch_transform(
        self,
        ctx: DispatchResponseTransformContext<'_>,
    ) -> Result<DispatchResponsePolicyOutcome>;
}

impl ResponseTransform for ListenerResponsePolicyDecision {
    async fn apply_dispatch_transform(
        self,
        ctx: DispatchResponseTransformContext<'_>,
    ) -> Result<DispatchResponsePolicyOutcome> {
        match self {
            ListenerResponsePolicyDecision::Continue {
                response,
                headers,
                cache_bypass,
                suppress_retry,
                mirror,
                policy_tags,
            } => {
                record_response_policy_action(ctx.audit.kind, "continue");
                Ok(DispatchResponsePolicyOutcome::Continue {
                    response,
                    headers,
                    cache_bypass,
                    suppress_retry,
                    mirror,
                    policy_tags,
                })
            }
            ListenerResponsePolicyDecision::LocalResponse {
                response,
                headers,
                policy_tags,
            } => {
                let mut response = ctx
                    .http_modules
                    .prepare_downstream_response(response)
                    .await?;
                finalize_response_with_headers_in_place(
                    ctx.request_method,
                    ctx.request_version,
                    ctx.proxy_name,
                    &mut response,
                    headers.as_deref(),
                    false,
                );
                ctx.http_modules
                    .on_logging(Some(response.status()), None)
                    .await;
                annotate_dispatch_response(
                    &mut response,
                    ctx.audit,
                    ctx.local_response_outcome,
                    &policy_tags,
                );
                Ok(DispatchResponsePolicyOutcome::Response(response))
            }
        }
    }
}

pub(crate) async fn apply_dispatch_response_policy(
    input: DispatchResponsePolicyInput<'_>,
) -> Result<DispatchResponsePolicyOutcome> {
    let DispatchResponsePolicyInput {
        response,
        engine,
        candidates,
        rule_context,
        headers,
        request_rpc,
        body_observation,
        http_modules,
        audit,
        local_response_outcome,
        request_method,
        request_version,
        proxy_name,
    } = input;
    let decision = apply_listener_response_policy(
        engine,
        candidates,
        rule_context,
        response,
        headers,
        request_rpc,
        body_observation,
    )
    .await?;
    decision
        .apply_dispatch_transform(DispatchResponseTransformContext {
            http_modules,
            audit,
            local_response_outcome,
            request_method,
            request_version,
            proxy_name,
        })
        .await
}
