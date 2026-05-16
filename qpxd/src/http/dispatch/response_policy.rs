use super::{DispatchAuditContext, annotate_dispatch_response, record_response_policy_action};
use crate::http::body::Body;
use crate::http::l7::{finalize_response_for_request, finalize_response_with_headers_in_place};
use crate::http::response_policy::{
    HttpResponseRuleEngine, ListenerResponsePolicyDecision, ResponseBodyObservationLimits,
    ResponseRuleCandidates, apply_listener_response_policy,
};
use anyhow::Result;
use hyper::{Method, Response};
use qpx_core::rules::{CompiledHeaderControl, RuleMatchContext};
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
    pub(crate) request_method: &'a Method,
    pub(crate) request_version: http::Version,
    pub(crate) proxy_name: &'a str,
    pub(crate) pre_finalize_local_response: bool,
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

pub(crate) async fn apply_dispatch_response_policy(
    input: DispatchResponsePolicyInput<'_>,
) -> Result<DispatchResponsePolicyOutcome> {
    match apply_listener_response_policy(
        input.engine,
        input.candidates,
        input.rule_context,
        input.response,
        input.headers,
        input.request_rpc,
        input.body_observation,
    )
    .await?
    {
        ListenerResponsePolicyDecision::Continue {
            response,
            headers,
            cache_bypass,
            suppress_retry,
            mirror,
            policy_tags,
        } => {
            record_response_policy_action(input.audit.kind, "continue");
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
            let response = input
                .http_modules
                .prepare_downstream_response(response)
                .await?;
            let mut response = if input.pre_finalize_local_response {
                finalize_response_for_request(
                    input.request_method,
                    input.request_version,
                    input.proxy_name,
                    response,
                    false,
                )
            } else {
                response
            };
            finalize_response_with_headers_in_place(
                input.request_method,
                input.request_version,
                input.proxy_name,
                &mut response,
                headers.as_deref(),
                false,
            );
            input
                .http_modules
                .on_logging(Some(response.status()), None)
                .await;
            annotate_dispatch_response(
                &mut response,
                input.audit,
                crate::http::dispatch::DispatchOutcome::ResponseLocalResponse,
                &policy_tags,
            );
            Ok(DispatchResponsePolicyOutcome::Response(response))
        }
    }
}
