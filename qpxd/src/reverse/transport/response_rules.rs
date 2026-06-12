use super::ReverseConnInfo;
use crate::destination::DestinationMetadata;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchOutcome, DispatchResponsePolicyInput,
    DispatchResponsePolicyOutcome, apply_dispatch_response_policy,
};
use crate::http::policy::response_policy::{
    HttpResponseRuleEngine, ResponseBodyObservationLimits, ResponseRuleCandidates,
};
#[cfg(test)]
use crate::http::policy::response_policy::{
    ListenerResponsePolicyDecision, apply_listener_response_policy,
};
use crate::http::policy::rule_context::{
    ResponseRuleContextInput, build_response_rule_match_context,
};
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::rpc::RpcMatchContext;
use crate::policy_context::ResolvedIdentity;
use anyhow::Result;
use hyper::Response;
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_core::rules::{CompiledHeaderControl, RuleMatchContext};
use qpx_core::tls::UpstreamCertificateInfo;
use qpx_http::body::Body;
use std::sync::Arc;
use std::time::Duration;

pub(super) struct ResponseRuleInput<'a> {
    pub(super) route: &'a crate::reverse::router::HttpRoute,
    pub(super) base: &'a BaseRequestFields,
    pub(super) conn: &'a ReverseConnInfo,
    pub(super) destination: &'a DestinationMetadata,
    pub(super) upstream_cert: Option<&'a UpstreamCertificateInfo>,
    pub(super) identity: &'a ResolvedIdentity,
    pub(super) request_rpc: Option<&'a RpcMatchContext>,
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) response: Response<Body>,
    pub(super) max_observed_response_body_bytes: usize,
    pub(super) response_body_read_timeout: Duration,
    pub(super) force_response_body_observation: bool,
}

pub(super) struct DispatchResponseRuleInput<'a> {
    pub(super) rule: ResponseRuleInput<'a>,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) audit: &'a DispatchAuditContext,
    pub(super) request_method: &'a hyper::Method,
    pub(super) request_version: http::Version,
    pub(super) proxy_name: &'a str,
}

struct ResponsePolicyParts<'a> {
    engine: Option<&'a HttpResponseRuleEngine>,
    candidates: ResponseRuleCandidates,
    rule_context: RuleMatchContext<'a>,
}

fn response_policy_parts<'a>(
    route: &'a crate::reverse::router::HttpRoute,
    base: &'a BaseRequestFields,
    conn: &'a ReverseConnInfo,
    destination: &'a DestinationMetadata,
    upstream_cert: Option<&'a UpstreamCertificateInfo>,
    identity: &'a ResolvedIdentity,
    response_status: u16,
) -> ResponsePolicyParts<'a> {
    let engine = route.response_rules.as_deref();
    let candidates = engine
        .map(|engine| {
            engine.candidate_profile(MatchPrefilterContext {
                method: Some(base.method.as_str()),
                dst_port: base.dst_port,
                src_ip: base.peer_ip,
                host: base.host.as_deref(),
                sni: base.sni.as_deref(),
                path: base.path.as_deref(),
            })
        })
        .unwrap_or_default();
    let rule_context = build_response_rule_match_context(ResponseRuleContextInput {
        base,
        headers: None,
        destination,
        identity,
        response_status,
        response_size: None,
        rpc: None,
        client_cert: conn.peer_certificate_info.as_deref(),
        upstream_cert,
    });
    ResponsePolicyParts {
        engine,
        candidates,
        rule_context,
    }
}

#[cfg(test)]
pub(super) async fn apply_response_rules(
    input: ResponseRuleInput<'_>,
) -> Result<ListenerResponsePolicyDecision> {
    let ResponseRuleInput {
        route,
        base,
        conn,
        destination,
        upstream_cert,
        identity,
        request_rpc,
        route_headers,
        response,
        max_observed_response_body_bytes,
        response_body_read_timeout,
        force_response_body_observation,
    } = input;
    if route.response_rules.is_none() && !force_response_body_observation {
        return Ok(ListenerResponsePolicyDecision::Continue {
            response,
            headers: route_headers,
            cache_bypass: false,
            suppress_retry: false,
            mirror: None,
            policy_tags: Vec::new(),
        });
    }
    let response_status = response.status().as_u16();
    let ResponsePolicyParts {
        engine,
        candidates,
        rule_context,
    } = response_policy_parts(
        route,
        base,
        conn,
        destination,
        upstream_cert,
        identity,
        response_status,
    );
    let decision = apply_listener_response_policy(
        engine,
        candidates,
        rule_context,
        response,
        route_headers,
        request_rpc,
        ResponseBodyObservationLimits {
            max_body_bytes: max_observed_response_body_bytes,
            read_timeout: response_body_read_timeout,
            force_body: force_response_body_observation,
        },
    )
    .await?;

    Ok(decision)
}

pub(super) async fn apply_dispatch_response_rules(
    input: DispatchResponseRuleInput<'_>,
) -> Result<DispatchResponsePolicyOutcome> {
    let DispatchResponseRuleInput {
        rule,
        http_modules,
        audit,
        request_method,
        request_version,
        proxy_name,
    } = input;
    let ResponseRuleInput {
        route,
        base,
        conn,
        destination,
        upstream_cert,
        identity,
        request_rpc,
        route_headers,
        response,
        max_observed_response_body_bytes,
        response_body_read_timeout,
        force_response_body_observation,
    } = rule;
    if route.response_rules.is_none() && !force_response_body_observation {
        return Ok(DispatchResponsePolicyOutcome::Continue {
            response,
            headers: route_headers,
            cache_bypass: false,
            suppress_retry: false,
            mirror: None,
            policy_tags: Vec::new(),
        });
    }
    let response_status = response.status().as_u16();
    let ResponsePolicyParts {
        engine,
        candidates,
        rule_context,
    } = response_policy_parts(
        route,
        base,
        conn,
        destination,
        upstream_cert,
        identity,
        response_status,
    );
    apply_dispatch_response_policy(DispatchResponsePolicyInput {
        response,
        engine,
        candidates,
        rule_context,
        headers: route_headers,
        request_rpc,
        body_observation: ResponseBodyObservationLimits {
            max_body_bytes: max_observed_response_body_bytes,
            read_timeout: response_body_read_timeout,
            force_body: force_response_body_observation,
        },
        http_modules,
        audit,
        local_response_outcome: DispatchOutcome::ResponseRuleLocalResponse,
        request_method,
        request_version,
        proxy_name,
    })
    .await
}
