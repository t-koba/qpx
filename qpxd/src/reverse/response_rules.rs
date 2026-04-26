use super::{ResponseRuleDecision, ReverseConnInfo};
use crate::destination::DestinationMetadata;
use crate::http::base_fields::BaseRequestFields;
use crate::http::body::Body;
use crate::http::response_policy::{
    apply_listener_response_policy, ListenerResponsePolicyDecision, ResponseBodyObservationLimits,
};
use crate::http::rpc::RpcMatchContext;
use crate::http::rule_context::{build_response_rule_match_context, ResponseRuleContextInput};
use crate::policy_context::ResolvedIdentity;
use crate::tls::UpstreamCertificateInfo;
use anyhow::Result;
use hyper::Response;
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_core::rules::CompiledHeaderControl;
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
}

pub(super) async fn apply_response_rules(
    input: ResponseRuleInput<'_>,
) -> Result<ResponseRuleDecision> {
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
    } = input;
    let Some(engine) = route.response_rules.as_ref() else {
        return Ok(ResponseRuleDecision::Continue {
            response,
            route_headers,
            cache_bypass: false,
            suppress_retry: false,
            mirror: None,
            policy_tags: Arc::from(Vec::<String>::new()),
        });
    };
    let candidates = engine.candidate_profile(MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: base.dst_port,
        src_ip: base.peer_ip,
        host: base.host.as_deref(),
        sni: base.sni.as_deref(),
        path: base.path.as_deref(),
    });
    let response_status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let decision = apply_listener_response_policy(
        Some(engine),
        candidates,
        build_response_rule_match_context(ResponseRuleContextInput {
            base,
            headers: &response_headers,
            destination,
            identity,
            response_status,
            response_size: None,
            rpc: None,
            client_cert: conn.peer_certificate_info.as_deref(),
            upstream_cert,
        }),
        response,
        route_headers,
        request_rpc,
        ResponseBodyObservationLimits {
            max_body_bytes: max_observed_response_body_bytes,
            read_timeout: response_body_read_timeout,
        },
    )
    .await?;

    match decision {
        ListenerResponsePolicyDecision::Continue {
            response,
            headers,
            cache_bypass,
            suppress_retry,
            mirror,
            policy_tags,
        } => Ok(ResponseRuleDecision::Continue {
            response,
            route_headers: headers,
            cache_bypass,
            suppress_retry,
            mirror,
            policy_tags: Arc::from(policy_tags),
        }),
        ListenerResponsePolicyDecision::LocalResponse {
            response,
            headers,
            policy_tags,
        } => Ok(ResponseRuleDecision::LocalResponse {
            response,
            route_headers: headers,
            policy_tags: Arc::from(policy_tags),
        }),
    }
}
