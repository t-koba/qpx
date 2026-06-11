use super::MitmRouteContext;
use super::upstream::{MitmDispatch, dispatch_mitm_upstream};
use crate::destination::DestinationInputs;
#[cfg(feature = "auth-basic")]
use crate::forward::proxy_auth_required;
use crate::forward::{
    ForwardPolicyDecision, evaluate_forward_policy, evaluate_forward_policy_staged,
};
use crate::http::body::size::observed_request_size;
use crate::http::dispatch::{
    DispatchAuditInput, DispatchGuardInput, DispatchOutcome, DispatchRequestPrepareInput,
    ExtAuthzHttpAccessInput, ExtAuthzHttpAccessOutcome, PreparedDispatchRequest, ProxyKind,
    annotate_dispatch_response, annotated_local_response, apply_ext_authz_http_access,
    build_dispatch_audit_context, evaluate_http_guard, prepare_dispatch_request,
    rate_limit_response_for_parts, request_body_too_large_response,
};
use crate::http::pipeline::PolicyStage;
use crate::http::policy::response_policy::response_request_obs;
use crate::http::policy::rule_context::{
    RequestRuleContextInput, build_request_rule_match_context,
};
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::common::{blocked_response as blocked, forbidden_response as forbidden};
use crate::http::protocol::l7::finalize_response_for_request;
use crate::http::protocol::websocket::is_websocket_upgrade;
use crate::policy_context::{ExtAuthzInput, ExtAuthzMode, enforce_ext_authz};
use crate::rate_limit::{RateLimitContext, TransportScope};
use crate::runtime::Runtime;
use anyhow::{Result, anyhow};
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response};
use qpx_core::config::{ActionKind, LocalResponseConfig};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_http::body::Body;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(test)]
mod tests;

enum MitmEarlyResponse {
    Response(Response<Body>),
    Local(LocalResponseConfig),
}

#[tracing::instrument(skip_all, fields(kind = "mitm", host = %route.host, method = %base.method))]
pub(super) async fn dispatch_mitm_request(
    mut req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    sender: Arc<Mutex<SendRequest<Body>>>,
    route: MitmRouteContext<'_>,
) -> Result<Response<Body>> {
    let state = runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let mitm_plan = state
        .plan
        .mitm_plan(route.listener_name, None)
        .ok_or_else(|| anyhow!("compiled MITM listener execution plan not found"))?;
    let base_plan = mitm_plan.http;
    let effective_policy = base_plan.policy_context.clone();
    let http_guard = base_plan.guard.as_deref();
    let websocket = is_websocket_upgrade(req.headers());
    let client_upgrade = websocket.then(|| crate::http::protocol::upgrade::on(&mut req));
    let path_owned = base.path.clone().unwrap_or_else(|| "/".to_string());
    let engine = state
        .policy
        .rules_by_listener
        .get(route.listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: Some(route.dst_port),
        src_ip: Some(route.src_addr.ip()),
        host: Some(route.host),
        sni: Some(route.sni),
        path: Some(path_owned.as_str()),
    };
    let response_engine = base_plan.response_rules.as_deref();
    let response_candidates_for_request = response_engine
        .map(|engine| engine.candidate_profile(prefilter_ctx.clone()))
        .unwrap_or_default();
    let max_observed_request_body_bytes = http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(state.plan.limits.body.max_observed_request_body_bytes))
        .unwrap_or(state.plan.limits.body.max_observed_request_body_bytes);
    let max_observed_request_body_bytes =
        base_plan.request_body_observation_limit(max_observed_request_body_bytes);
    let request_version_for_observation = req.version();
    let PreparedDispatchRequest {
        req: prepared_req,
        observation_plan: initial_observation_plan,
        sanitized_headers,
        identity,
        mut request_rpc,
    } = match prepare_dispatch_request(DispatchRequestPrepareInput {
        req,
        rule_engine: engine,
        response_candidates: &response_candidates_for_request,
        prefilter_ctx,
        defer_policy_observation: true,
        http_guard,
        max_observed_request_body_bytes,
        read_timeout: std::time::Duration::from_millis(base_plan.streaming.body_read_timeout_ms),
        request_method: &base.method,
        request_version: request_version_for_observation,
        proxy_name,
        state: &state,
        effective_policy: &effective_policy,
        remote_ip: route.src_addr.ip(),
    })
    .await?
    {
        Ok(prepared) => prepared,
        Err(response) => return Ok(response),
    };
    req = prepared_req;
    let mut request_body_observed = initial_observation_plan.needs_body;
    let mut request_rpc_observed = request_rpc.is_some();
    let request_uri = base.request_uri.as_str();
    let req_method = req.method().clone();
    let req_version = req.version();
    let mut identity = identity;
    let upstream_cert = route.upstream_cert.as_deref();
    let destination = state.classify_destination(
        &DestinationInputs {
            host: Some(route.host),
            ip: route.host.parse().ok(),
            sni: Some(route.sni),
            scheme: Some("https"),
            port: Some(route.dst_port),
            cert_subject: upstream_cert.and_then(|cert| cert.subject.as_deref()),
            cert_issuer: upstream_cert.and_then(|cert| cert.issuer.as_deref()),
            cert_san_dns: upstream_cert
                .map(|cert| cert.san_dns.as_slice())
                .unwrap_or(&[]),
            cert_san_uri: upstream_cert
                .map(|cert| cert.san_uri.as_slice())
                .unwrap_or(&[]),
            cert_fingerprint_sha256: upstream_cert
                .and_then(|cert| cert.fingerprint_sha256.as_deref()),
            ..Default::default()
        },
        state
            .plan
            .ingress_edge_execution_plan(route.listener_name, None)
            .and_then(|plan| plan.destination_resolution.as_ref()),
    );
    if let Some(response) = evaluate_http_guard(DispatchGuardInput {
        profile: http_guard,
        req: &req,
        destination: &destination,
        proxy_name,
        audit: build_dispatch_audit_context(DispatchAuditInput {
            state: state.clone(),
            kind: ProxyKind::Mitm,
            scope_name: route.listener_name,
            remote_addr: route.src_addr,
            host: Some(route.host.to_string()),
            sni: Some(route.sni.to_string()),
            request_method: req.method().clone(),
            path: Some(path_owned.clone()),
            matched_rule: None,
            matched_route: None,
            identity: &identity,
            destination: &destination,
            ext_authz: None,
        }),
    })
    .await?
    {
        return Ok(response);
    }
    let ctx = build_request_rule_match_context(RequestRuleContextInput {
        base: &base,
        headers: &sanitized_headers,
        destination: &destination,
        identity: &identity,
        request_size: observed_request_size(&req),
        rpc: request_rpc.as_ref(),
        client_cert: None,
        upstream_cert,
    });
    let mut decision = evaluate_forward_policy_staged(
        &runtime,
        route.listener_name,
        ctx,
        &sanitized_headers,
        req.method().as_str(),
        request_uri,
    )
    .await?;
    if let PolicyStage::Observe(requirements) = decision {
        let observation_plan =
            crate::http::body::observation::RequestObservationPlan::from_requirements(requirements);
        req = match observation_plan
            .observe_request(
                req,
                max_observed_request_body_bytes,
                std::time::Duration::from_millis(base_plan.streaming.body_read_timeout_ms),
            )
            .await
        {
            Ok(req) => req,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                return request_body_too_large_response(
                    &base.method,
                    request_version_for_observation,
                    proxy_name,
                    None,
                );
            }
            Err(err) => return Err(err),
        };
        request_body_observed |= observation_plan.needs_body;
        if observation_plan.needs_rpc {
            request_rpc = Some(crate::http::rpc::inspect_request(&req).await);
            request_rpc_observed = true;
        }
        let ctx = build_request_rule_match_context(RequestRuleContextInput {
            base: &base,
            headers: &sanitized_headers,
            destination: &destination,
            identity: &identity,
            request_size: observed_request_size(&req),
            rpc: request_rpc.as_ref(),
            client_cert: None,
            upstream_cert,
        });
        decision = PolicyStage::Decision(
            evaluate_forward_policy(
                &runtime,
                route.listener_name,
                ctx,
                &sanitized_headers,
                req.method().as_str(),
                request_uri,
            )
            .await?,
        );
    }
    let decision = match decision {
        PolicyStage::Decision(decision) => decision,
        PolicyStage::Observe(_) => {
            return Err(anyhow!(
                "MITM policy still requires request body observation after observation pass"
            ));
        }
    };
    let ctx = build_request_rule_match_context(RequestRuleContextInput {
        base: &base,
        headers: &sanitized_headers,
        destination: &destination,
        identity: &identity,
        request_size: observed_request_size(&req),
        rpc: request_rpc.as_ref(),
        client_cert: None,
        upstream_cert,
    });
    let response_request_observation =
        response_request_obs(response_engine, &response_candidates_for_request, &ctx);
    let (mut headers, matched_rule, early_response) = match decision {
        ForwardPolicyDecision::Allow(allowed) => {
            identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
            if matches!(allowed.action.kind, ActionKind::Block) {
                (
                    None,
                    allowed.matched_rule.map(|s| s.to_string()),
                    Some(MitmEarlyResponse::Response(finalize_response_for_request(
                        req.method(),
                        req.version(),
                        proxy_name,
                        blocked(state.messages.blocked.as_str()),
                        false,
                    ))),
                )
            } else if matches!(allowed.action.kind, ActionKind::Respond) {
                let local = allowed
                    .action
                    .local_response
                    .as_ref()
                    .ok_or_else(|| anyhow!("respond action requires local_response"))?;
                (
                    None,
                    allowed.matched_rule.map(|s| s.to_string()),
                    Some(MitmEarlyResponse::Local(local.clone())),
                )
            } else {
                (
                    allowed.headers,
                    allowed.matched_rule.map(|s| s.to_string()),
                    None,
                )
            }
        }
        #[cfg(feature = "auth-basic")]
        ForwardPolicyDecision::Challenge(chal) => {
            let response = proxy_auth_required(chal, state.messages.proxy_auth_required.as_str());
            (
                None,
                None,
                Some(MitmEarlyResponse::Response(finalize_response_for_request(
                    req.method(),
                    req.version(),
                    proxy_name,
                    response,
                    false,
                ))),
            )
        }
        #[cfg(feature = "auth-basic")]
        ForwardPolicyDecision::Forbidden => (
            None,
            None,
            Some(MitmEarlyResponse::Response(finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                forbidden(state.messages.forbidden.as_str()),
                false,
            ))),
        ),
    };
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(route.listener_name, matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled MITM listener execution plan not found"))?;
    let request_limit_ctx = RateLimitContext::from_identity(
        route.src_addr.ip(),
        &identity,
        matched_rule.as_deref(),
        None,
    );
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &selected_plan.rate_limits,
        None,
        TransportScope::Request,
        &request_limit_ctx,
        1,
    )?;
    let ext_authz = if early_response.is_none() {
        Some(
            enforce_ext_authz(
                &state,
                &effective_policy,
                ExtAuthzInput {
                    proxy_kind: ProxyKind::Forward,
                    proxy_name,
                    scope_name: route.listener_name,
                    remote_ip: route.src_addr.ip(),
                    dst_port: Some(route.dst_port),
                    host: Some(route.host),
                    sni: Some(route.sni),
                    method: Some(req.method().as_str()),
                    path: Some(path_owned.as_str()),
                    uri: Some(request_uri),
                    matched_rule: matched_rule.as_deref(),
                    matched_route: None,
                    action: None,
                    headers: Some(&sanitized_headers),
                    identity: &identity,
                },
            )
            .await?,
        )
    } else {
        None
    };
    let audit = build_dispatch_audit_context(DispatchAuditInput {
        state: state.clone(),
        kind: ProxyKind::Mitm,
        scope_name: route.listener_name,
        remote_addr: route.src_addr,
        host: Some(route.host.to_string()),
        sni: Some(route.sni.to_string()),
        request_method: req_method.clone(),
        path: Some(path_owned.clone()),
        matched_rule: matched_rule.clone(),
        matched_route: None,
        identity: &identity,
        destination: &destination,
        ext_authz: ext_authz.as_ref(),
    });
    let annotate_with_tags =
        |response: &mut Response<Body>, outcome: DispatchOutcome, extra_policy_tags: &[String]| {
            annotate_dispatch_response(response, &audit, outcome, extra_policy_tags);
        };
    let annotate = |response: &mut Response<Body>, outcome: DispatchOutcome| {
        annotate_with_tags(response, outcome, &[]);
    };
    let mut timeout_override = None;
    if let Some(ext_authz) = ext_authz {
        match apply_ext_authz_http_access(ExtAuthzHttpAccessInput {
            enforcement: ext_authz,
            mode: ExtAuthzMode::ForwardMitmHttp,
            base_headers: headers,
            request_limit: Some((
                &mut request_limits,
                &request_limit_ctx,
                &state.policy.rate_limiters,
            )),
            request_head: (req.method(), req.version()),
            proxy_name,
            default_deny_response: forbidden(state.messages.forbidden.as_str()),
            audit: &audit,
        })? {
            ExtAuthzHttpAccessOutcome::Continue(allow) => {
                headers = allow.headers;
                timeout_override = allow.timeout_override;
            }
            ExtAuthzHttpAccessOutcome::Blocked(response, _) => {
                return Ok(crate::http::capture::stream::limit_response_body_for_plan(
                    response,
                    selected_plan,
                ));
            }
        }
    }
    if let Some(retry_after) = retry_after {
        let response = rate_limit_response_for_parts(
            req.method(),
            req.version(),
            proxy_name,
            Some(retry_after),
            audit.clone(),
        );
        return Ok(crate::http::capture::stream::limit_response_body_for_plan(
            response,
            selected_plan,
        ));
    }
    if let Some(early_response) = early_response {
        let response = match early_response {
            MitmEarlyResponse::Response(mut response) => {
                annotate(&mut response, DispatchOutcome::EarlyResponse);
                response
            }
            MitmEarlyResponse::Local(local) => annotated_local_response(
                req.method(),
                req.version(),
                proxy_name,
                &local,
                None,
                &audit,
                DispatchOutcome::EarlyResponse,
            )?,
        };
        return Ok(crate::http::capture::stream::limit_response_body_for_plan(
            response,
            selected_plan,
        ));
    }

    let (observed_req, needs_rpc) =
        match crate::http::body::observation::observe_missing_request_requirements(
            req,
            response_request_observation,
            request_body_observed,
            request_rpc_observed,
            max_observed_request_body_bytes,
            std::time::Duration::from_millis(base_plan.streaming.body_read_timeout_ms),
        )
        .await
        {
            Ok(observed) => observed,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                let response = request_body_too_large_response(
                    &base.method,
                    request_version_for_observation,
                    proxy_name,
                    Some(&audit),
                )?;
                return Ok(response);
            }
            Err(err) => return Err(err),
        };
    req = observed_req;
    if needs_rpc {
        request_rpc = Some(crate::http::rpc::inspect_request(&req).await);
    }
    req = match crate::http::body::size::limit_request_body(
        req,
        selected_plan.streaming.max_request_body_bytes,
    ) {
        Ok(req) => req,
        Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
            let response = request_body_too_large_response(
                &base.method,
                request_version_for_observation,
                proxy_name,
                Some(&audit),
            )?;
            return Ok(response);
        }
        Err(err) => return Err(err),
    };

    let upstream_cert_for_dispatch = route.upstream_cert.clone();
    dispatch_mitm_upstream(MitmDispatch {
        req,
        base: &base,
        runtime,
        sender,
        route,
        selected_plan,
        effective_policy,
        request_limits,
        identity,
        matched_rule,
        headers,
        timeout_override,
        request_rpc,
        destination,
        upstream_cert: upstream_cert_for_dispatch,
        audit,
        websocket,
        client_upgrade,
        req_method,
        req_version,
    })
    .await
}
