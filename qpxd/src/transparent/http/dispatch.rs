use super::{ConnectTarget, resolve_http_target};
use crate::destination::DestinationInputs;
use crate::http::body::Body;
use crate::http::body::size::observed_request_size;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchGuardInput, DispatchRateLimitInput, DispatchRequestPrepareInput,
    PreparedDispatchRequest, evaluate_http_guard, prepare_dispatch_request, rate_limit_response,
};
use crate::http::policy::rule_context::{
    RequestRuleContextInput, build_request_rule_match_context,
};
use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
use crate::http::protocol::l7::finalize_response_for_request;
use crate::http::protocol::preflight::{PreflightOptions, PreflightOutcome, preflight_validate};
use crate::rate_limit::RateLimitContext;
use crate::runtime::Runtime;
use anyhow::{Result, anyhow};
use hyper::{Request, Response, StatusCode};
use std::net::SocketAddr;

mod access;
mod complete;
mod local;
mod policy;
mod types;

use self::access::{TransparentPrepareAuditInput, build_transparent_prepare_audit_context};
use self::complete::complete_transparent_request;
use self::policy::{
    evaluate_transparent_policy, evaluate_transparent_policy_staged, transparent_prefilter_context,
};
use self::types::*;

#[tracing::instrument(
    skip_all,
    fields(kind = "transparent", host = tracing::field::Empty, method = %req.method())
)]
pub(super) async fn dispatch_transparent_request(
    req: Request<Body>,
    runtime: Runtime,
    remote_addr: SocketAddr,
    original_target: Option<ConnectTarget>,
    listener_name: &str,
) -> Result<hyper::Response<Body>> {
    execute_transparent_request(req, runtime, remote_addr, original_target, listener_name).await
}

async fn execute_transparent_request(
    req: Request<Body>,
    runtime: Runtime,
    remote_addr: SocketAddr,
    original_target: Option<ConnectTarget>,
    listener_name: &str,
) -> Result<hyper::Response<Body>> {
    match prepare_transparent_request(req, runtime, remote_addr, original_target, listener_name)
        .await?
    {
        TransparentPrepareOutcome::Response(response) => Ok(*response),
        TransparentPrepareOutcome::Prepared(prepared) => {
            complete_transparent_request(*prepared).await
        }
    }
}

async fn prepare_transparent_request(
    mut req: Request<Body>,
    runtime: Runtime,
    remote_addr: SocketAddr,
    original_target: Option<ConnectTarget>,
    listener_name: &str,
) -> Result<TransparentPrepareOutcome> {
    let state = runtime.state();
    let proxy_name_owned = state.plan.identity.proxy_name.to_string();
    let proxy_name = proxy_name_owned.as_str();
    if let PreflightOutcome::Reject(response) = preflight_validate(
        &req,
        proxy_name,
        PreflightOptions::reject_connect(
            state.plan.limits.general.trace_enabled,
            state.messages.trace_disabled.as_str(),
            StatusCode::METHOD_NOT_ALLOWED,
            "transparent HTTP forward_edges do not support CONNECT",
        ),
    ) {
        return Ok(TransparentPrepareOutcome::Response(response));
    }
    let engine = state
        .policy
        .rules_by_listener
        .get(listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;
    let listener_cfg = state
        .ingress_edge_settings(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?
        .clone();
    let compiled_edge = state
        .plan
        .transparent_edge(listener_name)
        .ok_or_else(|| anyhow!("compiled transparent edge not found"))?;
    let effective_policy = compiled_edge.default_plan.policy_context.clone();
    let http_guard = compiled_edge.default_plan.guard.as_deref();

    let (connect_target, host_for_match) = resolve_http_target(&req, original_target.as_ref())?;
    let base = extract_base_request_fields(
        &req,
        BaseRequestContext {
            peer_ip: Some(remote_addr.ip()),
            dst_port: Some(connect_target.port()),
            host: host_for_match.as_deref(),
            scheme: Some("http"),
            ..Default::default()
        },
    );
    let prefilter_ctx =
        transparent_prefilter_context(&base, &connect_target, remote_addr, &host_for_match);
    let response_engine = compiled_edge.default_plan.response_rules.clone();
    let response_candidates_for_request = response_engine
        .as_deref()
        .map(|engine| engine.candidate_profile(prefilter_ctx.clone()))
        .unwrap_or_default();
    let max_observed_request_body_bytes = http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(state.plan.limits.body.max_observed_request_body_bytes))
        .unwrap_or(state.plan.limits.body.max_observed_request_body_bytes);
    let max_observed_request_body_bytes =
        compiled_edge.body_observation_limit(max_observed_request_body_bytes);
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
        read_timeout: std::time::Duration::from_millis(
            compiled_edge.default_plan.streaming.body_read_timeout_ms,
        ),
        request_method: &base.method,
        request_version: request_version_for_observation,
        proxy_name,
        state: &state,
        effective_policy: &effective_policy,
        remote_ip: remote_addr.ip(),
    })
    .await?
    {
        Ok(prepared) => prepared,
        Err(response) => return Ok(TransparentPrepareOutcome::Response(Box::new(response))),
    };
    req = prepared_req;
    let mut request_body_observed = initial_observation_plan.needs_body;
    let mut request_rpc_observed = request_rpc.is_some();
    let path = base.path.as_deref();
    let destination = state.classify_destination(
        &DestinationInputs {
            host: host_for_match.as_deref(),
            ip: host_for_match
                .as_deref()
                .and_then(|value| value.parse().ok()),
            scheme: base.scheme.as_deref(),
            port: Some(connect_target.port()),
            ..Default::default()
        },
        compiled_edge.default_plan.destination_resolution.as_ref(),
    );
    if let Some(response) = evaluate_http_guard(DispatchGuardInput {
        profile: http_guard,
        req: &req,
        destination: &destination,
        proxy_name,
        audit: DispatchAuditContext::new(
            state.clone(),
            crate::http::dispatch::ProxyKind::Transparent,
            listener_name,
            remote_addr,
            req.method().clone(),
            path.map(str::to_string),
            identity.to_log_context(None, None, None),
        )
        .with_host(host_for_match.clone()),
    })
    .await?
    {
        return Ok(TransparentPrepareOutcome::Response(Box::new(response)));
    }
    let mut policy_stage = evaluate_transparent_policy_staged(TransparentPolicyInput {
        engine,
        req: &req,
        base: &base,
        sanitized_headers: &sanitized_headers,
        destination: &destination,
        identity: &identity,
        request_rpc: request_rpc.as_ref(),
        proxy_name,
        forbidden_message: state.messages.forbidden.as_str(),
    })?;
    if let TransparentPolicyStage::Observe(requirements) = policy_stage {
        let observation_plan =
            crate::http::body::observation::RequestObservationPlan::from_requirements(requirements);
        req = match observation_plan
            .observe_request(
                req,
                max_observed_request_body_bytes,
                std::time::Duration::from_millis(
                    compiled_edge.default_plan.streaming.body_read_timeout_ms,
                ),
            )
            .await
        {
            Ok(req) => req,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                return Ok(TransparentPrepareOutcome::Response(Box::new(
                    finalize_response_for_request(
                        &base.method,
                        request_version_for_observation,
                        proxy_name,
                        Response::builder()
                            .status(StatusCode::PAYLOAD_TOO_LARGE)
                            .body(Body::from("request body too large"))?,
                        false,
                    ),
                )));
            }
            Err(err) => return Err(err),
        };
        request_body_observed |= observation_plan.needs_body;
        if observation_plan.needs_rpc {
            request_rpc = Some(crate::http::rpc::inspect_request(&req).await);
            request_rpc_observed = true;
        }
        policy_stage = TransparentPolicyStage::Decision(Box::new(evaluate_transparent_policy(
            TransparentPolicyInput {
                engine,
                req: &req,
                base: &base,
                sanitized_headers: &sanitized_headers,
                destination: &destination,
                identity: &identity,
                request_rpc: request_rpc.as_ref(),
                proxy_name,
                forbidden_message: state.messages.forbidden.as_str(),
            },
        )?));
    }
    let policy_evaluation = match policy_stage {
        TransparentPolicyStage::Decision(decision) => *decision,
        TransparentPolicyStage::Observe(_) => {
            return Err(anyhow!(
                "transparent policy still requires request body observation after observation pass"
            ));
        }
    };
    let response_request_observation = response_engine
        .as_deref()
        .map(|engine| {
            let ctx = build_request_rule_match_context(RequestRuleContextInput {
                base: &base,
                headers: &sanitized_headers,
                destination: &destination,
                identity: &identity,
                request_size: observed_request_size(&req),
                rpc: request_rpc.as_ref(),
                client_cert: None,
                upstream_cert: None,
            });
            engine.request_observation_requirements_for_candidates(
                &response_candidates_for_request,
                &ctx,
            )
        })
        .unwrap_or_default();
    let TransparentPolicyEvaluation {
        policy,
        early_response,
        matched_rule,
        request_rpc,
    } = policy_evaluation;
    let selected_plan = compiled_edge
        .execution_plan_for_rule(matched_rule.as_deref())
        .clone();
    let body_read_timeout =
        std::time::Duration::from_millis(compiled_edge.default_plan.streaming.body_read_timeout_ms);
    let request_limit_ctx =
        RateLimitContext::from_identity(remote_addr.ip(), &identity, matched_rule.as_deref(), None);
    let crate::rate_limit::RequestLimitAcquire {
        limits: request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &selected_plan.rate_limits,
        None,
        crate::rate_limit::TransportScope::Request,
        &request_limit_ctx,
        1,
    )?;
    if let Some(retry_after) = retry_after {
        return Ok(TransparentPrepareOutcome::Response(Box::new(
            rate_limit_response(DispatchRateLimitInput {
                req: &req,
                proxy_name,
                retry_after: Some(retry_after),
                audit: build_transparent_prepare_audit_context(TransparentPrepareAuditInput {
                    state: &state,
                    identity: &identity,
                    destination: &destination,
                    listener_name,
                    remote_addr,
                    host: host_for_match.clone(),
                    request_method: req.method(),
                    path,
                    matched_rule: matched_rule.as_deref(),
                }),
            }),
        )));
    }
    Ok(TransparentPrepareOutcome::Prepared(Box::new(
        TransparentPreparedRequest {
            req,
            context: crate::http::pipeline::types::RequestContext {
                runtime: None,
                state,
                proxy_name: proxy_name_owned,
                listener_name: listener_name.to_string(),
                listener_cfg,
                remote_addr,
            },
            limits: crate::http::pipeline::types::RequestLimits {
                request_limits,
                request_limit_ctx,
                max_observed_request_body_bytes,
                body_read_timeout,
            },
            observation: crate::http::pipeline::types::RequestObservation {
                request_rpc,
                response_request_observation,
                request_body_observed,
                request_rpc_observed,
            },
            mode: TransparentPreparedMode {
                connect_target,
                host_for_match,
            },
            base,
            policy: TransparentPreparedPolicy {
                effective_policy,
                destination,
                identity,
                sanitized_headers,
                response_engine,
                selected_plan,
                policy,
                early_response,
                matched_rule,
            },
        },
    )))
}

#[cfg(test)]
mod tests;
