use super::{ConnectTarget, resolve_http_target};
use crate::http::dispatch::{
    DispatchRequestPrepareInput, PreparedDispatchRequest, evaluate_http_guard,
    prepare_dispatch_request, request_body_too_large_response,
};
use crate::http::pipeline::PolicyStage;
use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
use crate::runtime::Runtime;
use anyhow::{Result, anyhow};
use hyper::Request;
use qpx_http::body::Body;
use std::net::SocketAddr;

mod complete;
mod local;
mod policy;
mod prepare_helpers;
mod prepared;
mod types;

use self::complete::complete_transparent_request;
use self::policy::{
    evaluate_transparent_policy, evaluate_transparent_policy_staged, transparent_prefilter_context,
};
use self::prepare_helpers::{
    body_read_timeout as transparent_body_read_timeout, destination as transparent_destination,
    guard_input as transparent_guard_input, preflight_rejection as transparent_preflight_rejection,
    request_observation_limit as transparent_request_observation_limit,
    response_request_observation as transparent_response_request_observation,
};
use self::prepared::{TransparentBuildInput, build_transparent_prepared};
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
    if let Some(response) = transparent_preflight_rejection(
        &req,
        proxy_name,
        state.plan.limits.general.trace_enabled,
        state.messages.trace_disabled.as_str(),
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
    let max_observed_request_body_bytes =
        transparent_request_observation_limit(compiled_edge, http_guard, &state);
    let body_read_timeout = transparent_body_read_timeout(compiled_edge);
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
        read_timeout: body_read_timeout,
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
    let destination = transparent_destination(
        &state,
        &host_for_match,
        &base,
        &connect_target,
        compiled_edge.default_plan.destination_resolution.as_ref(),
    );
    if let Some(response) = evaluate_http_guard(transparent_guard_input(
        http_guard,
        &req,
        &destination,
        &state,
        proxy_name,
        listener_name,
        remote_addr,
        path,
        &identity,
        host_for_match.clone(),
    ))
    .await?
    {
        return Ok(TransparentPrepareOutcome::Response(Box::new(response)));
    }
    macro_rules! transparent_policy_input {
        () => {
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
            }
        };
    }
    let mut policy_stage = evaluate_transparent_policy_staged(transparent_policy_input!())?;
    if let PolicyStage::Observe(requirements) = policy_stage {
        let observation_plan =
            crate::http::body::observation::RequestObservationPlan::from_requirements(requirements);
        req = match observation_plan
            .observe_request(req, max_observed_request_body_bytes, body_read_timeout)
            .await
        {
            Ok(req) => req,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                return Ok(TransparentPrepareOutcome::Response(Box::new(
                    request_body_too_large_response(
                        &base.method,
                        request_version_for_observation,
                        proxy_name,
                        None,
                    )?,
                )));
            }
            Err(err) => return Err(err),
        };
        request_body_observed |= observation_plan.needs_body;
        if observation_plan.needs_rpc {
            request_rpc = Some(crate::http::rpc::inspect_request(&req).await);
            request_rpc_observed = true;
        }
        policy_stage = PolicyStage::Decision(Box::new(evaluate_transparent_policy(
            transparent_policy_input!(),
        )?));
    }
    let policy_evaluation = match policy_stage {
        PolicyStage::Decision(decision) => *decision,
        PolicyStage::Observe(_) => {
            return Err(anyhow!(
                "transparent policy still requires request body observation after observation pass"
            ));
        }
    };
    let response_request_observation = transparent_response_request_observation(
        &req,
        &base,
        &sanitized_headers,
        &destination,
        &identity,
        request_rpc.as_ref(),
        response_engine.as_deref(),
        &response_candidates_for_request,
    );
    let selected_plan = compiled_edge
        .execution_plan_for_rule(policy_evaluation.matched_rule.as_deref())
        .clone();
    build_transparent_prepared(TransparentBuildInput {
        req,
        state,
        proxy_name_owned,
        listener_name,
        listener_cfg,
        remote_addr,
        base,
        connect_target,
        host_for_match,
        effective_policy,
        destination,
        identity,
        sanitized_headers,
        response_engine,
        selected_plan,
        response_request_observation,
        max_observed_request_body_bytes,
        body_read_timeout,
        request_body_observed,
        request_rpc_observed,
        policy_evaluation,
    })
}

#[cfg(test)]
mod tests;
