use crate::http::body::size::{limit_request_body, observed_request_size};
use crate::http::dispatch::{
    DispatchAuditContext, DispatchAuditInput, DispatchError, DispatchGuardInput,
    DispatchRequestPrepareInput, PreparedDispatchRequest, ProxyKind,
    annotated_max_forwards_response, build_dispatch_audit_context, evaluate_http_guard,
    prepare_dispatch_request, rate_limit_response_for_parts, request_body_too_large_response,
};
use crate::http::pipeline::PolicyStage;
use crate::http::policy::response_policy::response_request_obs;
use crate::http::policy::rule_context::{
    RequestRuleContextInput, build_request_rule_match_context,
};
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::rate_limit::{RateLimitContext, TransportScope};
use crate::runtime::Runtime;
use anyhow::anyhow;
use hyper::{Request, Response};
use qpx_http::body::Body;
use tokio::time::{Duration, timeout};
mod http_execute;
mod local;
mod policy;
mod prepare;
mod request_dispatch_cache;
mod request_dispatch_upstream;
mod target;
mod types;

use self::http_execute::{ForwardPreparedHttpInput, execute_forward_http_after_prepare};
use self::local::{handle_forward_ftp, handle_forward_local_action};
use self::policy::{build_forward_rate_limit_audit_context, evaluate_forward_policy_outcome};
use self::prepare::prepare_forward_dispatch;
use self::target::{
    forward_destination_metadata, forward_prefilter_context, resolve_forward_target_or_response,
};
use self::types::*;

#[tracing::instrument(
    skip_all,
    fields(kind = "forward", host = %base.host.as_deref().unwrap_or(""), method = %base.method)
)]
pub(super) async fn dispatch_forward_request(
    req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: std::net::SocketAddr,
) -> std::result::Result<Response<Body>, DispatchError> {
    execute_forward_request(req, base, runtime, listener_name, remote_addr).await
}

async fn execute_forward_request(
    req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: std::net::SocketAddr,
) -> std::result::Result<Response<Body>, DispatchError> {
    match prepare_forward_request(req, base, runtime, listener_name, remote_addr).await? {
        ForwardPrepareOutcome::Response(response) => Ok(*response),
        ForwardPrepareOutcome::Prepared(prepared) => {
            let streaming = prepared.policy.selected_plan.streaming;
            let mut response = complete_forward_request(*prepared).await?;
            response.extensions_mut().insert(streaming);
            Ok(response)
        }
    }
}

fn spawn_drain_local_response_request_body(
    mut body: Body,
    body_read_timeout: Duration,
    max_drain_bytes: usize,
) {
    tokio::spawn(async move {
        let mut drained = 0usize;
        loop {
            match timeout(body_read_timeout, body.data()).await {
                Ok(Some(Ok(chunk))) => {
                    drained = drained.saturating_add(chunk.len());
                    if drained > max_drain_bytes {
                        tracing::debug!(
                            drained,
                            max_drain_bytes,
                            "local response request body drain exceeded limit"
                        );
                        return;
                    }
                }
                Ok(Some(Err(err))) => {
                    tracing::debug!(error = ?err, "local response request body drain failed");
                    return;
                }
                Ok(None) => break,
                Err(_) => {
                    tracing::debug!("local response request body drain timed out");
                    return;
                }
            }
        }
        match timeout(body_read_timeout, body.trailers()).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                tracing::debug!(error = ?err, "local response request trailer drain failed");
            }
            Err(_) => {
                tracing::debug!("local response request trailer drain timed out");
            }
        }
    });
}

async fn prepare_forward_request(
    mut req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: std::net::SocketAddr,
) -> std::result::Result<ForwardPrepareOutcome, DispatchError> {
    let state = runtime.state();
    let proxy_name_owned = state.plan.identity.proxy_name.to_string();
    let proxy_name = proxy_name_owned.as_str();
    let compiled_edge = state
        .plan
        .forward_edge(listener_name)
        .ok_or_else(|| anyhow!("compiled forward edge not found"))?;
    let listener_cfg = compiled_edge.listener.clone();
    let effective_policy = compiled_edge.default_plan.policy_context.clone();
    let http_guard = compiled_edge.default_plan.guard.as_deref();
    let is_ftp_request = base
        .scheme
        .as_deref()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("ftp"));
    let host = match resolve_forward_target_or_response(
        &req,
        &base,
        &state,
        &listener_cfg,
        proxy_name,
        is_ftp_request,
    )? {
        Ok(host) => host,
        Err(response) => {
            let response = crate::http::capture::stream::limit_response_body_for_plan(
                response,
                &compiled_edge.default_plan,
            );
            return Ok(ForwardPrepareOutcome::Response(Box::new(response)));
        }
    };
    let engine = state
        .policy
        .rules_by_listener
        .get(listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;
    let prefilter_ctx = forward_prefilter_context(&base, &host);
    let response_engine = compiled_edge.default_plan.response_rules.clone();
    let response_candidates_for_request = response_engine
        .as_deref()
        .map(|engine| engine.candidate_profile(prefilter_ctx.clone()))
        .unwrap_or_default();
    let edge_body_limit = state.plan.limits.body.max_observed_request_body_bytes;
    let max_observed_request_body_bytes = http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .unwrap_or(edge_body_limit)
        .min(edge_body_limit);
    let max_observed_request_body_bytes =
        compiled_edge.request_body_observation_limit(max_observed_request_body_bytes);
    let body_read_timeout =
        Duration::from_millis(compiled_edge.default_plan.streaming.body_read_timeout_ms);
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
        Err(response) => {
            let response = crate::http::capture::stream::limit_response_body_for_plan(
                response,
                &compiled_edge.default_plan,
            );
            return Ok(ForwardPrepareOutcome::Response(Box::new(response)));
        }
    };
    req = prepared_req;
    let mut request_body_observed = initial_observation_plan.needs_body;
    let mut request_rpc_observed = request_rpc.is_some();
    let path = base.path.as_deref();
    let destination = forward_destination_metadata(
        &state,
        &base,
        &host,
        compiled_edge.default_plan.destination_resolution.as_ref(),
    );
    if let Some(response) = evaluate_http_guard(DispatchGuardInput {
        profile: http_guard,
        req: &req,
        destination: &destination,
        proxy_name,
        audit: build_dispatch_audit_context(DispatchAuditInput {
            state: state.clone(),
            kind: ProxyKind::Forward,
            scope_name: listener_name,
            remote_addr,
            host: Some(host.host.clone()),
            sni: None,
            request_method: req.method().clone(),
            path: path.map(str::to_string),
            matched_rule: None,
            matched_route: None,
            identity: &identity,
            destination: &destination,
            ext_authz: None,
        }),
    })
    .await?
    {
        let response = crate::http::capture::stream::limit_response_body_for_plan(
            response,
            &compiled_edge.default_plan,
        );
        return Ok(ForwardPrepareOutcome::Response(Box::new(response)));
    }
    macro_rules! forward_rule_ctx {
        ($identity:expr, $request_rpc:expr) => {
            build_request_rule_match_context(RequestRuleContextInput {
                base: &base,
                headers: &sanitized_headers,
                destination: &destination,
                identity: $identity,
                request_size: observed_request_size(&req),
                rpc: $request_rpc,
                client_cert: None,
                upstream_cert: None,
            })
        };
    }
    let ctx = forward_rule_ctx!(&identity, request_rpc.as_ref());
    let policy_response = ForwardPolicyResponseInput {
        #[cfg(feature = "auth-basic")]
        state: &state,
        identity: &identity,
        destination: &destination,
        #[cfg(feature = "auth-basic")]
        proxy_name,
        listener_name,
        remote_addr,
        host: host.host.as_str(),
        #[cfg(feature = "auth-basic")]
        request_method: &base.method,
        #[cfg(feature = "auth-basic")]
        request_version: req.version(),
        path,
    };
    macro_rules! evaluate_policy {
        ($ctx:expr, $stage_observation:expr) => {
            evaluate_forward_policy_outcome(ForwardPolicyOutcomeInput {
                runtime: &runtime,
                listener_name,
                ctx: $ctx,
                sanitized_headers: &sanitized_headers,
                response: policy_response,
                auth_method: req.method().as_str(),
                auth_uri: base.request_uri.as_str(),
                stage_observation: $stage_observation,
            })
        };
    }
    let mut policy_outcome = evaluate_policy!(ctx, true).await?;
    if let PolicyStage::Observe(requirements) = policy_outcome {
        let observation_plan =
            crate::http::body::observation::RequestObservationPlan::from_requirements(requirements);
        req = match observation_plan
            .observe_request(req, max_observed_request_body_bytes, body_read_timeout)
            .await
        {
            Ok(req) => req,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                let response = request_body_too_large_response(
                    &base.method,
                    request_version_for_observation,
                    proxy_name,
                    None,
                )?;
                let response = crate::http::capture::stream::limit_response_body_for_plan(
                    response,
                    &compiled_edge.default_plan,
                );
                return Ok(ForwardPrepareOutcome::Response(Box::new(response)));
            }
            Err(err) => return Err(err.into()),
        };
        if observation_plan.needs_rpc {
            request_rpc = Some(crate::http::rpc::inspect_request(&req).await);
            request_rpc_observed = true;
        }
        request_body_observed |= observation_plan.needs_body;
        let ctx = forward_rule_ctx!(&identity, request_rpc.as_ref());
        policy_outcome = evaluate_policy!(ctx, false).await?;
    }
    let ForwardAllowedPolicy {
        action,
        headers,
        matched_rule,
        identity,
    } = match policy_outcome {
        PolicyStage::Decision(allowed) => *allowed,
        PolicyStage::Observe(_) => {
            return Err(anyhow!(
                "forward policy still requires request body observation after observation pass"
            )
            .into());
        }
    };
    let ctx = forward_rule_ctx!(&identity, request_rpc.as_ref());
    let response_request_observation = response_request_obs(
        response_engine.as_deref(),
        &response_candidates_for_request,
        &ctx,
    );
    let selected_plan = compiled_edge
        .execution_plan_for_rule(matched_rule.as_deref())
        .clone();
    let cache_policy = selected_plan.cache.clone();
    let request_limit_ctx =
        RateLimitContext::from_identity(remote_addr.ip(), &identity, matched_rule.as_deref(), None);
    let crate::rate_limit::RequestLimitAcquire {
        limits: request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &selected_plan.rate_limits,
        None,
        TransportScope::Request,
        &request_limit_ctx,
        1,
    )?;
    if let Some(retry_after) = retry_after {
        let response = rate_limit_response_for_parts(
            req.method(),
            req.version(),
            proxy_name,
            Some(retry_after),
            build_forward_rate_limit_audit_context(
                state.clone(),
                policy_response,
                req.method(),
                matched_rule.as_deref(),
            ),
        );
        let response =
            crate::http::capture::stream::limit_response_body_for_plan(response, &selected_plan);
        return Err(DispatchError::RateLimited {
            response: Box::new(response),
        });
    }
    Ok(ForwardPrepareOutcome::Prepared(Box::new(
        ForwardPreparedRequest {
            req,
            base,
            context: crate::http::pipeline::types::RequestContext {
                runtime: Some(runtime),
                state,
                proxy_name: proxy_name_owned,
                listener_name: listener_name.to_string(),
                listener_cfg,
                remote_addr,
            },
            policy: crate::http::pipeline::types::ResolvedPolicy {
                effective_policy,
                destination,
                identity,
                sanitized_headers,
                response_engine,
                selected_plan,
                action,
                headers,
                matched_rule: matched_rule.map(|rule| rule.to_string()),
                cache_policy,
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
            mode: ForwardPreparedMode {
                host,
                is_ftp_request,
            },
        },
    )))
}

async fn complete_forward_request(
    prepared: ForwardPreparedRequest,
) -> std::result::Result<Response<Body>, DispatchError> {
    let ForwardPreparedRequest {
        mut req,
        base,
        context,
        policy,
        limits,
        observation,
        mode,
    } = prepared;
    let runtime = context.runtime.ok_or_else(missing_forward_runtime)?;
    let state = context.state;
    let proxy_name = context.proxy_name;
    let listener_name = context.listener_name;
    let listener_cfg = context.listener_cfg;
    let remote_addr = context.remote_addr;
    let host = mode.host;
    let is_ftp_request = mode.is_ftp_request;
    let effective_policy = policy.effective_policy;
    let destination = policy.destination;
    let identity = policy.identity;
    let sanitized_headers = policy.sanitized_headers;
    let response_engine = policy.response_engine;
    let selected_plan = policy.selected_plan;
    let action = policy.action;
    let headers = policy.headers;
    let matched_rule = policy.matched_rule;
    let cache_policy = policy.cache_policy;
    let mut request_limits = limits.request_limits;
    let request_limit_ctx = limits.request_limit_ctx;
    let max_observed_request_body_bytes = limits.max_observed_request_body_bytes;
    let body_read_timeout = limits.body_read_timeout;
    let mut request_rpc = observation.request_rpc;
    let response_request_observation = observation.response_request_observation;
    let request_body_observed = observation.request_body_observed;
    let request_rpc_observed = observation.request_rpc_observed;
    let proxy_name = proxy_name.as_str();
    let listener_name = listener_name.as_str();
    let request_method = req.method().clone();
    let client_version = req.version();
    let mut action = action;
    let mut headers = headers;
    let mut cache_policy = cache_policy;
    let decision =
        crate::http::dispatch::enforce_http_access(crate::http::dispatch::HttpAccessInput {
            state: &state,
            policy: &effective_policy,
            kind: ProxyKind::Forward,
            mode: crate::policy_context::ExtAuthzMode::ForwardHttp,
            enforce_ext_authz: true,
            proxy_name,
            scope_name: listener_name,
            remote_addr,
            dst_port: host.port,
            host: Some(host.host.as_str()),
            sni: None,
            request_method: &request_method,
            request_version: client_version,
            path: base.path.as_deref(),
            uri: Some(base.request_uri.as_str()),
            matched_rule: matched_rule.as_deref(),
            matched_route: None,
            action: Some(&action),
            sanitized_headers: &sanitized_headers,
            identity: &identity,
            destination: &destination,
            base_headers: headers.take(),
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
    let (audit, timeout_override) = match decision {
        crate::http::dispatch::HttpAccessDecision::Blocked {
            response,
            rate_limited,
        } => {
            let response = crate::http::capture::stream::limit_response_body_for_plan(
                *response,
                &selected_plan,
            );
            return Err(if rate_limited {
                DispatchError::RateLimited {
                    response: Box::new(response),
                }
            } else {
                DispatchError::ExtAuthzDenied {
                    response: Box::new(response),
                }
            });
        }
        crate::http::dispatch::HttpAccessDecision::Allow(allowed) => {
            let crate::http::dispatch::HttpAccessAllowed { audit, controls } = *allowed;
            let timeout_override = controls.as_ref().and_then(|allow| allow.timeout_override);
            if let Some(allow) = controls {
                headers = allow.headers.clone();
                cache_policy = (!allow.cache_bypass).then_some(cache_policy).flatten();
                allow.apply_action_overrides(&mut action);
            }
            (audit, timeout_override)
        }
    };

    if let Some(response) = handle_forward_local_action(
        &req,
        &state,
        proxy_name,
        &action,
        headers.as_deref(),
        &audit,
    )? {
        spawn_drain_local_response_request_body(
            req.into_body(),
            body_read_timeout,
            selected_plan.streaming.max_request_body_bytes,
        );
        return Ok(response);
    }

    req = match limit_request_body(req, selected_plan.streaming.max_request_body_bytes) {
        Ok(req) => req,
        Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
            return forward_payload_too_large_response(&base, client_version, proxy_name, &audit);
        }
        Err(err) => return Err(err.into()),
    };

    if is_ftp_request {
        let response = handle_forward_ftp(
            req,
            &listener_cfg,
            &state,
            &request_method,
            proxy_name,
            headers.as_deref(),
            &audit,
        )
        .await?;
        return Ok(response);
    }

    let (observed_req, needs_rpc) =
        match crate::http::body::observation::observe_missing_request_requirements(
            req,
            response_request_observation,
            request_body_observed,
            request_rpc_observed,
            max_observed_request_body_bytes,
            body_read_timeout,
        )
        .await
        {
            Ok(observed) => observed,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                return forward_payload_too_large_response(
                    &base,
                    client_version,
                    proxy_name,
                    &audit,
                );
            }
            Err(err) => return Err(err.into()),
        };
    req = observed_req;
    if needs_rpc {
        request_rpc = Some(crate::http::rpc::inspect_request(&req).await);
    }
    if let Some(response) = annotated_max_forwards_response(
        &mut req,
        proxy_name,
        state.plan.limits.general.trace_reflect_all_headers,
        state.plan.limits.body.max_observed_request_body_bytes,
        Duration::from_millis(selected_plan.streaming.body_read_timeout_ms),
        &audit,
    )
    .await
    {
        return Ok(response);
    }
    let ready = match prepare_forward_dispatch(ForwardDispatchPrepareInput {
        req,
        state: state.clone(),
        effective_policy: &effective_policy,
        remote_addr,
        proxy_name,
        listener_name,
        selected_plan: &selected_plan,
        action: &action,
        headers: headers.as_deref(),
        cache_policy: cache_policy.as_ref(),
        identity: &identity,
        request_limits,
        request_limit_ctx,
        timeout_override,
        host: &host,
        request_method: &request_method,
        audit: &audit,
    })
    .await?
    {
        ForwardDispatchPrepareOutcome::Response(response) => {
            let response = crate::http::capture::stream::limit_response_body_for_plan(
                *response,
                &selected_plan,
            );
            return Ok(response);
        }
        ForwardDispatchPrepareOutcome::Prepared(ready) => *ready,
    };
    execute_forward_http_after_prepare(ForwardPreparedHttpInput {
        ready,
        runtime: &runtime,
        action: &action,
        listener_name,
        request_method: &request_method,
        client_version,
        proxy_name,
        cache_policy: cache_policy.as_ref(),
        headers,
        state: &state,
        audit: &audit,
        response_engine: response_engine.as_deref(),
        selected_plan: &selected_plan,
        base: &base,
        destination: &destination,
        identity: &identity,
        host: &host,
        remote_addr,
        request_rpc: request_rpc.as_ref(),
    })
    .await
    .map_err(DispatchError::from)
}

fn missing_forward_runtime() -> DispatchError {
    DispatchError::Internal(anyhow::anyhow!("forward prepared request missing runtime"))
}

fn forward_payload_too_large_response(
    base: &BaseRequestFields,
    client_version: http::Version,
    proxy_name: &str,
    audit: &DispatchAuditContext,
) -> std::result::Result<Response<Body>, DispatchError> {
    Ok(request_body_too_large_response(
        &base.method,
        client_version,
        proxy_name,
        Some(audit),
    )?)
}
