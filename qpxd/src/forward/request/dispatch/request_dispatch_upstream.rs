use super::super::HostPort;
use crate::http::capture::stream::emit_optional_response_for_export;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchCacheWriteInput, DispatchOutcome, DispatchResponsePolicyInput,
    DispatchResponsePolicyOutcome, annotate_dispatch_response, apply_dispatch_response_policy,
    finalize_dispatch_stale_if_error_response, record_upstream_request_duration,
    write_dispatch_cache_result,
};
use crate::http::policy::response_policy::ResponseBodyObservationLimits;
use crate::http::policy::rule_context::{
    ResponseRuleContextInput, build_response_rule_match_context,
};
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use crate::upstream::http1::proxy_http1_request_with_interim;
use anyhow::Result;
use hyper::{Method, Request, Response};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_http::body::Body;
use qpxd_cache::CacheRequestKey;
use std::sync::Arc;
use tokio::time::Duration;

pub(super) struct ForwardUpstreamInput<'a> {
    pub(super) req: Request<Body>,
    pub(super) upstream: Option<&'a crate::upstream::pool::ResolvedUpstreamProxy>,
    pub(super) http_authority: &'a str,
    pub(super) upstream_timeout: Duration,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) export_session: Option<&'a crate::exporter::ExportSession>,
    pub(super) request_method: &'a Method,
    pub(super) client_version: http::Version,
    pub(super) proxy_name: &'a str,
    pub(super) headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    pub(super) cache_policy: Option<qpx_core::config::CachePolicyConfig>,
    pub(super) request_headers_snapshot: Option<&'a http::HeaderMap>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) cache_target_key: Option<&'a CacheRequestKey>,
    pub(super) revalidation_state: Option<qpxd_cache::RevalidationState>,
    pub(super) cache_collapse_guard: Option<qpxd_cache::RequestCollapseGuard>,
    pub(super) response_engine:
        Option<&'a crate::http::policy::response_policy::HttpResponseRuleEngine>,
    pub(super) selected_plan: &'a crate::runtime::ExecutionPlan,
    pub(super) base: &'a BaseRequestFields,
    pub(super) destination: &'a crate::destination::DestinationMetadata,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) host: &'a HostPort,
    pub(super) remote_addr: std::net::SocketAddr,
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    pub(super) audit: &'a DispatchAuditContext,
}

pub(super) async fn execute_forward_upstream(
    input: ForwardUpstreamInput<'_>,
) -> Result<Response<Body>> {
    let ForwardUpstreamInput {
        mut req,
        upstream,
        http_authority,
        upstream_timeout,
        http_modules,
        export_session,
        request_method,
        client_version,
        proxy_name,
        mut headers,
        mut cache_policy,
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        revalidation_state,
        cache_collapse_guard,
        response_engine,
        selected_plan,
        base,
        destination,
        identity,
        host,
        remote_addr,
        state,
        request_rpc,
        audit,
    } = input;
    let upstream_started = std::time::Instant::now();
    http_modules.on_upstream_request(&mut req).await?;
    req = crate::http::capture::stream::emit_request_for_export(
        req,
        selected_plan,
        export_session,
        true,
    )
    .await;
    let proxied_result =
        proxy_http1_request_with_interim(req, upstream, http_authority, upstream_timeout).await;
    record_upstream_request_duration(audit.kind, upstream_started.elapsed());
    let proxied = match proxied_result {
        Ok(resp) => resp,
        Err(err) => {
            http_modules.on_error(&err).await;
            if let Some(stale) = finalize_forward_stale_if_error(
                &revalidation_state,
                selected_plan,
                http_modules,
                request_method,
                proxy_name,
                headers.as_deref(),
                audit,
            )
            .await?
            {
                return Ok(
                    emit_optional_response_for_export(stale, selected_plan, export_session).await,
                );
            }
            return Err(err);
        }
    };
    let mut response = proxied.response;
    if !proxied.interim.is_empty() {
        response.extensions_mut().insert(proxied.interim);
    }
    response = http_modules.on_upstream_response(response).await?;
    let response_policy_tags = match apply_forward_response_policy(ForwardResponsePolicyInput {
        response,
        response_engine,
        selected_plan,
        base,
        destination,
        identity,
        host,
        remote_addr,
        state,
        request_method,
        client_version,
        proxy_name,
        headers,
        request_rpc,
        http_modules,
        audit,
    })
    .await?
    {
        DispatchResponsePolicyOutcome::Response(response) => {
            return Ok(
                emit_optional_response_for_export(response, selected_plan, export_session).await,
            );
        }
        DispatchResponsePolicyOutcome::Continue {
            response: updated,
            headers: updated_headers,
            cache_bypass,
            suppress_retry: _suppress_retry,
            mirror: _mirror,
            policy_tags,
        } => {
            response = updated;
            headers = updated_headers;
            if cache_bypass {
                cache_policy = None;
            }
            policy_tags
        }
    };
    let response_delay_secs = upstream_started.elapsed().as_secs();
    if response.status().is_server_error()
        && let Some(stale) = finalize_forward_stale_if_error(
            &revalidation_state,
            selected_plan,
            http_modules,
            request_method,
            proxy_name,
            headers.as_deref(),
            audit,
        )
        .await?
    {
        return Ok(emit_optional_response_for_export(stale, selected_plan, export_session).await);
    }
    response = write_dispatch_cache_result(DispatchCacheWriteInput {
        response,
        cache_policy: cache_policy.as_ref(),
        response_cache_bypass: false,
        request_headers_snapshot,
        cache_target_key,
        cache_lookup_key,
        revalidation_state,
        request_collapse_guard: cache_collapse_guard,
        request_method,
        response_delay_secs,
        state,
    })
    .await?;
    response = http_modules.prepare_downstream_response(response).await?;
    finalize_response_with_headers_in_place(
        request_method,
        response.version(),
        proxy_name,
        &mut response,
        headers.as_deref(),
        false,
    );
    response = emit_optional_response_for_export(response, selected_plan, export_session).await;
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_dispatch_response(
        &mut response,
        audit,
        DispatchOutcome::Allow,
        &response_policy_tags,
    );
    Ok(response)
}

pub(super) struct ForwardResponsePolicyInput<'a> {
    pub(super) response: Response<Body>,
    pub(super) response_engine:
        Option<&'a crate::http::policy::response_policy::HttpResponseRuleEngine>,
    pub(super) selected_plan: &'a crate::runtime::ExecutionPlan,
    pub(super) base: &'a BaseRequestFields,
    pub(super) destination: &'a crate::destination::DestinationMetadata,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) host: &'a HostPort,
    pub(super) remote_addr: std::net::SocketAddr,
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) request_method: &'a Method,
    pub(super) client_version: http::Version,
    pub(super) proxy_name: &'a str,
    pub(super) headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    pub(super) request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) audit: &'a DispatchAuditContext,
}

async fn apply_forward_response_policy(
    input: ForwardResponsePolicyInput<'_>,
) -> Result<DispatchResponsePolicyOutcome> {
    let response_prefilter_ctx = MatchPrefilterContext {
        method: Some(input.request_method.as_str()),
        dst_port: input.host.port,
        src_ip: Some(input.remote_addr.ip()),
        host: Some(input.host.host.as_str()),
        sni: None,
        path: input.base.path.as_deref(),
    };
    let response_candidates = input
        .response_engine
        .map(|engine| engine.candidate_profile(response_prefilter_ctx))
        .unwrap_or_default();
    let response_status = input.response.status().as_u16();
    let response_headers = input.response.headers().clone();
    apply_dispatch_response_policy(DispatchResponsePolicyInput {
        response: input.response,
        engine: input.response_engine,
        candidates: response_candidates,
        rule_context: build_response_rule_match_context(ResponseRuleContextInput {
            base: input.base,
            headers: Some(&response_headers),
            destination: input.destination,
            identity: input.identity,
            response_status,
            response_size: None,
            rpc: None,
            client_cert: None,
            upstream_cert: None,
        }),
        headers: input.headers,
        request_rpc: input.request_rpc,
        body_observation: ResponseBodyObservationLimits {
            max_body_bytes: input.selected_plan.response_body_observation_limit(
                input
                    .state
                    .plan
                    .limits
                    .body
                    .max_observed_response_body_bytes,
            ),
            read_timeout: std::time::Duration::from_millis(
                input
                    .state
                    .plan
                    .limits
                    .timeouts
                    .upstream_http_timeout_ms
                    .max(1),
            ),
            force_body: false,
        },
        http_modules: input.http_modules,
        audit: input.audit,
        local_response_outcome: crate::http::dispatch::DispatchOutcome::ResponseLocalResponse,
        request_method: input.request_method,
        request_version: input.client_version,
        proxy_name: input.proxy_name,
    })
    .await
}

async fn finalize_forward_stale_if_error(
    revalidation_state: &Option<qpxd_cache::RevalidationState>,
    selected_plan: &crate::runtime::ExecutionPlan,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    request_method: &Method,
    proxy_name: &str,
    headers: Option<&qpx_core::rules::CompiledHeaderControl>,
    audit: &DispatchAuditContext,
) -> Result<Option<Response<Body>>> {
    finalize_dispatch_stale_if_error_response(
        revalidation_state.as_ref(),
        selected_plan,
        request_method,
        proxy_name,
        headers,
        http_modules,
        audit,
    )
    .await
}
