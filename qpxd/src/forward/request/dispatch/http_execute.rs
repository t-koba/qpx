use super::super::HostPort;
use super::request_dispatch_cache::{
    ForwardCacheCollapseInput, ForwardCacheLookupInput, try_forward_cache_collapse,
    try_forward_cache_lookup,
};
use super::request_dispatch_upstream::{ForwardUpstreamInput, execute_forward_upstream};
use super::types::ForwardDispatchReady;
use crate::http::body::Body;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchCacheCollapseOutcome, DispatchCacheLookupOutcome,
};
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::runtime::Runtime;
use anyhow::Result;
use hyper::{Method, Response};
use std::sync::Arc;

pub(super) struct ForwardPreparedHttpInput<'a> {
    pub(super) ready: ForwardDispatchReady,
    pub(super) runtime: &'a Runtime,
    pub(super) action: &'a qpx_core::config::ActionConfig,
    pub(super) listener_name: &'a str,
    pub(super) request_method: &'a Method,
    pub(super) client_version: http::Version,
    pub(super) proxy_name: &'a str,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) audit: &'a DispatchAuditContext,
    pub(super) response_engine:
        Option<&'a crate::http::policy::response_policy::HttpResponseRuleEngine>,
    pub(super) selected_plan: &'a crate::runtime::ExecutionPlan,
    pub(super) base: &'a BaseRequestFields,
    pub(super) destination: &'a crate::destination::DestinationMetadata,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) host: &'a HostPort,
    pub(super) remote_addr: std::net::SocketAddr,
    pub(super) request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
}

pub(super) async fn execute_forward_http_after_prepare(
    input: ForwardPreparedHttpInput<'_>,
) -> Result<Response<Body>> {
    let ForwardDispatchReady {
        mut req,
        mut http_modules,
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        upstream,
        upstream_timeout,
        http_authority,
        export_session,
        _concurrency_permits,
    } = input.ready;
    let mut revalidation_state;
    match try_forward_cache_lookup(ForwardCacheLookupInput {
        req: &mut req,
        runtime: input.runtime,
        action: input.action,
        listener_name: input.listener_name,
        http_authority: http_authority.as_str(),
        upstream_timeout,
        request_method: input.request_method,
        client_version: input.client_version,
        proxy_name: input.proxy_name,
        headers: input.headers.as_deref(),
        cache_policy: input.cache_policy,
        request_headers_snapshot: request_headers_snapshot.as_ref(),
        cache_lookup_key: cache_lookup_key.as_ref(),
        cache_target_key: cache_target_key.as_ref(),
        state: input.state,
        http_modules: &mut http_modules,
        audit: input.audit,
    })
    .await?
    {
        DispatchCacheLookupOutcome::Response(response) => return Ok(response),
        DispatchCacheLookupOutcome::Continue(state) => revalidation_state = state,
    }
    let cache_collapse_guard = match try_forward_cache_collapse(ForwardCacheCollapseInput {
        req: &mut req,
        request_method: input.request_method,
        client_version: input.client_version,
        proxy_name: input.proxy_name,
        headers: input.headers.as_deref(),
        request_headers_snapshot: request_headers_snapshot.as_ref(),
        cache_policy: input.cache_policy,
        cache_lookup_key: cache_lookup_key.as_ref(),
        state: input.state,
        http_modules: &mut http_modules,
        upstream_timeout,
        audit: input.audit,
        revalidation_state,
    })
    .await?
    {
        DispatchCacheCollapseOutcome::Response(response) => return Ok(*response),
        DispatchCacheCollapseOutcome::Continue {
            revalidation_state: state,
            guard,
        } => {
            revalidation_state = state.map(|state| *state);
            guard
        }
    };
    execute_forward_upstream(ForwardUpstreamInput {
        req,
        upstream: upstream.as_ref(),
        http_authority: http_authority.as_str(),
        upstream_timeout,
        http_modules: &mut http_modules,
        export_session: export_session.as_ref(),
        request_method: input.request_method,
        client_version: input.client_version,
        proxy_name: input.proxy_name,
        headers: input.headers,
        cache_policy: input.cache_policy.cloned(),
        request_headers_snapshot: request_headers_snapshot.as_ref(),
        cache_lookup_key: cache_lookup_key.as_ref(),
        cache_target_key: cache_target_key.as_ref(),
        revalidation_state,
        cache_collapse_guard,
        response_engine: input.response_engine,
        selected_plan: input.selected_plan,
        base: input.base,
        destination: input.destination,
        identity: input.identity,
        host: input.host,
        remote_addr: input.remote_addr,
        state: input.state,
        request_rpc: input.request_rpc,
        audit: input.audit,
    })
    .await
}
