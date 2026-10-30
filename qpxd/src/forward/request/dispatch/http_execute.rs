use super::request_dispatch_cache::{
    ForwardCacheCollapseInput, ForwardCacheContext, ForwardCacheLookupInput,
    try_forward_cache_collapse, try_forward_cache_lookup,
};
use super::request_dispatch_upstream::{
    ForwardRequestContext, ForwardUpstreamInput, execute_forward_upstream,
};
use super::types::ForwardDispatchReady;
use crate::http::dispatch::{DispatchCacheCollapseOutcome, DispatchCacheLookupOutcome};
use crate::runtime::Runtime;
use anyhow::Result;
use qpx_core::http_message::Response as OwnerResponse;
use qpx_http::body::Body;

pub(super) struct ForwardPreparedHttpInput<'a> {
    pub(super) context: ForwardRequestContext<'a>,
    pub(super) ready: ForwardDispatchReady,
    pub(super) runtime: &'a Runtime,
    pub(super) action: &'a qpx_core::config::ActionConfig,
    pub(super) listener_name: &'a str,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
}

pub(super) async fn execute_forward_http_after_prepare(
    input: ForwardPreparedHttpInput<'_>,
) -> Result<OwnerResponse<Body>> {
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
    let cache_context = ForwardCacheContext {
        request_method: input.context.request_method,
        client_version: input.context.client_version,
        proxy_name: input.context.proxy_name,
        headers: input.context.headers.as_deref(),
        selected_plan: input.context.selected_plan,
        cache_policy: input.cache_policy,
        request_headers_snapshot: request_headers_snapshot.as_ref(),
        cache_lookup_key: cache_lookup_key.as_ref(),
        state: input.context.state,
        upstream_timeout,
        audit: input.context.audit,
    };
    let mut revalidation_state;
    match try_forward_cache_lookup(ForwardCacheLookupInput {
        context: cache_context,
        req: &mut req,
        runtime: input.runtime,
        action: input.action,
        listener_name: input.listener_name,
        http_authority: http_authority.as_str(),
        cache_target_key: cache_target_key.as_ref(),
        http_modules: &mut http_modules,
    })
    .await?
    {
        DispatchCacheLookupOutcome::Response(response) => {
            return Ok(
                crate::http::capture::stream::emit_optional_response_for_export(
                    *response,
                    input.context.selected_plan,
                    export_session.as_ref(),
                )
                .await,
            );
        }
        DispatchCacheLookupOutcome::Continue(state) => revalidation_state = state.map(|s| *s),
    }
    let cache_collapse_guard = match try_forward_cache_collapse(ForwardCacheCollapseInput {
        context: cache_context,
        req: &mut req,
        http_modules: &mut http_modules,
        revalidation_state,
    })
    .await?
    {
        DispatchCacheCollapseOutcome::Response(response) => {
            return Ok(
                crate::http::capture::stream::emit_optional_response_for_export(
                    *response,
                    input.context.selected_plan,
                    export_session.as_ref(),
                )
                .await,
            );
        }
        DispatchCacheCollapseOutcome::Continue {
            revalidation_state: state,
            guard,
        } => {
            revalidation_state = state.map(|state| *state);
            guard
        }
    };
    execute_forward_upstream(ForwardUpstreamInput {
        context: input.context,
        req,
        upstream: upstream.as_ref(),
        http_authority: http_authority.as_str(),
        upstream_timeout,
        http_modules: &mut http_modules,
        export_session: export_session.as_ref(),
        cache_policy: input.cache_policy.cloned(),
        request_headers_snapshot: request_headers_snapshot.as_ref(),
        cache_lookup_key: cache_lookup_key.as_ref(),
        cache_target_key: cache_target_key.as_ref(),
        revalidation_state,
        cache_collapse_guard,
    })
    .await
}
