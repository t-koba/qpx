use super::super::mirrors::dispatch_mirrors;
use crate::http::dispatch::{
    DispatchCacheWriteInput, DispatchOutcome, annotate_dispatch_response,
    write_dispatch_cache_result,
};
use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use crate::reverse::router::{HttpRoute, SelectedMirrorTarget};
use crate::reverse::transport::request_template::{ReverseReplayRecorder, ReverseRequestTemplate};
use anyhow::Result;
use hyper::{Method, Response};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use qpxd_cache::CacheRequestKey;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

pub(super) struct ReverseFinalizeResponseInput<'a> {
    pub(super) response: Response<Body>,
    pub(super) state: &'a Arc<crate::runtime::RuntimeState>,
    pub(super) route: &'a HttpRoute,
    pub(super) request_method: &'a Method,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) response_cache_bypass: bool,
    pub(super) request_headers_snapshot: Option<&'a qpx_core::http_message::Request<()>>,
    pub(super) cache_target_key: Option<&'a CacheRequestKey>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) revalidation_state: &'a mut Option<qpxd_cache::RevalidationState>,
    pub(super) cache_collapse_guard: &'a mut Option<qpxd_cache::RequestCollapseGuard>,
    pub(super) started: Option<Instant>,
    pub(super) route_headers_for_response: Option<Arc<CompiledHeaderControl>>,
    pub(super) export_session: Option<&'a crate::exporter::ExportSession>,
    pub(super) template: Option<&'a ReverseRequestTemplate>,
    pub(super) replay_recorder: Option<&'a ReverseReplayRecorder>,
    pub(super) mirror_upstreams: &'a mut Vec<SelectedMirrorTarget>,
    pub(super) mirror: Option<bool>,
    pub(super) route_timeout: Duration,
    pub(super) proxy_name: &'a str,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) audit_ctx: &'a crate::http::dispatch::DispatchAuditContext,
    pub(super) policy_tags: &'a [String],
}

pub(super) async fn finalize_reverse_dispatch_response(
    input: ReverseFinalizeResponseInput<'_>,
) -> Result<Response<Body>> {
    let ReverseFinalizeResponseInput {
        response: mut resp,
        state,
        route,
        request_method,
        cache_policy,
        response_cache_bypass,
        request_headers_snapshot,
        cache_target_key,
        cache_lookup_key,
        revalidation_state,
        cache_collapse_guard,
        started,
        route_headers_for_response,
        export_session,
        template,
        replay_recorder,
        mirror_upstreams,
        mirror,
        route_timeout,
        proxy_name,
        http_modules,
        audit_ctx,
        policy_tags,
    } = input;
    resp = write_dispatch_cache_result(DispatchCacheWriteInput {
        response: resp,
        cache_policy,
        response_cache_bypass,
        request_headers_snapshot,
        cache_target_key,
        cache_lookup_key,
        revalidation_state: revalidation_state.take(),
        request_collapse_guard: cache_collapse_guard.take(),
        request_method,
        response_delay_secs: cache_policy
            .and_then(|_| started.map(|started| started.elapsed().as_secs()))
            .unwrap_or(0),
        state,
    })
    .await?;
    resp = http_modules.prepare_downstream_response(resp).await?;
    finalize_response_with_headers_in_place(
        request_method,
        resp.version(),
        proxy_name,
        &mut resp,
        route_headers_for_response.as_deref(),
        false,
    );
    resp = crate::http::capture::stream::emit_optional_response_for_export(
        resp,
        &route.plan,
        export_session,
    )
    .await;
    if mirror.unwrap_or(true) && !mirror_upstreams.is_empty() {
        if let Some(template) = template {
            dispatch_mirrors(
                state.pools.clone(),
                template,
                std::mem::take(mirror_upstreams),
                route_timeout,
                route.policy.health.clone(),
                route.policy.lifecycle.clone(),
                route.upstream_trust.clone(),
                proxy_name,
            );
        } else if let Some(recorder) = replay_recorder
            && let Some(template) = recorder.template().await
        {
            dispatch_mirrors(
                state.pools.clone(),
                template.as_ref(),
                std::mem::take(mirror_upstreams),
                route_timeout,
                route.policy.health.clone(),
                route.policy.lifecycle.clone(),
                route.upstream_trust.clone(),
                proxy_name,
            );
        }
    }
    http_modules.on_logging(Some(resp.status()), None).await;
    annotate_dispatch_response(&mut resp, audit_ctx, DispatchOutcome::Allow, policy_tags);
    Ok(resp)
}
