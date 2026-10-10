use super::{ReverseRetryDispatch, ReverseRetryPrepareInput};
use crate::reverse::health::UpstreamEndpoint;
use crate::reverse::router::SelectedMirrorTarget;
use crate::reverse::transport::mirrors::{
    StreamingMirrorDispatch, dispatch_streaming_mirrors, request_is_templateable,
};
use crate::reverse::transport::request_template::{
    ReverseReplayRecorder, ReverseRequestHeadTemplate, ReverseRequestTemplate,
    request_is_retryable, request_may_have_body,
};
use anyhow::Result;
use hyper::Request;
use std::sync::Arc;
use tokio::time::Duration;

pub(super) async fn prepare_reverse_retry_dispatch(
    input: ReverseRetryPrepareInput<'_>,
) -> Result<ReverseRetryDispatch> {
    let ReverseRetryPrepareInput {
        req,
        route,
        state,
        request_method,
        seed,
        sticky_seed,
        decision_service_mirror_upstreams,
        route_timeout,
        proxy_name,
    } = input;
    if route.policy.retry_attempts == 1
        && !route
            .plan
            .flags
            .contains(crate::runtime::PlanFlags::MIRRORING)
        && decision_service_mirror_upstreams.is_empty()
    {
        return Ok(ReverseRetryDispatch {
            attempts: 1,
            first_request: Some(req),
            template: None,
            replay_recorder: None,
            mirror_upstreams: Vec::new(),
        });
    }
    let retry_body_threshold_bytes = if route.policy.retry_body_replay {
        route.policy.retry_body_threshold_bytes
    } else {
        0
    };
    let can_retry = request_is_retryable(&req, request_method, retry_body_threshold_bytes);
    let max_template_body_bytes = state
        .plan
        .limits
        .upstream
        .max_reverse_retry_template_body_bytes;
    let templateable = request_is_templateable(&req, max_template_body_bytes);
    let attempts = if can_retry && templateable {
        route.policy.retry_attempts
    } else {
        1
    };
    let selected_mirrors = route.select_mirror_upstreams(seed, sticky_seed);
    let mut streaming_mirrors = Vec::new();
    let mut mirror_upstreams = Vec::new();
    let decision_service_mirror_body_limit = Some(
        state
            .plan
            .limits
            .upstream
            .max_reverse_retry_template_body_bytes,
    );
    let mut decision_service_mirrors = decision_service_mirror_upstreams
        .into_iter()
        .map(UpstreamEndpoint::new)
        .map(Arc::new)
        .map(|upstream| SelectedMirrorTarget {
            upstream,
            max_mirror_body_bytes: decision_service_mirror_body_limit,
        })
        .collect::<Vec<_>>();
    if attempts == 1 {
        streaming_mirrors.extend(selected_mirrors);
        streaming_mirrors.append(&mut decision_service_mirrors);
    } else {
        mirror_upstreams.extend(selected_mirrors);
        mirror_upstreams.extend(decision_service_mirrors);
    }
    let req = if streaming_mirrors.is_empty() {
        req
    } else {
        let mirror_limits = streaming_mirrors
            .iter()
            .map(|mirror| mirror.max_mirror_body_bytes)
            .collect::<Vec<_>>();
        let (parts, body) = req.into_parts();
        let template = ReverseRequestHeadTemplate::from_parts(&parts);
        let (primary_body, mirror_bodies) = qpx_http::body::tee::tee_body_lossy_with_metrics(
            body,
            mirror_limits,
            route.plan.streaming.body_channel_capacity,
            Some("reverse_streaming_mirror"),
        );
        dispatch_streaming_mirrors(StreamingMirrorDispatch {
            pools: state.pools.clone(),
            template,
            mirror_upstreams: streaming_mirrors,
            mirror_bodies,
            timeout_dur: route_timeout,
            health_policy: route.policy.health.clone(),
            lifecycle: route.policy.lifecycle.clone(),
            upstream_trust: route.upstream_trust.clone(),
            proxy_name,
        });
        Request::from_parts(parts, primary_body)
    };
    let need_template = attempts > 1 || !mirror_upstreams.is_empty();
    let (first_request, template, replay_recorder) =
        if need_template && !request_may_have_body(&req) {
            let template = ReverseRequestTemplate::without_body(&req);
            (Some(req), Some(template), None)
        } else if need_template {
            let (req, recorder) = ReverseReplayRecorder::wrap_first_request(
                req,
                max_template_body_bytes,
                Duration::from_millis(route.plan.streaming.body_read_timeout_ms),
                route.plan.streaming.body_channel_capacity,
            );
            (Some(req), None, Some(recorder))
        } else {
            (Some(req), None, None)
        };
    Ok(ReverseRetryDispatch {
        attempts,
        first_request,
        template,
        replay_recorder,
        mirror_upstreams,
    })
}
