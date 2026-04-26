use crate::http::body::Body;
use crate::http::body_size::{
    buffer_request_body, buffer_response_body, observe_request_body_size,
    observe_response_body_size,
};
use crate::http::response_policy::ResponseRuleCandidates;
use anyhow::Result;
use hyper::{Request, Response};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_core::rules::RuleEngine;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RequestObservationPlan {
    pub(crate) needs_size: bool,
    pub(crate) needs_body: bool,
    pub(crate) needs_rpc: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ResponseObservationPlan {
    pub(crate) needs_size: bool,
    pub(crate) needs_body: bool,
    pub(crate) needs_rpc_context: bool,
    pub(crate) needs_rpc_observation: bool,
}

impl RequestObservationPlan {
    pub(crate) fn from_policy_candidates(
        engine: &RuleEngine,
        response_candidates: &ResponseRuleCandidates,
        ctx: MatchPrefilterContext<'_>,
    ) -> Self {
        Self {
            needs_size: engine.candidate_requires_request_size(ctx.clone()),
            needs_body: engine.candidate_requires_request_body_observation(ctx.clone())
                || response_candidates.requires_request_body_observation,
            needs_rpc: engine.candidate_requires_request_rpc_context(ctx)
                || response_candidates.requires_request_rpc_context,
        }
    }

    pub(crate) fn include(&mut self, needs_size: bool, needs_body: bool, needs_rpc: bool) -> bool {
        self.needs_size |= needs_size;
        self.needs_body |= needs_body;
        self.needs_rpc |= needs_rpc;
        self.needs_size && self.needs_body && self.needs_rpc
    }

    pub(crate) fn include_body(&mut self, needs_body: bool) {
        self.needs_body |= needs_body;
    }

    pub(crate) async fn observe_request(
        self,
        req: Request<Body>,
        max_body_bytes: usize,
        read_timeout: Duration,
    ) -> Result<Request<Body>> {
        if self.needs_body {
            buffer_request_body(req, max_body_bytes, read_timeout).await
        } else if self.needs_size {
            observe_request_body_size(req, max_body_bytes, read_timeout).await
        } else {
            Ok(req)
        }
    }
}

impl ResponseObservationPlan {
    pub(crate) fn from_policy_candidates(candidates: &ResponseRuleCandidates) -> Self {
        Self {
            needs_size: candidates.requires_response_size,
            needs_body: candidates.requires_response_body_observation,
            needs_rpc_context: candidates.requires_response_rpc_context,
            needs_rpc_observation: candidates.requires_response_rpc_observation,
        }
    }

    pub(crate) async fn observe_response(
        self,
        response: Response<Body>,
        max_body_bytes: usize,
        read_timeout: Duration,
    ) -> Result<Response<Body>> {
        if self.needs_body {
            buffer_response_body(response, max_body_bytes, read_timeout).await
        } else if self.needs_size {
            observe_response_body_size(response, max_body_bytes, read_timeout).await
        } else {
            Ok(response)
        }
    }
}
