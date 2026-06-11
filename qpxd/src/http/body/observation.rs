use crate::http::body::size::{
    buffer_request_body_with_reason, buffer_response_body_with_reason,
    observe_request_body_size_with_reason, observe_response_body_size_with_reason,
};
use crate::http::policy::response_policy::ResponseRuleCandidates;
use anyhow::Result;
use hyper::{Request, Response};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_core::rules::{CandidateRequestObservationRequirements, RuleEngine};
use qpx_http::body::Body;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RequestObservationPlan {
    pub(crate) needs_size: bool,
    pub(crate) needs_body: bool,
    pub(crate) needs_rpc: bool,
    request_body_reason: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ResponseObservationPlan {
    pub(crate) needs_size: bool,
    pub(crate) needs_body: bool,
    pub(crate) needs_rpc_context: bool,
    pub(crate) needs_rpc_observation: bool,
    response_body_reason: &'static str,
}

impl Default for RequestObservationPlan {
    fn default() -> Self {
        Self {
            needs_size: false,
            needs_body: false,
            needs_rpc: false,
            request_body_reason: "request.body",
        }
    }
}

impl Default for ResponseObservationPlan {
    fn default() -> Self {
        Self {
            needs_size: false,
            needs_body: false,
            needs_rpc_context: false,
            needs_rpc_observation: false,
            response_body_reason: "response.body",
        }
    }
}

impl RequestObservationPlan {
    pub(crate) fn from_requirements(requirements: CandidateRequestObservationRequirements) -> Self {
        let mut plan = Self {
            needs_size: requirements.needs_size,
            needs_body: requirements.needs_body,
            needs_rpc: requirements.needs_rpc,
            ..Self::default()
        };
        if requirements.needs_body {
            plan.request_body_reason = "rpc.body";
        }
        plan
    }

    pub(crate) fn from_policy_candidates(
        engine: &RuleEngine,
        response_candidates: &ResponseRuleCandidates,
        ctx: MatchPrefilterContext<'_>,
    ) -> Self {
        let requirements = engine.candidate_request_observation_requirements(ctx);
        let mut plan = Self {
            needs_size: requirements.needs_size,
            needs_body: requirements.needs_body
                || response_candidates.requires_request_body_observation,
            needs_rpc: requirements.needs_rpc || response_candidates.requires_request_rpc_context,
            ..Self::default()
        };
        if plan.needs_body {
            plan.request_body_reason = "rpc.body";
        }
        plan
    }

    pub(crate) fn include(&mut self, needs_size: bool, needs_body: bool, needs_rpc: bool) -> bool {
        self.needs_size |= needs_size;
        if needs_body && !self.needs_body {
            self.request_body_reason = if needs_rpc {
                "rpc.body"
            } else {
                "request.body"
            };
            self.needs_body = true;
        }
        self.needs_rpc |= needs_rpc;
        self.needs_size && self.needs_body && self.needs_rpc
    }

    pub(crate) fn include_body_with_reason(&mut self, needs_body: bool, reason: &'static str) {
        if needs_body && !self.needs_body {
            self.request_body_reason = reason;
            self.needs_body = true;
        }
    }

    pub(crate) fn is_empty(self) -> bool {
        !self.needs_size && !self.needs_body && !self.needs_rpc
    }

    pub(crate) async fn observe_request(
        self,
        req: Request<Body>,
        max_body_bytes: usize,
        read_timeout: Duration,
    ) -> Result<Request<Body>> {
        if self.needs_body {
            buffer_request_body_with_reason(
                req,
                max_body_bytes,
                read_timeout,
                self.request_body_reason(),
            )
            .await
        } else if self.needs_size {
            observe_request_body_size_with_reason(
                req,
                max_body_bytes,
                read_timeout,
                "request.size_exact_unknown",
            )
            .await
        } else {
            Ok(req)
        }
    }

    fn request_body_reason(self) -> &'static str {
        self.request_body_reason
    }
}

pub(crate) async fn observe_missing_request_requirements(
    req: Request<Body>,
    requirements: CandidateRequestObservationRequirements,
    request_body_observed: bool,
    request_rpc_observed: bool,
    max_observed_request_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<(Request<Body>, bool)> {
    if requirements.is_empty()
        || ((request_body_observed || !requirements.needs_body)
            && (request_rpc_observed || !requirements.needs_rpc))
    {
        return Ok((req, false));
    }
    let observation_plan = RequestObservationPlan::from_requirements(requirements);
    let req = observation_plan
        .observe_request(req, max_observed_request_body_bytes, body_read_timeout)
        .await?;
    Ok((req, observation_plan.needs_rpc))
}

impl ResponseObservationPlan {
    pub(crate) fn include_body(&mut self, needs_body: bool) {
        self.include_body_with_reason(needs_body, "response.body");
    }

    pub(crate) fn include_body_with_reason(&mut self, needs_body: bool, reason: &'static str) {
        if needs_body && !self.needs_body {
            self.response_body_reason = reason;
            self.needs_body = true;
        }
    }

    pub(crate) async fn observe_response(
        self,
        response: Response<Body>,
        max_body_bytes: usize,
        read_timeout: Duration,
    ) -> Result<Response<Body>> {
        if self.needs_body {
            buffer_response_body_with_reason(
                response,
                max_body_bytes,
                read_timeout,
                self.response_body_reason(),
            )
            .await
        } else if self.needs_size {
            observe_response_body_size_with_reason(
                response,
                max_body_bytes,
                read_timeout,
                "response.size_exact_unknown",
            )
            .await
        } else {
            Ok(response)
        }
    }

    fn response_body_reason(self) -> &'static str {
        self.response_body_reason
    }
}

#[cfg(test)]
mod tests {
    use crate::http::body::observation::*;

    #[test]
    fn request_body_reason_prefers_guard_when_rpc_only_matcher_is_present() {
        let mut plan =
            RequestObservationPlan::from_requirements(CandidateRequestObservationRequirements {
                needs_rpc: true,
                ..CandidateRequestObservationRequirements::default()
            });

        plan.include_body_with_reason(true, "http_guard.body");

        assert!(plan.needs_body);
        assert!(plan.needs_rpc);
        assert_eq!(plan.request_body_reason(), "http_guard.body");
    }

    #[test]
    fn rpc_body_requirement_keeps_rpc_body_reason() {
        let plan =
            RequestObservationPlan::from_requirements(CandidateRequestObservationRequirements {
                needs_body: true,
                needs_rpc: true,
                ..CandidateRequestObservationRequirements::default()
            });

        assert_eq!(plan.request_body_reason(), "rpc.body");
    }

    #[test]
    fn response_rpc_body_requirement_keeps_rpc_response_reason() {
        let mut plan = ResponseObservationPlan::default();
        plan.include_body_with_reason(true, "rpc.response_body");

        assert_eq!(plan.response_body_reason(), "rpc.response_body");
    }
}
