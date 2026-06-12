use crate::http::body::observation::ResponseObservationPlan;
use crate::http::body::size::observed_response_size;
use crate::http::local_response::build_local_response;
use crate::http::rpc::RpcMatchContext;
use crate::policy_context::merge_header_controls;
use anyhow::Result;
use hyper::Response;
use qpx_core::config::HttpResponseRuleConfig;
use qpx_core::prefilter::{MatchPrefilterContext, MatchPrefilterIndex, StringInterner};
use qpx_core::rules::{
    CandidateRequestObservationRequirements, CompiledHeaderControl, RuleMatchContext,
};
use qpx_http::body::Body;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy)]
pub(crate) struct ResponseBodyObservationLimits {
    pub(crate) max_body_bytes: usize,
    pub(crate) read_timeout: Duration,
    pub(crate) force_body: bool,
}

pub(crate) enum ListenerResponsePolicyDecision {
    Continue {
        response: Response<Body>,
        headers: Option<Arc<CompiledHeaderControl>>,
        cache_bypass: bool,
        suppress_retry: bool,
        mirror: Option<bool>,
        policy_tags: Vec<String>,
    },
    LocalResponse {
        response: Response<Body>,
        headers: Option<Arc<CompiledHeaderControl>>,
        policy_tags: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct HttpResponseRuleEngine {
    rules: Vec<CompiledHttpResponseRule>,
    prefilter: MatchPrefilterIndex,
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledHttpResponseRule {
    pub(crate) matcher: qpx_core::matchers::CompiledMatch,
    pub(crate) local_response: Option<qpx_core::config::LocalResponseConfig>,
    pub(crate) headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) cache_bypass: bool,
    pub(crate) suppress_retry: bool,
    pub(crate) mirror: Option<bool>,
    pub(crate) policy_tags: Arc<[String]>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ResponseRuleCandidates {
    pub(crate) indices: Vec<usize>,
    pub(crate) requires_response_size: bool,
    pub(crate) requires_response_body_observation: bool,
    pub(crate) requires_response_rpc_context: bool,
    pub(crate) requires_request_rpc_context: bool,
    pub(crate) requires_request_body_observation: bool,
    pub(crate) requires_response_rpc_observation: bool,
}

impl HttpResponseRuleEngine {
    pub(crate) fn len(&self) -> usize {
        self.rules.len()
    }

    pub(crate) fn new(rules: &[HttpResponseRuleConfig]) -> Result<Option<Self>> {
        if rules.is_empty() {
            return Ok(None);
        }

        let mut interner = StringInterner::default();
        let mut compiled = Vec::with_capacity(rules.len());
        let mut hints = Vec::with_capacity(rules.len());
        for rule in rules {
            let (matcher, hint) = qpx_core::matchers::CompiledMatch::compile(
                rule.r#match.as_ref().unwrap_or(&Default::default()),
                &mut interner,
            )?;
            compiled.push(CompiledHttpResponseRule {
                matcher,
                local_response: rule.effects.local_response.clone(),
                headers: rule
                    .effects
                    .headers
                    .as_ref()
                    .map(CompiledHeaderControl::compile)
                    .transpose()?
                    .map(Arc::new),
                cache_bypass: rule
                    .effects
                    .cache
                    .as_ref()
                    .map(|cache| cache.bypass)
                    .unwrap_or(false),
                suppress_retry: rule
                    .effects
                    .retry
                    .as_ref()
                    .map(|retry| retry.suppress)
                    .unwrap_or(false),
                mirror: rule
                    .effects
                    .mirror
                    .as_ref()
                    .and_then(|mirror| mirror.enabled),
                policy_tags: Arc::<[String]>::from(rule.effects.tags.clone()),
            });
            hints.push(hint);
        }

        let mut prefilter = MatchPrefilterIndex::new(compiled.len());
        for (idx, hint) in hints.iter().enumerate() {
            prefilter.insert_hint(idx, hint, &mut interner);
        }

        Ok(Some(Self {
            rules: compiled,
            prefilter,
        }))
    }

    pub(crate) fn candidate_profile(
        &self,
        ctx: MatchPrefilterContext<'_>,
    ) -> ResponseRuleCandidates {
        let mut out = ResponseRuleCandidates::default();
        self.prefilter.for_each_candidate(&ctx, |idx| {
            out.indices.push(idx);
            if let Some(rule) = self.rules.get(idx) {
                out.requires_response_size |= rule.matcher.requires_response_size();
                out.requires_response_body_observation |=
                    rule.matcher.requires_response_body_observation();
                out.requires_response_rpc_context |= rule.matcher.requires_response_rpc_context();
                out.requires_request_rpc_context |=
                    rule.matcher.requires_response_request_rpc_context();
                out.requires_request_body_observation |=
                    rule.matcher.requires_response_request_body_observation();
                out.requires_response_rpc_observation |=
                    rule.matcher.requires_response_rpc_observation();
            }
            false
        });
        out
    }

    pub(crate) fn rule_at(&self, idx: usize) -> Option<&CompiledHttpResponseRule> {
        self.rules.get(idx)
    }

    pub(crate) fn request_observation_requirements_for_candidates(
        &self,
        candidates: &ResponseRuleCandidates,
        ctx: &RuleMatchContext<'_>,
    ) -> CandidateRequestObservationRequirements {
        let mut out = CandidateRequestObservationRequirements::default();
        for idx in candidates.indices.iter().copied() {
            let Some(rule) = self.rules.get(idx) else {
                continue;
            };
            if !rule
                .matcher
                .matches_known_request_without_body_observation(ctx)
            {
                continue;
            }
            out.needs_body |= rule.matcher.requires_response_request_body_observation();
            out.needs_rpc |= rule.matcher.requires_response_request_rpc_context();
        }
        out
    }

    fn observation_plan_from_matching_candidates_from(
        &self,
        candidates: &[usize],
        start: usize,
        ctx: &RuleMatchContext<'_>,
    ) -> ResponseObservationPlan {
        let mut out = ResponseObservationPlan::default();
        for idx in candidates.iter().copied().skip(start) {
            let Some(rule) = self.rules.get(idx) else {
                continue;
            };
            if !rule.matcher.matches_without_response_body_observation(ctx) {
                continue;
            }
            out.needs_size |= rule.matcher.requires_response_size();
            out.include_body_with_reason(
                rule.matcher.requires_response_body_observation(),
                "rpc.response_body",
            );
            out.needs_rpc_context |= rule.matcher.requires_response_rpc_context();
            out.needs_rpc_observation |= rule.matcher.requires_response_rpc_observation();
        }
        out
    }

    pub(crate) fn any_rule_requires_response_request_body_observation(&self) -> bool {
        self.any_rule_requires(|rule| rule.matcher.requires_response_request_body_observation())
    }

    pub(crate) fn any_rule_requires_response_request_rpc_context(&self) -> bool {
        self.any_rule_requires(|rule| rule.matcher.requires_response_request_rpc_context())
    }

    pub(crate) fn any_rule_requires_response_body_observation(&self) -> bool {
        self.any_rule_requires(|rule| rule.matcher.requires_response_body_observation())
    }

    pub(crate) fn any_rule_requires_response_size(&self) -> bool {
        self.any_rule_requires(|rule| rule.matcher.requires_response_size())
    }

    pub(crate) fn any_rule_requires_response_size_matcher(&self) -> bool {
        self.any_rule_requires(|rule| rule.matcher.requires_response_size_matcher())
    }

    pub(crate) fn any_rule_requires_response_rpc_observation(&self) -> bool {
        self.any_rule_requires(|rule| rule.matcher.requires_response_rpc_observation())
    }

    fn any_rule_requires(&self, f: impl Fn(&CompiledHttpResponseRule) -> bool) -> bool {
        self.rules.iter().any(f)
    }
}

pub(crate) fn response_request_obs(
    engine: Option<&HttpResponseRuleEngine>,
    candidates: &ResponseRuleCandidates,
    ctx: &RuleMatchContext<'_>,
) -> CandidateRequestObservationRequirements {
    engine.map_or_else(CandidateRequestObservationRequirements::default, |engine| {
        engine.request_observation_requirements_for_candidates(candidates, ctx)
    })
}

pub(crate) async fn apply_listener_response_policy(
    engine: Option<&HttpResponseRuleEngine>,
    candidates: ResponseRuleCandidates,
    mut ctx: RuleMatchContext<'_>,
    mut response: Response<Body>,
    headers: Option<Arc<CompiledHeaderControl>>,
    request_rpc: Option<&RpcMatchContext>,
    body_observation: ResponseBodyObservationLimits,
) -> Result<ListenerResponsePolicyDecision> {
    let Some(engine) = engine else {
        let mut observation_plan = ResponseObservationPlan::default();
        observation_plan.include_body(body_observation.force_body);
        response = observation_plan
            .observe_response(
                response,
                body_observation.max_body_bytes,
                body_observation.read_timeout,
            )
            .await?;
        return Ok(ListenerResponsePolicyDecision::Continue {
            response,
            headers,
            cache_bypass: false,
            suppress_retry: false,
            mirror: None,
            policy_tags: Vec::new(),
        });
    };
    let mut observation_plan = if body_observation.force_body {
        let mut plan = ResponseObservationPlan::default();
        plan.include_body(true);
        response = plan
            .observe_response(
                response,
                body_observation.max_body_bytes,
                body_observation.read_timeout,
            )
            .await?;
        plan
    } else {
        ResponseObservationPlan::default()
    };
    if !body_observation.force_body {
        let mut early_ctx = ctx;
        early_ctx.response_status = Some(response.status().as_u16());
        early_ctx.headers = Some(response.headers());
        if let Some(request_rpc) = request_rpc {
            early_ctx.rpc_protocol = request_rpc.protocol.as_deref();
            early_ctx.rpc_service = request_rpc.service.as_deref();
            early_ctx.rpc_method = request_rpc.method.as_deref();
            early_ctx.rpc_streaming = request_rpc.streaming.as_deref();
        }
        let mut needs_observation = None;
        for (pos, idx) in candidates.indices.iter().copied().enumerate() {
            let Some(rule) = engine.rule_at(idx) else {
                continue;
            };
            let rule_needs_observation = rule.matcher.requires_response_size()
                || rule.matcher.requires_response_body_observation()
                || rule.matcher.requires_response_rpc_observation();
            if rule_needs_observation {
                if !rule
                    .matcher
                    .matches_without_response_body_observation(&early_ctx)
                {
                    continue;
                }
                needs_observation = Some(pos);
                break;
            }
            if rule.matcher.matches(&early_ctx) {
                return apply_compiled_response_rule(rule, response, headers);
            }
        }
        if let Some(pos) = needs_observation {
            observation_plan = engine.observation_plan_from_matching_candidates_from(
                &candidates.indices,
                pos,
                &early_ctx,
            );
            response = observation_plan
                .observe_response(
                    response,
                    body_observation.max_body_bytes,
                    body_observation.read_timeout,
                )
                .await?;
        }
    }
    let response_rpc = if observation_plan.needs_rpc_observation {
        let default_request_rpc;
        let request_rpc = match request_rpc {
            Some(request_rpc) => request_rpc,
            None => {
                default_request_rpc = RpcMatchContext::default();
                &default_request_rpc
            }
        };
        Some(crate::http::rpc::inspect_response(request_rpc, &response).await)
    } else {
        None
    };
    if observation_plan.needs_rpc_context {
        if let Some(response_rpc) = response_rpc.as_ref() {
            ctx.rpc_protocol = response_rpc.protocol.as_deref();
            ctx.rpc_service = response_rpc.service.as_deref();
            ctx.rpc_method = response_rpc.method.as_deref();
            ctx.rpc_streaming = response_rpc.streaming.as_deref();
            ctx.rpc_status = response_rpc.status.as_deref();
            ctx.rpc_message_size = response_rpc.message_size;
            ctx.rpc_message = response_rpc.message.as_deref();
            ctx.rpc_trailers = response_rpc.trailers.as_ref();
        } else if let Some(request_rpc) = request_rpc {
            ctx.rpc_protocol = request_rpc.protocol.as_deref();
            ctx.rpc_service = request_rpc.service.as_deref();
            ctx.rpc_method = request_rpc.method.as_deref();
            ctx.rpc_streaming = request_rpc.streaming.as_deref();
        }
    }
    if let Some(rpc) = response_rpc.as_ref().or(request_rpc) {
        response.extensions_mut().insert(rpc.to_log_context());
    }
    ctx.response_status = Some(response.status().as_u16());
    ctx.response_size = observed_response_size(&response);
    ctx.headers = Some(response.headers());

    for idx in candidates.indices {
        let Some(rule) = engine.rule_at(idx) else {
            continue;
        };
        if !rule.matcher.matches(&ctx) {
            continue;
        }
        return apply_compiled_response_rule(rule, response, headers);
    }

    Ok(ListenerResponsePolicyDecision::Continue {
        response,
        headers,
        cache_bypass: false,
        suppress_retry: false,
        mirror: None,
        policy_tags: Vec::new(),
    })
}

pub(crate) fn apply_compiled_response_rule(
    rule: &CompiledHttpResponseRule,
    response: Response<Body>,
    headers: Option<Arc<CompiledHeaderControl>>,
) -> Result<ListenerResponsePolicyDecision> {
    let merged_headers = merge_header_controls(headers, rule.headers.clone());
    let cache_bypass = rule.cache_bypass
        || rule.matcher.requires_response_context()
        || rule
            .headers
            .as_deref()
            .map(CompiledHeaderControl::has_response_mutations)
            .unwrap_or(false);
    let policy_tags = rule.policy_tags.as_ref().to_vec();
    if let Some(local) = rule.local_response.as_ref() {
        return Ok(ListenerResponsePolicyDecision::LocalResponse {
            response: build_local_response(local)?,
            headers: merged_headers,
            policy_tags,
        });
    }
    Ok(ListenerResponsePolicyDecision::Continue {
        response,
        headers: merged_headers,
        cache_bypass,
        suppress_retry: rule.suppress_retry,
        mirror: rule.mirror,
        policy_tags,
    })
}

#[cfg(test)]
mod tests;
