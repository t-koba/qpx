//! Compiled rule model and evaluation helpers.

#![allow(missing_docs)]

use crate::config::{ActionConfig, RuleAuthConfig, RuleConfig};
use crate::matchers::{CompiledMatch, MatchCompileError};
use crate::prefilter::{MatchPrefilterContext, MatchPrefilterIndex, StringInterner};
use std::sync::Arc;

mod context;
mod header_control;
mod observation;

pub use context::RuleMatchContext;
pub use header_control::{CompiledHeaderControl, CompiledRegexReplace};
pub use observation::CandidateRequestObservationRequirements;

type Result<T> = std::result::Result<T, RuleCompileError>;

#[derive(Debug, thiserror::Error)]
pub enum RuleCompileError {
    #[error(transparent)]
    Match(#[from] MatchCompileError),
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct RuleEngine {
    rules: Vec<Rule>,
    default_action: Arc<ActionConfig>,
    prefilter: MatchPrefilterIndex,
}

#[derive(Debug, Clone, Copy)]
pub struct RuleOutcomeRef<'a> {
    pub action: &'a ActionConfig,
    pub headers: Option<&'a Arc<CompiledHeaderControl>>,
    pub auth: Option<&'a RuleAuthConfig>,
    pub matched_rule: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    name: Arc<str>,
    matcher: CompiledMatch,
    action: Option<Arc<ActionConfig>>,
    auth: Option<Arc<RuleAuthConfig>>,
    headers: Option<Arc<CompiledHeaderControl>>,
}

impl RuleEngine {
    pub fn new(rules: Vec<RuleConfig>, default_action: ActionConfig) -> Result<Self> {
        let mut interner = StringInterner::default();
        let mut compiled_rules = Vec::with_capacity(rules.len());
        let mut hints = Vec::with_capacity(rules.len());

        for rule in rules {
            let match_cfg = rule.r#match.unwrap_or_default();
            let (matcher, hint) = CompiledMatch::compile(&match_cfg, &mut interner)?;
            let headers = match rule.headers {
                Some(control) => Some(Arc::new(
                    CompiledHeaderControl::compile(&control)
                        .map_err(|e| anyhow::anyhow!("rule {} header control: {}", rule.name, e))?,
                )),
                None => None,
            };
            compiled_rules.push(Rule {
                name: interner.intern(&rule.name),
                matcher,
                action: rule.action.map(Arc::new),
                auth: rule.auth.map(Arc::new),
                headers,
            });
            hints.push(hint);
        }

        let mut prefilter = MatchPrefilterIndex::new(compiled_rules.len());
        for (idx, hint) in hints.iter().enumerate() {
            prefilter.insert_hint(idx, hint, &mut interner);
        }

        Ok(Self {
            rules: compiled_rules,
            default_action: Arc::new(default_action),
            prefilter,
        })
    }

    pub fn evaluate_ref<'a>(&'a self, ctx: &RuleMatchContext<'_>) -> RuleOutcomeRef<'a> {
        let prefilter_ctx = MatchPrefilterContext {
            method: ctx.method,
            dst_port: ctx.dst_port,
            src_ip: ctx.src_ip,
            host: ctx.host,
            sni: ctx.sni,
            path: ctx.path,
        };

        self.prefilter
            .find_first(&prefilter_ctx, |idx| {
                let rule = &self.rules[idx];
                if rule.matches(ctx) {
                    return Some(RuleOutcomeRef {
                        action: rule
                            .action
                            .as_deref()
                            .unwrap_or(self.default_action.as_ref()),
                        headers: rule.headers.as_ref(),
                        auth: rule.auth.as_deref(),
                        matched_rule: Some(rule.name.as_ref()),
                    });
                }
                None
            })
            .unwrap_or(RuleOutcomeRef {
                action: self.default_action.as_ref(),
                headers: None,
                auth: None,
                matched_rule: None,
            })
    }

    pub fn first_matcher<'a>(&'a self, ctx: &RuleMatchContext<'_>) -> Option<&'a Rule> {
        let prefilter_ctx = MatchPrefilterContext {
            method: ctx.method,
            dst_port: ctx.dst_port,
            src_ip: ctx.src_ip,
            host: ctx.host,
            sni: ctx.sni,
            path: ctx.path,
        };

        self.prefilter.find_first(&prefilter_ctx, |idx| {
            let rule = &self.rules[idx];
            if rule.matcher.matches(ctx) {
                return Some(rule);
            }
            None
        })
    }

    pub fn matcher_candidate_indices(&self, ctx: &RuleMatchContext<'_>) -> Vec<usize> {
        let prefilter_ctx = MatchPrefilterContext {
            method: ctx.method,
            dst_port: ctx.dst_port,
            src_ip: ctx.src_ip,
            host: ctx.host,
            sni: ctx.sni,
            path: ctx.path,
        };

        let mut out = Vec::new();
        self.prefilter.for_each_candidate(&prefilter_ctx, |idx| {
            if self.rules[idx].matcher.matches(ctx) {
                out.push(idx);
            }
            false
        });
        out
    }

    pub fn candidate_rule_indices(&self, ctx: MatchPrefilterContext<'_>) -> Vec<usize> {
        let mut out = Vec::new();
        self.prefilter.for_each_candidate(&ctx, |idx| {
            out.push(idx);
            false
        });
        out
    }

    pub fn candidate_requires_request_size(&self, ctx: MatchPrefilterContext<'_>) -> bool {
        self.candidate_rule_indices(ctx).into_iter().any(|idx| {
            self.rules
                .get(idx)
                .map(Rule::requires_request_size)
                .unwrap_or(false)
        })
    }

    pub fn candidate_request_observation_requirements(
        &self,
        ctx: MatchPrefilterContext<'_>,
    ) -> CandidateRequestObservationRequirements {
        let mut out = CandidateRequestObservationRequirements::default();
        self.prefilter.for_each_candidate(&ctx, |idx| {
            if let Some(rule) = self.rules.get(idx) {
                out.needs_size |= rule.requires_request_size();
                out.needs_body |= rule.requires_request_body_observation();
                out.needs_rpc |= rule.requires_request_rpc_context();
            }
            out.needs_size && out.needs_body && out.needs_rpc
        });
        out
    }

    pub fn candidate_requires_request_body_observation(
        &self,
        ctx: MatchPrefilterContext<'_>,
    ) -> bool {
        self.candidate_rule_indices(ctx).into_iter().any(|idx| {
            self.rules
                .get(idx)
                .map(Rule::requires_request_body_observation)
                .unwrap_or(false)
        })
    }

    pub fn candidate_requires_request_rpc_context(&self, ctx: MatchPrefilterContext<'_>) -> bool {
        self.candidate_rule_indices(ctx).into_iter().any(|idx| {
            self.rules
                .get(idx)
                .map(Rule::requires_request_rpc_context)
                .unwrap_or(false)
        })
    }

    pub fn candidate_requires_response_size(&self, ctx: MatchPrefilterContext<'_>) -> bool {
        self.candidate_rule_indices(ctx).into_iter().any(|idx| {
            self.rules
                .get(idx)
                .map(Rule::requires_response_size)
                .unwrap_or(false)
        })
    }

    pub fn any_rule_requires_tls_fingerprint(&self) -> bool {
        self.rules.iter().any(Rule::requires_tls_fingerprint)
    }

    pub fn rule_at(&self, idx: usize) -> Option<&Rule> {
        self.rules.get(idx)
    }

    pub fn default_action(&self) -> &ActionConfig {
        self.default_action.as_ref()
    }
}

impl Rule {
    pub fn matcher_matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        self.matcher.matches(ctx)
    }

    pub fn matcher_matches_without_request_body_observation(
        &self,
        ctx: &RuleMatchContext<'_>,
    ) -> bool {
        self.matcher.matches_without_request_body_observation(ctx)
    }

    pub fn matches_without_request_body_observation(&self, ctx: &RuleMatchContext<'_>) -> bool {
        if !self.matcher.matches_without_request_body_observation(ctx) {
            return false;
        }

        self.auth_matches(ctx)
    }

    pub fn request_observation_requirements(&self) -> CandidateRequestObservationRequirements {
        CandidateRequestObservationRequirements {
            needs_size: self.requires_request_size(),
            needs_body: self.requires_request_body_observation(),
            needs_rpc: self.requires_request_rpc_context(),
        }
    }

    pub fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        if !self.matcher.matches(ctx) {
            return false;
        }

        self.auth_matches(ctx)
    }

    fn auth_matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        match self.auth.as_deref() {
            Some(auth) => {
                auth.groups.is_empty() || auth.groups.iter().any(|g| ctx.user_groups.contains(g))
            }
            None => true,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn name_arc(&self) -> Arc<str> {
        self.name.clone()
    }

    pub fn auth(&self) -> Option<&RuleAuthConfig> {
        self.auth.as_deref()
    }

    pub fn action(&self) -> Option<&ActionConfig> {
        self.action.as_deref()
    }

    pub fn headers(&self) -> Option<&Arc<CompiledHeaderControl>> {
        self.headers.as_ref()
    }

    pub fn requires_request_size(&self) -> bool {
        self.matcher.requires_request_size()
    }

    pub fn requires_request_body_observation(&self) -> bool {
        self.matcher.requires_request_body_observation()
    }

    pub fn requires_request_rpc_context(&self) -> bool {
        self.matcher.requires_request_rpc_context()
    }

    pub fn requires_response_size(&self) -> bool {
        self.matcher.requires_response_size()
    }

    pub fn requires_response_context(&self) -> bool {
        self.matcher.requires_response_context()
    }

    pub fn requires_tls_fingerprint(&self) -> bool {
        self.matcher.requires_tls_fingerprint()
    }
}

#[cfg(test)]
mod tests;
