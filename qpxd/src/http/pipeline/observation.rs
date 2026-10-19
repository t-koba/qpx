//! Staged request-policy observation for the HTTP pipeline.
//!
//! Both forward and transparent dispatch stage policy before the request body
//! is observed: they walk prefilter candidates in order and request observation
//! only when the first candidate that can still match needs it.

use qpx_core::prefilter::MatchPrefilterContext;
use qpx_core::rules::{CandidateRequestObservationRequirements, RuleEngine, RuleMatchContext};

/// Returns the observation needed before a policy decision can be made.
///
/// Builds the same [`MatchPrefilterContext`] as staged callers, skips
/// candidates that fail `matches_without_request_body_observation`, and unions
/// requirements from the first matching observation-dependent candidate and
/// later eligible candidates. Returns `None` when an earlier header-only
/// candidate fully matches or no candidate needs observation.
pub(crate) fn staged_request_observation_requirements(
    engine: &RuleEngine,
    ctx: &RuleMatchContext<'_>,
) -> Option<CandidateRequestObservationRequirements> {
    let prefilter_ctx = MatchPrefilterContext {
        method: ctx.method,
        dst_port: ctx.dst_port,
        src_ip: ctx.src_ip,
        host: ctx.host,
        sni: ctx.sni,
        path: ctx.path,
    };
    let candidates = engine.candidate_rule_indices(prefilter_ctx);
    for (pos, idx) in candidates.iter().copied().enumerate() {
        let Some(rule) = engine.rule_at(idx) else {
            continue;
        };
        let requirements = rule.request_observation_requirements();
        if !requirements.is_empty() {
            if !rule.matches_without_request_body_observation(ctx) {
                continue;
            }
            let mut combined = CandidateRequestObservationRequirements::default();
            for later_idx in candidates.iter().copied().skip(pos) {
                if let Some(later) = engine.rule_at(later_idx) {
                    let later_requirements = later.request_observation_requirements();
                    if later_requirements.is_empty()
                        || later.matches_without_request_body_observation(ctx)
                    {
                        combined.include(later_requirements);
                    }
                }
            }
            return Some(combined);
        }
        if rule.matches(ctx) {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue};
    use qpx_core::config::{
        ActionConfig, ActionKind, HeaderMatch, MatchConfig, RpcMatchConfig, RuleConfig,
    };

    fn test_engine(rules: Vec<RuleConfig>) -> RuleEngine {
        RuleEngine::new(
            rules,
            ActionConfig {
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            },
        )
        .expect("engine")
    }

    fn rule(name: &str, r#match: MatchConfig) -> RuleConfig {
        RuleConfig {
            name: name.to_string(),
            r#match: Some(r#match),
            auth: None,
            action: None,
            headers: None,
            rate_limit: None,
        }
    }

    #[test]
    fn header_match_prevents_later_size_rule_from_forcing_observation() {
        let engine = test_engine(vec![
            rule(
                "header-only",
                MatchConfig {
                    headers: vec![HeaderMatch {
                        name: "x-mode".to_string(),
                        value: Some("fast".to_string()),
                        regex: None,
                    }],
                    ..Default::default()
                },
            ),
            rule(
                "size-later",
                MatchConfig {
                    request_size: vec![">=1".to_string()],
                    ..Default::default()
                },
            ),
        ]);
        let mut headers = HeaderMap::new();
        headers.insert("x-mode", HeaderValue::from_static("fast"));
        let ctx = RuleMatchContext {
            headers: Some(&headers),
            user_groups: &[],
            posture: &[],
            ..Default::default()
        };
        assert!(staged_request_observation_requirements(&engine, &ctx).is_none());
    }

    #[test]
    fn matching_size_rule_returns_size_requirement() {
        let engine = test_engine(vec![rule(
            "size-first",
            MatchConfig {
                method: vec!["GET".to_string()],
                request_size: vec![">=1".to_string()],
                ..Default::default()
            },
        )]);
        let ctx = RuleMatchContext {
            method: Some("GET"),
            user_groups: &[],
            posture: &[],
            ..Default::default()
        };
        let requirements =
            staged_request_observation_requirements(&engine, &ctx).expect("observation");
        assert!(requirements.needs_size);
        assert!(!requirements.needs_body);
        assert!(!requirements.needs_rpc);
    }

    #[test]
    fn later_matching_rules_contribute_observation_requirements() {
        let engine = test_engine(vec![
            rule(
                "size-first",
                MatchConfig {
                    method: vec!["GET".to_string()],
                    request_size: vec![">=1".to_string()],
                    ..Default::default()
                },
            ),
            rule(
                "rpc-later",
                MatchConfig {
                    method: vec!["GET".to_string()],
                    rpc: Some(RpcMatchConfig {
                        method: vec!["Lookup".to_string()],
                        streaming: vec!["client".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
        ]);
        let ctx = RuleMatchContext {
            method: Some("GET"),
            rpc_method: Some("Lookup"),
            user_groups: &[],
            posture: &[],
            ..Default::default()
        };
        let requirements =
            staged_request_observation_requirements(&engine, &ctx).expect("observation");
        assert!(requirements.needs_size);
        assert!(requirements.needs_rpc);
        assert!(requirements.needs_body);
    }

    #[test]
    fn non_matching_observation_rule_requires_nothing() {
        let engine = test_engine(vec![rule(
            "other-host-size",
            MatchConfig {
                host: vec!["other.example".to_string()],
                request_size: vec![">=1".to_string()],
                ..Default::default()
            },
        )]);
        let ctx = RuleMatchContext {
            host: Some("example.com"),
            user_groups: &[],
            posture: &[],
            ..Default::default()
        };
        assert!(staged_request_observation_requirements(&engine, &ctx).is_none());
    }
}
