use crate::http::pipeline::{PolicyStage, staged_request_observation_requirements};
use crate::runtime::Runtime;
#[cfg(feature = "auth-basic")]
use crate::runtime::auth::AuthChallenge;
use crate::runtime::auth::{AuthOutcome, AuthenticatedUser};
use anyhow::Result;
use qpx_core::config::ActionConfig;
use qpx_core::http_message::Headers;
use qpx_core::rules::CompiledHeaderControl;
use qpx_core::rules::RuleMatchContext;
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) struct AllowedPolicy {
    pub(crate) action: ActionConfig,
    pub(crate) headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) matched_rule: Option<Arc<str>>,
    pub(crate) authenticated_user: Option<AuthenticatedUser>,
}

pub(crate) enum ForwardPolicyDecision {
    Allow(Box<AllowedPolicy>),
    #[cfg(feature = "auth-basic")]
    Challenge(AuthChallenge),
    #[cfg(feature = "auth-basic")]
    Forbidden,
}

pub(crate) async fn evaluate_forward_policy_staged(
    runtime: &Runtime,
    listener_name: &str,
    ctx: RuleMatchContext<'_>,
    request_headers: &Headers,
    auth_method: &str,
    auth_uri: &str,
) -> Result<PolicyStage<ForwardPolicyDecision>> {
    let state = runtime.state();
    let engine = state.policy.rule_engine_for_listener(listener_name)?;
    if let Some(requirements) = staged_request_observation_requirements(engine, &ctx) {
        return Ok(PolicyStage::Observe(requirements));
    }

    evaluate_forward_policy(
        runtime,
        listener_name,
        ctx,
        request_headers,
        auth_method,
        auth_uri,
    )
    .await
    .map(PolicyStage::Decision)
}

pub(crate) async fn evaluate_forward_policy(
    runtime: &Runtime,
    listener_name: &str,
    ctx: RuleMatchContext<'_>,
    request_headers: &Headers,
    auth_method: &str,
    auth_uri: &str,
) -> Result<ForwardPolicyDecision> {
    let state = runtime.state();
    let engine = state.policy.rule_engine_for_listener(listener_name)?;

    let candidates = engine.matcher_candidate_indices(&ctx);
    if candidates.is_empty() {
        return Ok(ForwardPolicyDecision::Allow(Box::new(AllowedPolicy {
            action: engine.default_action().clone(),
            headers: None,
            matched_rule: None,
            authenticated_user: None,
        })));
    }

    let mut auth_cache: HashMap<String, AuthOutcome> = HashMap::new();

    for idx in candidates {
        let Some(rule) = engine.rule_at(idx) else {
            continue;
        };

        let mut authenticated_user = None;
        if let Some(auth_cfg) = rule.auth() {
            if !auth_cfg.require.is_empty() {
                let key = normalized_require_key(&auth_cfg.require);
                let outcome = match auth_cache.get(&key) {
                    Some(outcome) => outcome.clone(),
                    None => {
                        let outcome = state
                            .security
                            .auth
                            .authenticate_proxy(
                                ctx.src_ip,
                                request_headers,
                                &auth_cfg.require,
                                auth_method,
                                auth_uri,
                            )
                            .await?;
                        auth_cache.insert(key, outcome.clone());
                        outcome
                    }
                };

                match outcome {
                    AuthOutcome::Allowed(user) => {
                        if !auth_cfg.groups.is_empty()
                            && !auth_cfg.groups.iter().any(|g| user.groups.contains(g))
                        {
                            continue;
                        }
                        authenticated_user = Some(user);
                    }
                    #[cfg(feature = "auth-basic")]
                    AuthOutcome::Challenge(challenge) => {
                        return Ok(ForwardPolicyDecision::Challenge(challenge));
                    }
                    #[cfg(feature = "auth-basic")]
                    AuthOutcome::Denied(_) => return Ok(ForwardPolicyDecision::Forbidden),
                }
            } else if !auth_cfg.groups.is_empty() {
                continue;
            }
        }

        return Ok(ForwardPolicyDecision::Allow(Box::new(AllowedPolicy {
            action: rule
                .action()
                .cloned()
                .unwrap_or_else(|| engine.default_action().clone()),
            headers: rule.headers().cloned(),
            matched_rule: Some(rule.name_arc()),
            authenticated_user,
        })));
    }

    Ok(ForwardPolicyDecision::Allow(Box::new(AllowedPolicy {
        action: engine.default_action().clone(),
        headers: None,
        matched_rule: None,
        authenticated_user: None,
    })))
}

fn normalized_require_key(require: &[String]) -> String {
    let mut providers = require.iter().map(String::as_str).collect::<Vec<_>>();
    providers.sort();
    providers.dedup();
    providers.join(",")
}

#[cfg(all(test, feature = "auth-basic"))]
mod tests;
