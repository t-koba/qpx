pub mod guard;
pub mod response_policy;
pub mod rule_context;

use crate::http::local_response::finalized_local_response;
use crate::http::protocol::l7::finalize_response_for_request;
use anyhow::{Result, anyhow};
use hyper::{Method, Response, Version};
use qpx_core::config::{ActionConfig, ActionKind};
use qpx_core::rules::{CompiledHeaderControl, RuleEngine, RuleMatchContext};
use qpx_http::body::Body;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct EvaluatedAction {
    pub action: ActionConfig,
    pub headers: Option<Arc<CompiledHeaderControl>>,
    pub matched_rule: Option<String>,
}

pub enum ListenerPolicyDecision {
    Proceed(Box<EvaluatedAction>),
    Early(Box<Response<Body>>, Option<String>),
}

pub(crate) fn evaluate_listener_policy(
    engine: &RuleEngine,
    ctx: &RuleMatchContext<'_>,
    method: &Method,
    version: Version,
    proxy_name: &str,
    deny_builder: fn(&str) -> Response<Body>,
    deny_message: &str,
) -> Result<ListenerPolicyDecision> {
    let outcome = engine.evaluate_ref(ctx);
    let auth_required = outcome.auth.map(|a| !a.require.is_empty()).unwrap_or(false);
    let matched_rule = outcome.matched_rule.map(|s| s.to_string());

    if auth_required || matches!(outcome.action.kind, ActionKind::Block) {
        return Ok(ListenerPolicyDecision::Early(
            Box::new(finalize_response_for_request(
                method,
                version,
                proxy_name,
                deny_builder(deny_message),
                false,
            )),
            matched_rule,
        ));
    }

    if matches!(outcome.action.kind, ActionKind::Respond) {
        let local = outcome
            .action
            .local_response
            .as_ref()
            .ok_or_else(|| anyhow!("respond action requires local_response"))?;
        return Ok(ListenerPolicyDecision::Early(
            Box::new(finalized_local_response(
                method,
                version,
                proxy_name,
                local,
                outcome.headers.map(|h| h.as_ref()),
            )?),
            matched_rule,
        ));
    }

    Ok(ListenerPolicyDecision::Proceed(Box::new(EvaluatedAction {
        action: outcome.action.clone(),
        headers: outcome.headers.cloned(),
        matched_rule,
    })))
}
