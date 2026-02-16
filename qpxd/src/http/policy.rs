use crate::http::l7::{finalize_response_for_request, finalize_response_with_headers};
use crate::http::local_response::build_local_response;
use anyhow::{anyhow, Result};
use hyper::{Body, Method, Response, Version};
use qpx_core::config::{ActionConfig, ActionKind};
use qpx_core::rules::{CompiledHeaderControl, RuleEngine, RuleMatchContext};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct EvaluatedAction {
    pub action: ActionConfig,
    pub headers: Option<Arc<CompiledHeaderControl>>,
}

pub enum ListenerPolicyDecision {
    Proceed(Box<EvaluatedAction>),
    Early(Response<Body>),
}

pub fn evaluate_listener_policy(
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

    if auth_required || matches!(outcome.action.kind, ActionKind::Block) {
        return Ok(ListenerPolicyDecision::Early(
            finalize_response_for_request(
                method,
                version,
                proxy_name,
                deny_builder(deny_message),
                false,
            ),
        ));
    }

    if matches!(outcome.action.kind, ActionKind::Respond) {
        let local = outcome
            .action
            .local_response
            .as_ref()
            .ok_or_else(|| anyhow!("respond action requires local_response"))?;
        return Ok(ListenerPolicyDecision::Early(
            finalize_response_with_headers(
                method,
                version,
                proxy_name,
                build_local_response(local)?,
                outcome.headers.map(|h| h.as_ref()),
                false,
            ),
        ));
    }

    Ok(ListenerPolicyDecision::Proceed(Box::new(EvaluatedAction {
        action: outcome.action.clone(),
        headers: outcome.headers.cloned(),
    })))
}
