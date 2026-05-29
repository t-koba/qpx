use anyhow::Result;
use qpx_core::config::{ActionConfig, ActionKind, RuleConfig};
use qpx_core::rules::{RuleEngine, RuleMatchContext};
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionFilterStage {
    Accept,
    ClientHello,
}

impl ConnectionFilterStage {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::ClientHello => "client_hello",
        }
    }
}

pub(crate) fn compile_connection_filter(rules: Vec<RuleConfig>) -> Result<Option<RuleEngine>> {
    if rules.is_empty() {
        return Ok(None);
    }
    Ok(Some(RuleEngine::new(rules, allow_connection())?))
}

pub(crate) fn evaluate_connection_filter<'a>(
    engine: Option<&'a RuleEngine>,
    ctx: &RuleMatchContext<'_>,
) -> Option<&'a str> {
    let outcome = engine?.evaluate_ref(ctx);
    if matches!(outcome.action.kind, ActionKind::Block) {
        return Some(outcome.matched_rule.unwrap_or("<default>"));
    }
    None
}

pub(crate) fn emit_connection_filter_audit(
    scope_kind: &'static str,
    scope_name: &str,
    remote_addr: SocketAddr,
    local_port: u16,
    stage: ConnectionFilterStage,
    matched_rule: &str,
    sni: Option<&str>,
) {
    if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
        tracing::warn!(
            target: "audit_log",
            event = "connection_filter_drop",
            scope = scope_kind,
            name = scope_name,
            remote = %remote_addr,
            dst_port = local_port,
            stage = stage.as_str(),
            matched_rule,
            sni = sni.unwrap_or(""),
        );
    }
}

fn allow_connection() -> ActionConfig {
    ActionConfig {
        kind: ActionKind::Direct,
        upstream: None,
        local_response: None,
    }
}
