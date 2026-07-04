use super::decision_service_access::DecisionServiceRateLimit;
use super::{
    DecisionServiceHttpAccessInput, DecisionServiceHttpAccessOutcome, DispatchAuditContext,
    DispatchAuditInput, ProxyKind, apply_decision_service_http_access,
    build_dispatch_audit_context,
};
use crate::destination::DestinationMetadata;
use crate::policy_context::{
    DecisionServiceAllowControls, DecisionServiceInput, DecisionServiceMode,
    EffectivePolicyContext, ResolvedIdentity, enforce_decision_service,
};
use crate::runtime::RuntimeState;
use anyhow::Result;
use hyper::{HeaderMap, Method, Response};
use qpx_core::config::ActionConfig;
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use std::net::SocketAddr;
use std::sync::Arc;

/// Mode-independent HTTP access-control stage: decision service,
/// dispatch audit context construction, and decision_service allow/deny application
/// in one pass. Mode dispatchers feed mode-specific values as data instead of
/// duplicating this sequence.
pub(crate) struct HttpAccessInput<'a> {
    pub(crate) state: &'a Arc<RuntimeState>,
    pub(crate) policy: &'a EffectivePolicyContext,
    pub(crate) kind: ProxyKind,
    pub(crate) mode: DecisionServiceMode,
    /// `false` skips decision_service enforcement (e.g. transparent requests without
    /// an evaluated policy) while still producing the audit context.
    pub(crate) enforce_decision_service: bool,
    pub(crate) proxy_name: &'a str,
    pub(crate) scope_name: &'a str,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) dst_port: Option<u16>,
    pub(crate) host: Option<&'a str>,
    pub(crate) sni: Option<&'a str>,
    pub(crate) request_method: &'a Method,
    pub(crate) request_version: http::Version,
    pub(crate) path: Option<&'a str>,
    pub(crate) uri: Option<&'a str>,
    pub(crate) matched_rule: Option<&'a str>,
    pub(crate) matched_route: Option<&'a str>,
    pub(crate) action: Option<&'a ActionConfig>,
    pub(crate) sanitized_headers: &'a HeaderMap,
    pub(crate) identity: &'a ResolvedIdentity,
    pub(crate) destination: &'a DestinationMetadata,
    pub(crate) base_headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) request_limit: Option<DecisionServiceRateLimit<'a>>,
    pub(crate) default_deny_response: Response<Body>,
}

pub(crate) enum HttpAccessDecision {
    /// Request may proceed. `controls` is `None` when decision_service was skipped.
    Allow(Box<HttpAccessAllowed>),
    /// Request was denied or rate limited; `response` is already finalized
    /// and annotated.
    Blocked {
        response: Box<Response<Body>>,
        rate_limited: bool,
    },
}

pub(crate) struct HttpAccessAllowed {
    pub(crate) audit: DispatchAuditContext,
    pub(crate) controls: Option<DecisionServiceAllowControls>,
}

pub(crate) async fn enforce_http_access(input: HttpAccessInput<'_>) -> Result<HttpAccessDecision> {
    let decision_service = if input.enforce_decision_service {
        Some(
            enforce_decision_service(
                input.state,
                input.policy,
                DecisionServiceInput {
                    mode: input.mode,
                    proxy_kind: input.kind,
                    proxy_name: input.proxy_name,
                    scope_name: input.scope_name,
                    remote_ip: input.remote_addr.ip(),
                    dst_port: input.dst_port,
                    host: input.host,
                    sni: input.sni,
                    method: Some(input.request_method.as_str()),
                    path: input.path,
                    uri: input.uri,
                    matched_rule: input.matched_rule,
                    matched_route: input.matched_route,
                    action: input.action,
                    headers: Some(input.sanitized_headers),
                    identity: input.identity,
                },
            )
            .await?,
        )
    } else {
        None
    };
    let audit = build_dispatch_audit_context(DispatchAuditInput {
        state: input.state.clone(),
        kind: input.kind,
        scope_name: input.scope_name,
        remote_addr: input.remote_addr,
        host: input.host.map(ToOwned::to_owned),
        sni: input.sni.map(ToOwned::to_owned),
        request_method: input.request_method.clone(),
        path: input.path.map(ToOwned::to_owned),
        matched_rule: input.matched_rule.map(ToOwned::to_owned),
        matched_route: input.matched_route.map(ToOwned::to_owned),
        identity: input.identity,
        destination: input.destination,
        decision_service: decision_service.as_ref(),
    });
    let Some(decision_service) = decision_service else {
        return Ok(HttpAccessDecision::Allow(Box::new(HttpAccessAllowed {
            audit,
            controls: None,
        })));
    };
    match apply_decision_service_http_access(DecisionServiceHttpAccessInput {
        enforcement: decision_service,
        mode: input.mode,
        base_headers: input.base_headers,
        request_limit: input.request_limit,
        request_head: (input.request_method, input.request_version),
        proxy_name: input.proxy_name,
        default_deny_response: input.default_deny_response,
        audit: &audit,
    })? {
        DecisionServiceHttpAccessOutcome::Continue(controls) => {
            Ok(HttpAccessDecision::Allow(Box::new(HttpAccessAllowed {
                audit,
                controls: Some(controls),
            })))
        }
        DecisionServiceHttpAccessOutcome::Blocked(response, rate_limited) => {
            Ok(HttpAccessDecision::Blocked {
                response: Box::new(response),
                rate_limited,
            })
        }
    }
}
