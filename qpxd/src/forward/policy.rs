use crate::runtime::Runtime;
use anyhow::{anyhow, Result};
use hyper::HeaderMap;
use qpx_core::auth::{AuthChallenge, AuthOutcome};
use qpx_core::config::ActionConfig;
use qpx_core::rules::CompiledHeaderControl;
use qpx_core::rules::RuleMatchContext;
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) struct AllowedPolicy {
    pub(crate) action: ActionConfig,
    pub(crate) headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) matched_rule: Option<Arc<str>>,
}

pub(crate) enum ForwardPolicyDecision {
    Allow(Box<AllowedPolicy>),
    Challenge(AuthChallenge),
    Forbidden,
}

pub(crate) async fn evaluate_forward_policy(
    runtime: &Runtime,
    listener_name: &str,
    ctx: RuleMatchContext<'_>,
    request_headers: &HeaderMap,
    auth_method: &str,
    auth_uri: &str,
) -> Result<ForwardPolicyDecision> {
    let state = runtime.state();
    let engine = state
        .rules_by_listener
        .get(listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;

    let candidates = engine.matcher_candidate_indices(&ctx);
    if candidates.is_empty() {
        return Ok(ForwardPolicyDecision::Allow(Box::new(AllowedPolicy {
            action: engine.default_action().clone(),
            headers: None,
            matched_rule: None,
        })));
    }

    let mut auth_cache: HashMap<String, AuthOutcome> = HashMap::new();

    for idx in candidates {
        let Some(rule) = engine.rule_at(idx) else {
            continue;
        };

        if let Some(auth_cfg) = rule.auth() {
            if !auth_cfg.require.is_empty() {
                let key = normalized_require_key(&auth_cfg.require);
                let outcome = match auth_cache.get(&key) {
                    Some(outcome) => outcome.clone(),
                    None => {
                        let outcome = state
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
                    }
                    AuthOutcome::Challenge(challenge) => {
                        return Ok(ForwardPolicyDecision::Challenge(challenge))
                    }
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
        })));
    }

    Ok(ForwardPolicyDecision::Allow(Box::new(AllowedPolicy {
        action: engine.default_action().clone(),
        headers: None,
        matched_rule: None,
    })))
}

fn normalized_require_key(require: &[String]) -> String {
    let mut providers = require.iter().map(String::as_str).collect::<Vec<_>>();
    providers.sort();
    providers.dedup();
    providers.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Runtime;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use hyper::header::HeaderValue;
    use hyper::HeaderMap;
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CacheConfig, Config,
        IdentityConfig, ListenerConfig, ListenerMode, LocalUser, MessagesConfig, RuleAuthConfig,
        RuleConfig, RuntimeConfig, SystemLogConfig,
    };

    #[tokio::test]
    async fn groups_mismatch_continues_to_next_rule() {
        let config = Config {
            version: 1,
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig::default(),
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            acme: None,
            exporter: None,
            auth: AuthConfig {
                users: vec![LocalUser {
                    username: "user".to_string(),
                    password: Some("pass".to_string()),
                    ha1: None,
                }],
                ldap: None,
            },
            listeners: vec![ListenerConfig {
                name: "forward".to_string(),
                mode: ListenerMode::Forward,
                listen: "127.0.0.1:0".to_string(),
                default_action: ActionConfig {
                    kind: ActionKind::Block,
                    upstream: None,
                    local_response: None,
                },
                tls_inspection: None,
                rules: vec![
                    RuleConfig {
                        name: "grouped".to_string(),
                        r#match: None,
                        auth: Some(RuleAuthConfig {
                            require: vec!["local".to_string()],
                            groups: vec!["dev".to_string()],
                        }),
                        action: Some(ActionConfig {
                            kind: ActionKind::Block,
                            upstream: None,
                            local_response: None,
                        }),
                        headers: None,
                        rate_limit: None,
                    },
                    RuleConfig {
                        name: "fallback".to_string(),
                        r#match: None,
                        auth: None,
                        action: Some(ActionConfig {
                            kind: ActionKind::Direct,
                            upstream: None,
                            local_response: None,
                        }),
                        headers: None,
                        rate_limit: None,
                    },
                ],
                upstream_proxy: None,
                http3: None,
                ftp: Default::default(),
                xdp: None,
                cache: None,
                rate_limit: None,
            }],
            reverse: Vec::new(),
            upstreams: Vec::new(),
            cache: CacheConfig::default(),
        };

        let runtime = Runtime::new(config).expect("runtime");

        let credentials = BASE64.encode("user:pass");
        let mut headers = HeaderMap::new();
        headers.insert(
            "proxy-authorization",
            HeaderValue::from_str(format!("Basic {}", credentials).as_str()).unwrap(),
        );

        let ctx = RuleMatchContext {
            src_ip: None,
            dst_port: None,
            host: None,
            sni: None,
            method: Some("GET"),
            path: Some("/"),
            headers: None,
            user_groups: &[],
        };

        let decision = evaluate_forward_policy(
            &runtime,
            "forward",
            ctx,
            &headers,
            "GET",
            "http://example.com/",
        )
        .await
        .expect("policy");
        match decision {
            ForwardPolicyDecision::Allow(policy) => {
                assert!(matches!(policy.action.kind, ActionKind::Direct));
            }
            _ => panic!("unexpected decision"),
        }
    }
}
