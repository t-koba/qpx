use crate::config::{ActionConfig, HeaderControl, RuleAuthConfig, RuleConfig};
use crate::matchers::CompiledMatch;
use crate::prefilter::{MatchPrefilterContext, MatchPrefilterIndex, StringInterner};
use anyhow::Result;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct RuleEngine {
    rules: Vec<Rule>,
    default_action: Arc<ActionConfig>,
    prefilter: MatchPrefilterIndex,
}

#[derive(Debug, Clone)]
pub struct CompiledRegexReplace {
    header: http::header::HeaderName,
    pattern: regex::Regex,
    replace: String,
}

#[derive(Debug, Clone, Copy)]
pub struct RuleOutcomeRef<'a> {
    pub action: &'a ActionConfig,
    pub headers: Option<&'a Arc<CompiledHeaderControl>>,
    pub auth: Option<&'a RuleAuthConfig>,
    pub matched_rule: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct CompiledHeaderControl {
    request_set: Vec<(http::header::HeaderName, http::HeaderValue)>,
    request_add: Vec<(http::header::HeaderName, http::HeaderValue)>,
    request_remove: Vec<http::header::HeaderName>,
    request_regex_replace: Vec<CompiledRegexReplace>,
    response_set: Vec<(http::header::HeaderName, http::HeaderValue)>,
    response_add: Vec<(http::header::HeaderName, http::HeaderValue)>,
    response_remove: Vec<http::header::HeaderName>,
    response_regex_replace: Vec<CompiledRegexReplace>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    name: Arc<str>,
    matcher: CompiledMatch,
    action: Option<Arc<ActionConfig>>,
    auth: Option<Arc<RuleAuthConfig>>,
    headers: Option<Arc<CompiledHeaderControl>>,
}

#[derive(Debug, Clone)]
pub struct RuleMatchContext<'a> {
    pub src_ip: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub host: Option<&'a str>,
    pub sni: Option<&'a str>,
    pub method: Option<&'a str>,
    pub path: Option<&'a str>,
    pub headers: Option<&'a http::HeaderMap>,
    pub user_groups: &'a [String],
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

    pub fn rule_at(&self, idx: usize) -> Option<&Rule> {
        self.rules.get(idx)
    }

    pub fn default_action(&self) -> &ActionConfig {
        self.default_action.as_ref()
    }
}

impl Rule {
    pub fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        if !self.matcher.matches(ctx) {
            return false;
        }

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
}

impl CompiledHeaderControl {
    pub fn compile(raw: &HeaderControl) -> Result<Self> {
        Ok(Self {
            request_set: compile_header_set(&raw.request_set, "request_set")?,
            request_add: compile_header_set(&raw.request_add, "request_add")?,
            request_remove: compile_header_remove(&raw.request_remove, "request_remove")?,
            request_regex_replace: compile_regex_replace(
                &raw.request_regex_replace,
                "request_regex_replace",
            )?,
            response_set: compile_header_set(&raw.response_set, "response_set")?,
            response_add: compile_header_set(&raw.response_add, "response_add")?,
            response_remove: compile_header_remove(&raw.response_remove, "response_remove")?,
            response_regex_replace: compile_regex_replace(
                &raw.response_regex_replace,
                "response_regex_replace",
            )?,
        })
    }

    pub fn request_set(&self) -> &[(http::header::HeaderName, http::HeaderValue)] {
        &self.request_set
    }

    pub fn request_add(&self) -> &[(http::header::HeaderName, http::HeaderValue)] {
        &self.request_add
    }

    pub fn request_remove(&self) -> &[http::header::HeaderName] {
        &self.request_remove
    }

    pub fn request_regex_replace(&self) -> &[CompiledRegexReplace] {
        &self.request_regex_replace
    }

    pub fn response_set(&self) -> &[(http::header::HeaderName, http::HeaderValue)] {
        &self.response_set
    }

    pub fn response_add(&self) -> &[(http::header::HeaderName, http::HeaderValue)] {
        &self.response_add
    }

    pub fn response_remove(&self) -> &[http::header::HeaderName] {
        &self.response_remove
    }

    pub fn response_regex_replace(&self) -> &[CompiledRegexReplace] {
        &self.response_regex_replace
    }
}

impl CompiledRegexReplace {
    pub fn header(&self) -> &http::header::HeaderName {
        &self.header
    }

    pub fn pattern(&self) -> &regex::Regex {
        &self.pattern
    }

    pub fn replace(&self) -> &str {
        &self.replace
    }
}

fn compile_header_set(
    raw: &std::collections::HashMap<String, String>,
    context: &str,
) -> Result<Vec<(http::header::HeaderName, http::HeaderValue)>> {
    let mut out = Vec::with_capacity(raw.len());
    for (name, value) in raw {
        let name = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow::anyhow!("{context}: invalid header name: {name}"))?;
        let value = http::HeaderValue::from_str(value.as_str())
            .map_err(|_| anyhow::anyhow!("{context}: invalid header value for {name}"))?;
        out.push((name, value));
    }
    Ok(out)
}

fn compile_header_remove(raw: &[String], context: &str) -> Result<Vec<http::header::HeaderName>> {
    let mut out = Vec::with_capacity(raw.len());
    for name in raw {
        let name = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow::anyhow!("{context}: invalid header name: {name}"))?;
        out.push(name);
    }
    Ok(out)
}

fn compile_regex_replace(
    raw: &[crate::config::RegexReplace],
    context: &str,
) -> Result<Vec<CompiledRegexReplace>> {
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let header = http::header::HeaderName::from_bytes(item.header.as_bytes())
            .map_err(|_| anyhow::anyhow!("{context}: invalid header name: {}", item.header))?;
        let pattern = regex::Regex::new(item.pattern.as_str())
            .map_err(|e| anyhow::anyhow!("{context}: invalid regex {}: {}", item.pattern, e))?;
        out.push(CompiledRegexReplace {
            header,
            pattern,
            replace: item.replace.clone(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ActionKind, MatchConfig};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn action(kind: ActionKind) -> ActionConfig {
        ActionConfig {
            kind,
            upstream: None,
            local_response: None,
        }
    }

    #[test]
    fn evaluates_first_match_in_order() {
        let rules = vec![
            RuleConfig {
                name: "first".to_string(),
                r#match: Some(MatchConfig {
                    host: vec!["*.example.com".to_string()],
                    ..Default::default()
                }),
                auth: None,
                action: Some(action(ActionKind::Block)),
                headers: None,
                rate_limit: None,
            },
            RuleConfig {
                name: "second".to_string(),
                r#match: Some(MatchConfig {
                    host: vec!["api.example.com".to_string()],
                    ..Default::default()
                }),
                auth: None,
                action: Some(action(ActionKind::Proxy)),
                headers: None,
                rate_limit: None,
            },
        ];
        let engine = RuleEngine::new(rules, action(ActionKind::Direct)).expect("engine");
        let ctx = RuleMatchContext {
            src_ip: None,
            dst_port: None,
            host: Some("api.example.com"),
            sni: None,
            method: None,
            path: None,
            headers: None,
            user_groups: &[],
        };

        let out = engine.evaluate_ref(&ctx);
        assert!(matches!(out.action.kind, ActionKind::Block));
        assert_eq!(out.matched_rule, Some("first"));
    }

    #[test]
    fn group_restriction_requires_membership() {
        let rules = vec![RuleConfig {
            name: "group-rule".to_string(),
            r#match: Some(MatchConfig::default()),
            auth: Some(RuleAuthConfig {
                require: vec!["ldap".to_string()],
                groups: vec!["dev".to_string()],
            }),
            action: Some(action(ActionKind::Proxy)),
            headers: None,
            rate_limit: None,
        }];
        let engine = RuleEngine::new(rules, action(ActionKind::Direct)).expect("engine");

        let deny_ctx = RuleMatchContext {
            src_ip: None,
            dst_port: None,
            host: None,
            sni: None,
            method: None,
            path: None,
            headers: None,
            user_groups: &[],
        };
        let allow_ctx = RuleMatchContext {
            user_groups: &["dev".to_string()],
            ..deny_ctx
        };

        let denied = engine.evaluate_ref(&deny_ctx);
        assert!(matches!(denied.action.kind, ActionKind::Direct));
        assert!(denied.matched_rule.is_none());

        let allowed = engine.evaluate_ref(&allow_ctx);
        assert!(matches!(allowed.action.kind, ActionKind::Proxy));
        assert_eq!(allowed.matched_rule, Some("group-rule"));
    }

    #[test]
    fn prefilter_keeps_first_match_semantics_with_exact_host() {
        let rules = vec![
            RuleConfig {
                name: "exact".to_string(),
                r#match: Some(MatchConfig {
                    host: vec!["api.example.com".to_string()],
                    ..Default::default()
                }),
                auth: None,
                action: Some(action(ActionKind::Block)),
                headers: None,
                rate_limit: None,
            },
            RuleConfig {
                name: "wildcard".to_string(),
                r#match: Some(MatchConfig {
                    host: vec!["*.example.com".to_string()],
                    ..Default::default()
                }),
                auth: None,
                action: Some(action(ActionKind::Proxy)),
                headers: None,
                rate_limit: None,
            },
        ];
        let engine = RuleEngine::new(rules, action(ActionKind::Direct)).expect("engine");

        let exact_ctx = RuleMatchContext {
            src_ip: None,
            dst_port: None,
            host: Some("api.example.com"),
            sni: None,
            method: Some("GET"),
            path: Some("/"),
            headers: None,
            user_groups: &[],
        };
        let exact = engine.evaluate_ref(&exact_ctx);
        assert!(matches!(exact.action.kind, ActionKind::Block));
        assert_eq!(exact.matched_rule, Some("exact"));

        let wildcard_ctx = RuleMatchContext {
            host: Some("www.example.com"),
            ..exact_ctx
        };
        let wildcard = engine.evaluate_ref(&wildcard_ctx);
        assert!(matches!(wildcard.action.kind, ActionKind::Proxy));
        assert_eq!(wildcard.matched_rule, Some("wildcard"));
    }

    #[test]
    fn prefilter_handles_cidr_lookup_from_radix() {
        let rules = vec![
            RuleConfig {
                name: "v4".to_string(),
                r#match: Some(MatchConfig {
                    src_ip: vec!["10.0.0.0/8".to_string()],
                    ..Default::default()
                }),
                auth: None,
                action: Some(action(ActionKind::Block)),
                headers: None,
                rate_limit: None,
            },
            RuleConfig {
                name: "v6".to_string(),
                r#match: Some(MatchConfig {
                    src_ip: vec!["2001:db8::/32".to_string()],
                    ..Default::default()
                }),
                auth: None,
                action: Some(action(ActionKind::Proxy)),
                headers: None,
                rate_limit: None,
            },
        ];
        let engine = RuleEngine::new(rules, action(ActionKind::Direct)).expect("engine");

        let v4_ctx = RuleMatchContext {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 2, 3, 4))),
            dst_port: None,
            host: None,
            sni: None,
            method: None,
            path: None,
            headers: None,
            user_groups: &[],
        };
        let out = engine.evaluate_ref(&v4_ctx);
        assert!(matches!(out.action.kind, ActionKind::Block));
        assert_eq!(out.matched_rule, Some("v4"));

        let v6_ctx = RuleMatchContext {
            src_ip: Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            ..v4_ctx
        };
        let out = engine.evaluate_ref(&v6_ctx);
        assert!(matches!(out.action.kind, ActionKind::Proxy));
        assert_eq!(out.matched_rule, Some("v6"));
    }

    #[test]
    fn regex_headers_stay_on_slow_path() {
        let rules = vec![RuleConfig {
            name: "regex".to_string(),
            r#match: Some(MatchConfig {
                headers: vec![crate::config::HeaderMatch {
                    name: "x-test".to_string(),
                    value: None,
                    regex: Some("^abc[0-9]+$".to_string()),
                }],
                ..Default::default()
            }),
            auth: None,
            action: Some(action(ActionKind::Block)),
            headers: None,
            rate_limit: None,
        }];

        let engine = RuleEngine::new(rules, action(ActionKind::Direct)).expect("engine");
        let mut headers = http::HeaderMap::new();
        headers.insert("x-test", http::HeaderValue::from_static("abc42"));

        let ctx = RuleMatchContext {
            src_ip: None,
            dst_port: None,
            host: None,
            sni: None,
            method: Some("GET"),
            path: Some("/"),
            headers: Some(&headers),
            user_groups: &[],
        };

        let out = engine.evaluate_ref(&ctx);
        assert!(matches!(out.action.kind, ActionKind::Block));
    }
}
