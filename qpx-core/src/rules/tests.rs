use super::*;
use crate::config::{ActionKind, MatchConfig};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
        user: None,
        user_groups: &[],
        device_id: None,
        posture: &[],
        tenant: None,
        auth_strength: None,
        idp: None,
        ..Default::default()
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
        user: None,
        user_groups: &[],
        device_id: None,
        posture: &[],
        tenant: None,
        auth_strength: None,
        idp: None,
        ..Default::default()
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
        user: None,
        user_groups: &[],
        device_id: None,
        posture: &[],
        tenant: None,
        auth_strength: None,
        idp: None,
        ..Default::default()
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
        user: None,
        user_groups: &[],
        device_id: None,
        posture: &[],
        tenant: None,
        auth_strength: None,
        idp: None,
        ..Default::default()
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
        user: None,
        user_groups: &[],
        device_id: None,
        posture: &[],
        tenant: None,
        auth_strength: None,
        idp: None,
        ..Default::default()
    };

    let out = engine.evaluate_ref(&ctx);
    assert!(matches!(out.action.kind, ActionKind::Block));
}
