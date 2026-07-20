// Extracted from rate_limit.rs; public surface is re-exported by mod.rs.
use super::key::{DEFAULT_MAX_ENTRIES, KeyKind, LimiterKey, SRC_IP_SHARDS};
use super::quota::QuotaState;
use super::*;
use qpx_core::config::{
    ActionConfig, ActionKind, IngressEdgeConfig, IngressEdgeMode, RateLimitApplyTo,
    RateLimitConfig, RateLimitProfileConfig,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

#[test]
fn rate_limit_plan_requires_extended_context_only_for_extended_keys() {
    for (key, expected) in [
        ("global", false),
        ("src_ip", false),
        ("user", true),
        ("group", true),
        ("tenant", true),
        ("device", true),
        ("route", true),
        ("upstream", true),
    ] {
        let config = RateLimitConfig {
            enabled: true,
            apply_to: vec![RateLimitApplyTo::Request],
            key: key.to_string(),
            requests: Some(qpx_core::config::RateLimitRequestsConfig {
                rps: Some(10),
                burst: Some(10),
                quota: None,
            }),
            traffic: None,
            sessions: None,
        };
        let plan = CompiledRateLimitPlan::from_sets(
            RateLimitSet::from_config(Some(&config)),
            RateLimitSet::default(),
        );

        assert_eq!(
            plan.requires_extended_context(TransportScope::Request),
            expected,
            "unexpected context requirement for {key}"
        );
        assert!(!plan.requires_extended_context(TransportScope::Connect));
    }
}

#[test]
fn collect_profile_rejects_unknown_profile_name() {
    let listener = IngressEdgeConfig {
        name: "forward".to_string(),
        mode: IngressEdgeMode::Forward,
        listen: "127.0.0.1:0".to_string(),
        default_action: ActionConfig {
            kind: ActionKind::Direct,
            upstream: None,
            local_response: None,
        },
        original_dst: None,
        tls_inspection: None,
        rules: Vec::new(),
        connection_filter: Vec::new(),
        streaming: None,
        grpc: None,
        sse: None,
        streaming_requirement: None,
        upstream_proxy: None,
        http3: None,
        ftp: Default::default(),
        xdp: None,
        cache: None,
        capture: None,
        rate_limit: None,
        policy_context: None,
        http: None,
        http_guard_profile: None,
        destination_resolution: None,
        http_modules: Vec::new(),
    };
    let profile = RateLimitProfileConfig {
        name: "known".to_string(),
        limit: RateLimitConfig {
            enabled: true,
            apply_to: vec![RateLimitApplyTo::Request],
            key: "user".to_string(),
            requests: Some(qpx_core::config::RateLimitRequestsConfig {
                rps: Some(10),
                burst: Some(10),
                quota: None,
            }),
            traffic: None,
            sessions: None,
        },
    };
    let limiters = RateLimiters::from_config(&[listener], &[profile]);

    assert!(
        limiters
            .collect_profile(Some("missing"), TransportScope::Request)
            .is_err()
    );
    assert!(
        limiters
            .collect_profile(Some("known"), TransportScope::Request)
            .is_ok()
    );
    assert!(
        limiters
            .collect_profile(None, TransportScope::Request)
            .expect("no profile")
            .is_empty()
    );
}

#[test]
fn absent_decision_profile_does_not_consume_route_limit_twice() {
    let config = RateLimitConfig {
        enabled: true,
        apply_to: vec![RateLimitApplyTo::Request],
        key: "global".to_string(),
        requests: Some(qpx_core::config::RateLimitRequestsConfig {
            rps: Some(1),
            burst: Some(1),
            quota: None,
        }),
        traffic: None,
        sessions: None,
    };
    let plan = CompiledRateLimitPlan::from_sets(
        RateLimitSet::from_config(Some(&config)),
        RateLimitSet::default(),
    );
    let rate_limiters = RateLimiters::default();
    let ctx = RateLimitContext::default();
    let RequestLimitAcquire {
        mut limits,
        retry_after,
    } = rate_limiters
        .collect_checked_plan_request(&plan, None, TransportScope::Request, &ctx, 1)
        .expect("collect route rate limit");

    assert_eq!(retry_after, None);
    assert_eq!(
        limits
            .merge_profile_and_check(&rate_limiters, None, TransportScope::Request, &ctx, 1,)
            .expect("merge absent decision profile"),
        None
    );
    assert!(
        rate_limiters
            .collect_checked_plan_request(&plan, None, TransportScope::Request, &ctx, 1)
            .expect("collect second route request")
            .retry_after
            .is_some(),
        "the next request must observe exactly one consumed token"
    );
}

#[test]
fn initial_profile_check_also_enforces_route_limit() {
    let route_config = RateLimitConfig {
        enabled: true,
        apply_to: vec![RateLimitApplyTo::Request],
        key: "global".to_string(),
        requests: Some(qpx_core::config::RateLimitRequestsConfig {
            rps: Some(1),
            burst: Some(1),
            quota: None,
        }),
        traffic: None,
        sessions: None,
    };
    let profile = RateLimitProfileConfig {
        name: "external".to_string(),
        limit: RateLimitConfig {
            enabled: true,
            apply_to: vec![RateLimitApplyTo::Request],
            key: "global".to_string(),
            requests: Some(qpx_core::config::RateLimitRequestsConfig {
                rps: Some(1_000_000_000),
                burst: Some(1_000_000_000),
                quota: None,
            }),
            traffic: None,
            sessions: None,
        },
    };
    let plan = CompiledRateLimitPlan::from_sets(
        RateLimitSet::from_config(Some(&route_config)),
        RateLimitSet::default(),
    );
    let rate_limiters = RateLimiters::from_config(
        std::iter::empty::<&IngressEdgeConfig>(),
        std::slice::from_ref(&profile),
    );
    let ctx = RateLimitContext::default();

    assert_eq!(
        rate_limiters
            .collect_checked_plan_request(
                &plan,
                Some("external"),
                TransportScope::Request,
                &ctx,
                1,
            )
            .expect("collect first request")
            .retry_after,
        None
    );
    assert!(
        rate_limiters
            .collect_checked_plan_request(
                &plan,
                Some("external"),
                TransportScope::Request,
                &ctx,
                1,
            )
            .expect("collect second request")
            .retry_after
            .is_some(),
        "the route limit must remain authoritative when a profile is present"
    );
}

#[test]
fn reserve_bytes_enforces_quota() {
    let limits = AppliedRateLimits {
        byte_quota_limiters: vec![Arc::new(QuotaLimiter::new(
            KeyKind::User,
            Duration::from_secs(60),
            None,
            Some(8),
        ))]
        .into(),
        ..Default::default()
    };
    let ctx = RateLimitContext {
        user: Some("alice".to_string()),
        ..Default::default()
    };

    assert_eq!(limits.reserve_bytes(&ctx, 4), Ok(Duration::ZERO));
    assert_eq!(limits.reserve_bytes(&ctx, 5), Err(()));
}

#[test]
fn quota_state_prunes_expired_and_caps_cardinality() {
    let now = Instant::now();
    let mut state = QuotaState::new(2);
    for user in ["alice", "bob"] {
        let entry = state.entry(
            LimiterKey::Text(Arc::from(user)),
            now,
            Duration::from_secs(60),
        );
        entry.requests_used = 1;
    }
    assert_eq!(state.entries.len(), 2);

    let _ = state.entry(
        LimiterKey::Text(Arc::from("carol")),
        now,
        Duration::from_secs(60),
    );
    assert_eq!(state.entries.len(), 2);
    assert!(
        !state
            .entries
            .contains(&LimiterKey::Text(Arc::from("alice")))
    );

    let later = now + Duration::from_secs(61);
    let _ = state.entry(
        LimiterKey::Text(Arc::from("dave")),
        later,
        Duration::from_secs(60),
    );
    assert_eq!(state.entries.len(), 1);
    assert!(state.entries.contains(&LimiterKey::Text(Arc::from("dave"))));
    assert_eq!(state.entries.len(), 1);
}

#[test]
fn token_bucket_lru_refresh_keeps_single_entry() {
    let limiter = RateLimiter::new(KeyKind::User, 1_000_000.0, 1_000_000.0);
    let ctx = RateLimitContext {
        user: Some("alice".to_string()),
        ..Default::default()
    };
    for _ in 0..(DEFAULT_MAX_ENTRIES / SRC_IP_SHARDS * 3) {
        assert_eq!(limiter.try_acquire_with_context(&ctx, 1), None);
    }
    assert_eq!(limiter.test_entry_count_for_context(&ctx), 1);
}
