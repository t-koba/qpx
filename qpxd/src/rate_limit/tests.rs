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
fn reserve_bytes_enforces_quota() {
    let limits = AppliedRateLimits {
        byte_quota_limiters: vec![Arc::new(QuotaLimiter::new(
            KeyKind::User,
            Duration::from_secs(60),
            None,
            Some(8),
        ))],
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
