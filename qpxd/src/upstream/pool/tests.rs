use super::cluster::{ManagedUpstreamEndpoint, PassiveHealthPolicy, UpstreamProxyCluster};
use super::send::upstream_proxy_pool_key;
use super::sender_pool::UpstreamProxyPool;
use crate::runtime::now_millis;
use crate::upstream::health::LATENCY_P95_DEFAULT_MIN_SAMPLES;
use crate::upstream::health::PassiveFailureKind;
use crate::upstream::http1::parse_upstream_proxy_endpoint;
use arc_swap::ArcSwap;
use qpx_core::tls::CompiledUpstreamTlsTrust;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use tokio::time::Duration;

fn policy() -> PassiveHealthPolicy {
    PassiveHealthPolicy {
        consecutive_5xx: 1,
        consecutive_timeouts: 1,
        consecutive_connect_errors: 1,
        consecutive_resets: 1,
        max_ejection: Duration::from_secs(30),
        latency_threshold: None,
        latency_min_samples: LATENCY_P95_DEFAULT_MIN_SAMPLES,
    }
}

#[test]
fn cluster_skips_ejected_endpoint() {
    let first = Arc::new(ManagedUpstreamEndpoint::new(
        parse_upstream_proxy_endpoint("http://127.0.0.1:3128").expect("endpoint"),
    ));
    let second = Arc::new(ManagedUpstreamEndpoint::new(
        parse_upstream_proxy_endpoint("http://127.0.0.2:3128").expect("endpoint"),
    ));
    let cluster = Arc::new(UpstreamProxyCluster {
        key: Arc::<str>::from("corp"),
        static_endpoints: Arc::new(vec![first.clone(), second.clone()]),
        endpoints: ArcSwap::from_pointee(vec![first.clone(), second.clone()]),
        discovery: None,
        trust: None,
        discovery_started: AtomicBool::new(false),
        passive_health: Some(policy()),
        max_concurrency: None,
        rr_counter: AtomicUsize::new(0),
    });

    let first_pick = cluster.select().expect("first pick");
    assert_eq!(first_pick.endpoint().authority, "127.0.0.1:3128");
    first_pick.mark_connect_error();
    drop(first_pick);

    let second_pick = cluster.select().expect("second pick");
    assert_eq!(second_pick.endpoint().authority, "127.0.0.2:3128");
}

#[test]
fn upstream_proxy_pool_key_includes_trust_policy() {
    let endpoint = parse_upstream_proxy_endpoint("https://proxy.example:8443").expect("endpoint");
    let trust_a =
        CompiledUpstreamTlsTrust::from_config(Some(&qpx_core::config::UpstreamTlsTrustConfig {
            pin_sha256: vec![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ],
            issuer: Vec::new(),
            san_dns: Vec::new(),
            san_uri: Vec::new(),
            client_cert: None,
            client_key: None,
        }))
        .expect("compile trust a")
        .expect("trust a");
    let trust_b =
        CompiledUpstreamTlsTrust::from_config(Some(&qpx_core::config::UpstreamTlsTrustConfig {
            pin_sha256: vec![
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            ],
            issuer: Vec::new(),
            san_dns: Vec::new(),
            san_uri: Vec::new(),
            client_cert: None,
            client_key: None,
        }))
        .expect("compile trust b")
        .expect("trust b");
    assert_ne!(
        upstream_proxy_pool_key(&endpoint, Some(&trust_a)),
        upstream_proxy_pool_key(&endpoint, Some(&trust_b))
    );
    assert_eq!(
        upstream_proxy_pool_key(&endpoint, Some(&trust_a)),
        upstream_proxy_pool_key(&endpoint, Some(&trust_a))
    );
}

#[test]
fn cluster_respects_max_concurrency() {
    let endpoint = Arc::new(ManagedUpstreamEndpoint::new(
        parse_upstream_proxy_endpoint("http://127.0.0.1:3128").expect("endpoint"),
    ));
    let cluster = Arc::new(UpstreamProxyCluster {
        key: Arc::<str>::from("corp"),
        static_endpoints: Arc::new(vec![endpoint.clone()]),
        endpoints: ArcSwap::from_pointee(vec![endpoint]),
        discovery: None,
        trust: None,
        discovery_started: AtomicBool::new(false),
        passive_health: None,
        max_concurrency: Some(1),
        rr_counter: AtomicUsize::new(0),
    });

    let first = cluster.select().expect("first selection");
    assert!(cluster.select().is_err());
    drop(first);
    assert!(cluster.select().is_ok());
}

#[test]
fn dynamic_discovery_refresh_reuses_existing_endpoint_state() {
    let endpoint = Arc::new(ManagedUpstreamEndpoint::new(
        parse_upstream_proxy_endpoint("http://127.0.0.1:3128").expect("endpoint"),
    ));
    let cluster = Arc::new(UpstreamProxyCluster {
        key: Arc::<str>::from("corp"),
        static_endpoints: Arc::new(Vec::new()),
        endpoints: ArcSwap::from_pointee(vec![endpoint.clone()]),
        discovery: None,
        trust: None,
        discovery_started: AtomicBool::new(false),
        passive_health: Some(policy()),
        max_concurrency: None,
        rr_counter: AtomicUsize::new(0),
    });

    endpoint.mark_passive_failure(
        cluster.passive_health.as_ref(),
        PassiveFailureKind::ConnectError,
    );
    assert!(!endpoint.is_healthy(now_millis()));

    let combined = cluster.reconcile_dynamic_endpoints(vec![
        parse_upstream_proxy_endpoint("http://127.0.0.1:3128").expect("endpoint"),
    ]);
    let refreshed = combined
        .iter()
        .find(|candidate| candidate.endpoint.authority == "127.0.0.1:3128")
        .expect("refreshed endpoint");

    assert!(Arc::ptr_eq(refreshed, &endpoint));
    assert!(!refreshed.is_healthy(now_millis()));
}

#[test]
fn pooled_endpoint_outlier_does_not_trip_p95() {
    let endpoint = Arc::new(ManagedUpstreamEndpoint::new(
        parse_upstream_proxy_endpoint("http://127.0.0.1:3128").expect("endpoint"),
    ));
    let policy = PassiveHealthPolicy {
        consecutive_5xx: 100,
        consecutive_timeouts: 100,
        consecutive_connect_errors: 100,
        consecutive_resets: 100,
        max_ejection: Duration::from_secs(30),
        latency_threshold: Some(Duration::from_millis(100)),
        latency_min_samples: LATENCY_P95_DEFAULT_MIN_SAMPLES,
    };
    for _ in 0..99 {
        endpoint.mark_passive_latency(Some(&policy), Duration::from_millis(1));
    }
    endpoint.mark_passive_latency(Some(&policy), Duration::from_millis(101));
    assert!(
        endpoint.is_healthy(now_millis()),
        "single 101ms sample ejected a pooled endpoint with p95 1ms"
    );
    for _ in 0..100 {
        endpoint.mark_passive_latency(Some(&policy), Duration::from_millis(150));
    }
    assert!(!endpoint.is_healthy(now_millis()));
}

#[test]
fn cluster_adaptive_failure_rate_ejects_endpoint() {
    let endpoint = Arc::new(ManagedUpstreamEndpoint::new(
        parse_upstream_proxy_endpoint("http://127.0.0.1:3128").expect("endpoint"),
    ));
    let policy = PassiveHealthPolicy {
        consecutive_5xx: 100,
        consecutive_timeouts: 100,
        consecutive_connect_errors: 100,
        consecutive_resets: 100,
        max_ejection: Duration::from_secs(30),
        latency_threshold: None,
        latency_min_samples: LATENCY_P95_DEFAULT_MIN_SAMPLES,
    };
    for _ in 0..4 {
        endpoint.mark_passive_success();
    }
    for _ in 0..4 {
        endpoint.mark_passive_failure(Some(&policy), PassiveFailureKind::ConnectError);
    }
    assert!(!endpoint.is_healthy(now_millis()));
}

#[tokio::test]
async fn existing_endpoint_slot_adopts_increased_concurrency_limit() {
    let pool = UpstreamProxyPool::new();
    pool.set_max_concurrent_per_endpoint(1);
    let initial = pool.slot_for("existing").await;
    let first = initial.try_acquire().expect("initial permit");
    assert!(initial.try_acquire().is_err());

    pool.set_max_concurrent_per_endpoint(2);
    let existing = pool.slot_for("existing").await;
    assert!(Arc::ptr_eq(&initial, &existing));
    let fresh = pool.slot_for("fresh").await;
    let fresh_first = fresh.try_acquire().expect("fresh first permit");
    let fresh_second = fresh.try_acquire().expect("fresh second permit");
    assert!(fresh.try_acquire().is_err());

    let existing_second = existing.try_acquire();
    assert!(
        existing_second.is_ok(),
        "existing endpoint slot remained at the old concurrency limit after reload"
    );
    drop((first, existing_second, fresh_first, fresh_second));
}

#[tokio::test]
async fn existing_endpoint_slot_adopts_decreased_concurrency_limit_with_held_permits() {
    let pool = UpstreamProxyPool::new();
    pool.set_max_concurrent_per_endpoint(4);
    let initial = pool.slot_for("shrinking").await;
    let mut held: Vec<_> = (0..4)
        .map(|_| initial.try_acquire().expect("initial permit"))
        .collect();
    assert_eq!(initial.semaphore.available_permits(), 0);

    pool.set_max_concurrent_per_endpoint(1);
    let slot = pool.slot_for("shrinking").await;
    assert!(slot.try_acquire().is_err());
    assert_eq!(slot.semaphore.available_permits(), 0);

    let released = held.remove(0);
    drop(released);
    assert_eq!(
        slot.semaphore.available_permits(),
        0,
        "released permit must be forgotten while the limiter shrinks"
    );
    drop(held);

    let only = slot.try_acquire().expect("single permit after shrink");
    assert!(slot.try_acquire().is_err());
    drop(only);
}

#[tokio::test]
async fn repeated_limit_reloads_do_not_overshoot_or_panic() {
    let pool = UpstreamProxyPool::new();
    pool.set_max_concurrent_per_endpoint(4);
    let slot = pool.slot_for("reloads").await;
    let mut held: Vec<_> = (0..4)
        .map(|_| slot.try_acquire().expect("initial permit"))
        .collect();

    pool.set_max_concurrent_per_endpoint(1);
    let _ = pool.slot_for("reloads").await;
    pool.set_max_concurrent_per_endpoint(3);
    let _ = pool.slot_for("reloads").await;
    drop(held.remove(0));
    assert_eq!(slot.semaphore.available_permits(), 0);
    drop(held);
    assert_eq!(slot.semaphore.available_permits(), 3);

    let first = slot.try_acquire().expect("first permit");
    let second = slot.try_acquire().expect("second permit");
    let third = slot.try_acquire().expect("third permit");
    assert!(slot.try_acquire().is_err());
    drop((first, second, third));
}

#[test]
fn unconfigured_failure_kind_breaks_forward_consecutive_streaks() {
    let endpoint = Arc::new(ManagedUpstreamEndpoint::new(
        parse_upstream_proxy_endpoint("http://127.0.0.1:3128").expect("endpoint"),
    ));
    let policy = PassiveHealthPolicy {
        consecutive_5xx: 2,
        consecutive_timeouts: 100,
        consecutive_connect_errors: 100,
        consecutive_resets: 0,
        max_ejection: Duration::from_secs(30),
        latency_threshold: None,
        latency_min_samples: LATENCY_P95_DEFAULT_MIN_SAMPLES,
    };

    endpoint.mark_passive_failure(Some(&policy), PassiveFailureKind::Http5xx);
    endpoint.mark_passive_failure(Some(&policy), PassiveFailureKind::Reset);
    endpoint.mark_passive_failure(Some(&policy), PassiveFailureKind::Http5xx);
    assert!(
        endpoint.is_healthy(now_millis()),
        "an unconfigured reset interrupts the 5xx streak"
    );

    endpoint.mark_passive_failure(Some(&policy), PassiveFailureKind::Http5xx);
    assert!(
        !endpoint.is_healthy(now_millis()),
        "two adjacent 5xx failures still eject"
    );
}
