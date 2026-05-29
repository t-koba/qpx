use super::cluster::{
    ManagedUpstreamEndpoint, PassiveFailureKind, PassiveHealthPolicy, UpstreamProxyCluster,
    now_millis,
};
use super::send::upstream_proxy_pool_key;
use crate::tls::CompiledUpstreamTlsTrust;
use crate::upstream::http1::parse_upstream_proxy_endpoint;
use arc_swap::ArcSwap;
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
    };
    for _ in 0..4 {
        endpoint.mark_passive_success();
    }
    for _ in 0..4 {
        endpoint.mark_passive_failure(Some(&policy), PassiveFailureKind::ConnectError);
    }
    assert!(!endpoint.is_healthy(now_millis()));
}
