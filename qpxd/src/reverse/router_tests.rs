use super::router_selection::{endpoint_lifecycle_state, EndpointLifecycleState};
use super::*;
use qpx_core::config::{HealthCheckConfig, MatchConfig, ResilienceConfig, ResilienceRetryConfig};

fn empty_pool() -> Arc<UpstreamPool> {
    UpstreamPool::new(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        EndpointLifecycleRuntime::default(),
    )
}

#[test]
fn weighted_backend_selection_is_stable() {
    let backends = vec![
        WeightedBackend {
            weight: 9,
            upstreams: empty_pool(),
            rr_counter: AtomicUsize::new(0),
        },
        WeightedBackend {
            weight: 1,
            upstreams: empty_pool(),
            rr_counter: AtomicUsize::new(0),
        },
    ];
    for seed in 0..9 {
        assert_eq!(select_weighted_backend_idx(&backends, seed), Some(0));
    }
    assert_eq!(select_weighted_backend_idx(&backends, 9), Some(1));
    assert_eq!(select_weighted_backend_idx(&backends, 19), Some(1));
    assert_eq!(select_weighted_backend_idx(&backends, 20), Some(0));
}

#[test]
fn route_policy_uses_configured_values() {
    let cfg = ReverseRouteConfig {
        name: None,
        r#match: MatchConfig::default(),
        upstreams: vec!["http://127.0.0.1:8080".to_string()],
        backends: Vec::new(),
        mirrors: Vec::new(),
        local_response: None,
        headers: None,
        lb: "least_conn".to_string(),
        timeout_ms: Some(12_000),
        health_check: Some(HealthCheckConfig {
            interval_ms: 1500,
            timeout_ms: 700,
            fail_threshold: 5,
            cooldown_ms: 9_000,
            http: None,
        }),
        cache: None,
        rate_limit: None,
        path_rewrite: None,
        upstream_trust_profile: None,
        upstream_trust: None,
        lifecycle: None,
        ipc: None,
        affinity: None,
        policy_context: None,
        http: None,
        http_guard_profile: None,
        destination_resolution: None,
        resilience: Some(ResilienceConfig {
            retry: Some(ResilienceRetryConfig {
                attempts: 4,
                backoff_ms: 250,
                budget: None,
            }),
            ..Default::default()
        }),
        http_modules: Vec::new(),
    };
    let policy = RoutePolicy::from_http_config(&cfg).expect("policy");
    assert!(matches!(policy.lb, LoadBalanceStrategy::LeastConnections));
    assert_eq!(policy.retry_attempts, 4);
    assert_eq!(policy.retry_backoff, Duration::from_millis(250));
    assert_eq!(policy.timeout, Duration::from_millis(12_000));
    assert_eq!(policy.health.interval, Duration::from_millis(1500));
    assert_eq!(policy.health.timeout, Duration::from_millis(700));
    assert_eq!(policy.health.fail_threshold, 5);
    assert_eq!(policy.health.cooldown, Duration::from_millis(9_000));
}

#[test]
fn route_policy_default_health_and_lb() {
    let cfg = ReverseRouteConfig {
        name: None,
        r#match: MatchConfig::default(),
        upstreams: vec!["http://127.0.0.1:8080".to_string()],
        backends: Vec::new(),
        mirrors: Vec::new(),
        local_response: None,
        headers: None,
        lb: "round_robin".to_string(),
        timeout_ms: None,
        health_check: None,
        cache: None,
        rate_limit: None,
        path_rewrite: None,
        upstream_trust_profile: None,
        upstream_trust: None,
        lifecycle: None,
        ipc: None,
        affinity: None,
        policy_context: None,
        http: None,
        http_guard_profile: None,
        destination_resolution: None,
        resilience: None,
        http_modules: Vec::new(),
    };
    let policy = RoutePolicy::from_http_config(&cfg).expect("policy");
    assert!(matches!(policy.lb, LoadBalanceStrategy::RoundRobin));
    assert_eq!(policy.retry_attempts, 1);
    assert_eq!(policy.retry_backoff, Duration::from_millis(0));
    assert_eq!(policy.timeout, Duration::from_millis(30_000));
    assert_eq!(policy.health.interval, Duration::from_secs(5));
    assert_eq!(policy.health.timeout, Duration::from_secs(1));
    assert_eq!(policy.health.fail_threshold, 3);
    assert_eq!(policy.health.cooldown, Duration::from_secs(30));
}

#[test]
fn route_policy_uses_lifecycle_values() {
    let cfg = ReverseRouteConfig {
        name: None,
        r#match: MatchConfig::default(),
        upstreams: vec!["http://127.0.0.1:8080".to_string()],
        backends: Vec::new(),
        mirrors: Vec::new(),
        local_response: None,
        headers: None,
        lb: "round_robin".to_string(),
        timeout_ms: None,
        health_check: None,
        cache: None,
        rate_limit: None,
        path_rewrite: None,
        upstream_trust_profile: None,
        upstream_trust: None,
        lifecycle: Some(qpx_core::config::EndpointLifecycleConfig {
            slow_start_ms: Some(8_000),
            warmup_ms: Some(1_500),
            drain_timeout_ms: Some(9_000),
        }),
        ipc: None,
        affinity: None,
        policy_context: None,
        http: None,
        http_guard_profile: None,
        destination_resolution: None,
        resilience: None,
        http_modules: Vec::new(),
    };
    let policy = RoutePolicy::from_http_config(&cfg).expect("policy");
    assert_eq!(
        policy.lifecycle.slow_start,
        Some(Duration::from_millis(8_000))
    );
    assert_eq!(policy.lifecycle.warmup, Some(Duration::from_millis(1_500)));
    assert_eq!(
        policy.lifecycle.drain_timeout,
        Some(Duration::from_millis(9_000))
    );
}

#[test]
fn draining_endpoint_is_not_selected_while_healthy_peers_exist() {
    let policy = RoutePolicy {
        retry_attempts: 1,
        retry_backoff: Duration::ZERO,
        retry_budget: RetryBudgetRuntime::new(1),
        timeout: Duration::from_secs(30),
        health: HealthCheckRuntime::from_config(None),
        passive_health: None,
        lifecycle: EndpointLifecycleRuntime {
            slow_start: None,
            warmup: None,
            drain_timeout: Some(Duration::from_secs(30)),
        },
        max_upstream_concurrency: None,
        lb: LoadBalanceStrategy::RoundRobin,
    };
    let stable = Arc::new(UpstreamEndpoint::new("http://stable".to_string()));
    let draining = Arc::new(UpstreamEndpoint::new("http://drain".to_string()));
    assert!(draining.mark_draining(&policy.lifecycle));
    let selected = select_upstream_inner(
        &[stable.clone(), draining],
        &policy,
        &AtomicUsize::new(0),
        1,
        1,
    )
    .expect("selected");
    assert_eq!(selected.target, stable.target);
}

#[test]
fn half_open_endpoint_requires_zero_inflight() {
    let policy = RoutePolicy {
        retry_attempts: 1,
        retry_backoff: Duration::ZERO,
        retry_budget: RetryBudgetRuntime::new(1),
        timeout: Duration::from_secs(30),
        health: HealthCheckRuntime {
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            fail_threshold: 1,
            cooldown: Duration::from_millis(1),
            http: None,
        },
        passive_health: None,
        lifecycle: EndpointLifecycleRuntime::default(),
        max_upstream_concurrency: None,
        lb: LoadBalanceStrategy::RoundRobin,
    };
    let healthy = Arc::new(UpstreamEndpoint::new("http://healthy".to_string()));
    let half_open = Arc::new(UpstreamEndpoint::new("http://half-open".to_string()));
    half_open.mark_failure(&policy.health);
    std::thread::sleep(Duration::from_millis(2));
    half_open.inflight.store(1, Ordering::Relaxed);

    let selected = select_upstream_inner(
        &[healthy.clone(), half_open.clone()],
        &policy,
        &AtomicUsize::new(0),
        7,
        7,
    )
    .expect("selected");
    assert_eq!(selected.target, healthy.target);

    half_open.inflight.store(0, Ordering::Relaxed);
    let selected = select_upstream_inner(
        std::slice::from_ref(&half_open),
        &policy,
        &AtomicUsize::new(0),
        11,
        11,
    )
    .expect("selected");
    assert_eq!(selected.target, half_open.target);
}

#[test]
fn recovered_endpoint_enters_warmup_then_slow_start() {
    let endpoint = Arc::new(UpstreamEndpoint::new("http://recover".to_string()));
    let health = HealthCheckRuntime::from_config(None);
    let lifecycle = EndpointLifecycleRuntime {
        slow_start: Some(Duration::from_secs(30)),
        warmup: Some(Duration::from_secs(5)),
        drain_timeout: None,
    };
    endpoint.mark_failure(&health);
    endpoint.mark_failure(&health);
    endpoint.mark_failure(&health);
    endpoint.mark_success(&lifecycle);

    let now_ms = now_millis();
    assert!(matches!(
        endpoint_lifecycle_state(&endpoint, &lifecycle, now_ms),
        EndpointLifecycleState::Warming
    ));
    let after_warmup = endpoint.warmup_until_ms().saturating_add(1);
    assert!(matches!(
        endpoint_lifecycle_state(&endpoint, &lifecycle, after_warmup),
        EndpointLifecycleState::Ramping(progress) if progress < 0.01
    ));
    let ready_at = endpoint
        .recovery_start_ms()
        .saturating_add(Duration::from_secs(31).as_millis() as u64);
    assert!(matches!(
        endpoint_lifecycle_state(&endpoint, &lifecycle, ready_at),
        EndpointLifecycleState::Ready
    ));
}

#[test]
fn dynamic_discovery_churn_reuses_draining_endpoint_when_target_returns() {
    let lifecycle = EndpointLifecycleRuntime {
        slow_start: Some(Duration::from_secs(30)),
        warmup: Some(Duration::from_secs(5)),
        drain_timeout: Some(Duration::from_secs(10)),
    };
    let first = Arc::new(UpstreamEndpoint::new("http://a".to_string()));
    let pool = UpstreamPool::new(vec![], vec![first.clone()], vec![], lifecycle.clone());

    let combined =
        pool.reconcile_dynamic_endpoints(vec![OriginEndpoint::direct("http://b".to_string())]);
    let drained_first = combined
        .iter()
        .find(|endpoint| endpoint.target == "http://a")
        .expect("draining first endpoint")
        .clone();
    let replacement = combined
        .iter()
        .find(|endpoint| endpoint.target == "http://b")
        .expect("replacement endpoint")
        .clone();
    assert!(Arc::ptr_eq(&drained_first, &first));
    assert!(drained_first.is_draining());
    assert!(replacement.warmup_until_ms() > 0);

    pool.endpoints.store(Arc::new(combined));

    let combined =
        pool.reconcile_dynamic_endpoints(vec![OriginEndpoint::direct("http://a".to_string())]);
    let reactivated_first = combined
        .iter()
        .find(|endpoint| endpoint.target == "http://a")
        .expect("reactivated first endpoint")
        .clone();
    let draining_replacement = combined
        .iter()
        .find(|endpoint| endpoint.target == "http://b")
        .expect("draining replacement endpoint")
        .clone();
    assert!(Arc::ptr_eq(&reactivated_first, &first));
    assert!(!reactivated_first.is_draining());
    assert!(reactivated_first.warmup_until_ms() > 0);
    assert!(draining_replacement.is_draining());
}

#[test]
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
fn tls_passthrough_prefilter_does_not_require_host_or_path() {
    let cfg = ReverseConfig {
        name: "rev".to_string(),
        listen: "127.0.0.1:0".to_string(),
        tls: Some(qpx_core::config::ReverseTlsConfig {
            certificates: Vec::new(),
            client_ca: None,
        }),
        http3: None,
        xdp: None,
        enforce_sni_host_match: false,
        sni_host_exceptions: Vec::new(),
        policy_context: None,
        destination_resolution: None,
        connection_filter: Vec::new(),
        routes: Vec::new(),
        tls_passthrough_routes: vec![ReverseTlsPassthroughRouteConfig {
            r#match: qpx_core::config::TlsPassthroughMatchConfig {
                src_ip: Vec::new(),
                dst_port: vec![443],
                sni: vec!["example.com".to_string()],
            },
            upstreams: vec!["127.0.0.1:8443".to_string()],
            lb: "round_robin".to_string(),
            timeout_ms: None,
            health_check: None,
            resilience: None,
            lifecycle: None,
            affinity: None,
        }],
    };

    let registry = crate::http::modules::default_http_module_registry();
    let router = ReverseRouter::new(cfg, &[], registry.as_ref()).expect("router");
    let selected = router.select_tls_passthrough_upstream(
        "203.0.113.10".parse().expect("ip"),
        443,
        Some("example.com"),
    );
    let selected_addr = selected
        .as_ref()
        .and_then(|upstream| upstream.origin.connect_authority(443).ok());
    assert_eq!(selected_addr.as_deref(), Some("127.0.0.1:8443"));
}

#[test]
fn retry_budget_requires_success_to_replenish() {
    let budget = RetryBudgetRuntime::new(2);
    assert!(budget.try_consume_retry());
    assert!(!budget.try_consume_retry());
    budget.record_success();
    assert!(budget.try_consume_retry());
}
