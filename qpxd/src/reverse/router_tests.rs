use super::router_selection::{EndpointLifecycleState, endpoint_lifecycle_state};
use super::*;
use qpx_core::config::{
    EdgeConfig, HealthCheckConfig, MatchConfig, ResilienceConfig, ResilienceRetryConfig,
};

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
        target: qpx_core::config::ReverseRouteTargetConfig::Upstream {
            upstreams: vec!["http://127.0.0.1:8080".to_string()],
            lb: "least_conn".to_string(),
        },
        mirrors: Vec::new(),
        headers: None,
        timeout_ms: Some(12_000),
        health_check: Some(HealthCheckConfig {
            interval_ms: 1500,
            timeout_ms: 700,
            fail_threshold: 5,
            cooldown_ms: 9_000,
            http: None,
        }),
        cache: None,
        capture: None,
        rate_limit: None,
        path_rewrite: None,
        upstream_trust_profile: None,
        upstream_trust: None,
        lifecycle: None,
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
        target: qpx_core::config::ReverseRouteTargetConfig::Upstream {
            upstreams: vec!["http://127.0.0.1:8080".to_string()],
            lb: "round_robin".to_string(),
        },
        mirrors: Vec::new(),
        headers: None,
        timeout_ms: None,
        health_check: None,
        cache: None,
        capture: None,
        rate_limit: None,
        path_rewrite: None,
        upstream_trust_profile: None,
        upstream_trust: None,
        lifecycle: None,
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
        target: qpx_core::config::ReverseRouteTargetConfig::Upstream {
            upstreams: vec!["http://127.0.0.1:8080".to_string()],
            lb: "round_robin".to_string(),
        },
        mirrors: Vec::new(),
        headers: None,
        timeout_ms: None,
        health_check: None,
        cache: None,
        capture: None,
        rate_limit: None,
        path_rewrite: None,
        upstream_trust_profile: None,
        upstream_trust: None,
        lifecycle: Some(qpx_core::config::EndpointLifecycleConfig {
            slow_start_ms: Some(8_000),
            warmup_ms: Some(1_500),
            drain_timeout_ms: Some(9_000),
        }),
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
    let cfg = ReverseEdgeConfig {
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
fn reverse_router_rejects_compiled_route_count_mismatch() {
    let (cfg, compiled, registry) = compiled_reverse_fixture(false);
    let mut bad = compiled.clone();
    bad.routes = Vec::new().into();

    let err = expect_router_error(ReverseRouter::new_with_plan(
        cfg,
        &[],
        registry.as_ref(),
        &bad,
    ));
    assert!(err.to_string().contains("compiled route count mismatch"));
}

#[test]
fn reverse_router_rejects_compiled_route_identity_mismatch() {
    let (mut cfg, compiled, registry) = compiled_reverse_fixture(false);
    cfg.routes[0].name = Some("changed".to_string());

    let err = expect_router_error(ReverseRouter::new_with_plan(
        cfg,
        &[],
        registry.as_ref(),
        &compiled,
    ));
    assert!(err.to_string().contains("route id mismatch"));
}

#[test]
fn reverse_router_rejects_compiled_route_target_kind_mismatch() {
    let (cfg, compiled, registry) = compiled_reverse_fixture(false);
    let mut routes = compiled.routes.to_vec();
    routes[0].target = CompiledReverseRouteTarget::LocalResponse { status: 204 };
    let mut bad = compiled.clone();
    bad.routes = routes.into();

    let err = expect_router_error(ReverseRouter::new_with_plan(
        cfg,
        &[],
        registry.as_ref(),
        &bad,
    ));
    assert!(err.to_string().contains("route target kind mismatch"));
}

#[test]
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
fn reverse_router_rejects_compiled_tls_passthrough_count_mismatch() {
    let (cfg, compiled, registry) = compiled_reverse_fixture(true);
    let mut bad = compiled.clone();
    bad.tls_passthrough_routes = Vec::new().into();

    let err = expect_router_error(ReverseRouter::new_with_plan(
        cfg,
        &[],
        registry.as_ref(),
        &bad,
    ));
    assert!(
        err.to_string()
            .contains("compiled TLS passthrough route count mismatch")
    );
}

fn compiled_reverse_fixture(
    include_tls_passthrough: bool,
) -> (
    ReverseEdgeConfig,
    crate::runtime::CompiledReverseEdge,
    Arc<HttpModuleRegistry>,
) {
    let cfg = ReverseEdgeConfig {
        name: "rev".to_string(),
        listen: "127.0.0.1:0".to_string(),
        tls: include_tls_passthrough.then_some(qpx_core::config::ReverseTlsConfig {
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
        routes: vec![ReverseRouteConfig {
            name: Some("app".to_string()),
            r#match: MatchConfig {
                host: vec!["example.com".to_string()],
                ..Default::default()
            },
            target: qpx_core::config::ReverseRouteTargetConfig::Upstream {
                upstreams: vec!["http://127.0.0.1:8080".to_string()],
                lb: "round_robin".to_string(),
            },
            mirrors: Vec::new(),
            headers: None,
            timeout_ms: None,
            health_check: None,
            cache: None,
            capture: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            affinity: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: Vec::new(),
        }],
        #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
        tls_passthrough_routes: if include_tls_passthrough {
            vec![ReverseTlsPassthroughRouteConfig {
                r#match: qpx_core::config::TlsPassthroughMatchConfig {
                    src_ip: Vec::new(),
                    dst_port: vec![443],
                    sni: vec!["tls.example.com".to_string()],
                },
                upstreams: vec!["127.0.0.1:8443".to_string()],
                lb: "round_robin".to_string(),
                timeout_ms: None,
                health_check: None,
                resilience: None,
                lifecycle: None,
                affinity: None,
            }]
        } else {
            Vec::new()
        },
        #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
        tls_passthrough_routes: Vec::new(),
    };
    let registry = crate::http::modules::default_http_module_registry();
    let runtime_config = qpx_core::config::Config {
        state_dir: None,
        identity: Default::default(),
        messages: Default::default(),
        runtime: Default::default(),
        telemetry: Default::default(),
        security: Default::default(),
        http: Default::default(),
        traffic: Default::default(),
        acme: None,
        edges: vec![EdgeConfig::Reverse(cfg.clone())],
        upstreams: Vec::new(),
        caches: Vec::new(),
    };
    let state = crate::runtime::RuntimeState::build_with_http_module_registry(
        runtime_config,
        registry.clone(),
    )
    .expect("runtime state");
    let compiled = state
        .plan
        .reverse_edge(cfg.name.as_str())
        .expect("compiled edge")
        .clone();
    (cfg, compiled, registry)
}

fn expect_router_error(result: Result<ReverseRouter>) -> anyhow::Error {
    match result {
        Ok(_) => panic!("router construction should fail"),
        Err(err) => err,
    }
}

#[test]
fn retry_budget_requires_success_to_replenish() {
    let budget = RetryBudgetRuntime::new(2);
    assert!(budget.try_consume_retry());
    assert!(!budget.try_consume_retry());
    budget.record_success();
    assert!(budget.try_consume_retry());
}
