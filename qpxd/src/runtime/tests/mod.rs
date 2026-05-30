use super::plan::CompiledEdge;
use super::*;
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CachePolicyConfig,
    CaptureBodyMode, CapturePlaintextPolicyConfig, CapturePolicyConfig, CaptureRedactionConfig,
    HttpModuleConfig, HttpPolicyConfig, IngressEdgeConfig, IngressEdgeMode, IpcMode,
    IpcUpstreamConfig, MatchConfig, NamedSetConfig, NamedSetKind, OtelConfig, PolicyContextConfig,
    RateLimitApplyTo, RateLimitConfig, RateLimitRequestsConfig, ReverseEdgeConfig,
    ReverseRouteConfig, ReverseRouteTargetConfig, ReverseTlsPassthroughRouteConfig, RuleConfig,
    StreamingRequirement, SystemLogConfig, TlsInspectionConfig, TlsPassthroughMatchConfig,
    UnknownLengthExactSizePolicy, UpstreamTlsTrustConfig, UpstreamTlsTrustProfileConfig, XdpConfig,
};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn base_config() -> Config {
    Config {
        state_dir: None,
        identity: Default::default(),
        messages: Default::default(),
        runtime: Default::default(),
        telemetry: qpx_core::config::TelemetryConfig {
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            exporter: None,
        },
        security: qpx_core::config::SecurityConfig {
            auth: AuthConfig {
                users: Vec::new(),
                ldap: None,
            },
            identity_sources: Vec::new(),
            decisions: qpx_core::config::DecisionConfig {
                ext_authz: Vec::new(),
            },
            destination: Default::default(),
            named_sets: Vec::new(),
            upstream_trust_profiles: Vec::new(),
        },
        http: qpx_core::config::HttpGlobalConfig::default(),
        traffic: qpx_core::config::TrafficConfig::default(),
        acme: None,
        edges: Vec::new(),
        upstreams: Vec::new(),
        caches: Vec::new(),
    }
}

fn push_ingress(config: &mut Config, edge: IngressEdgeConfig) {
    config
        .edges
        .push(qpx_core::config::EdgeConfig::Forward(edge));
}

fn push_reverse(config: &mut Config, edge: ReverseEdgeConfig) {
    config
        .edges
        .push(qpx_core::config::EdgeConfig::Reverse(edge));
}

fn ingress_mut(config: &mut Config, idx: usize) -> &mut IngressEdgeConfig {
    config.ingress_edges_mut().nth(idx).expect("ingress edge")
}

fn ingress(config: &Config, idx: usize) -> &IngressEdgeConfig {
    config.ingress_edges().nth(idx).expect("ingress edge")
}

fn reverse_mut(config: &mut Config, idx: usize) -> &mut ReverseEdgeConfig {
    config.reverse_edges_mut().nth(idx).expect("reverse edge")
}

fn allow_action() -> ActionConfig {
    ActionConfig {
        kind: ActionKind::Direct,
        upstream: None,
        local_response: None,
    }
}

fn reverse_route(name: &str) -> ReverseRouteConfig {
    ReverseRouteConfig {
        name: Some(name.to_string()),
        r#match: MatchConfig::default(),
        target: ReverseRouteTargetConfig::Upstream {
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
        http: Some(HttpPolicyConfig {
            response_rules: Vec::new(),
        }),
        http_guard_profile: None,
        destination_resolution: None,
        resilience: None,
        http_modules: Vec::new(),
        streaming: None,
        grpc: None,
        sse: None,
        streaming_requirement: Some(StreamingRequirement::Preferred),
    }
}

fn reverse_edge(route: ReverseRouteConfig) -> ReverseEdgeConfig {
    ReverseEdgeConfig {
        name: "reverse_edges".to_string(),
        listen: "127.0.0.1:19090".to_string(),
        tls: None,
        http3: None,
        xdp: None,
        enforce_sni_host_match: false,
        sni_host_exceptions: Vec::new(),
        policy_context: None,
        destination_resolution: None,
        connection_filter: Vec::new(),
        streaming: None,
        grpc: None,
        sse: None,
        routes: vec![route],
        tls_passthrough_routes: Vec::new(),
    }
}

fn single_reverse_route_flags(config: Config) -> PlanFlags {
    let runtime = Runtime::new(config).expect("runtime");
    let state = runtime.state();
    match state.plan.edges.as_ref() {
        [CompiledEdge::Reverse(edge)] => edge.routes[0].plan.flags,
        edges => panic!("expected one reverse_edges edge, got {}", edges.len()),
    }
}

fn single_reverse_route_plan(config: Config) -> ExecutionPlan {
    let runtime = Runtime::new(config).expect("runtime");
    let state = runtime.state();
    match state.plan.edges.as_ref() {
        [CompiledEdge::Reverse(edge)] => edge.routes[0].plan.clone(),
        edges => panic!("expected one reverse_edges edge, got {}", edges.len()),
    }
}

fn temp_named_set_file(name: &str, contents: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("qpx-{name}-{unique}.txt"));
    fs::write(&path, contents).expect("write named set file");
    path
}

#[cfg(unix)]
fn temp_exporter_shm_path(name: &str) -> String {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir()
        .join(format!("qpx-{name}-{unique}.shm"))
        .to_string_lossy()
        .into_owned()
}

mod hot_reload;
mod hot_reload_tail_tests;
mod named_sets;
mod plan;
