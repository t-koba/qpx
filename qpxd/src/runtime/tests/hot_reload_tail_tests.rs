use super::*;

#[test]
fn hot_reload_requires_server_restart_for_acceptor_tuning_change() {
    let mut old = base_config();
    old.runtime.acceptor_tasks_per_listener = Some(1);
    push_ingress(
        &mut old,
        IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:18080".to_string(),
            default_action: allow_action(),
            original_dst: None,
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: Some(StreamingRequirement::Preferred),
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
        },
    );

    let mut new = old.clone();
    new.runtime.acceptor_tasks_per_listener = Some(4);

    ensure_hot_reload_compatible(&old, &new)
        .expect("acceptor tuning change should be reload-safe with server restart");
    assert!(requires_server_restart(&old, &new));
}

#[test]
fn hot_reload_requires_server_restart_for_xdp_startup_change() {
    let mut old = base_config();
    push_ingress(
        &mut old,
        IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:18080".to_string(),
            default_action: allow_action(),
            original_dst: None,
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: Some(StreamingRequirement::Preferred),
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
        },
    );

    let mut new = old.clone();
    ingress_mut(&mut new, 0).xdp = Some(XdpConfig {
        enabled: true,
        metadata_mode: "proxy-v2".to_string(),
        require_metadata: true,
        trusted_peers: vec!["127.0.0.0/8".to_string()],
    });

    ensure_hot_reload_compatible(&old, &new)
        .expect("xdp startup change should be reload-safe with server restart");
    assert!(requires_server_restart(&old, &new));
}

#[test]
fn hot_reload_rejects_worker_thread_change() {
    let mut old = base_config();
    old.runtime.worker_threads = Some(2);
    push_ingress(
        &mut old,
        IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:18080".to_string(),
            default_action: allow_action(),
            original_dst: None,
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: Some(StreamingRequirement::Preferred),
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
        },
    );

    let mut new = old.clone();
    new.runtime.worker_threads = Some(8);

    let err = ensure_hot_reload_compatible(&old, &new)
        .expect_err("worker thread change must still require process restart");
    assert!(err.to_string().contains("runtime startup tuning changed"));
}
