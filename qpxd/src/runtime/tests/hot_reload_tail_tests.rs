use super::*;

#[tokio::test]
async fn hot_reload_preserves_webdav_read_admission_for_active_snapshots() {
    let directory = tempfile::tempdir().expect("real WebDAV runtime directory");
    let mut config = base_config();
    config.runtime.worker_threads = Some(2);
    let without_webdav = Runtime::new(config.clone()).expect("runtime without WebDAV");
    assert!(without_webdav.state().webdav_read_semaphore.is_none());
    config
        .http
        .origins
        .webdav
        .push(qpx_core::config::WebDavOriginConfig {
            name: "dav".to_string(),
            root: directory.path().to_string_lossy().into_owned(),
            metadata: directory
                .path()
                .join("metadata.redb")
                .to_string_lossy()
                .into_owned(),
            max_depth: 32,
            max_multistatus_entries: 10000,
            max_lock_timeout_seconds: 86400,
        });
    let runtime = Runtime::new(config.clone()).expect("WebDAV runtime");
    let previous = runtime.state();
    let admission = previous.webdav_read_semaphore.as_ref().unwrap();
    let active = admission.clone().acquire_owned().await.unwrap();
    let replacement = RuntimeState::build(config).expect("replacement WebDAV runtime");
    runtime.swap(replacement);
    let current = runtime.state();
    let carried = current.webdav_read_semaphore.as_ref().unwrap();
    assert!(Arc::ptr_eq(admission, carried));
    assert_eq!(carried.available_permits(), 1);
    drop(active);
    assert_eq!(carried.available_permits(), 2);
}

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
