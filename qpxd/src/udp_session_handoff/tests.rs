use crate::rate_limit::RateLimitContext;
use crate::udp_session_handoff::*;
use qpx_core::config::{
    AccessLogConfig, AuditLogConfig, AuthConfig, Config, IdentityConfig, MessagesConfig,
    RuntimeConfig, SystemLogConfig,
};
use std::fs;
fn test_config() -> Config {
    Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        telemetry: qpx_core::config::TelemetryConfig {
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            exporter: None,
        },
        security: qpx_core::config::SecurityConfig {
            auth: AuthConfig::default(),
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

#[test]
fn udp_session_handoff_round_trip_restores_connected_sockets() {
    let _guard = crate::test_env_lock().lock().expect("env lock");

    let upstream = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind upstream");
    let transparent_socket =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("bind transparent socket");
    transparent_socket
        .connect(upstream.local_addr().expect("upstream local"))
        .expect("connect transparent");
    transparent_socket
        .set_nonblocking(true)
        .expect("nonblocking");

    let mut state = UdpSessionRestoreState::default();
    state.insert_transparent(
        "transparent".to_string(),
        TransparentUdpListenerRestore {
            listen: "127.0.0.1:19443".to_string(),
            exported_elapsed_ms: 42,
            sessions: vec![TransparentUdpSessionRestore {
                session_id: 7,
                upstream_local_addr: transparent_socket.local_addr().expect("local"),
                upstream_peer_addr: transparent_socket.peer_addr().expect("peer"),
                socket: duplicate_std_udp_socket_for_test(&transparent_socket),
                client_addr: "127.0.0.1:39001".parse().expect("client"),
                target_key: "example.com:443".to_string(),
                last_seen_ms: 37,
                client_cid_len: Some(8),
                server_cid_len: Some(4),
                cids: vec![ExportedQuicConnectionId {
                    len: 4,
                    bytes: {
                        let mut bytes = [0u8; 20];
                        bytes[..4].copy_from_slice(&[1, 2, 3, 4]);
                        bytes
                    },
                }],
                matched_rule: Some("allow".to_string()),
                rate_limit_profile: Some("profile".to_string()),
                rate_limit_ctx: RateLimitContext::default(),
            }],
        },
    );

    let handoff = state
        .prepare_handoff(&test_config())
        .expect("prepare handoff")
        .expect("handoff");
    // SAFETY: this test serializes environment mutation through the process test env lock.
    unsafe {
        std::env::set_var(
            UdpSessionRestoreState::handoff_env_key(),
            &handoff.env_value,
        );
    }
    std::mem::forget(handoff.kept_fds);

    let mut restored = UdpSessionRestoreState::take_from_env()
        .expect("from env")
        .expect("restore state");
    let listener = restored
        .take_transparent("transparent", "127.0.0.1:19443")
        .expect("take transparent")
        .expect("listener restore");
    assert_eq!(listener.exported_elapsed_ms, 42);
    assert_eq!(listener.sessions.len(), 1);
    assert_eq!(
        listener.sessions[0].socket.peer_addr().expect("peer"),
        upstream.local_addr().expect("upstream addr")
    );
    assert!(restored.is_empty());
    let _ = fs::remove_file(handoff.cleanup_path);
}

fn duplicate_std_udp_socket_for_test(socket: &std::net::UdpSocket) -> std::net::UdpSocket {
    crate::udp_socket_handoff::duplicate_std_udp_socket(socket).expect("duplicate socket")
}
