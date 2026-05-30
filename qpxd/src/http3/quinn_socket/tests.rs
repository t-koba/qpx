use super::QuinnBrokerKind;
use super::broker::new_local_broker_socket;
use super::endpoint::NoopQuinnUdpIngressFilter;
use super::frame::{BrokerFrame, OwnedTransmit, decode_frame, encode_frame};
use super::handoff::{QuinnBrokerRestoreSet, prepare_quic_broker_handoff};
use super::routing::{ROUTE_STATE_MAX_ADDRS, ROUTE_STATE_MAX_CIDS, RouteState};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;

fn long_packet(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let mut packet = vec![0xc0, 0, 0, 0, 1, dcid.len() as u8];
    packet.extend_from_slice(dcid);
    packet.push(scid.len() as u8);
    packet.extend_from_slice(scid);
    packet.extend_from_slice(&[0u8; 8]);
    packet
}

fn short_packet(dcid: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x40];
    packet.extend_from_slice(dcid);
    packet.extend_from_slice(&[0u8; 4]);
    packet
}

#[test]
fn route_state_matches_observed_long_and_short_headers() {
    let mut state = RouteState::default();
    let addr: SocketAddr = "127.0.0.1:4433".parse().expect("addr");
    let server_cid = [0x11, 0x22, 0x33, 0x44];
    let client_cid = [0xaa, 0xbb, 0xcc, 0xdd];

    state.observe_outbound(addr, &long_packet(&client_cid, &server_cid));
    assert!(
        state.matches_cid(&short_packet(&server_cid)),
        "short header should match observed server CID"
    );

    state.observe_inbound(addr, &long_packet(&server_cid, &client_cid));
    assert!(
        state.matches_cid(&long_packet(&server_cid, &client_cid)),
        "long header should match observed client/server CIDs"
    );
}

#[test]
fn route_state_caps_observed_addrs_and_cids() {
    let mut state = RouteState::default();
    for i in 0..(ROUTE_STATE_MAX_CIDS + 16) {
        let addr: SocketAddr = format!("127.0.0.1:{}", 10_000 + i).parse().expect("addr");
        let cid = (i as u64).to_be_bytes();
        state.observe_inbound(addr, &long_packet(&cid, &[0xaa, 0xbb, 0xcc, 0xdd]));
    }

    assert_eq!(state.addrs.len(), ROUTE_STATE_MAX_ADDRS);
    assert_eq!(state.cid_count(), ROUTE_STATE_MAX_CIDS);
    assert!(
        state.matches_cid(&long_packet(
            &((ROUTE_STATE_MAX_CIDS + 15) as u64).to_be_bytes(),
            &[0xaa, 0xbb, 0xcc, 0xdd]
        )),
        "latest observed CID should remain routable"
    );
}

#[test]
fn route_state_refresh_moves_entry_to_recent_eviction_position() {
    let mut state = RouteState::default();
    let first_addr: SocketAddr = "127.0.0.1:10000".parse().expect("addr");
    let first_cid = 1u64.to_be_bytes();
    state.observe_inbound(
        first_addr,
        &long_packet(&first_cid, &[0xaa, 0xbb, 0xcc, 0xdd]),
    );

    for i in 1..ROUTE_STATE_MAX_CIDS {
        let addr: SocketAddr = format!("127.0.0.1:{}", 10_000 + i).parse().expect("addr");
        let cid = ((i + 1) as u64).to_be_bytes();
        state.observe_inbound(addr, &long_packet(&cid, &[0xaa, 0xbb, 0xcc, 0xdd]));
    }

    state.observe_inbound(
        first_addr,
        &long_packet(&first_cid, &[0xaa, 0xbb, 0xdd, 0xee]),
    );
    let new_addr: SocketAddr = "127.0.0.1:65000".parse().expect("addr");
    state.observe_inbound(
        new_addr,
        &long_packet(&999_999u64.to_be_bytes(), &[0xaa, 0xbb, 0xcc, 0xdd]),
    );

    assert!(state.addrs.contains_key(&first_addr));
    assert!(state.matches_cid(&long_packet(&first_cid, &[0xaa, 0xbb, 0xcc, 0xdd])));
}

#[test]
fn route_state_compacts_refresh_queues_for_repeated_keys() {
    let mut state = RouteState::default();
    let addr: SocketAddr = "127.0.0.1:10000".parse().expect("addr");
    let cid = 1u64.to_be_bytes();
    for _ in 0..(ROUTE_STATE_MAX_CIDS * 3) {
        state.observe_inbound(addr, &long_packet(&cid, &[0xaa, 0xbb, 0xcc, 0xdd]));
    }
    let (addr_queue_len, cid_queue_len) = state.queue_lengths();
    assert_eq!(state.addrs.len(), 1);
    assert_eq!(state.cid_count(), 1);
    assert!(addr_queue_len <= ROUTE_STATE_MAX_ADDRS * 2);
    assert!(cid_queue_len <= ROUTE_STATE_MAX_CIDS * 2);
}

fn test_config() -> qpx_core::config::Config {
    qpx_core::config::Config {
        state_dir: None,
        identity: Default::default(),
        messages: Default::default(),
        runtime: Default::default(),
        telemetry: qpx_core::config::TelemetryConfig {
            system_log: Default::default(),
            access_log: Default::default(),
            audit_log: Default::default(),
            metrics: None,
            otel: None,
            exporter: None,
        },
        security: qpx_core::config::SecurityConfig {
            auth: Default::default(),
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

#[cfg(any(unix, windows))]
#[test]
fn broker_frame_round_trip_preserves_transmit() {
    let transmit = BrokerFrame::OutboundTransmit(OwnedTransmit {
        destination: "127.0.0.1:9443".parse().expect("destination"),
        ecn: quinn::udp::EcnCodepoint::from_bits(0b10),
        contents: Bytes::from_static(&[1, 2, 3, 4, 5, 6]),
        segment_size: Some(3),
        src_ip: Some("127.0.0.1".parse().expect("src ip")),
    });
    let encoded = encode_frame(&transmit).expect("encode");
    let decoded = decode_frame(encoded.as_slice()).expect("decode");
    match decoded {
        BrokerFrame::OutboundTransmit(decoded) => {
            assert_eq!(decoded.destination, "127.0.0.1:9443".parse().unwrap());
            assert_eq!(decoded.contents.as_ref(), &[1, 2, 3, 4, 5, 6]);
            assert_eq!(decoded.segment_size, Some(3));
            assert_eq!(decoded.src_ip, Some("127.0.0.1".parse().unwrap()));
        }
        other => panic!("unexpected frame: {other:?}"),
    }
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn quic_broker_handoff_round_trip_restores_roles() {
    let _guard = crate::test_env_lock().lock().expect("env lock");

    let forward_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("forward bind");
    let reverse_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("reverse_edges bind");
    let (_, forward_handle) = new_local_broker_socket(
        "forward-h3",
        QuinnBrokerKind::Forward,
        forward_socket,
        Arc::new(NoopQuinnUdpIngressFilter),
    )
    .expect("forward broker");
    let (_, reverse_handle) = new_local_broker_socket(
        "reverse_edges-h3",
        QuinnBrokerKind::ReverseTerminate,
        reverse_socket,
        Arc::new(NoopQuinnUdpIngressFilter),
    )
    .expect("reverse_edges broker");

    let handoff = prepare_quic_broker_handoff(&[forward_handle, reverse_handle], &test_config())
        .expect("prepare handoff")
        .expect("handoff");
    unsafe {
        std::env::set_var(QuinnBrokerRestoreSet::handoff_env_key(), &handoff.env_value);
    }
    #[cfg(unix)]
    std::mem::forget(handoff.kept_fds);

    let mut restored = QuinnBrokerRestoreSet::take_from_env()
        .expect("take handoff")
        .expect("restore");
    assert!(
        restored.take_forward("forward-h3").is_some(),
        "forward broker should restore by role"
    );
    assert!(
        restored.take_reverse("reverse_edges-h3").is_some(),
        "reverse_edges broker should restore by role"
    );
    restored.ensure_consumed().expect("restore consumed");
}
