use super::*;
use qpx_core::tls::UpstreamCertificateInfo;
use tokio::io::duplex;

fn test_https_origin_slot() -> HttpsOriginSlot {
    HttpsOriginSlot {
        http1_idle: Arc::new(AsyncMutex::new(Vec::new())),
        h2: StdMutex::new(H2PoolState::default()),
        h2_ready: Arc::new(Notify::new()),
        h2_rr: AtomicUsize::new(0),
    }
}

#[test]
fn https_origin_pool_key_uses_stable_trust_policy_key() {
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
        https_origin_pool_key(
            "127.0.0.1:443",
            "example.test",
            "example.test",
            true,
            Some(&trust_a)
        ),
        https_origin_pool_key(
            "127.0.0.1:443",
            "example.test",
            "example.test",
            true,
            Some(&trust_b)
        )
    );
    assert_eq!(
        https_origin_pool_key(
            "127.0.0.1:443",
            "example.test",
            "example.test",
            true,
            Some(&trust_a)
        ),
        https_origin_pool_key(
            "127.0.0.1:443",
            "example.test",
            "example.test",
            true,
            Some(&trust_a)
        )
    );
}

async fn spawn_test_h2_sender_with_limits(
    max_concurrent_streams: Option<u32>,
    initial_max_send_streams: Option<usize>,
) -> Result<SharedOriginH2Sender> {
    let (client_io, server_io) = duplex(16 * 1024);
    tokio::spawn(async move {
        let mut builder = h2::server::Builder::new();
        if let Some(max_concurrent_streams) = max_concurrent_streams {
            builder.max_concurrent_streams(max_concurrent_streams);
        }
        let mut server = builder
            .handshake::<_, Bytes>(server_io)
            .await
            .expect("server handshake");
        while let Some(result) = server.accept().await {
            let _ = result.expect("server accept");
        }
    });
    let mut builder = h2::client::Builder::new();
    if let Some(initial_max_send_streams) = initial_max_send_streams {
        builder.initial_max_send_streams(initial_max_send_streams);
    }
    let (sender, connection) = builder.handshake(client_io).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

async fn spawn_test_h2_sender() -> Result<SharedOriginH2Sender> {
    spawn_test_h2_sender_with_limits(None, None).await
}

#[test]
fn h2_connection_reservation_drop_releases_connecting_slot() {
    let slot = test_https_origin_slot();
    let reservation = slot
        .try_reserve_h2_connection()
        .expect("reservation should succeed");
    assert_eq!(slot.h2.lock().expect("pool").connecting, 1);
    drop(reservation);
    let guard = slot.h2.lock().expect("pool");
    assert_eq!(guard.connecting, 0);
    assert!(guard.connections.is_empty());
}

#[tokio::test]
async fn h2_connection_reservation_complete_moves_connection_into_pool() -> Result<()> {
    let slot = test_https_origin_slot();
    let reservation = slot
        .try_reserve_h2_connection()
        .expect("reservation should succeed");
    let shared = Arc::new(SharedTlsH2OriginConnection {
        sender: spawn_test_h2_sender().await?,
        upstream_cert: UpstreamCertificateInfo::default(),
        inflight_streams: Arc::new(AtomicUsize::new(0)),
    });
    reservation.complete(shared.clone());
    let guard = slot.h2.lock().expect("pool");
    assert_eq!(guard.connecting, 0);
    assert_eq!(guard.connections.len(), 1);
    assert!(Arc::ptr_eq(&guard.connections[0], &shared));
    Ok(())
}

#[tokio::test]
async fn try_take_ready_h2_sender_reuses_busy_connection_below_scale_out_threshold() -> Result<()> {
    let slot = test_https_origin_slot();
    let shared = Arc::new(SharedTlsH2OriginConnection {
        sender: spawn_test_h2_sender_with_limits(Some(64), Some(64)).await?,
        upstream_cert: UpstreamCertificateInfo::default(),
        inflight_streams: Arc::new(AtomicUsize::new(63)),
    });
    slot.add_h2_connection(shared.clone());

    let selected = try_take_ready_h2_sender(&slot, "test-upstream")
        .await
        .expect("busy h2 connection should still be reused");
    assert!(Arc::ptr_eq(&selected.0, &shared));
    Ok(())
}

#[tokio::test]
async fn try_take_ready_h2_sender_uses_large_peer_budget_without_premature_scale_out() -> Result<()>
{
    let slot = test_https_origin_slot();
    let shared = Arc::new(SharedTlsH2OriginConnection {
        sender: spawn_test_h2_sender_with_limits(Some(128), Some(128)).await?,
        upstream_cert: UpstreamCertificateInfo::default(),
        inflight_streams: Arc::new(AtomicUsize::new(96)),
    });
    slot.add_h2_connection(shared.clone());

    let selected = try_take_ready_h2_sender(&slot, "test-upstream")
        .await
        .expect("high-budget h2 connection should still be reused");
    assert!(Arc::ptr_eq(&selected.0, &shared));
    Ok(())
}

#[tokio::test]
async fn try_take_ready_h2_sender_prefers_scale_out_for_saturated_connection() -> Result<()> {
    let slot = test_https_origin_slot();
    let shared = Arc::new(SharedTlsH2OriginConnection {
        sender: spawn_test_h2_sender_with_limits(Some(1), Some(1)).await?,
        upstream_cert: UpstreamCertificateInfo::default(),
        inflight_streams: Arc::new(AtomicUsize::new(1)),
    });
    slot.add_h2_connection(shared);

    assert!(slot.can_open_additional_h2_connection());
    assert!(
        try_take_ready_h2_sender(&slot, "test-upstream")
            .await
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn try_take_ready_h2_sender_prefers_reusable_connection_over_saturated_one() -> Result<()> {
    let slot = test_https_origin_slot();
    let saturated = Arc::new(SharedTlsH2OriginConnection {
        sender: spawn_test_h2_sender_with_limits(Some(1), Some(1)).await?,
        upstream_cert: UpstreamCertificateInfo::default(),
        inflight_streams: Arc::new(AtomicUsize::new(1)),
    });
    let reusable = Arc::new(SharedTlsH2OriginConnection {
        sender: spawn_test_h2_sender().await?,
        upstream_cert: UpstreamCertificateInfo::default(),
        inflight_streams: Arc::new(AtomicUsize::new(2)),
    });
    slot.add_h2_connection(saturated);
    slot.add_h2_connection(reusable.clone());

    let selected = try_take_ready_h2_sender(&slot, "test-upstream")
        .await
        .expect("reusable h2 connection should be selected");
    assert!(Arc::ptr_eq(&selected.0, &reusable));
    Ok(())
}
