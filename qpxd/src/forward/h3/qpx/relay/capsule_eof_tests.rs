use super::*;
#[cfg(unix)]
use std::io::Write;
use std::sync::Arc;
use tokio::sync::mpsc;

const WAIT: Duration = Duration::from_secs(5);
// A clean FIN leaves the opposite direction open, so capsule regressions use
// a short idle deadline instead of the multi-second WAIT bound of assertions.
const RELAY_IDLE: Duration = Duration::from_millis(750);

#[derive(Clone)]
struct CaptureStream(mpsc::Sender<qpx_h3::RequestStream>);

impl qpx_h3::RequestHandler for CaptureStream {
    fn settings(&self) -> qpx_h3::Settings {
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            read_timeout: WAIT,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        _: qpx_h3::Request,
        _: qpx_h3::ConnectionInfo,
        _: qpx_h3::RequestStream,
    ) -> qpx_h3::H3Result<()> {
        panic!("expected CONNECT-IP");
    }

    async fn handle_connect_stream(
        &self,
        _: qpx_core::http_message::Request<()>,
        mut stream: qpx_h3::RequestStream,
        _: qpx_h3::ConnectionInfo,
        _: qpx_h3::Protocol,
        _: Option<qpx_h3::StreamDatagrams>,
    ) -> qpx_h3::H3Result<()> {
        stream
            .send_response_head(
                &http::Response::builder()
                    .status(200)
                    .header("capsule-protocol", "?1")
                    .body(())?,
            )
            .await?;
        self.0
            .send(stream)
            .await
            .map_err(|_| anyhow!("capture closed"))?;
        Ok(())
    }
}

// Actual HTTP/3 streams keep the assertions at the wire boundary: a returned
// relay error alone would not prove that H3_MESSAGE_ERROR reached the sender.
async fn stream_pair() -> Result<(
    qpx_h3::ExtendedConnectStream,
    qpx_h3::RequestStream,
    tokio::task::JoinHandle<()>,
)> {
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let der = cert.cert.der().clone();
    let provider = quinn::rustls::crypto::ring::default_provider();
    let mut tls = quinn::rustls::ServerConfig::builder_with_provider(provider.clone().into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?)),
        "127.0.0.1:0".parse()?,
    )?;
    let addr = endpoint.local_addr()?;
    let (tx, mut rx) = mpsc::channel(1);
    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.unwrap();
        let _ = qpx_h3::serve_connection(incoming, addr.port(), CaptureStream(tx)).await;
    });
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.add(der)?;
    let mut tls = quinn::rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls)?,
    )));
    let conn = timeout(WAIT, endpoint.connect(addr, "localhost")?).await??;
    let client = timeout(
        WAIT,
        qpx_h3::open_extended_connect_stream(
            endpoint,
            conn,
            http::Request::builder()
                .method("CONNECT")
                .uri("https://localhost/ip/")
                .header("capsule-protocol", "?1")
                .body(())?,
            Some(qpx_h3::Protocol::ConnectIp),
            qpx_h3::Settings {
                enable_extended_connect: true,
                enable_datagram: true,
                read_timeout: WAIT,
                ..Default::default()
            },
            WAIT,
        ),
    )
    .await??;
    let stream = timeout(WAIT, rx.recv())
        .await?
        .ok_or_else(|| anyhow!("missing stream"))?;
    Ok((client, stream, server))
}

fn policy() -> ConnectIpPacketPolicy {
    ConnectIpPacketPolicy::new(
        vec!["192.0.2.0/24".parse().unwrap()],
        vec!["198.51.100.0/24".parse().unwrap()],
        1280,
    )
    .unwrap()
}

async fn send_fragmented(stream: &mut qpx_h3::RequestStream, bytes: &[u8]) -> Result<()> {
    for byte in bytes {
        stream.send_data(Bytes::copy_from_slice(&[*byte])).await?;
    }
    Ok(())
}

async fn assert_completion(stream: &mut qpx_h3::RequestStream, malformed: bool) -> Result<()> {
    let result = timeout(WAIT, stream.recv_data()).await?;
    if malformed {
        let code = match result {
            Err(qpx_h3::H3Error::Io(err)) => match err
                .get_ref()
                .and_then(|e| e.downcast_ref::<quinn::ReadError>())
            {
                Some(quinn::ReadError::Reset(code)) => *code,
                other => panic!("expected QUIC reset, got {other:?}"),
            },
            Err(qpx_h3::H3Error::Read(quinn::ReadError::Reset(code))) => code,
            Err(qpx_h3::H3Error::ReadExact(quinn::ReadExactError::ReadError(
                quinn::ReadError::Reset(code),
            ))) => code,
            other => panic!("expected stream reset, got {other:?}"),
        };
        assert_eq!(u64::from(code), 0x10e, "H3_MESSAGE_ERROR");
    } else {
        assert!(result?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn connect_ip_chained_capsule_eof_both_directions() -> Result<()> {
    for from_upstream in [false, true] {
        for residue in [&[][..], &[0x40], &[0, 0x40], &[0, 3, 0, 42]] {
            for prefix in [false, true] {
                let (mut downstream, downstream_stream, downstream_task) = stream_pair().await?;
                let (upstream, mut upstream_peer, upstream_task) = stream_pair().await?;
                let relay =
                    tokio::spawn(relay_qpx_connect_ip_stream_chained(ChainedConnectIpRelay {
                        downstream: downstream_stream,
                        downstream_datagrams: None,
                        upstream: upstream.request_stream,
                        upstream_datagrams: None,
                        downstream_policy: policy(),
                        upstream_policy: policy(),
                        max_capsule_buffer_bytes: 1024,
                        idle_timeout: WAIT,
                    }));
                let (source, destination) = if from_upstream {
                    (&mut upstream_peer, &mut downstream.request_stream)
                } else {
                    (&mut downstream.request_stream, &mut upstream_peer)
                };
                if prefix {
                    // CONNECT-IP preserves unknown capsules when relaying.
                    send_fragmented(source, &[37, 1, 99]).await?;
                    let mut forwarded = Vec::new();
                    while forwarded.len() < 3 {
                        forwarded.extend_from_slice(
                            &timeout(WAIT, destination.recv_data()).await??.unwrap(),
                        );
                    }
                    assert_eq!(forwarded, [37, 1, 99]);
                }
                send_fragmented(source, residue).await?;
                source.finish().await?;
                if residue.is_empty() {
                    // A bidirectional capsule stream completes only after both
                    // receive directions have seen FIN.
                    destination.finish().await?;
                }
                let result = timeout(WAIT, relay).await??;
                assert_eq!(result.is_err(), !residue.is_empty(), "{residue:?}");
                if let Err(err) = result {
                    assert!(err.to_string().contains("incomplete capsule"));
                }
                assert_completion(source, !residue.is_empty()).await?;
                downstream_task.abort();
                upstream_task.abort();
                if let Some(task) = downstream.driver {
                    task.abort();
                }
                if let Some(task) = upstream.driver {
                    task.abort();
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn connect_ip_local_device_capsule_eof() -> Result<()> {
    for residue in [&[][..], &[0x40], &[0, 0x40], &[0, 3, 0, 42]] {
        for prefix in [false, true] {
            let (mut client, stream, server) = stream_pair().await?;
            let (device, peer) = crate::connect_ip::SystemIpDevice::test_pair()?;
            let relay = tokio::spawn(relay_qpx_connect_ip_device(
                stream,
                None,
                device,
                policy(),
                policy(),
                1024,
                WAIT,
            ));
            if prefix {
                send_fragmented(&mut client.request_stream, &[37, 1, 99]).await?;
            }
            send_fragmented(&mut client.request_stream, residue).await?;
            client.request_stream.finish().await?;
            // The client FIN closes only its send direction; the device leg
            // must also end before the relay propagates FIN back to H3.
            drop(peer);
            let result = timeout(WAIT, relay).await??;
            assert_eq!(result.is_err(), !residue.is_empty(), "{residue:?}");
            if let Err(err) = result {
                assert!(err.to_string().contains("incomplete capsule"));
            }
            assert_completion(&mut client.request_stream, !residue.is_empty()).await?;
            server.abort();
            if let Some(task) = client.driver {
                task.abort();
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn connect_ip_chained_partial_capsule_timeout_and_cancellation_are_not_eof() -> Result<()> {
    for cancel in [false, true] {
        let (mut downstream, downstream_stream, downstream_task) = stream_pair().await?;
        let (upstream, _upstream_peer, upstream_task) = stream_pair().await?;
        // No FIN: pending bytes alone do not establish a malformed stream.
        send_fragmented(&mut downstream.request_stream, &[0, 3, 0, 42]).await?;
        if cancel {
            downstream.request_stream.abort_message_stream();
        }
        let result = timeout(
            WAIT,
            relay_qpx_connect_ip_stream_chained(ChainedConnectIpRelay {
                downstream: downstream_stream,
                downstream_datagrams: None,
                upstream: upstream.request_stream,
                upstream_datagrams: None,
                downstream_policy: policy(),
                upstream_policy: policy(),
                max_capsule_buffer_bytes: 1024,
                idle_timeout: Duration::from_millis(100),
            }),
        )
        .await?;
        if cancel {
            let err = result.expect_err("cancelled receive must remain a transport error");
            assert!(!err.to_string().contains("incomplete capsule"));
        } else {
            result?;
            assert_completion(&mut downstream.request_stream, false).await?;
        }
        downstream_task.abort();
        upstream_task.abort();
        if let Some(task) = downstream.driver {
            task.abort();
        }
        if let Some(task) = upstream.driver {
            task.abort();
        }
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn connect_ip_device_partial_capsule_timeout_and_cancellation_are_not_eof() -> Result<()> {
    for cancel in [false, true] {
        let (mut client, stream, server) = stream_pair().await?;
        let (device, peer) = crate::connect_ip::SystemIpDevice::test_pair()?;
        send_fragmented(&mut client.request_stream, &[0, 3, 0, 42]).await?;
        if cancel {
            client.request_stream.abort_message_stream();
        }
        let result = timeout(
            WAIT,
            relay_qpx_connect_ip_device(
                stream,
                None,
                device,
                policy(),
                policy(),
                1024,
                Duration::from_millis(100),
            ),
        )
        .await;
        drop(peer);
        let result = result?;
        if cancel {
            let err = result.expect_err("cancelled receive must remain a transport error");
            assert!(!err.to_string().contains("incomplete capsule"));
        } else {
            result?;
            assert_completion(&mut client.request_stream, false).await?;
        }
        server.abort();
        if let Some(task) = client.driver {
            task.abort();
        }
    }
    Ok(())
}

fn udp_config() -> ConnectUdpConfig {
    ConnectUdpConfig {
        enabled: true,
        idle_timeout_secs: 1,
        max_capsule_buffer_bytes: 1024,
        uri_template: None,
    }
}

async fn send_data_capsule(stream: &mut qpx_h3::RequestStream, payload: &[u8]) -> Result<()> {
    stream
        .send_data(encode_capsule_header(0, payload.len())?)
        .await?;
    if !payload.is_empty() {
        stream.send_data(Bytes::copy_from_slice(payload)).await?;
    }
    Ok(())
}

// Both CONNECT-UDP and CONNECT-IP carry a context ID before the payload.
async fn assert_forwarded_datagram(
    stream: &mut qpx_h3::RequestStream,
    expected: &[u8],
) -> Result<()> {
    let mut capsules = CapsuleBuffer::new();
    loop {
        let chunk = timeout(WAIT, stream.recv_data())
            .await??
            .ok_or_else(|| anyhow!("stream FIN before the peer capsule arrived"))?;
        capsules.push(chunk, 1024)?;
        if let Some((capsule_type, payload)) = capsules.take_next()? {
            assert_eq!(capsule_type, 0);
            assert_eq!(decode_connect_udp_payload(&payload), Some(expected));
            return Ok(());
        }
    }
}

#[tokio::test]
async fn connect_ip_chained_capsule_after_peer_fin_is_forwarded() -> Result<()> {
    let (mut downstream, downstream_stream, downstream_task) = stream_pair().await?;
    let (upstream, mut upstream_peer, upstream_task) = stream_pair().await?;
    let relay = tokio::spawn(relay_qpx_connect_ip_stream_chained(ChainedConnectIpRelay {
        downstream: downstream_stream,
        downstream_datagrams: None,
        upstream: upstream.request_stream,
        upstream_datagrams: None,
        downstream_policy: policy(),
        upstream_policy: policy(),
        max_capsule_buffer_bytes: 1024,
        idle_timeout: RELAY_IDLE,
    }));

    downstream.request_stream.finish().await?;
    // Only the upstream send half gets FIN: the upstream receive leg stays live.
    assert_completion(&mut upstream_peer, false).await?;
    send_fragmented(&mut upstream_peer, &[37, 1, 99]).await?;
    let mut forwarded = Vec::new();
    while forwarded.len() < 3 {
        forwarded.extend_from_slice(
            &timeout(WAIT, downstream.request_stream.recv_data())
                .await??
                .ok_or_else(|| anyhow!("FIN before the post-FIN capsule"))?,
        );
    }
    assert_eq!(forwarded, [37, 1, 99]);

    upstream_peer.finish().await?;
    timeout(WAIT, relay).await???;
    assert_completion(&mut downstream.request_stream, false).await?;
    assert_completion(&mut upstream_peer, false).await?;
    downstream_task.abort();
    upstream_task.abort();
    if let Some(task) = downstream.driver {
        task.abort();
    }
    if let Some(task) = upstream.driver {
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn connect_ip_chained_malformed_residue_at_eof_still_resets() -> Result<()> {
    let (mut downstream, downstream_stream, downstream_task) = stream_pair().await?;
    let (upstream, _upstream_peer, upstream_task) = stream_pair().await?;
    let relay = tokio::spawn(relay_qpx_connect_ip_stream_chained(ChainedConnectIpRelay {
        downstream: downstream_stream,
        downstream_datagrams: None,
        upstream: upstream.request_stream,
        upstream_datagrams: None,
        downstream_policy: policy(),
        upstream_policy: policy(),
        max_capsule_buffer_bytes: 1024,
        idle_timeout: RELAY_IDLE,
    }));

    send_fragmented(&mut downstream.request_stream, &[0, 3, 0, 42]).await?;
    downstream.request_stream.finish().await?;
    let err = timeout(WAIT, relay)
        .await??
        .expect_err("truncated capsule must reset");
    assert!(err.to_string().contains("incomplete capsule"));
    assert_completion(&mut downstream.request_stream, true).await?;
    downstream_task.abort();
    upstream_task.abort();
    if let Some(task) = downstream.driver {
        task.abort();
    }
    if let Some(task) = upstream.driver {
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn connect_ip_chained_one_fin_then_idle_is_not_malformed() -> Result<()> {
    let (mut downstream, downstream_stream, downstream_task) = stream_pair().await?;
    let (upstream, mut upstream_peer, upstream_task) = stream_pair().await?;
    let relay = tokio::spawn(relay_qpx_connect_ip_stream_chained(ChainedConnectIpRelay {
        downstream: downstream_stream,
        downstream_datagrams: None,
        upstream: upstream.request_stream,
        upstream_datagrams: None,
        downstream_policy: policy(),
        upstream_policy: policy(),
        max_capsule_buffer_bytes: 1024,
        idle_timeout: RELAY_IDLE,
    }));

    downstream.request_stream.finish().await?;
    assert_completion(&mut upstream_peer, false).await?;
    timeout(WAIT, relay).await???;
    assert_completion(&mut downstream.request_stream, false).await?;
    downstream_task.abort();
    upstream_task.abort();
    if let Some(task) = downstream.driver {
        task.abort();
    }
    if let Some(task) = upstream.driver {
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn connect_udp_local_response_after_client_fin_is_forwarded() -> Result<()> {
    let (mut client, stream, server) = stream_pair().await?;
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    udp.connect(peer.local_addr()?).await?;
    peer.connect(udp.local_addr()?).await?;
    let relay = tokio::spawn(relay_qpx_connect_udp_stream(
        stream,
        udp,
        udp_config(),
        None,
        RateLimitContext::default(),
        AppliedRateLimits::default(),
    ));

    send_data_capsule(&mut client.request_stream, &[0, b'g', b'o']).await?;
    let mut buf = [0u8; 32];
    let read = timeout(WAIT, peer.recv(&mut buf)).await??;
    assert_eq!(&buf[..read], b"go");

    client.request_stream.finish().await?;
    peer.send(b"after-fin").await?;
    assert_forwarded_datagram(&mut client.request_stream, b"after-fin").await?;

    timeout(WAIT, relay).await???;
    assert_completion(&mut client.request_stream, false).await?;
    server.abort();
    if let Some(task) = client.driver {
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn connect_udp_local_malformed_residue_at_eof_resets() -> Result<()> {
    let (mut client, stream, server) = stream_pair().await?;
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    udp.connect(peer.local_addr()?).await?;
    peer.connect(udp.local_addr()?).await?;
    let relay = tokio::spawn(relay_qpx_connect_udp_stream(
        stream,
        udp,
        udp_config(),
        None,
        RateLimitContext::default(),
        AppliedRateLimits::default(),
    ));

    send_fragmented(&mut client.request_stream, &[0, 3, 0, 42]).await?;
    client.request_stream.finish().await?;
    let err = timeout(WAIT, relay)
        .await??
        .expect_err("truncated capsule must reset");
    assert!(err.to_string().contains("incomplete capsule"));
    assert_completion(&mut client.request_stream, true).await?;
    server.abort();
    if let Some(task) = client.driver {
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn connect_udp_chained_data_after_peer_fin_is_forwarded() -> Result<()> {
    let (mut downstream, downstream_stream, downstream_task) = stream_pair().await?;
    let (upstream, mut upstream_peer, upstream_task) = stream_pair().await?;
    let relay = tokio::spawn(relay_qpx_connect_udp_stream_chained(
        downstream_stream,
        None,
        upstream.request_stream,
        None,
        udp_config(),
        RateLimitContext::default(),
        AppliedRateLimits::default(),
    ));

    downstream.request_stream.finish().await?;
    assert_completion(&mut upstream_peer, false).await?;
    upstream_peer
        .send_data(Bytes::from_static(b"peer-after-fin"))
        .await?;
    let mut forwarded = Vec::new();
    while forwarded.len() < b"peer-after-fin".len() {
        forwarded.extend_from_slice(
            &timeout(WAIT, downstream.request_stream.recv_data())
                .await??
                .ok_or_else(|| anyhow!("FIN before the post-FIN DATA"))?,
        );
    }
    assert_eq!(forwarded, b"peer-after-fin");

    upstream_peer.finish().await?;
    timeout(WAIT, relay).await???;
    assert_completion(&mut downstream.request_stream, false).await?;
    assert_completion(&mut upstream_peer, false).await?;
    downstream_task.abort();
    upstream_task.abort();
    if let Some(task) = downstream.driver {
        task.abort();
    }
    if let Some(task) = upstream.driver {
        task.abort();
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn connect_ip_device_packet_after_client_fin_is_forwarded() -> Result<()> {
    let (mut client, stream, server) = stream_pair().await?;
    let (device, mut peer) = crate::connect_ip::SystemIpDevice::test_pair()?;
    let relay = tokio::spawn(relay_qpx_connect_ip_device(
        stream,
        None,
        device,
        policy(),
        policy(),
        1024,
        Duration::from_secs(1),
    ));

    client.request_stream.finish().await?;
    assert!(
        timeout(
            Duration::from_millis(100),
            client.request_stream.recv_data()
        )
        .await
        .is_err(),
        "client FIN must not end the device direction"
    );
    let packet = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2,
    ];
    peer.write_all(&packet)?;
    assert_forwarded_datagram(&mut client.request_stream, &packet).await?;
    drop(peer);
    timeout(WAIT, relay).await???;
    assert_completion(&mut client.request_stream, false).await?;
    server.abort();
    if let Some(task) = client.driver {
        task.abort();
    }
    Ok(())
}
