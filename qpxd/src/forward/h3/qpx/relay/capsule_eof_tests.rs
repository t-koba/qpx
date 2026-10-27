use super::*;
use std::sync::Arc;
use tokio::sync::mpsc;

const WAIT: Duration = Duration::from_secs(5);

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
            let result = timeout(WAIT, relay).await;
            // Release any blocking file read before asserting (also on timeout).
            drop(peer);
            let result = result??;
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
