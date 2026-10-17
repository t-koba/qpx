use super::*;
use crate::protocol::{FRAME_HEADERS, read_varint, write_frame};
use crate::qpack::encode_response_head;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

struct Peer {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    _critical: (quinn::SendStream, quinn::SendStream, quinn::SendStream),
}

async fn session_pair() -> anyhow::Result<(ClientSession, Peer)> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let provider = quinn::rustls::crypto::ring::default_provider();
    let mut server_tls =
        quinn::rustls::ServerConfig::builder_with_provider(provider.clone().into())
            .with_protocol_versions(&[&quinn::rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)?;
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls)?));
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = quinn::Endpoint::server(config, addr)?;
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.add(cert)?;
    let mut client_tls = quinn::rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::Endpoint::client(addr)?;
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_tls)?,
    )));
    let (connection, peer) = tokio::try_join!(
        async { Ok::<_, anyhow::Error>(client.connect(server.local_addr()?, "localhost")?.await?) },
        async { Ok::<_, anyhow::Error>(server.accept().await.unwrap().await?) }
    )?;
    let settings = Settings {
        enable_extended_connect: true,
        enable_webtransport: true,
        max_webtransport_sessions: 16,
        read_timeout: TEST_TIMEOUT,
        ..Default::default()
    };
    let critical = open_critical_streams(&peer, &settings).await?;
    let session = ClientSession::new(client, connection, settings, TEST_TIMEOUT).await?;
    Ok((
        session,
        Peer {
            _endpoint: server,
            connection: peer,
            _critical: critical,
        },
    ))
}

fn request() -> http::Request<()> {
    http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://localhost/session")
        .body(())
        .unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Outcome {
    Complete,
    Drop,
    Reject,
    ReadError,
    Cancel,
}

async fn lifecycle(outcome: Outcome) -> anyhow::Result<()> {
    timeout(TEST_TIMEOUT, async {
        let (session, peer) = session_pair().await?;
        let registry = &session.inner.registry;
        let baseline = registry.len();
        assert_eq!(baseline, 0);
        // Repeat on the same session: no connection teardown can hide stale entries.
        for _ in 0..3 {
            let mut open = Box::pin(session.open_extended_connect_stream(
                request(), Some(Protocol::WebTransport), TEST_TIMEOUT,
            ));
            let (mut send, mut recv) = tokio::select! {
                result = &mut open => panic!("open completed before peer response: {:?}", result.err()),
                streams = peer.connection.accept_bi() => streams?,
            };
            assert_eq!(read_varint(&mut recv).await?, Some(FRAME_HEADERS));
            let len = read_varint(&mut recv).await?.unwrap() as usize;
            recv.read_exact(&mut vec![0; len]).await?;
            let id: u64 = recv.id().into();
            assert_eq!(registry.len(), baseline + 1);
            let bidi = registry.bidi_sender(id).unwrap().downgrade();
            let uni = registry.uni_sender(id).unwrap().downgrade();
            // Route both stream types before the response, including for cancelled
            // setup. Wait for actual queueing, not just successful peer writes.
            let mut opener = OpenStreams::new(peer.connection.clone(), TEST_TIMEOUT);
            let _peer_bidi = opener.open_webtransport_bidi(id).await?;
            let _peer_uni = opener.open_webtransport_uni(id).await?;
            {
                let bidi_tx = registry.bidi_sender(id).unwrap();
                let uni_tx = registry.uni_sender(id).unwrap();
                while bidi_tx.capacity() == bidi_tx.max_capacity()
                    || uni_tx.capacity() == uni_tx.max_capacity()
                {
                    tokio::task::yield_now().await;
                }
            }
            if matches!(outcome, Outcome::Cancel) {
                // Drop the actual future, not just its Pin<&mut _> wrapper.
                drop(open);
            } else {
                if matches!(outcome, Outcome::ReadError) {
                    send.reset(quinn::VarInt::from_u32(0x10c))?;
                } else {
                    let status = if matches!(outcome, Outcome::Reject) { 403 } else { 200 };
                    let response = http::Response::builder().status(status).body(())?;
                    write_frame(&mut send, FRAME_HEADERS, &encode_response_head(&response)).await?;
                }
                let result = open.await;
                if matches!(outcome, Outcome::ReadError) {
                    assert!(result.is_err());
                } else {
                    let mut stream = result?;
                    if matches!(outcome, Outcome::Reject) {
                        assert_eq!(stream.response.status(), 403);
                        assert!(stream.associated_bidi.is_none());
                        assert!(stream.associated_uni.is_none());
                        assert_eq!(registry.len(), baseline);
                    } else {
                        assert_eq!(stream.response.status(), 200);
                        assert_eq!(registry.len(), baseline + 1);
                        assert!(stream.associated_bidi.as_mut().unwrap().recv().await.is_some());
                        assert!(stream.associated_uni.as_mut().unwrap().recv().await.is_some());
                        if matches!(outcome, Outcome::Complete) {
                            stream.request_stream.finish().await?;
                            send.finish()?;
                            assert!(stream.request_stream.recv_data().await?.is_none());
                        }
                    }
                    drop(stream);
                }
            }
            assert_eq!(registry.len(), baseline, "{outcome:?}");
            assert!(bidi.upgrade().is_none(), "bidi channel retained: {outcome:?}");
            assert!(uni.upgrade().is_none(), "uni channel retained: {outcome:?}");
            assert_eq!(session.inflight_streams(), 0);
            assert!(session.inner.connection.close_reason().is_none());
        }
        Ok::<_, anyhow::Error>(())
    }).await?
}

#[tokio::test]
async fn registry_released_after_completion() -> anyhow::Result<()> {
    lifecycle(Outcome::Complete).await
}
#[tokio::test]
async fn registry_released_after_stream_drop() -> anyhow::Result<()> {
    lifecycle(Outcome::Drop).await
}
#[tokio::test]
async fn registry_released_after_rejection() -> anyhow::Result<()> {
    lifecycle(Outcome::Reject).await
}
#[tokio::test]
async fn registry_released_after_response_read_error() -> anyhow::Result<()> {
    lifecycle(Outcome::ReadError).await
}
#[tokio::test]
async fn registry_released_after_open_cancellation() -> anyhow::Result<()> {
    lifecycle(Outcome::Cancel).await
}

// This deliberately has no Tokio runtime: cleanup must not spawn an async task.
#[test]
fn stale_registration_does_not_remove_replacement() {
    let registry = Arc::new(ShardedSessionRegistry::new());
    let (bidi_tx, bidi_rx) = mpsc::channel(1);
    let (uni_tx, uni_rx) = mpsc::channel(1);
    let first = registry.register(0, SessionIngress { bidi_tx, uni_tx });
    let (bidi_tx, second_bidi_rx) = mpsc::channel(1);
    let (uni_tx, second_uni_rx) = mpsc::channel(1);
    let second_bidi = bidi_tx.downgrade();
    let second_uni = uni_tx.downgrade();
    let second = registry.register(0, SessionIngress { bidi_tx, uni_tx });
    drop(first);
    assert_eq!(registry.len(), 1);
    assert!(bidi_rx.is_closed());
    assert!(uni_rx.is_closed());
    assert!(
        registry
            .bidi_sender(0)
            .unwrap()
            .same_channel(&second_bidi.upgrade().unwrap())
    );
    assert!(
        registry
            .uni_sender(0)
            .unwrap()
            .same_channel(&second_uni.upgrade().unwrap())
    );
    drop(second);
    assert_eq!(registry.len(), 0);
    assert!(second_bidi_rx.is_closed());
    assert!(second_uni_rx.is_closed());
    assert!(second_bidi.upgrade().is_none());
    assert!(second_uni.upgrade().is_none());
}
