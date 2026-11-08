use crate::http3::listener::scheduler::PriorityScheduler;
use crate::http3::listener::*;

#[test]
fn classify_h3_connect_kind_rejects_unknown_extended_connect_protocols() {
    assert_eq!(classify_h3_connect_kind(None), H3ConnectKind::Connect);
    assert_eq!(
        classify_h3_connect_kind(Some(::h3::ext::Protocol::CONNECT_UDP)),
        H3ConnectKind::ConnectUdp
    );
    assert_eq!(
        classify_h3_connect_kind(Some(::h3::ext::Protocol::WEB_TRANSPORT)),
        H3ConnectKind::Extended(::h3::ext::Protocol::WEB_TRANSPORT)
    );
}

#[test]
fn priority_scheduler_prioritizes_urgency_and_non_incremental_work() {
    let mut scheduler = PriorityScheduler::new();
    scheduler.enqueue(
        "low",
        crate::http3::priority::StreamPriority {
            urgency: 7,
            incremental: false,
        },
    );
    scheduler.enqueue(
        "high-incremental",
        crate::http3::priority::StreamPriority {
            urgency: 0,
            incremental: true,
        },
    );
    scheduler.enqueue(
        "high",
        crate::http3::priority::StreamPriority {
            urgency: 0,
            incremental: false,
        },
    );

    assert_eq!(scheduler.next_task(), Some("high"));
    assert_eq!(scheduler.next_task(), Some("high-incremental"));
    assert_eq!(scheduler.next_task(), Some("low"));
    assert_eq!(scheduler.next_task(), None);
}

#[test]
fn priority_scheduler_orders_incremental_work_by_urgency() {
    let mut scheduler = PriorityScheduler::new();
    scheduler.enqueue(
        "u0-a",
        crate::http3::priority::StreamPriority {
            urgency: 0,
            incremental: true,
        },
    );
    scheduler.enqueue(
        "u0-b",
        crate::http3::priority::StreamPriority {
            urgency: 0,
            incremental: true,
        },
    );
    scheduler.enqueue(
        "u7",
        crate::http3::priority::StreamPriority {
            urgency: 7,
            incremental: true,
        },
    );

    assert_eq!(scheduler.next_task(), Some("u0-a"));
    assert_eq!(scheduler.next_task(), Some("u0-b"));
    assert_eq!(scheduler.next_task(), Some("u7"));
    assert_eq!(scheduler.next_task(), None);
}

#[test]
fn h3_field_section_cap_matches_edge_caps() {
    assert_eq!(
        super::connection::H3_MAX_FIELD_SECTION_SIZE as usize,
        crate::http::codec::h1_common::MAX_HEADER_BYTES,
        "H3 pre-decode cap must stay aligned with the H1 edge cap",
    );
    assert_eq!(
        super::connection::H3_MAX_FIELD_SECTION_SIZE,
        crate::http::codec::h2::H2_MAX_HEADER_LIST_SIZE as u64,
        "H3 pre-decode cap must stay aligned with the H2 transport cap",
    );
}

#[derive(Clone)]
struct CountLimitSelections(Arc<std::sync::atomic::AtomicUsize>);

#[async_trait]
impl H3RequestHandler for CountLimitSelections {
    type Response = Response<Body>;

    fn limits(&self) -> H3Limits {
        H3Limits {
            listener_name: "preflight-test".into(),
            max_concurrent_streams_per_connection: 1,
            datagram_channel_capacity: 1,
            streaming: ResolvedStreamingLimits {
                body_channel_capacity: 1,
                body_read_timeout_ms: 1000,
                body_send_timeout_ms: 1000,
                max_request_body_bytes: 1024,
                max_response_body_bytes: 1024,
                max_grpc_message_bytes: 1024,
                max_grpc_web_trailer_bytes: 1024,
                max_grpc_stream_duration_ms: 0,
                observe_grpc_messages: false,
                sse: Default::default(),
            },
            request_body_drain: H3RequestBodyDrainControl {
                config: Default::default(),
                semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
            },
            read_timeout: Duration::from_secs(5),
            proxy_name: "qpx-test".into(),
            error_body: "error".into(),
        }
    }

    fn request_streaming_limits(
        &self,
        _: &Request<()>,
        _: &H3ConnInfo,
        fallback: ResolvedStreamingLimits,
    ) -> ResolvedStreamingLimits {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        fallback
    }

    async fn handle_http(&self, _: Request<Body>, _: H3ConnInfo) -> Self::Response {
        Response::new(Body::empty())
    }

    async fn handle_connect(
        &self,
        _: Request<()>,
        _: H3ServerRequestStream,
        _: H3ConnInfo,
        _: H3ConnectKind,
        _: Option<H3StreamDatagrams>,
    ) -> Result<()> {
        panic!("ordinary request must not enter CONNECT handling")
    }
}

// Keep both endpoints alive for the caller's streams; callers own background tasks.
async fn h3_loopback() -> Result<(
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    quinn::Connection,
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
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.add(der)?;
    let mut tls = quinn::rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls)?,
    )));
    let (server_conn, client_conn) = tokio::try_join!(
        async {
            Ok::<_, anyhow::Error>(
                endpoint
                    .accept()
                    .await
                    .expect("incoming connection")
                    .await?,
            )
        },
        async { Ok::<_, anyhow::Error>(client.connect(addr, "localhost")?.await?) },
    )?;
    Ok((endpoint, client, server_conn, client_conn))
}

#[tokio::test]
async fn invalid_authority_rejected_before_streaming_limit_selection() -> Result<()> {
    use bytes::Bytes;
    use std::sync::atomic::{AtomicUsize, Ordering};

    tokio::time::timeout(Duration::from_secs(5), async {
        let (endpoint, _client, conn, client_conn) = h3_loopback().await?;
        let dst_port = endpoint.local_addr()?.port();
        let mut tasks = tokio::task::JoinSet::new();
        let selections = Arc::new(AtomicUsize::new(0));
        let handler = CountLimitSelections(selections.clone());
        tasks.spawn(async move {
            let info = H3ConnInfo {
                remote_addr: conn.remote_address(),
                dst_port,
                tls_sni: None,
                peer_certificates: None,
            };
            let mut h3_conn = ::h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(conn))
                .await
                .unwrap();
            while let Some(resolver) = h3_conn.accept().await.unwrap() {
                let (head, stream) = resolver.resolve_request().await.unwrap();
                handle_stream(
                    head,
                    stream,
                    info.clone(),
                    handler.clone(),
                    handler.limits(),
                    None,
                    None,
                )
                .await;
            }
        });
        let (mut connection, mut sender) = ::h3::client::builder()
            .build::<_, _, Bytes>(h3_quinn::Connection::new(client_conn))
            .await?;
        tasks.spawn(async move {
            let _ = std::future::poll_fn(|cx| connection.poll_close(cx)).await;
        });

        // http::Uri (and the H3 decoder) accept userinfo, but qpx must stop it
        // before the handler can inspect request-specific rules/routes.
        let mut stream = sender
            .send_request(::http::Request::get("https://user@localhost/").body(())?)
            .await?;
        stream.finish().await?;
        let response = stream.recv_response().await;
        assert_eq!(selections.load(Ordering::SeqCst), 0);
        let err = response.expect_err("malformed authority");
        assert!(
            matches!(err, ::h3::error::StreamError::RemoteTerminate { code, .. }
                if code == ::h3::error::Code::H3_MESSAGE_ERROR),
            "expected H3_MESSAGE_ERROR, got {err:?}"
        );

        // A valid request on the same connection does reach limit selection.
        let mut stream = sender
            .send_request(::http::Request::get("https://localhost/").body(())?)
            .await?;
        stream.finish().await?;
        assert_eq!(stream.recv_response().await?.status(), http::StatusCode::OK);
        assert_eq!(selections.load(Ordering::SeqCst), 1);
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn standard_h3_request_content_length_mismatches_fail_reads_and_drains() -> Result<()> {
    use bytes::Bytes;

    tokio::time::timeout(Duration::from_secs(5), async {
        let (_endpoint, _client, server_conn, conn) = h3_loopback().await?;
        let mut tasks = tokio::task::JoinSet::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tasks.spawn(async move {
            let mut connection = ::h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(server_conn))
                .await
                .unwrap();
            while let Some(resolver) = connection.accept().await.unwrap() {
                tx.send(resolver.resolve_request().await.unwrap())
                    .await
                    .unwrap();
            }
        });
        // Raw Quinn exposes STOP_SENDING via stopped(), unlike h3's client API.
        // Keep an empty SETTINGS control stream open for the connection.
        let mut control = conn.open_uni().await?;
        control.write_all(&[0x00, 0x04, 0x00]).await?;

        for drain in [false, true] {
            for (overflow, expected_error) in [
                (
                    false,
                    "HTTP/3 request Content-Length mismatch: expected 4, got 3",
                ),
                (true, "HTTP/3 request body exceeds Content-Length"),
            ] {
                let (mut remote, _response) = conn.open_bi().await?;
                // Static-only QPACK: POST, https, /, :authority localhost,
                // and content-length: 4 (literal using static name index 4).
                let headers = b"\x00\x00\xd4\xd7\xc1\x50\x09localhost\x54\x014";
                remote.write_all(&[0x01, headers.len() as u8]).await?;
                remote.write_all(headers).await?;
                remote.write_all(b"\x00\x03abc").await?;
                let (head, stream) = rx.recv().await.expect("decoded standard H3 request");
                assert_eq!(head.headers()[http::header::CONTENT_LENGTH], "4");
                let (_send, recv) = stream.split();
                let (mut body, completion) = h3_incoming_body(
                    recv,
                    H3IncomingBodyOptions {
                        read_timeout: Duration::from_secs(1),
                        max_body_bytes: 1024,
                        declared_content_length: Some(
                            head.headers()[http::header::CONTENT_LENGTH]
                                .to_str()?
                                .parse()?,
                        ),
                        grpc_observer: None,
                        listener_name: Arc::from("length-test"),
                        grpc_stream_deadline: None,
                        observe_grpc_messages: false,
                        drain_control: H3RequestBodyDrainControl {
                            config: Default::default(),
                            semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
                        },
                    },
                );
                // Defer FIN/overrun until the prefix is consumed so the drain
                // also has to preserve the partially read body's byte count.
                assert_eq!(body.data().await.expect("body prefix")?, b"abc".as_slice());
                if overflow {
                    remote.write_all(b"\x00\x02de").await?;
                }
                remote.finish()?;
                // Wait for FIN acknowledgement before polling the body again.
                // Open-send overflow currently panics in h3-quinn 0.0.10's
                // stop_sending after its lookahead leaves a pending read.
                // This test covers fully received mismatches, not that defect.
                assert_eq!(remote.stopped().await?, None, "request FIN acknowledged");
                if drain {
                    drop(body);
                } else {
                    // The h3 codec delivers the mismatched wire body to qpx:
                    // these are qpx's length errors, not a codec error wrapper.
                    assert_eq!(
                        body.data()
                            .await
                            .expect("body error")
                            .unwrap_err()
                            .to_string(),
                        expected_error,
                    );
                    assert!(
                        body.data().await.is_none(),
                        "body must stay terminal after its error"
                    );
                }
                assert_eq!(
                    completion.finish().await.unwrap_err().to_string(),
                    expected_error
                );
                // The body abort cannot expose a STOP_SENDING code once FIN
                // and all request bytes have been received by Quinn.
                assert_eq!(
                    remote.stopped().await?,
                    None,
                    "finished request (drain={drain})"
                );
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
