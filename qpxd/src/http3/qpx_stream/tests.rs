use super::*;
use futures_util::{StreamExt as _, stream};
use http::{Method, Response, StatusCode, header};
use http_body::Frame;
use http_body_util::StreamBody;
use qpx_core::http_message::Response as OwnerResponse;
use qpx_http::body::Body;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

#[derive(Clone)]
struct CaptureStream(mpsc::Sender<qpx_h3::RequestStream>);

impl qpx_h3::RequestHandler for CaptureStream {
    fn settings(&self) -> qpx_h3::Settings {
        qpx_h3::Settings::default()
    }

    async fn handle_request(
        &self,
        _: qpx_h3::Request,
        _: qpx_h3::ConnectionInfo,
        stream: qpx_h3::RequestStream,
    ) -> qpx_h3::H3Result<()> {
        self.0
            .send(stream)
            .await
            .map_err(|_| anyhow!("stream capture closed"))?;
        Ok(())
    }
}

// The caller owns the tasks so setup failures and test timeouts abort them too.
async fn qpx_loopback(
    tasks: &mut tokio::task::JoinSet<()>,
) -> Result<(
    quinn::Endpoint,
    quinn::Connection,
    mpsc::Receiver<qpx_h3::RequestStream>,
)> {
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
    let (tx, rx) = mpsc::channel(1);
    tasks.spawn(async move {
        let incoming = endpoint.accept().await.unwrap();
        qpx_h3::serve_connection(incoming, addr.port(), CaptureStream(tx))
            .await
            .unwrap();
    });
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
    let conn = client.connect(addr, "localhost")?.await?;
    Ok((client, conn, rx))
}

#[tokio::test]
async fn qpx_content_length_mismatches_reset_response_stream_with_message_error() -> Result<()> {
    timeout(Duration::from_secs(5), async {
        // JoinSet aborts the background tasks on success, failure or timeout.
        let mut tasks = tokio::task::JoinSet::new();
        let (_client, conn, mut rx) = qpx_loopback(&mut tasks).await?;
        let (mut connection, mut sender) = ::h3::client::builder()
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
            .await?;
        tasks.spawn(async move {
            let _ = std::future::poll_fn(|cx| connection.poll_close(cx)).await;
        });

        for (overflow, expected_error) in [
            (
                false,
                "qpx-h3 response Content-Length mismatch: expected 4, got 3",
            ),
            (true, "qpx-h3 response body exceeds Content-Length"),
        ] {
            let mut remote = sender
                .send_request(http::Request::get("https://localhost/").body(())?)
                .await?;
            remote.finish().await?;
            let mut local = rx.recv().await.expect("captured QPX request stream");
            let (resume, received_prefix) = oneshot::channel();
            // Do not trigger the mismatch until the prefix is read remotely:
            // QUIC reset is allowed to discard data not yet delivered.
            let tail = stream::once(async move {
                received_prefix.await.expect("client received prefix");
                overflow.then(|| {
                    Ok::<_, qpx_http::body::BodyError>(Frame::data(Bytes::from_static(b"de")))
                })
            })
            .filter_map(std::future::ready);
            let frames = stream::iter([Ok(Frame::data(Bytes::from_static(b"abc")))]).chain(tail);
            let response = OwnerResponse::from_http(
                Response::builder()
                    .header(header::CONTENT_LENGTH, "4")
                    .body(Body::wrap(StreamBody::new(frames)))?,
            );
            let (sent, received) = tokio::join!(
                send_qpx_response_stream_observed(
                    &mut local,
                    response,
                    &Method::GET,
                    H3ResponseSendOptions::unobserved(1024, Duration::from_secs(1)),
                ),
                async {
                    let response = remote.recv_response().await?;
                    assert_eq!(response.status(), StatusCode::OK);
                    assert_eq!(response.headers()[header::CONTENT_LENGTH], "4");
                    let mut prefix = remote.recv_data().await?.expect("in-range prefix");
                    assert_eq!(bytes::Buf::copy_to_bytes(&mut prefix, 3), b"abc".as_slice());
                    assert_eq!(bytes::Buf::remaining(&prefix), 0);
                    resume.send(()).unwrap();
                    // A clean FIN (underflow) or any bytes from the overrun
                    // chunk (including its in-range 'd') must fail this check.
                    let err = remote.recv_data().await.err().expect("remote stream reset");
                    assert!(
                        matches!(err, ::h3::error::StreamError::RemoteTerminate { code, .. }
                            if code == ::h3::error::Code::H3_MESSAGE_ERROR),
                        "expected H3_MESSAGE_ERROR, got {err:?}"
                    );
                    Ok::<_, anyhow::Error>(())
                }
            );
            received?;
            assert_eq!(
                sent.expect_err("mismatched Content-Length must fail")
                    .into_inner()
                    .to_string(),
                expected_error
            );
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn qpx_request_content_length_mismatches_abort_body_relay() -> Result<()> {
    timeout(Duration::from_secs(5), async {
        // JoinSet aborts the background tasks on success, failure or timeout.
        let mut tasks = tokio::task::JoinSet::new();
        let (_client, conn, mut rx) = qpx_loopback(&mut tasks).await?;
        // Keep the control stream open with empty SETTINGS. Use raw Quinn for
        // the request: h3::client::RequestStream does not expose stopped(), and
        // a receive-half abort sends STOP_SENDING, not a response RESET_STREAM.
        let mut control = conn.open_uni().await?;
        control.write_all(&[0x00, 0x04, 0x00]).await?;

        for (overflow, expected_error) in [
            (
                false,
                "qpx-h3 request Content-Length mismatch: expected 4, got 3",
            ),
            (true, "qpx-h3 request body exceeds Content-Length"),
        ] {
            let (mut remote, _response_recv) = conn.open_bi().await?;
            // HEADERS: a static-only QPACK block (zero required insert count
            // and delta base), :method POST, :scheme https, :path /, and a
            // literal :authority localhost (static name index 0).
            // Deliberately omit wire Content-Length: qpx-h3 validates it before
            // the relay; this test isolates the relay's declared length of 4.
            let headers = b"\x00\x00\xd4\xd7\xc1\x50\x09localhost";
            remote.write_all(&[0x01, headers.len() as u8]).await?;
            remote.write_all(headers).await?;
            // DATA frame with an in-range prefix; defer FIN/overrun until the
            // body consumer confirms that the relay forwarded all three bytes.
            remote.write_all(b"\x00\x03abc").await?;
            let local = rx.recv().await.expect("captured QPX request stream");
            let (_response_send, mut local) = local.split();
            let (body_sender, mut body) = Body::channel();
            let (relayed, consumed) = tokio::join!(
                relay_qpx_request_body_observed_from_recv(
                    &mut local,
                    body_sender,
                    QpxRequestBodyRelayOptions {
                        read_timeout: Duration::from_secs(1),
                        max_body_bytes: 1024,
                        declared_content_length: Some(4),
                        grpc_observer: None,
                        listener_name: None,
                        grpc_stream_deadline: None,
                        observe_grpc_messages: false,
                    },
                ),
                async {
                    assert_eq!(
                        body.data().await.expect("relayed prefix")?,
                        b"abc".as_slice()
                    );
                    if overflow {
                        // Leave the send side open so STOP_SENDING is observable.
                        remote.write_all(b"\x00\x02de").await?;
                    } else {
                        remote.finish()?;
                    }
                    // Neither a clean body EOF nor any part of the overrun
                    // chunk (even the in-range 'd') is an acceptable outcome.
                    assert!(body.data().await.expect("body abort").is_err());
                    let stopped = remote.stopped().await?;
                    if overflow {
                        assert_eq!(
                            stopped.map(u64::from),
                            Some(::h3::error::Code::H3_MESSAGE_ERROR.value()),
                            "expected H3_MESSAGE_ERROR STOP_SENDING"
                        );
                    } else {
                        // Quinn cannot stop a receive stream after reading its
                        // FIN: all data has been acknowledged, so no remote
                        // reset/stop code is available for this underflow.
                        assert_eq!(stopped, None, "underflow request was fully received");
                    }
                    Ok::<_, anyhow::Error>(())
                }
            );
            consumed?;
            assert_eq!(
                relayed
                    .expect_err("mismatched Content-Length must fail")
                    .to_string(),
                expected_error
            );
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
