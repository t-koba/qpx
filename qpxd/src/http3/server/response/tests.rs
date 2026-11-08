use super::*;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Version, header};

#[test]
fn owned_h3_head_matches_standard_preparation() {
    for method in [Method::GET, Method::HEAD, Method::CONNECT] {
        for status in [200, 204, 205, 304] {
            for values in [
                vec![],
                vec!["0"],
                vec!["7"],
                vec!["007", "7"],
                vec!["7, 007"],
                vec!["bad"],
                vec![""],
                vec!["1", "2"],
                vec!["18446744073709551616"],
            ] {
                let mut response = Response::builder()
                    .status(status)
                    .version(Version::HTTP_3)
                    .body(Body::empty())
                    .unwrap();
                for value in &values {
                    response.headers_mut().append(
                        header::CONTENT_LENGTH,
                        HeaderValue::from_str(value).unwrap(),
                    );
                }
                response.headers_mut().insert(
                    header::TRANSFER_ENCODING,
                    HeaderValue::from_static("chunked"),
                );
                response
                    .headers_mut()
                    .insert(header::TRAILER, HeaderValue::from_static("x-end"));
                for bytes in [b"first".as_slice(), b"opaque-\xff"] {
                    let mut value = HeaderValue::from_bytes(bytes).unwrap();
                    value.set_sensitive(true);
                    response.headers_mut().append(header::SET_COOKIE, value);
                }
                response.extensions_mut().insert(42usize);
                let (parts, body) = response.into_parts();
                let expected = prepare_h3_response_head(&parts, &method).unwrap();
                let exported = export_h3_response_for_codec(OwnerResponse::from_http(
                    Response::from_parts(parts, body),
                ))
                .unwrap();
                assert_eq!(exported.version(), Version::HTTP_3);
                assert_eq!(exported.extensions().get::<usize>(), Some(&42));
                let (parts, _) = exported.into_parts();
                let actual = prepare_h3_response_head(&parts, &method).unwrap();
                assert_eq!(actual.body_allowed, expected.body_allowed);
                assert_eq!(actual.content_length, expected.content_length);
                assert_eq!(actual.head.status(), expected.head.status());
                assert_eq!(actual.head.version(), expected.head.version());
                // These are the exact header fields passed to H3's HEADERS
                // encoder, including per-name duplicate order and opaque bytes.
                assert_eq!(actual.head.headers(), expected.head.headers());
                let cookies = actual
                    .head
                    .headers()
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .collect::<Vec<_>>();
                assert_eq!(cookies.len(), 2);
                assert_eq!(cookies[0].as_bytes(), b"first");
                assert_eq!(cookies[1].as_bytes(), b"opaque-\xff");
                assert!(cookies.iter().all(|value| value.is_sensitive()));
            }
        }
    }
}

#[tokio::test]
async fn static_h3_local_owner_matches_standard_finalization() {
    use http_body_util::BodyExt as _;

    for method in [Method::GET, Method::HEAD] {
        for status in [StatusCode::BAD_REQUEST, StatusCode::PAYLOAD_TOO_LARGE] {
            let body = b"static rejection";
            let actual = finalized_h3_static_response(status, body, &method, "edge")
                .expect("owner-backed static response")
                .into_http_for_library();
            let expected = finalize_response_for_request(
                &method,
                Version::HTTP_3,
                "edge",
                Response::builder()
                    .status(status)
                    .body(Body::from(body.to_vec()))
                    .expect("standard static response"),
                false,
            );

            assert_eq!(actual.status(), expected.status());
            assert_eq!(actual.version(), Version::HTTP_11);
            assert_eq!(actual.version(), expected.version());
            assert!(actual.headers().contains_key(header::DATE));
            assert!(expected.headers().contains_key(header::DATE));
            let mut actual_headers = actual.headers().clone();
            let mut expected_headers = expected.headers().clone();
            actual_headers.remove(header::DATE);
            expected_headers.remove(header::DATE);
            assert_eq!(actual_headers, expected_headers);
            assert_eq!(
                actual.into_body().collect().await.unwrap().to_bytes(),
                expected.into_body().collect().await.unwrap().to_bytes(),
            );
        }
    }
}

#[tokio::test]
async fn owned_h3_export_preserves_lazy_body_trailers_and_errors() {
    use futures_util::{StreamExt as _, stream};
    use http_body::Frame;
    use http_body_util::StreamBody;
    use qpx_http::body::BodyError;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    for fail in [false, true] {
        let polls = Arc::new(AtomicUsize::new(0));
        let polled = polls.clone();
        let mut trailers = HeaderMap::new();
        trailers.append("x-end", HeaderValue::from_static("one"));
        trailers.append("x-end", HeaderValue::from_static("two"));
        let last = if fail {
            Err(BodyError::new("test body error"))
        } else {
            Ok(Frame::trailers(trailers.clone()))
        };
        let frames =
            stream::iter([Ok(Frame::data(Bytes::from_static(b"abc"))), last]).inspect(move |_| {
                polled.fetch_add(1, Ordering::SeqCst);
            });
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Body::wrap(StreamBody::new(frames)))
            .unwrap();
        let mut body = export_h3_response_for_codec(OwnerResponse::from_http(response))
            .unwrap()
            .into_body();
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(body.data().await.unwrap().unwrap(), b"abc".as_slice());
        if fail {
            assert_eq!(
                body.data().await.unwrap().unwrap_err().to_string(),
                "test body error"
            );
        } else {
            assert!(body.data().await.is_none());
            assert_eq!(body.trailers().await.unwrap(), Some(trailers));
        }
    }
}

#[tokio::test]
async fn content_length_mismatches_reset_response_stream_with_message_error() -> Result<()> {
    use futures_util::{StreamExt as _, stream};
    use http_body::Frame;
    use http_body_util::StreamBody;
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;

    tokio::time::timeout(Duration::from_secs(5), async {
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
        let resume_body = Arc::new(tokio::sync::Notify::new());
        let resume_server_body = resume_body.clone();
        let (errors_tx, mut errors_rx) = tokio::sync::mpsc::channel(1);
        let server = tokio::spawn(async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            let mut connection = ::h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(conn))
                .await
                .unwrap();
            for overflow in [false, true] {
                let resolver = connection.accept().await.unwrap().unwrap();
                let (_, mut request_stream) = resolver.resolve_request().await.unwrap();
                let resume = resume_server_body.clone();
                // Wait until the client has received the in-range prefix. The
                // next poll either ends the body early or supplies an overrun.
                let tail = stream::once(async move {
                    resume.notified().await;
                    overflow.then(|| {
                        Ok::<_, qpx_http::body::BodyError>(Frame::data(Bytes::from_static(b"de")))
                    })
                })
                .filter_map(std::future::ready);
                let frames =
                    stream::iter([Ok(Frame::data(Bytes::from_static(b"abc")))]).chain(tail);
                let response = OwnerResponse::from_http(
                    Response::builder()
                        .header(header::CONTENT_LENGTH, "4")
                        .body(Body::wrap(StreamBody::new(frames)))
                        .unwrap(),
                );
                let err = send_h3_response_observed(
                    response,
                    &Method::GET,
                    &mut request_stream,
                    H3ResponseSendOptions::unobserved(1024, Duration::from_secs(1)),
                )
                .await
                .expect_err("mismatched Content-Length must fail");
                errors_tx.send(err.into_inner().to_string()).await.unwrap();
            }
            // Keep the connection alive and driven until the client has seen
            // the last stream reset, rather than closing it with the endpoint.
            let _ = connection.accept().await;
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
        let (mut connection, mut sender) = ::h3::client::builder()
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
            .await?;
        let driver =
            tokio::spawn(async move { std::future::poll_fn(|cx| connection.poll_close(cx)).await });

        for expected_error in [
            "HTTP/3 response Content-Length mismatch: expected 4, got 3",
            "HTTP/3 response body exceeds Content-Length",
        ] {
            let mut request_stream = sender
                .send_request(http::Request::get("https://localhost/").body(())?)
                .await?;
            request_stream.finish().await?;
            let response = request_stream.recv_response().await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_LENGTH], "4");
            let mut prefix = request_stream.recv_data().await?.unwrap();
            assert_eq!(bytes::Buf::copy_to_bytes(&mut prefix, 3), b"abc".as_slice());
            assert_eq!(bytes::Buf::remaining(&prefix), 0);
            resume_body.notify_one();
            // Neither a clean FIN (underflow) nor the excessive chunk
            // (overflow) may reach the client: both are remote stream resets.
            let err = request_stream
                .recv_data()
                .await
                .err()
                .expect("stream reset");
            assert!(
                matches!(err, ::h3::error::StreamError::RemoteTerminate { code, .. }
                    if code == ::h3::error::Code::H3_MESSAGE_ERROR),
                "expected H3_MESSAGE_ERROR, got {err:?}"
            );
            assert_eq!(errors_rx.recv().await.as_deref(), Some(expected_error));
        }
        driver.abort();
        server.abort();
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
