use super::stream::*;
use crate::http::response_carrier::ResponseCarrier;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Response};
use qpx_core::http_message::Response as OwnerResponse;
use qpx_http::body::Body;
use std::time::Duration;

fn response(lengths: &[&str], body: Body) -> Response<Body> {
    let mut response = Response::builder()
        .status(201)
        .version(http::Version::HTTP_2)
        .header("content-type", "text/plain")
        .header("content-type", "application/json")
        .header("etag", HeaderValue::from_bytes(b"\x80").unwrap())
        .header(
            "location",
            HeaderValue::from_bytes("/日本語".as_bytes()).unwrap(),
        )
        .header("authorization", "not-in-preview")
        .body(body)
        .unwrap();
    for length in lengths {
        response
            .headers_mut()
            .append("content-length", HeaderValue::from_str(length).unwrap());
    }
    response
        .headers_mut()
        .get_mut("content-type")
        .unwrap()
        .set_sensitive(true);
    response.extensions_mut().insert(42usize);
    response
}

fn fields(response: &impl ResponseCarrier) -> String {
    let mut out = String::new();
    response.preview_fields(&mut out, |_| true);
    out
}

#[tokio::test]
async fn response_preview_owner_matches_legacy_bytes_and_observed_prefix() {
    for lengths in [&[][..], &["0"], &["+10"], &["10, 10"], &["10", "11"]] {
        let standard = crate::http::body::size::buffer_response_body(
            response(lengths, Body::from("body-prefix")),
            32,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let expected = crate::exporter::serialize_response_preview_async(&standard).await;
        let owner = OwnerResponse::from_http(standard);
        assert_eq!(
            crate::exporter::serialize_response_preview_async(&owner).await,
            expected
        );
        let preview = String::from_utf8(expected).unwrap();
        assert!(preview.starts_with("HTTP/2 201 Created\r\n"));
        assert!(preview.contains("etag: \r\n"));
        assert!(preview.contains("location: \r\n"));
        assert!(preview.ends_with("\r\n\r\nbody-prefix"));
        assert!(!preview.contains("not-in-preview"));
        assert!(
            owner
                .headers()
                .iter()
                .find(|(n, _)| n.as_str() == "content-type")
                .unwrap()
                .1
                .is_sensitive()
        );
        assert_eq!(owner.extensions().get::<usize>(), Some(&42));
    }
}

#[tokio::test]
async fn response_limit_owner_matches_legacy_for_declared_lengths_and_exact_hints() {
    for lengths in [
        &[][..],
        &["0"],
        &["4"],
        &["+10"],
        &["10, 10"],
        &["10", "11"],
    ] {
        for (body, max) in [("abcd", 4), ("abcdefghij", 4), ("", 0)] {
            let mut standard = response(lengths, Body::from(body.to_string()));
            let mut owner =
                OwnerResponse::from_http(response(lengths, Body::from(body.to_string())));
            limit_response_body_to_max_bytes(&mut standard, max);
            limit_response_body_to_max_bytes(&mut owner, max);
            assert_eq!(fields(&owner), fields(&standard));
            assert_eq!(
                owner.headers().declared_content_length(),
                qpx_core::http_content_length::declared_content_length(standard.headers())
            );
            let actual = qpx_http::body::to_bytes(owner.body_mut()).await;
            let expected = qpx_http::body::to_bytes(standard.body_mut()).await;
            assert_eq!(
                actual
                    .as_ref()
                    .map(Bytes::as_ref)
                    .map_err(ToString::to_string),
                expected
                    .as_ref()
                    .map(Bytes::as_ref)
                    .map_err(ToString::to_string)
            );
            assert_eq!(owner.extensions().get::<usize>(), Some(&42));
        }
    }
}

fn streaming_body(abort: bool) -> Body {
    let (mut sender, body) = Body::channel_with_capacity(1);
    tokio::spawn(async move {
        sender.send_data(Bytes::from_static(b"abcd")).await.unwrap();
        if abort {
            sender.abort();
        } else {
            let mut trailers = HeaderMap::new();
            trailers.insert("x-trailer", HeaderValue::from_static("kept"));
            let _ = sender.send_trailers(trailers).await;
        }
    });
    body
}

async fn drain(response: &mut impl ResponseCarrier) -> (Vec<u8>, bool, Option<HeaderMap>) {
    let mut out = Vec::new();
    while let Some(chunk) = response.body_mut().data().await {
        match chunk {
            Ok(chunk) => out.extend_from_slice(&chunk),
            Err(_) => return (out, true, None),
        }
    }
    (out, false, response.body_mut().trailers().await.unwrap())
}

#[tokio::test]
async fn response_limit_owner_matches_legacy_for_streaming_errors_and_trailers() {
    for abort in [false, true] {
        for max in [3, 4] {
            let mut standard = response(&["4"], streaming_body(abort));
            let mut owner = OwnerResponse::from_http(response(&["4"], streaming_body(abort)));
            limit_response_body_to_max_bytes(&mut standard, max);
            limit_response_body_to_max_bytes(&mut owner, max);
            assert_eq!(fields(&owner), fields(&standard));
            assert_eq!(drain(&mut owner).await, drain(&mut standard).await);
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn response_capture_owner_matches_legacy_for_samples_full_errors_and_trailers() {
    use crate::exporter::ExporterSink;
    use qpx_core::config::{ExporterCaptureConfig, ExporterConfig};
    let path = std::env::temp_dir().join(format!(
        "qpx-response-parity-{}-{}.shm",
        std::process::id(),
        qpx_core::exporter::unix_timestamp_nanos()
    ));
    let sink = ExporterSink::from_config(&ExporterConfig {
        enabled: true,
        shm_path: path.to_string_lossy().into_owned(),
        shm_size_mb: 1,
        lossy: true,
        max_queue_events: 32,
        capture: ExporterCaptureConfig {
            plaintext: true,
            encrypted: false,
            max_chunk_bytes: 1024,
            redact: Default::default(),
        },
    })
    .unwrap();
    for sample in [false, true] {
        for abort in [false, true] {
            let standard = response(&["4, 4"], streaming_body(abort));
            let owner = OwnerResponse::from_http(response(&["4, 4"], streaming_body(abort)));
            let wrap = |response, session| {
                if sample {
                    sample_response_body_for_export(response, 2, 1, Duration::from_secs(1), session)
                } else {
                    capture_response_body_for_export(
                        response,
                        2,
                        1,
                        Duration::from_secs(1),
                        session,
                    )
                }
            };
            let mut standard = wrap(standard, sink.session("client", "server"));
            let mut owner = if sample {
                sample_response_body_for_export(
                    owner,
                    2,
                    1,
                    Duration::from_secs(1),
                    sink.session("client", "server"),
                )
            } else {
                capture_response_body_for_export(
                    owner,
                    2,
                    1,
                    Duration::from_secs(1),
                    sink.session("client", "server"),
                )
            };
            assert_eq!(fields(&owner), fields(&standard));
            assert_eq!(owner.status(), standard.status());
            assert_eq!(owner.version(), standard.version());
            assert_eq!(owner.extensions().get::<usize>(), Some(&42));
            let actual = drain(&mut owner).await;
            let expected = drain(&mut standard).await;
            assert_eq!(actual, expected);
            assert_eq!(actual.1, abort);
            if !abort {
                assert_eq!(actual.0, b"abcd");
                assert_eq!(actual.2.unwrap()["x-trailer"], "kept");
            }
        }
    }
    let mut ring = qpx_core::shm_ring::ShmRingBuffer::create_or_open(&path, 1024 * 1024).unwrap();
    for _ in 0..8 {
        tokio::time::timeout(Duration::from_secs(1), ring.wait_for_data())
            .await
            .unwrap()
            .unwrap();
        let event = qpx_core::exporter::CaptureEvent::decode_wire(Bytes::from(
            ring.try_pop().unwrap().unwrap(),
        ))
        .unwrap();
        assert_eq!(event.payload_bytes(), b"ab");
        assert_eq!(
            event.direction,
            qpx_core::exporter::CaptureDirection::ServerToClient
        );
        assert_eq!(
            event.plane,
            qpx_core::exporter::CapturePlane::ClientServerPlaintext
        );
    }
    assert!(ring.try_pop().unwrap().is_none());
    drop(sink);
    ring.unlink_doorbells().unwrap();
    drop(ring);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn response_annotation_owner_preserves_context_extensions_and_policy_tags() {
    use crate::http::dispatch::{
        DispatchAuditContext, DispatchOutcome, ProxyKind, annotate_dispatch_response,
    };
    use qpx_observability::access_log::RequestLogContext;
    let mut config: qpx_core::config::Config = serde_yaml::from_str("edges: []").unwrap();
    config.telemetry.access_log.output.enabled = true;
    let state = crate::runtime::Runtime::new(config).unwrap().state();
    let context = RequestLogContext {
        subject: Some("test-subject".into()),
        matched_rule: Some("rule".into()),
        policy_tags: vec!["base".into()],
        ..Default::default()
    };
    for kind in [ProxyKind::Forward, ProxyKind::Reverse] {
        let audit = DispatchAuditContext::new(
            Some(state.clone()),
            kind,
            Some("forward".into()),
            "127.0.0.1:1234".parse().unwrap(),
            http::Method::GET,
            Some("/".into()),
            context.clone(),
        );
        let mut standard = response(&[], Body::empty());
        let mut owner = OwnerResponse::from_http(response(&[], Body::empty()));
        let tags = vec![" base ".into(), " added ".into(), "".into(), "added".into()];
        annotate_dispatch_response(&mut standard, &audit, DispatchOutcome::Allow, &tags);
        annotate_dispatch_response(&mut owner, &audit, DispatchOutcome::Allow, &tags);
        let actual = owner.extensions().get::<RequestLogContext>().unwrap();
        let expected = standard.extensions().get::<RequestLogContext>().unwrap();
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
        assert_eq!(actual.policy_tags, ["base", "added"]);
        assert_eq!(audit.log_context.policy_tags, ["base"]);
        assert_eq!(owner.extensions().get::<usize>(), Some(&42));
        assert_eq!(fields(&owner), fields(&standard));
    }
}
