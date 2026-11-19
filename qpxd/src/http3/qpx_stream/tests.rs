use super::*;
use futures_util::{StreamExt as _, stream};
use http::{Method, Response, StatusCode, header};
use http_body::Frame;
use http_body_util::StreamBody;
use qpx_core::http_message::Response as OwnerResponse;
use qpx_http::body::Body;
use tokio::sync::{mpsc, oneshot};

use super::request_body::{RequestBodyDeadlineControl, RequestBodySendEvent, RequestBodySendProbe};

use super::test_support::qpx_loopback;

#[tokio::test]
async fn qpx_content_length_mismatches_reset_response_stream_with_message_error() -> Result<()> {
    timeout(Duration::from_secs(5), async {
        // JoinSet aborts the background tasks on success, failure or timeout.
        let mut tasks = tokio::task::JoinSet::new();
        let (_client, conn, mut rx) = qpx_loopback(&mut tasks, None).await?;
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
                    H3ResponseSendOptions::unobserved_with_timeouts(
                        1024,
                        Duration::from_secs(1),
                        Duration::from_secs(1),
                    ),
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
        let (_client, conn, mut rx) = qpx_loopback(&mut tasks, None).await?;
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
                        request_body_deadline: None,
                        observe_grpc_messages: false,
                        send_probe: None,
                    }
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

#[tokio::test]
async fn request_body_relay_deadline_stops_trickle_after_consumer_closes() -> Result<()> {
    timeout(Duration::from_secs(5), async {
        let mut tasks = tokio::task::JoinSet::new();
        let (_client, conn, mut rx) = qpx_loopback(&mut tasks, None).await?;
        let mut control = conn.open_uni().await?;
        control.write_all(&[0x00, 0x04, 0x00]).await?;

        let (mut remote, _response_recv) = conn.open_bi().await?;
        let headers = b"\x00\x00\xd4\xd7\xc1\x50\x09localhost";
        remote.write_all(&[0x01, headers.len() as u8]).await?;
        remote.write_all(headers).await?;

        let local = rx.recv().await.expect("captured QPX request stream");
        let (_response_send, mut local) = local.split();
        let (body_sender, mut body) = Body::channel();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let relay = tokio::spawn(async move {
            relay_qpx_request_body_observed_from_recv(
                &mut local,
                body_sender,
                QpxRequestBodyRelayOptions {
                    read_timeout: Duration::from_secs(2),
                    max_body_bytes: 1024,
                    declared_content_length: None,
                    grpc_observer: None,
                    listener_name: None,
                    grpc_stream_deadline: None,
                    request_body_deadline: Some(deadline),
                    observe_grpc_messages: false,
                    send_probe: None,
                },
            )
            .await
        });

        // Prime the relay and drop its consumer, as when an upstream response
        // closes the request-body channel before the client finishes uploading.
        remote.write_all(b"\x00\x01x").await?;
        assert_eq!(
            timeout(Duration::from_secs(1), body.data())
                .await?
                .expect("initial relayed data")?,
            Bytes::from_static(b"x")
        );
        drop(body);

        // Keep trickling inside the 2s idle timeout. The shorter absolute body
        // deadline must win and abort the H3 message stream anyway.
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if remote.write_all(b"\x00\x01x").await.is_err() {
                break;
            }
        }
        let error = timeout(Duration::from_secs(2), relay)
            .await??
            .expect_err("absolute request-body deadline must stop the trickle");
        assert_eq!(
            error.to_string(),
            "qpx-h3 request body duration exceeded configured limit"
        );
        assert_eq!(
            remote.stopped().await?.map(u64::from),
            Some(::h3::error::Code::H3_MESSAGE_ERROR.value())
        );
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
#[tokio::test]
async fn request_body_relay_deadline_stops_blocked_send() -> Result<()> {
    timeout(Duration::from_secs(5), async {
        let mut tasks = tokio::task::JoinSet::new();
        let (_client, conn, mut rx) = qpx_loopback(&mut tasks, None).await?;
        let mut control = conn.open_uni().await?;
        control.write_all(&[0x00, 0x04, 0x00]).await?;

        let (mut remote, _response_recv) = conn.open_bi().await?;
        let headers = b"\x00\x00\xd4\xd7\xc1\x50\x09localhost";
        remote.write_all(&[0x01, headers.len() as u8]).await?;
        remote.write_all(headers).await?;

        let local = rx.recv().await.expect("captured QPX request stream");
        let (_response_send, mut local) = local.split();
        // Keep the consumer alive but never drain it. With capacity 1, the
        // first forwarded DATA frame fills the channel and the second blocks
        // in sender.send_data, so only the configured request-body deadline
        // can end the relay; the read-side idle/deadline path is not waiting
        // here. The test drives the injected timer in the production deadline
        // arm after observing backpressure, and asserts the recorded Instant
        // below instead of racing a wall-clock deadline.
        let (body_sender, _undrained_body) = Body::channel_with_capacity(1);
        let (probe_tx, mut events) = mpsc::unbounded_channel();
        let deadline = Instant::now() + Duration::from_secs(3600);
        let control = RequestBodyDeadlineControl::new();
        let control_for_relay = control.clone();
        let relay = tokio::spawn(async move {
            relay_qpx_request_body_observed_from_recv(
                &mut local,
                body_sender,
                QpxRequestBodyRelayOptions {
                    read_timeout: Duration::from_secs(3),
                    max_body_bytes: 1024,
                    declared_content_length: None,
                    grpc_observer: None,
                    listener_name: None,
                    grpc_stream_deadline: None,
                    request_body_deadline: Some(deadline),
                    observe_grpc_messages: false,
                    send_probe: Some(RequestBodySendProbe {
                        events: probe_tx,
                        deadline_control: Some(control_for_relay),
                    }),
                },
            )
            .await
        });

        remote.write_all(b"\x00\x01x").await?;
        assert_eq!(
            timeout(Duration::from_secs(1), events.recv())
                .await?
                .expect("send probe alive"),
            RequestBodySendEvent::DataAccepted
        );
        remote.write_all(b"\x00\x01y").await?;
        assert_eq!(
            timeout(Duration::from_secs(1), events.recv())
                .await?
                .expect("send probe alive"),
            RequestBodySendEvent::DataSendPending
        );
        // Negative control: the relay is blocked on the full body channel and
        // must still be running before the configured deadline can fire.
        assert!(
            !relay.is_finished(),
            "relay finished before the blocked-send deadline fired"
        );

        // The blocked send is observed and still running; fire the injected
        // production deadline-arm timer now, without waiting for the far-future Instant.
        control.fire();
        let error = timeout(Duration::from_secs(3), relay)
            .await??
            .expect_err("absolute deadline must stop a blocked body send");
        assert_eq!(
            error.to_string(),
            "qpx-h3 request body duration exceeded configured limit"
        );
        control.assert_recorded(Some(deadline));
        assert_eq!(
            remote.stopped().await?.map(u64::from),
            Some(::h3::error::Code::H3_MESSAGE_ERROR.value())
        );
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
#[tokio::test]
async fn request_body_relay_deadline_stops_blocked_trailer_send() -> Result<()> {
    timeout(Duration::from_secs(5), async {
        let mut tasks = tokio::task::JoinSet::new();
        let (_client, conn, mut rx) = qpx_loopback(&mut tasks, None).await?;
        let mut control = conn.open_uni().await?;
        control.write_all(&[0x00, 0x04, 0x00]).await?;

        let (mut remote, _response_recv) = conn.open_bi().await?;
        let headers = b"\x00\x00\xd4\xd7\xc1\x50\x09localhost";
        remote.write_all(&[0x01, headers.len() as u8]).await?;
        remote.write_all(headers).await?;

        let local = rx.recv().await.expect("captured QPX request stream");
        let (_response_send, mut local) = local.split();
        // Keep the consumer alive but undrained so the single data frame fills
        // the channel and the subsequent trailer send blocks. QPACK literal
        // "x-end: done": header prefix 00 00, literal name len 5 then name,
        // literal value len 4 then value.
        let trailers = b"\x00\x00\x25x-end\x04done";
        let (body_sender, _undrained_body) = Body::channel_with_capacity(1);
        let (probe_tx, mut events) = mpsc::unbounded_channel();
        // Far-future real deadline: only the injected production deadline-arm
        // timer can release the blocked trailer send in this test.
        let deadline = Instant::now() + Duration::from_secs(3600);
        let control = RequestBodyDeadlineControl::new();
        let control_for_relay = control.clone();
        let relay = tokio::spawn(async move {
            relay_qpx_request_body_observed_from_recv(
                &mut local,
                body_sender,
                QpxRequestBodyRelayOptions {
                    read_timeout: Duration::from_secs(3),
                    max_body_bytes: 1024,
                    declared_content_length: None,
                    grpc_observer: None,
                    listener_name: None,
                    grpc_stream_deadline: None,
                    request_body_deadline: Some(deadline),
                    observe_grpc_messages: false,
                    send_probe: Some(RequestBodySendProbe {
                        events: probe_tx,
                        deadline_control: Some(control_for_relay),
                    }),
                },
            )
            .await
        });

        remote.write_all(b"\x00\x01x").await?;
        assert_eq!(
            timeout(Duration::from_secs(1), events.recv())
                .await?
                .expect("send probe alive"),
            RequestBodySendEvent::DataAccepted
        );
        // A second HEADERS frame (0x01) carries trailer fields, then FIN ends data.
        remote.write_all(&[0x01, trailers.len() as u8]).await?;
        remote.write_all(trailers).await?;
        remote.finish()?;
        assert_eq!(
            timeout(Duration::from_secs(1), events.recv())
                .await?
                .expect("send probe alive"),
            RequestBodySendEvent::TrailerSendPending
        );
        // Negative control: the relay is blocked on the full body channel and
        // must still be running before the configured deadline can fire.
        assert!(
            !relay.is_finished(),
            "relay finished before the blocked-trailer deadline fired"
        );

        control.fire();
        let error = timeout(Duration::from_secs(3), relay)
            .await??
            .expect_err("absolute deadline must stop a blocked trailer send");
        assert_eq!(
            error.to_string(),
            "qpx-h3 request body duration exceeded configured limit"
        );
        control.assert_recorded(Some(deadline));
        // The client has already FIN'd this stream, so STOP_SENDING is not
        // observable here; the blocked-send deadline error is the assertion.
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn request_body_relay_without_deadline_stays_blocked_on_full_channel() -> Result<()> {
    timeout(Duration::from_secs(5), async {
        let mut tasks = tokio::task::JoinSet::new();
        let (_client, conn, mut rx) = qpx_loopback(&mut tasks, None).await?;
        let mut control = conn.open_uni().await?;
        control.write_all(&[0x00, 0x04, 0x00]).await?;

        let (mut remote, _response_recv) = conn.open_bi().await?;
        let headers = b"\x00\x00\xd4\xd7\xc1\x50\x09localhost";
        remote.write_all(&[0x01, headers.len() as u8]).await?;
        remote.write_all(headers).await?;

        let local = rx.recv().await.expect("captured QPX request stream");
        let (_response_send, mut local) = local.split();
        // Same undrained body channel and backpressure as the positive
        // blocked-send test, but neither deadline is configured. Driving the
        // same in-memory control must not release the blocked send: with no
        // deadline there is no production deadline arm to drive.
        let (body_sender, _undrained_body) = Body::channel_with_capacity(1);
        let (probe_tx, mut events) = mpsc::unbounded_channel();
        let control = RequestBodyDeadlineControl::new();
        let control_for_relay = control.clone();
        let relay = tokio::spawn(async move {
            relay_qpx_request_body_observed_from_recv(
                &mut local,
                body_sender,
                QpxRequestBodyRelayOptions {
                    read_timeout: Duration::from_secs(3),
                    max_body_bytes: 1024,
                    declared_content_length: None,
                    grpc_observer: None,
                    listener_name: None,
                    grpc_stream_deadline: None,
                    request_body_deadline: None,
                    observe_grpc_messages: false,
                    send_probe: Some(RequestBodySendProbe {
                        events: probe_tx,
                        deadline_control: Some(control_for_relay),
                    }),
                },
            )
            .await
        });

        remote.write_all(b"\x00\x01x").await?;
        assert_eq!(
            timeout(Duration::from_secs(1), events.recv())
                .await?
                .expect("send probe alive"),
            RequestBodySendEvent::DataAccepted
        );
        remote.write_all(b"\x00\x01y").await?;
        assert_eq!(
            timeout(Duration::from_secs(1), events.recv())
                .await?
                .expect("send probe alive"),
            RequestBodySendEvent::DataSendPending
        );
        control.fire();
        tokio::task::yield_now().await;
        assert!(
            !relay.is_finished(),
            "firing the control released a send with no deadline configured"
        );
        control.assert_recorded(None);
        relay.abort();
        let _ = relay.await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
