//! External coverage: only qpxd's opaque module streaming types are available here.
use bytes::Bytes;
use http::{HeaderName, HeaderValue, StatusCode};
use qpxd::module_api::{Body, BodyError, BodyFrame, HttpModuleResponse, Trailers};
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll, Wake, Waker};

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn application_metadata_view_preserves_bytes_duplicates_and_hides_protocol_fields() {
    let application = HeaderName::from_static("x-app-metadata");
    let mut trailers = Trailers::new();
    trailers.append(
        application.clone(),
        HeaderValue::from_bytes(b"opaque-\x80").expect("obs-text value"),
    );
    trailers.append(application.clone(), HeaderValue::from_static("second"));
    trailers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_static("999"),
    );
    trailers.insert(
        HeaderName::from_static("grpc-status"),
        HeaderValue::from_static("7"),
    );
    trailers.insert(
        HeaderName::from_static("grpc-message"),
        HeaderValue::from_static("access%20denied"),
    );
    trailers.append(
        HeaderName::from_static("grpc-status-details-bin"),
        HeaderValue::from_static("AAE="),
    );
    trailers.append(
        HeaderName::from_static("grpc-status-details-bin"),
        HeaderValue::from_static("Ag"),
    );
    trailers.insert(
        HeaderName::from_static("connect-code"),
        HeaderValue::from_static("invalid_argument"),
    );
    trailers.insert(
        HeaderName::from_static("connect-message"),
        HeaderValue::from_static("bad%20request"),
    );

    let metadata = trailers.metadata();
    assert_eq!(
        metadata.get(&application).unwrap().as_bytes(),
        b"opaque-\x80"
    );
    let values = metadata
        .get_all(&application)
        .map(HeaderValue::as_bytes)
        .collect::<Vec<_>>();
    assert_eq!(values, [b"opaque-\x80".as_slice(), b"second"]);
    assert_eq!(metadata.iter().count(), 2);
    assert!(metadata.get(&http::header::CONTENT_LENGTH).is_none());
    assert!(
        metadata
            .get(&HeaderName::from_static("grpc-status"))
            .is_none()
    );
    assert!(
        metadata
            .get(&HeaderName::from_static("grpc-status-details-bin"))
            .is_none()
    );
    assert!(!trailers.contains_key(&HeaderName::from_static("grpc-status")));
    assert_eq!(trailers.grpc_status().as_deref(), Some("7"));
    assert_eq!(trailers.grpc_message().as_deref(), Some("access denied"));
    let details = trailers
        .grpc_status_details()
        .collect::<Result<Vec<_>, _>>()
        .expect("binary status details");
    assert_eq!(
        details,
        [Bytes::from_static(&[0, 1]), Bytes::from_static(&[2])]
    );
    assert_eq!(
        trailers.connect_status().as_deref(),
        Some("invalid_argument")
    );
    assert_eq!(trailers.connect_message().as_deref(), Some("bad request"));
    assert!(!format!("{metadata:?}").contains("opaque-"));
}

fn trailers() -> Trailers {
    let mut trailers = Trailers::new();
    trailers.insert(
        HeaderName::from_static("x-example"),
        HeaderValue::from_static("not-readable"),
    );
    trailers.append(
        HeaderName::from_static("x-example"),
        HeaderValue::from_static("second"),
    );
    trailers
}

#[tokio::test]
async fn ordered_frames_remain_opaque_and_forwardable() {
    let chunks = vec![Bytes::from_static(b"one"), Bytes::from_static(b"two")];
    let mut input = Body::replay_chunks(chunks.clone(), Some(trailers()));
    assert!(!format!("{input:?}").contains("not-readable"));
    let (mut sender, output) = Body::channel_with_capacity(3);
    while let Some(frame) = input.next_frame().await {
        sender
            .send_frame(frame.expect("input frame"))
            .await
            .expect("forward");
    }
    drop(sender);
    let mut response = HttpModuleResponse::new(StatusCode::OK, output);
    let mut body = response.take_body();
    for chunk in chunks {
        match body.next_frame().await.unwrap().unwrap() {
            BodyFrame::Data(data) => assert_eq!(data, chunk),
            _ => panic!("expected ordered data"),
        }
    }
    let BodyFrame::Trailers(mut trailers) = body.next_frame().await.unwrap().unwrap() else {
        panic!("expected trailers after data");
    };
    assert!(!format!("{trailers:?}").contains("not-readable"));
    let name = HeaderName::from_static("x-example");
    assert!(trailers.contains_key(&name));
    trailers.insert(name.clone(), HeaderValue::from_static("replacement"));
    assert!(trailers.contains_key(&name));
    trailers.remove(&name);
    assert!(!trailers.contains_key(&name));
    trailers.remove(&name);
    assert!(body.next_frame().await.is_none());
}

#[tokio::test]
async fn bounded_channel_backpressure_wakes_on_capacity_and_body_drop() {
    let (mut sender, body) = Body::channel_with_capacity(1);
    let mut response = HttpModuleResponse::new(StatusCode::OK, body);
    let mut body = response.take_body();
    sender.try_send_data(Bytes::from_static(b"first")).unwrap();
    assert!(sender.try_send_data(Bytes::from_static(b"full")).is_err());
    assert!(sender.try_send_trailers(trailers()).is_err());

    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    let mut blocked = Box::pin(sender.send_data(Bytes::from_static(b"second")));
    assert!(blocked.as_mut().poll(&mut cx).is_pending());
    assert_eq!(body.data().await.unwrap().unwrap(), "first");
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        blocked.as_mut().poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    drop(blocked);

    let mut blocked = Box::pin(sender.send_trailers(trailers()));
    assert!(blocked.as_mut().poll(&mut cx).is_pending());
    let before_drop = wakes.0.load(Ordering::SeqCst);
    drop(body);
    assert!(wakes.0.load(Ordering::SeqCst) > before_drop);
    assert!(matches!(
        blocked.as_mut().poll(&mut cx),
        Poll::Ready(Err(_))
    ));
    drop(blocked);
    assert!(sender.is_closed());
    assert!(poll(Box::pin(sender.closed()).as_mut()).is_ready());
    assert!(sender.send_data(Bytes::new()).await.is_err());
}

#[tokio::test]
async fn canceled_send_does_not_enqueue_and_drop_sender_finishes_stream() {
    let (mut sender, mut body) = Body::channel_with_capacity(1);
    sender.try_send_data(Bytes::from_static(b"queued")).unwrap();
    let mut canceled = Box::pin(sender.send_data(Bytes::from_static(b"canceled")));
    assert!(poll(canceled.as_mut()).is_pending());
    drop(canceled);
    assert_eq!(body.data().await.unwrap().unwrap(), "queued");
    sender.try_send_trailers(trailers()).unwrap();
    drop(sender);
    assert!(body.data().await.is_none());
    let trailers = body.trailers().await.unwrap().unwrap();
    assert!(trailers.contains_key(&HeaderName::from_static("x-example")));
    assert!(body.next_frame().await.is_none());
}

#[test]
fn closed_waiter_is_woken_without_scheduling_or_sleeping() {
    let (sender, body) = Body::channel();
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    let mut closed = Box::pin(sender.closed());
    assert!(closed.as_mut().poll(&mut cx).is_pending());
    drop(body);
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(closed.as_mut().poll(&mut cx).is_ready());
}

#[tokio::test]
async fn abort_and_limits_remain_stream_errors() {
    let (mut sender, mut body) = Body::channel_with_capacity(1);
    sender.try_send_data(Bytes::from_static(b"queued")).unwrap();
    sender.abort();
    assert_eq!(body.data().await.unwrap().unwrap(), "queued");
    assert_eq!(
        body.data().await.unwrap().unwrap_err(),
        BodyError::aborted()
    );
    assert!(body.next_frame().await.is_none());
    assert!(body.trailers().await.unwrap().is_none());
    assert_eq!(
        body.limit_bytes(1).to_bytes().await.unwrap_err(),
        BodyError::aborted()
    );
    assert!(sender.send_data(Bytes::new()).await.is_err());

    let mut body = Body::replay_chunks(
        vec![Bytes::from_static(b"12"), Bytes::from_static(b"34")],
        None,
    )
    .limit_bytes(3);
    assert_eq!(body.data().await.unwrap().unwrap(), "12");
    assert!(
        body.data()
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("limit exceeded")
    );
    assert!(body.next_frame().await.is_none());
    assert!(Body::from("four").limit_bytes(3).to_bytes().await.is_err());
}

#[tokio::test]
async fn standard_body_input_returns_only_opaque_ordered_frames() {
    use http_body::Frame;
    use http_body_util::StreamBody;
    // A standard body with a different error type exercises the input adapter;
    // no standard Frame or raw trailer map is returned by the module body.
    let mut raw_trailers = http::HeaderMap::new();
    raw_trailers.append("x-example", HeaderValue::from_static("not-readable"));
    let frames = vec![
        Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(b"one"))),
        Ok(Frame::data(Bytes::from_static(b"two"))),
        Ok(Frame::trailers(raw_trailers)),
    ];
    let mut body = Body::wrap(StreamBody::new(futures_util::stream::iter(frames)));
    for chunk in [b"one", b"two"] {
        let BodyFrame::Data(data) = body.next_frame().await.unwrap().unwrap() else {
            panic!("expected ordered data");
        };
        assert_eq!(data.as_ref(), chunk);
    }
    let BodyFrame::Trailers(trailers) = body.next_frame().await.unwrap().unwrap() else {
        panic!("expected opaque trailers");
    };
    assert!(trailers.contains_key(&HeaderName::from_static("x-example")));
    assert!(!format!("{trailers:?}").contains("not-readable"));
    assert!(body.next_frame().await.is_none());
}

// Incoming uses the same input-only adapter; it requires no conversion escape.
#[test]
fn hyper_incoming_is_a_compatible_input() {
    let _: fn(hyper::body::Incoming) -> Body = Body::wrap;
}

#[tokio::test]
async fn wrapped_standard_body_errors_remain_terminal() {
    use http_body::Frame;
    use http_body_util::StreamBody;
    let frames = vec![
        Ok(Frame::data(Bytes::from_static(b"before"))),
        Err(std::io::Error::other("wrapped stream failed")),
        Ok(Frame::data(Bytes::from_static(b"unreachable"))),
    ];
    let mut body = Body::wrap(StreamBody::new(futures_util::stream::iter(frames)));
    assert!(matches!(
        body.next_frame().await,
        Some(Ok(BodyFrame::Data(_)))
    ));
    assert_eq!(
        body.next_frame().await.unwrap().unwrap_err().to_string(),
        "wrapped stream failed"
    );
    assert!(body.next_frame().await.is_none());
    assert!(body.trailers().await.unwrap().is_none());
}
