//! External coverage: `RpcStreamSummary` exposes only the opaque `Trailers` facade.
#![cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]

use http::{HeaderMap, HeaderName, HeaderValue};
use qpxd::module_api::RpcStreamObserver;

fn response_headers(content_type: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(content_type),
    );
    headers
}

fn grpc_web_trailer_frame(block: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + block.len());
    frame.push(0x80);
    frame.extend_from_slice(&(block.len() as u32).to_be_bytes());
    frame.extend_from_slice(block);
    frame
}

fn connect_envelope(flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(flags);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn grpc_web_summary_exposes_typed_status_and_filtered_metadata() {
    let headers = response_headers("application/grpc-web+proto");
    let mut observer =
        RpcStreamObserver::from_headers(&headers, None, Some(16 * 1024 * 1024), Some(64 * 1024))
            .expect("gRPC-Web observer");
    assert_eq!(observer.protocol(), "grpc_web");

    observer
        .feed(&[0, 0, 0, 0, 3, b'a', b'b', b'c'])
        .expect("gRPC-Web message frame");

    let block = b"grpc-status: 7\r\ngrpc-message: access%20denied\r\ngrpc-status-details-bin: AAE=\r\nx-app-metadata: hello\r\ncontent-length: 999\r\n";
    observer
        .feed(&grpc_web_trailer_frame(block))
        .expect("gRPC-Web trailer frame");

    let summary = observer.finish().expect("gRPC-Web summary");
    assert_eq!(summary.message_count, 1);
    assert_eq!(summary.message_bytes, 3);

    let trailers = summary.trailers().expect("trailers");
    assert_eq!(trailers.grpc_status().as_deref(), Some("7"));
    assert_eq!(trailers.grpc_message().as_deref(), Some("access denied"));
    let details = trailers
        .grpc_status_details()
        .collect::<Result<Vec<_>, _>>()
        .expect("binary status details");
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].as_ref(), &[0, 1]);

    let name = HeaderName::from_static("x-app-metadata");
    assert_eq!(
        trailers.metadata().get(&name).and_then(|v| v.to_str().ok()),
        Some("hello")
    );
    assert!(trailers.contains_key(&name));
    assert!(
        trailers
            .metadata()
            .get(&HeaderName::from_static("grpc-status"))
            .is_none()
    );
    assert!(
        trailers
            .metadata()
            .get(&HeaderName::from_static("grpc-status-details-bin"))
            .is_none()
    );
    assert!(
        trailers
            .metadata()
            .get(&http::header::CONTENT_LENGTH)
            .is_none()
    );
    assert!(!trailers.contains_key(&HeaderName::from_static("grpc-status")));
    assert!(!format!("{trailers:?}").contains("hello"));
}

#[test]
fn connect_summary_exposes_typed_status_and_ordered_metadata() {
    let headers = response_headers("application/connect+proto");
    let mut observer =
        RpcStreamObserver::from_headers(&headers, None, Some(16 * 1024 * 1024), Some(64 * 1024))
            .expect("Connect observer");
    assert_eq!(observer.protocol(), "connect");

    observer
        .feed(&connect_envelope(0x00, b"hello"))
        .expect("Connect message envelope");

    let envelope = r#"{"error":{"code":"invalid_argument","message":"bad request"},"metadata":{"x-app-metadata":["first","second"],"connect-code":["smuggled"],"content-length":["999"]}}"#;
    observer
        .feed(&connect_envelope(0x02, envelope.as_bytes()))
        .expect("Connect end-stream envelope");

    let summary = observer.finish().expect("Connect summary");
    assert_eq!(summary.message_count, 1);
    assert_eq!(summary.message_bytes, 5);

    let trailers = summary.trailers().expect("trailers");
    assert_eq!(
        trailers.connect_status().as_deref(),
        Some("invalid_argument")
    );
    assert_eq!(trailers.connect_message().as_deref(), Some("bad request"));

    let name = HeaderName::from_static("x-app-metadata");
    let metadata = trailers.metadata();
    let values = metadata
        .get_all(&name)
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>();
    assert_eq!(values, vec!["first", "second"]);
    assert!(trailers.contains_key(&name));

    // Reserved protocol and HTTP-prohibited names stay filtered.
    assert!(
        trailers
            .metadata()
            .get(&HeaderName::from_static("connect-code"))
            .is_none()
    );
    assert!(!trailers.contains_key(&HeaderName::from_static("connect-code")));
    assert!(
        trailers
            .metadata()
            .get(&http::header::CONTENT_LENGTH)
            .is_none()
    );
    let names = metadata
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["x-app-metadata", "x-app-metadata"]);

    // gRPC semantics are absent on a Connect trailer set.
    assert!(trailers.grpc_status().is_none());
    assert!(!format!("{trailers:?}").contains("first"));
}
