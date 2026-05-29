use crate::response::{
    sanitize_interim_response_for_h3, sanitize_streaming_response_head_for_h3,
    sanitize_trailers_for_h3,
};

#[test]
fn sanitize_interim_and_trailers_strip_forbidden_fields() {
    let mut interim = http::Response::builder()
        .status(http::StatusCode::CONTINUE)
        .header(http::header::CONNECTION, "close")
        .header(http::header::TE, "trailers")
        .header(http::header::TRAILER, "x-end")
        .header(http::header::CONTENT_LENGTH, "0")
        .body(())
        .expect("interim");
    sanitize_interim_response_for_h3(&mut interim).expect("sanitize interim");
    assert!(!interim.headers().contains_key(http::header::CONNECTION));
    assert!(!interim.headers().contains_key(http::header::TE));
    assert!(!interim.headers().contains_key(http::header::TRAILER));
    assert!(!interim.headers().contains_key(http::header::CONTENT_LENGTH));

    let mut trailers = http::HeaderMap::new();
    trailers.insert(http::header::TE, "trailers".parse().unwrap());
    trailers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
    trailers.insert(http::header::CONTENT_LENGTH, "0".parse().unwrap());
    trailers.insert(
        http::header::AUTHORIZATION,
        "Bearer secret".parse().unwrap(),
    );
    trailers.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
    trailers.insert("x-safe-trailer", "ok".parse().unwrap());
    sanitize_trailers_for_h3(&mut trailers).expect("sanitize trailers");
    assert!(!trailers.contains_key(http::header::TE));
    assert!(!trailers.contains_key(http::header::TRANSFER_ENCODING));
    assert!(!trailers.contains_key(http::header::CONTENT_LENGTH));
    assert!(!trailers.contains_key(http::header::AUTHORIZATION));
    assert!(!trailers.contains_key(http::header::CONTENT_TYPE));
    assert_eq!(
        trailers
            .get("x-safe-trailer")
            .and_then(|value| value.to_str().ok()),
        Some("ok")
    );
}

#[test]
fn sanitize_interim_rejects_final_status_in_interim_slot() {
    let mut interim = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .expect("interim");
    let err = sanitize_interim_response_for_h3(&mut interim).expect_err("invalid interim");
    assert!(err.to_string().contains("informational"));
}

#[test]
fn sanitize_streaming_response_preserves_valid_content_length() {
    let mut response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_LENGTH, "99")
        .header(http::header::TRAILER, "x-end")
        .header(http::header::TE, "trailers")
        .body(())
        .expect("response");

    let body_allowed = sanitize_streaming_response_head_for_h3(&mut response).expect("sanitize");

    assert_eq!(body_allowed, Some(true));
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some("99")
    );
    assert!(!response.headers().contains_key(http::header::TRAILER));
    assert!(!response.headers().contains_key(http::header::TE));
}
