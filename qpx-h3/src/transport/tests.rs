use super::*;

#[test]
fn request_body_limit_tracks_cumulative_data() {
    let mut seen = 0;
    enforce_body_frame(Some(5), None, &mut seen, 3, "request").expect("first chunk");
    assert_eq!(seen, 3);
    let err = enforce_body_frame(Some(5), None, &mut seen, 3, "request")
        .expect_err("second chunk should exceed the limit");
    assert!(err.to_string().contains("max_request_body_bytes"));
}

#[test]
fn request_body_limit_is_disabled_for_client_response_streams() {
    let mut seen = 0;
    enforce_body_frame(None, None, &mut seen, 1, "response").expect("disabled limit");
    assert_eq!(seen, 1);
}

#[test]
fn request_content_length_excess_is_rejected_before_payload_exposure() {
    let mut seen = 0;
    let err = enforce_body_frame(None, Some(5), &mut seen, 6, "request")
        .expect_err("DATA frame should exceed declared content length");
    assert!(err.to_string().contains("exceeds Content-Length"));
    assert_eq!(seen, 6);
}

#[test]
fn request_content_length_requires_exact_completion() {
    enforce_body_content_length_complete(Some(5), 5, "request").expect("exact length");
    let err = enforce_body_content_length_complete(Some(5), 4, "request")
        .expect_err("short body should fail");
    assert!(err.to_string().contains("length mismatch"));
}

#[test]
fn response_content_length_excess_is_rejected_before_payload_exposure() {
    let mut seen = 0;
    let err = enforce_body_frame(None, Some(5), &mut seen, 10, "response")
        .expect_err("DATA frame should exceed declared response content length");
    assert!(
        err.to_string()
            .contains("response body exceeds Content-Length")
    );
    assert_eq!(seen, 10);
}

#[test]
fn no_body_response_declares_zero_received_length() {
    let response = http::Response::builder()
        .status(http::StatusCode::NO_CONTENT)
        .header(http::header::CONTENT_LENGTH, "10")
        .body(())
        .expect("response");
    assert_eq!(
        declared_response_body_length(&response, false).expect("declared"),
        Some(0)
    );
}

#[test]
fn response_content_length_tracks_send_and_finish() {
    let mut state = ResponseSendState {
        response_started: true,
        final_sent: true,
        body_allowed: true,
        head_request: false,
        declared_content_length: Some(5),
        sent_body_bytes: 0,
    };
    enforce_response_content_length_send(&mut state, 3).expect("first chunk");
    assert!(enforce_response_content_length_complete(&state).is_err());
    enforce_response_content_length_send(&mut state, 2).expect("second chunk");
    enforce_response_content_length_complete(&state).expect("complete body");
    let err = enforce_response_content_length_send(&mut state, 1)
        .expect_err("extra response body byte should fail");
    assert!(err.to_string().contains("exceeds Content-Length"));
}

#[test]
fn message_frame_payload_limits_keep_data_and_unknown_frames_separate() {
    assert_eq!(max_message_frame_payload_bytes(FRAME_DATA, 16, 4, 8), 16);
    assert_eq!(max_message_frame_payload_bytes(FRAME_HEADERS, 16, 4, 8), 8);
    assert_eq!(max_message_frame_payload_bytes(0x21, 16, 4, 8), 4);
}
