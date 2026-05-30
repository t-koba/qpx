use super::{
    FRAME_CANCEL_PUSH, FRAME_DATA, FRAME_GOAWAY, FRAME_MAX_PUSH_ID, FRAME_PING,
    FRAME_PRIORITY_UPDATE_PUSH, FRAME_PRIORITY_UPDATE_REQUEST, FRAME_PUSH_PROMISE,
    FRAME_WINDOW_UPDATE, H3_EXCESSIVE_LOAD, H3_FRAME_ERROR, H3_FRAME_UNEXPECTED, H3_ID_ERROR,
    MAX_BUFFERED_PRIORITY_UPDATES, PeerControlState, StreamPriority, decode_settings_frame,
    encode_varint, parse_priority, push_varint, read_frame, read_varint_slice,
    validate_control_stream_frame, validate_message_stream_frame,
};

#[test]
fn quic_varint_roundtrip() {
    for value in [0, 63, 64, 15293, 16383, 16384, 1_000_000, (1 << 30) - 1] {
        let encoded = encode_varint(value).unwrap();
        let (decoded, used) = read_varint_slice(&encoded).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(used, encoded.len());
    }
}

#[test]
fn settings_reject_reserved_http2_identifiers() {
    let mut payload = Vec::new();
    push_varint(&mut payload, 0x2);
    push_varint(&mut payload, 1);
    let err = decode_settings_frame(payload.as_slice()).unwrap_err();
    assert!(
        err.to_string()
            .contains("reserved HTTP/2 SETTINGS parameter 0x2"),
        "{err}"
    );
}

#[test]
fn control_stream_rejects_data_frames() {
    let err = validate_control_stream_frame(FRAME_DATA, false).unwrap_err();
    assert_eq!(err.code, H3_FRAME_UNEXPECTED);
}

#[test]
fn client_control_stream_rejects_max_push_id() {
    let err = validate_control_stream_frame(FRAME_MAX_PUSH_ID, true).unwrap_err();
    assert_eq!(err.code, H3_FRAME_UNEXPECTED);
    assert!(validate_control_stream_frame(FRAME_GOAWAY, true).is_ok());
}

#[test]
fn priority_parser_ignores_invalid_urgency_and_tracks_incremental() {
    assert_eq!(
        parse_priority("u=0, i=?1"),
        StreamPriority {
            urgency: 0,
            incremental: true
        }
    );
    assert_eq!(parse_priority("u=9").urgency, 3);
    assert!(!parse_priority("i=?0").incremental);
}

#[test]
fn message_stream_rejects_control_only_frames() {
    let err = validate_message_stream_frame(FRAME_CANCEL_PUSH).unwrap_err();
    assert_eq!(err.code, H3_FRAME_UNEXPECTED);
    let err = validate_message_stream_frame(FRAME_PUSH_PROMISE).unwrap_err();
    assert_eq!(err.code, H3_FRAME_UNEXPECTED);
    let err = validate_message_stream_frame(FRAME_WINDOW_UPDATE).unwrap_err();
    assert_eq!(err.code, H3_FRAME_UNEXPECTED);
    let err = validate_control_stream_frame(FRAME_PING, false).unwrap_err();
    assert_eq!(err.code, H3_FRAME_UNEXPECTED);
    let err = validate_message_stream_frame(FRAME_PRIORITY_UPDATE_REQUEST).unwrap_err();
    assert_eq!(err.code, H3_FRAME_UNEXPECTED);
    assert!(validate_control_stream_frame(FRAME_PRIORITY_UPDATE_REQUEST, false).is_ok());
    let err = validate_control_stream_frame(FRAME_PRIORITY_UPDATE_REQUEST, true).unwrap_err();
    assert_eq!(err.code, H3_FRAME_UNEXPECTED);
}

#[tokio::test]
async fn read_frame_rejects_oversized_payload_before_allocation() {
    let mut input = [FRAME_DATA as u8, 5u8].as_slice();
    let err = read_frame(&mut input, 4).await.unwrap_err();
    assert!(
        err.to_string().contains("exceeds limit 4"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn control_state_rejects_malformed_goaway_payload() {
    let state = PeerControlState::default();
    let err = state
        .handle_control_frame(FRAME_GOAWAY, &[0x40], true)
        .await
        .unwrap_err();
    assert_eq!(err.code, H3_FRAME_ERROR);
}

#[tokio::test]
async fn control_state_enforces_goaway_monotonicity() {
    let state = PeerControlState::default();
    state
        .handle_control_frame(FRAME_GOAWAY, &[0x00], true)
        .await
        .unwrap();
    let err = state
        .handle_control_frame(FRAME_GOAWAY, &[0x04], true)
        .await
        .unwrap_err();
    assert_eq!(err.code, H3_ID_ERROR);
}

#[tokio::test]
async fn control_state_enforces_max_push_id_monotonicity() {
    let state = PeerControlState::default();
    state
        .handle_control_frame(FRAME_MAX_PUSH_ID, &[0x05], false)
        .await
        .unwrap();
    let err = state
        .handle_control_frame(FRAME_MAX_PUSH_ID, &[0x04], false)
        .await
        .unwrap_err();
    assert_eq!(err.code, H3_ID_ERROR);
}

#[tokio::test]
async fn control_state_applies_request_priority_update_once() {
    let state = PeerControlState::default();
    let mut payload = Vec::new();
    push_varint(&mut payload, 4);
    payload.extend_from_slice(b"u=0, i=?1");

    state
        .handle_control_frame(FRAME_PRIORITY_UPDATE_REQUEST, &payload, false)
        .await
        .unwrap();

    assert_eq!(
        state.priority_for_request(4, Some("u=7")).await,
        StreamPriority {
            urgency: 0,
            incremental: true
        }
    );
    assert_eq!(
        state.priority_for_request(4, Some("u=7")).await,
        StreamPriority {
            urgency: 7,
            incremental: false
        }
    );
}

#[tokio::test]
async fn control_state_applies_priority_updates_after_request_start_without_buffering() {
    let state = PeerControlState::default();
    assert_eq!(
        state.priority_for_request(4, Some("u=7")).await,
        StreamPriority {
            urgency: 7,
            incremental: false
        }
    );

    let mut payload = Vec::new();
    push_varint(&mut payload, 4);
    payload.extend_from_slice(b"u=0, i=?1");
    state
        .handle_control_frame(FRAME_PRIORITY_UPDATE_REQUEST, &payload, false)
        .await
        .unwrap();

    assert!(state.has_started_request_without_buffered_priority(4).await);
    assert_eq!(
        state.latest_priority_for_request(4).await,
        Some(StreamPriority {
            urgency: 0,
            incremental: true
        })
    );
}

#[tokio::test]
async fn control_state_reads_known_payloads_without_frame_buffer() {
    let state = PeerControlState::default();
    let mut payload = Vec::new();
    push_varint(&mut payload, 4);
    payload.extend_from_slice(b"u=0, i=?1");
    let mut payload_reader = payload.as_slice();

    state
        .handle_control_frame_from_reader(
            &mut payload_reader,
            FRAME_PRIORITY_UPDATE_REQUEST,
            payload.len() as u64,
            128,
            false,
        )
        .await
        .unwrap();

    assert_eq!(
        state.priority_for_request(4, None).await,
        StreamPriority {
            urgency: 0,
            incremental: true
        }
    );
}

#[tokio::test]
async fn control_state_reader_rejects_trailing_single_varint_payload() {
    let state = PeerControlState::default();
    let mut payload = [0x00, 0x00].as_slice();
    let err = state
        .handle_control_frame_from_reader(&mut payload, FRAME_GOAWAY, 2, 128, true)
        .await
        .unwrap_err();
    assert_eq!(err.code, H3_FRAME_ERROR);
}

#[tokio::test]
async fn control_state_rejects_invalid_priority_update_targets_and_push() {
    let state = PeerControlState::default();
    let mut payload = Vec::new();
    push_varint(&mut payload, 1);
    payload.extend_from_slice(b"u=0");
    let err = state
        .handle_control_frame(FRAME_PRIORITY_UPDATE_REQUEST, &payload, false)
        .await
        .unwrap_err();
    assert_eq!(err.code, H3_ID_ERROR);

    let mut push_payload = Vec::new();
    push_varint(&mut push_payload, 0);
    push_payload.extend_from_slice(b"u=0");
    let err = state
        .handle_control_frame(FRAME_PRIORITY_UPDATE_PUSH, &push_payload, false)
        .await
        .unwrap_err();
    assert_eq!(err.code, H3_ID_ERROR);
}

#[tokio::test]
async fn control_state_caps_buffered_priority_updates() {
    let state = PeerControlState::default();
    for idx in 0..MAX_BUFFERED_PRIORITY_UPDATES {
        let mut payload = Vec::new();
        push_varint(&mut payload, (idx as u64) * 4);
        payload.extend_from_slice(b"u=1");
        state
            .handle_control_frame(FRAME_PRIORITY_UPDATE_REQUEST, &payload, false)
            .await
            .unwrap();
    }

    let mut payload = Vec::new();
    push_varint(&mut payload, (MAX_BUFFERED_PRIORITY_UPDATES as u64) * 4);
    payload.extend_from_slice(b"u=1");
    let err = state
        .handle_control_frame(FRAME_PRIORITY_UPDATE_REQUEST, &payload, false)
        .await
        .unwrap_err();
    assert_eq!(err.code, H3_EXCESSIVE_LOAD);
}
