use super::{
    DEFAULT_DYNAMIC_TABLE_CAPACITY, DEFAULT_MAX_BLOCKED_STREAMS, DecoderState, FieldDecodeError,
    STATIC_TABLE, append_header, decode_field_section_prefix, decode_request_head_from_fields,
    decode_required_insert_count, encode_header_prefix, encode_prefixed_int, encode_request_head,
    encode_response_head, encode_string, encode_trailers, fuzz_qpack_decoder, static_field,
    validate_h3_regular_field, validate_h3_response_field, validate_h3_trailer_field,
};
use http::HeaderValue;

#[test]
fn decodes_literal_trailers() {
    let trailers = {
        let state = DecoderState::new(0, DEFAULT_MAX_BLOCKED_STREAMS, u64::MAX);
        state
            .decode_field_lines(&[0, 0, 0x21, b'f', 0x03, b'b', b'a', b'r'])
            .unwrap()
            .fields
    };
    assert_eq!(trailers, vec![("f".to_string(), b"bar".to_vec())]);
}

#[test]
fn decodes_authority_form_connect() {
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(
            http::Uri::builder()
                .authority("example.com:443")
                .build()
                .unwrap(),
        )
        .body(())
        .unwrap();
    let payload = encode_request_head(&request, None).unwrap();
    let state = DecoderState::new(0, DEFAULT_MAX_BLOCKED_STREAMS, u64::MAX);
    let decoded = state.decode_field_lines(&payload).unwrap().fields;
    assert_eq!(decoded[0], (":method".to_string(), b"CONNECT".to_vec()));
}

#[test]
fn traditional_connect_rejects_scheme_and_path() {
    let fields = vec![
        (":method".to_string(), b"CONNECT".to_vec()),
        (":scheme".to_string(), b"https".to_vec()),
        (":authority".to_string(), b"example.com:443".to_vec()),
        (":path".to_string(), b"/forbidden".to_vec()),
    ];
    let err = decode_request_head_from_fields(fields).expect_err("traditional CONNECT must fail");
    assert!(err.to_string().contains("must not include"));
}

#[test]
fn response_head_roundtrip() {
    let response = http::Response::builder()
        .status(204)
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    let payload = encode_response_head(&response);
    let state = DecoderState::new(0, DEFAULT_MAX_BLOCKED_STREAMS, u64::MAX);
    let decoded = state.decode_field_lines(&payload).unwrap().fields;
    assert_eq!(decoded[0], (":status".to_string(), b"204".to_vec()));
    assert!(
        decoded
            .iter()
            .any(|(name, value)| name == "capsule-protocol" && value.as_slice() == b"?1")
    );
}

#[test]
fn response_fields_reject_te_trailers() {
    assert!(validate_h3_regular_field("te", b"trailers").is_ok());
    assert!(validate_h3_response_field("te", b"trailers").is_err());
}

#[test]
fn dynamic_qpack_indexed_field_decodes_after_insert() {
    let mut state = DecoderState::new(
        DEFAULT_DYNAMIC_TABLE_CAPACITY,
        DEFAULT_MAX_BLOCKED_STREAMS,
        u64::MAX,
    );
    state
        .table
        .set_max_size(DEFAULT_DYNAMIC_TABLE_CAPACITY)
        .unwrap();
    state
        .table
        .insert("x-dynamic".to_string(), b"value".to_vec())
        .unwrap();

    let mut payload = Vec::new();
    encode_header_prefix(
        &mut payload,
        1,
        1,
        state.table.total_inserted(),
        DEFAULT_DYNAMIC_TABLE_CAPACITY,
    );
    encode_prefixed_int(&mut payload, 6, 0b10, 0);

    let decoded = state.decode_field_lines(&payload).unwrap();
    assert!(decoded.dynamic_ref);
    assert_eq!(
        decoded.fields,
        vec![("x-dynamic".to_string(), b"value".to_vec())]
    );
}

#[test]
fn dynamic_qpack_name_reference_decodes_after_insert() {
    let mut state = DecoderState::new(
        DEFAULT_DYNAMIC_TABLE_CAPACITY,
        DEFAULT_MAX_BLOCKED_STREAMS,
        u64::MAX,
    );
    state
        .table
        .set_max_size(DEFAULT_DYNAMIC_TABLE_CAPACITY)
        .unwrap();
    state
        .table
        .insert("x-name".to_string(), b"seed".to_vec())
        .unwrap();

    let mut payload = Vec::new();
    encode_header_prefix(
        &mut payload,
        1,
        1,
        state.table.total_inserted(),
        DEFAULT_DYNAMIC_TABLE_CAPACITY,
    );
    encode_prefixed_int(&mut payload, 4, 0b0100, 0);
    encode_string(&mut payload, 8, 0, b"next");

    let decoded = state.decode_field_lines(&payload).unwrap();
    assert_eq!(
        decoded.fields,
        vec![("x-name".to_string(), b"next".to_vec())]
    );
}

#[test]
fn missing_dynamic_refs_report_blocking_state() {
    let state = DecoderState::new(
        DEFAULT_DYNAMIC_TABLE_CAPACITY,
        DEFAULT_MAX_BLOCKED_STREAMS,
        u64::MAX,
    );
    let mut payload = Vec::new();
    encode_header_prefix(&mut payload, 1, 1, 0, DEFAULT_DYNAMIC_TABLE_CAPACITY);
    encode_prefixed_int(&mut payload, 6, 0b10, 0);

    match state.decode_field_lines(&payload) {
        Err(FieldDecodeError::MissingRefs(1)) => {}
        other => panic!("unexpected decode result: {other:?}"),
    }
}

#[test]
fn required_insert_count_wraps_against_current_total() {
    let required = decode_required_insert_count(1, 128, DEFAULT_DYNAMIC_TABLE_CAPACITY).unwrap();
    assert_eq!(required, 256);
}

#[test]
fn non_zero_encoded_insert_count_must_not_decode_to_zero() {
    let err = decode_required_insert_count(1, 0, DEFAULT_DYNAMIC_TABLE_CAPACITY)
        .expect_err("non-zero encoded insert count cannot represent zero");
    assert!(matches!(err, FieldDecodeError::DecompressionFailed(_)));
}

#[test]
fn oversized_encoded_insert_count_is_malformed() {
    let max_entries = DEFAULT_DYNAMIC_TABLE_CAPACITY / 32;
    let err =
        decode_required_insert_count(2 * max_entries + 1, 128, DEFAULT_DYNAMIC_TABLE_CAPACITY)
            .expect_err("encoded insert count beyond full range must fail");
    assert!(matches!(err, FieldDecodeError::DecompressionFailed(_)));
}

#[test]
fn encoded_insert_count_underflow_is_malformed() {
    let err = decode_required_insert_count(132, 0, DEFAULT_DYNAMIC_TABLE_CAPACITY)
        .expect_err("wrapped required insert count before zero must fail");
    assert!(matches!(err, FieldDecodeError::DecompressionFailed(_)));
    fuzz_qpack_decoder(&[132, 10]);
}

#[test]
fn field_prefix_roundtrip() {
    let mut payload = Vec::new();
    encode_header_prefix(&mut payload, 10, 5, 12, DEFAULT_DYNAMIC_TABLE_CAPACITY);
    let mut cursor = payload.as_slice();
    let decoded =
        decode_field_section_prefix(&mut cursor, 13, DEFAULT_DYNAMIC_TABLE_CAPACITY).unwrap();
    assert_eq!(decoded.required_insert_count, 10);
    assert_eq!(decoded.base, 5);
}

#[test]
fn trailers_encode_roundtrip_shape() {
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-end", HeaderValue::from_static("done"));
    let payload = encode_trailers(&trailers);
    let state = DecoderState::new(0, DEFAULT_MAX_BLOCKED_STREAMS, u64::MAX);
    let decoded = state.decode_field_lines(&payload).unwrap().fields;
    assert_eq!(decoded, vec![("x-end".to_string(), b"done".to_vec())]);
}

#[test]
fn request_trailers_reject_prohibited_fields() {
    assert!(validate_h3_trailer_field("x-end", b"done").is_ok());
    assert!(validate_h3_trailer_field("content-length", b"0").is_err());
    assert!(validate_h3_trailer_field("authorization", b"Bearer token").is_err());
    assert!(validate_h3_trailer_field("content-type", b"text/plain").is_err());
}

#[test]
fn static_table_layout_is_stable() {
    assert_eq!(STATIC_TABLE.len(), 99);
    assert_eq!(static_field(17), Some((":method", "GET")));
}

#[test]
fn cookie_fields_are_merged_for_generic_context() {
    let mut headers = http::HeaderMap::new();
    append_header(&mut headers, "cookie", b"a=1").expect("first cookie");
    append_header(&mut headers, "cookie", b"b=2").expect("second cookie");

    let cookie = headers
        .get(http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("cookie header");
    assert_eq!(cookie, "a=1; b=2");
    assert_eq!(headers.get_all(http::header::COOKIE).iter().count(), 1);
}

#[test]
fn regular_field_values_preserve_non_utf8_bytes() {
    let mut headers = http::HeaderMap::new();
    append_header(&mut headers, "x-obs", b"\xff").expect("obs-text value");
    assert_eq!(headers["x-obs"].as_bytes(), b"\xff");
}

#[test]
fn h3_forbidden_regular_fields_are_rejected() {
    assert!(validate_h3_regular_field("connection", b"close").is_err());
    assert!(validate_h3_regular_field("transfer-encoding", b"chunked").is_err());
    assert!(validate_h3_regular_field("te", b"trailers").is_ok());
    assert!(validate_h3_regular_field("te", b"trailers, gzip").is_err());
}
