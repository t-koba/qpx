use super::*;
use crate::entry::{
    not_modified_from_envelope, response_from_envelope_for_request,
    response_from_envelope_for_request_with_body,
};
use http::header::{CACHE_CONTROL, ETAG};

// Historical field order, spelling, duplicates and malformed stored fields are
// all wire data, not a serialization of the hydrated HeaderMap.
const OLD_JSON: &str = r#"{"status":200,"headers":[["X-Repeat","first"],["Content-Length","00042, 42"],["x-repeat","second"],["ETag","\"v1\""],["Cache-Control","public, max-age=60"],["bad name","ignored"],["x-invalid","line\nbreak"],["content-range","bytes 1-2/99"]],"body_len":9,"stored_at_ms":1000,"initial_age_secs":2,"response_delay_secs":1,"freshness_lifetime_secs":60,"vary_headers":[],"vary_values":[]}"#;

fn old_envelope() -> CachedResponseEnvelope {
    let mut raw = CACHE_METADATA_MAGIC.to_vec();
    raw.extend_from_slice(OLD_JSON.as_bytes());
    decode_cached_response_metadata(Bytes::from(raw)).expect("historical metadata")
}

#[test]
fn historical_metadata_round_trips_exactly_even_after_hydration() {
    let envelope = old_envelope();
    assert_eq!(envelope.headers.declared_content_length(), Some(42));
    assert_eq!(envelope.etag(), Some("\"v1\""));
    assert_eq!(envelope.response_directives().max_age, Some(60));
    assert_eq!(
        envelope
            .headers
            .get(http::HeaderName::from_static("content-length")),
        None
    );
    assert_eq!(format!("{:?}", envelope.headers), "CachedHeaders { .. }");
    let encoded = encode_cached_response_metadata(&envelope).expect("encode");
    assert_eq!(&encoded[..CACHE_METADATA_MAGIC.len()], CACHE_METADATA_MAGIC);
    assert_eq!(&encoded[CACHE_METADATA_MAGIC.len()..], OLD_JSON.as_bytes());
    assert_eq!(envelope.body_len, 9);
    assert_eq!(envelope.response_delay_secs, 1);
}

#[test]
fn older_metadata_without_response_delay_keeps_its_default() {
    let json = OLD_JSON.replace("\"response_delay_secs\":1,", "");
    let mut raw = CACHE_METADATA_MAGIC.to_vec();
    raw.extend_from_slice(json.as_bytes());
    let envelope = decode_cached_response_metadata(Bytes::from(raw)).expect("older metadata");
    assert_eq!(envelope.response_delay_secs, 0);
    assert_eq!(envelope.headers.declared_content_length(), Some(42));
}

#[tokio::test]
async fn replay_preserves_duplicates_and_uses_typed_head_body_and_range_lengths() {
    let mut envelope = old_envelope();
    envelope.body = CachedBody::from_bytes(Bytes::from_static(b"123456789"));
    let req = RequestDirectives::default();
    let get = response_from_envelope_for_request(&Method::GET, &req, &envelope, 2000, "HIT")
        .expect("GET");
    assert_eq!(
        crate::tests::wire_headers(get.headers())[CONTENT_LENGTH],
        "9"
    );
    assert_eq!(
        crate::tests::wire_headers(get.headers())
            .get_all(CONTENT_LENGTH)
            .iter()
            .count(),
        1
    );
    assert_eq!(
        crate::tests::wire_headers(get.headers())
            .get_all("x-repeat")
            .iter()
            .map(|v| v.to_str().expect("text"))
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    assert!(!crate::tests::wire_headers(get.headers()).contains_key("x-invalid"));
    assert!(!crate::tests::wire_headers(get.headers()).contains_key(CONTENT_RANGE));
    assert_eq!(
        qpx_http::body::to_bytes(get.into_head_and_body().1)
            .await
            .expect("body"),
        "123456789"
    );

    // A stored HEAD declaration is not the number of body bytes in the cache.
    let head = response_from_envelope_for_request(&Method::HEAD, &req, &envelope, 2000, "HIT")
        .expect("HEAD");
    assert_eq!(
        crate::tests::wire_headers(head.headers())[CONTENT_LENGTH],
        "42"
    );
    assert!(
        qpx_http::body::to_bytes(head.into_head_and_body().1)
            .await
            .expect("empty")
            .is_empty()
    );

    let ranged = RequestDirectives {
        range: Some(ByteRangeSpec::From {
            start: 2,
            end: Some(4),
        }),
        ..Default::default()
    };
    let partial = response_from_envelope_for_request(&Method::GET, &ranged, &envelope, 2000, "HIT")
        .expect("range");
    assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        crate::tests::wire_headers(partial.headers())[CONTENT_LENGTH],
        "3"
    );
    assert_eq!(
        crate::tests::wire_headers(partial.headers())[CONTENT_RANGE],
        "bytes 2-4/9"
    );
    assert_eq!(
        qpx_http::body::to_bytes(partial.into_head_and_body().1)
            .await
            .expect("partial"),
        "345"
    );
    let streamed = response_from_envelope_for_request_with_body(
        &Method::GET,
        &ranged,
        &envelope,
        2000,
        "HIT",
        Body::from("345"),
        3,
    )
    .expect("streamed range");
    assert_eq!(streamed.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        crate::tests::wire_headers(streamed.headers())[CONTENT_LENGTH],
        "3"
    );
    assert_eq!(
        crate::tests::wire_headers(streamed.headers())[CONTENT_RANGE],
        "bytes 2-4/9"
    );

    let outside = RequestDirectives {
        range: Some(ByteRangeSpec::From {
            start: 90,
            end: None,
        }),
        ..Default::default()
    };
    let unsatisfied =
        response_from_envelope_for_request(&Method::GET, &outside, &envelope, 2000, "HIT")
            .expect("416");
    assert_eq!(unsatisfied.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        crate::tests::wire_headers(unsatisfied.headers())[CONTENT_LENGTH],
        "0"
    );
    assert_eq!(
        crate::tests::wire_headers(unsatisfied.headers())[CONTENT_RANGE],
        "bytes */9"
    );

    let nm = not_modified_from_envelope(&Method::GET, &envelope, 2000, "HIT").expect("304");
    assert_eq!(nm.status(), StatusCode::NOT_MODIFIED);
    assert!(!crate::tests::wire_headers(nm.headers()).contains_key(CONTENT_LENGTH));
    assert_eq!(crate::tests::wire_headers(nm.headers())[ETAG], "\"v1\"");
    assert!(
        qpx_http::body::to_bytes(nm.into_head_and_body().1)
            .await
            .expect("empty")
            .is_empty()
    );
}

#[test]
fn head_falls_back_to_stored_body_length_for_absent_invalid_or_conflicting_declarations() {
    for values in [
        vec![],
        vec!["+42"],
        vec!["42", "43"],
        vec![""],
        vec!["18446744073709551616"],
    ] {
        let mut envelope = old_envelope();
        envelope.headers = CachedHeaders::from_pairs(
            values
                .into_iter()
                .map(|v| ("Content-Length".into(), v.into()))
                .collect(),
        );
        let head = response_from_envelope_for_request(
            &Method::HEAD,
            &RequestDirectives::default(),
            &envelope,
            2000,
            "HIT",
        )
        .expect("HEAD");
        assert_eq!(
            crate::tests::wire_headers(head.headers())[CONTENT_LENGTH],
            "9"
        );
    }
}

#[test]
fn merge_keeps_exact_exclusions_and_replaces_duplicate_fields_in_place() {
    let mut envelope = old_envelope();
    let mut pairs = envelope.headers.pairs_for_test();
    pairs.extend([
        ("content-encoding".into(), "gzip".into()),
        ("connection".into(), "old-hop".into()),
        ("transfer-encoding".into(), "chunked".into()),
        ("x-nominated".into(), "stored".into()),
        ("x-binary-update".into(), "stored".into()),
    ]);
    envelope.headers = CachedHeaders::from_pairs(pairs);
    let mut nm = http::HeaderMap::new();
    for (name, value) in [
        ("content-length", "0"),
        ("content-encoding", "br"),
        ("content-range", "bytes */0"),
        ("connection", "x-nominated"),
        ("x-nominated", "304 only"),
        ("transfer-encoding", "chunked"),
        ("cache-control", "public, max-age=120"),
        ("etag", "\"v2\""),
        ("content-type", "text/plain"),
        ("content-security-policy", "default-src 'none'"),
    ] {
        nm.append(
            http::HeaderName::from_bytes(name.as_bytes()).expect("name"),
            http::HeaderValue::from_str(value).expect("value"),
        );
    }
    nm.append(
        "connection",
        http::HeaderValue::from_static(" X-Other, keep-alive "),
    );
    nm.append("x-other", http::HeaderValue::from_static("304 only"));
    nm.append(
        "x-binary-update",
        http::HeaderValue::from_bytes(b"\xff").unwrap(),
    );
    nm.append("x-repeat", http::HeaderValue::from_static("new-first"));
    nm.append("x-repeat", http::HeaderValue::from_static("new-second"));
    let merged = envelope
        .headers
        .merge_after_304(&crate::tests::owned_headers(&nm));
    assert_eq!(
        &merged.pairs_for_test()[..3],
        &[
            ("X-Repeat".into(), "new-first".into()),
            ("X-Repeat".into(), "new-second".into()),
            ("Content-Length".into(), "00042, 42".into()),
        ]
    );
    assert_eq!(merged.declared_content_length(), Some(42));
    assert_eq!(
        merged
            .get(http::header::CONTENT_ENCODING)
            .expect("encoding"),
        "gzip"
    );
    assert_eq!(merged.get(CONTENT_RANGE).expect("range"), "bytes 1-2/99");
    assert_eq!(
        merged
            .get(http::HeaderName::from_static("x-nominated"))
            .expect("stored field"),
        "stored"
    );
    assert!(merged.get(http::header::CONNECTION).is_none());
    assert!(merged.get(http::header::TRANSFER_ENCODING).is_none());
    assert_eq!(merged.get(ETAG).expect("validator"), "\"v2\"");
    assert_eq!(
        merged.get(CACHE_CONTROL).expect("directives"),
        "public, max-age=120"
    );
    assert_eq!(
        merged.get(http::header::CONTENT_TYPE).expect("type"),
        "text/plain"
    );
    assert_eq!(
        merged
            .get(http::header::CONTENT_SECURITY_POLICY)
            .expect("policy"),
        "default-src 'none'"
    );
    assert!(
        merged
            .get(http::HeaderName::from_static("x-other"))
            .is_none()
    );
    assert_eq!(
        merged
            .get(http::HeaderName::from_static("x-binary-update"))
            .unwrap(),
        "stored"
    );
    assert_eq!(merged.directives().max_age, Some(120));
    // Encoding the merged owner uses the unchanged persistence codec, not live pairs.
    envelope.headers = merged;
    let encoded = encode_cached_response_metadata(&envelope).unwrap();
    let restored = decode_cached_response_metadata(Bytes::from(encoded.clone())).unwrap();
    assert_eq!(encode_cached_response_metadata(&restored).unwrap(), encoded);
}

mod closed_persistence_tests {
    use super::*;

    #[test]
    fn closed_persistence_preserves_historical_bytes_and_metadata() {
        for lengths in [
            vec![],
            vec!["0"],
            vec!["005"],
            vec!["5, 005", " 5 "],
            vec!["invalid"],
            vec!["5", "6"],
        ] {
            let mut raw = http::Response::new(());
            for value in lengths {
                raw.headers_mut()
                    .append(http::header::CONTENT_LENGTH, value.parse().unwrap());
            }
            for value in ["one", "two"] {
                raw.headers_mut().append("x-repeat", value.parse().unwrap());
            }
            raw.headers_mut()
                .insert("x-binary", http::HeaderValue::from_bytes(b"\xff").unwrap());
            raw.headers_mut()
                .insert("x-private", "stripped".parse().unwrap());
            raw.headers_mut()
                .insert("x-no-cache", "stripped too".parse().unwrap());
            raw.headers_mut()
                .insert("x-text", "\"quoted\"\tvalue\\suffix".parse().unwrap());
            let expected: Vec<_> = raw
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    (name != "x-private" && name != "x-no-cache")
                        .then(|| {
                            value
                                .to_str()
                                .ok()
                                .map(|value| (name.as_str().to_owned(), value.to_owned()))
                        })
                        .flatten()
                })
                .collect();
            let owned = qpx_core::http_message::Response::from_http(raw);
            let directives = ResponseDirectives {
                private_fields: vec!["x-private".into()],
                no_cache_fields: vec!["x-no-cache".into()],
                ..Default::default()
            };
            let mut envelope = old_envelope();
            envelope.headers = CachedHeaders::from_live(owned.headers(), &directives);
            assert_eq!(envelope.headers.pairs_for_test(), expected);
            let expected_json = format!(
                r#"{{"status":200,"headers":{},"body_len":9,"stored_at_ms":1000,"initial_age_secs":2,"response_delay_secs":1,"freshness_lifetime_secs":60,"vary_headers":[],"vary_values":[]}}"#,
                serde_json::to_string(&expected).unwrap()
            );
            let mut expected_bytes = CACHE_METADATA_MAGIC.to_vec();
            expected_bytes.extend_from_slice(expected_json.as_bytes());
            let encoded = encode_cached_response_metadata(&envelope).unwrap();
            assert_eq!(encoded, expected_bytes);
            let restored = decode_cached_response_metadata(Bytes::from(encoded)).unwrap();
            // Hydration and policy reads must not rewrite persisted spellings.
            assert_eq!(
                restored.headers.map().declared_content_length(),
                owned.headers().declared_content_length()
            );
            assert_eq!(
                restored
                    .headers
                    .get(http::HeaderName::from_static("x-repeat"))
                    .unwrap(),
                "one"
            );
            assert_eq!(restored.body_len, 9);
            assert_eq!(restored.response_delay_secs, 1);
            assert_eq!(
                encode_cached_response_metadata(&restored).unwrap(),
                expected_bytes
            );
        }
    }
}
