//! External positive controls: effects never need raw owned storage or CL text access.
use http::HeaderMap;
use http::header::{CONTENT_LENGTH, HeaderName, HeaderValue};
use qpx_core::http_message::{
    HeaderExpansionEncoding as Encoding, HeaderExpansionError as Error,
    HeaderExpansionPlan as Plan, HeaderExpansionSegment as Segment, HeaderTransferMode as Mode,
    HeaderTransferPatch as Patch, Headers, OrdinaryHeaderName, Request,
};

fn field() -> HeaderName {
    HeaderName::from_static("x-selected")
}

fn insert(headers: &mut Headers, name: HeaderName, value: HeaderValue, mode: Mode) {
    match (name == CONTENT_LENGTH, mode) {
        (true, Mode::Append) => headers.append_content_length_value(value),
        (true, Mode::Replace) => headers.set_content_length_value(value),
        (false, Mode::Append) => headers.append(OrdinaryHeaderName::try_from(name).unwrap(), value),
        (false, Mode::Replace) => {
            headers.insert(OrdinaryHeaderName::try_from(name).unwrap(), value);
        }
    }
}

fn import(raw: HeaderMap) -> Headers {
    let mut request = http::Request::new(());
    *request.headers_mut() = raw;
    Request::from_http(request).headers().clone()
}

#[test]
fn transfer_matrix_preserves_literal_first_value_bytes_sensitivity_and_order() {
    let cases: &[&[&[u8]]] = &[
        &[],
        &[b""],
        &[b"0"],
        &[b" 007 ", b"7"],
        &[b"1", b"2"],
        &[b"1, 2", b"3"],
        &[b"not a length", b"4"],
        &[b"18446744073709551616"],
        &[b"\xff\x80", b"textual later"],
        &[b"a\tb"],
    ];
    for source_name in [CONTENT_LENGTH, field()] {
        for destination in [CONTENT_LENGTH, field()] {
            for values in cases {
                for sensitive in [false, true] {
                    let mut raw = HeaderMap::new();
                    for bytes in *values {
                        let mut value = HeaderValue::from_bytes(bytes).unwrap();
                        value.set_sensitive(sensitive);
                        raw.append(source_name.clone(), value);
                    }
                    let source = import(raw.clone());
                    let mut response = http::Response::new(());
                    *response.headers_mut() = raw.clone();
                    for mode in [Mode::Append, Mode::Replace] {
                        for from_response in [false, true] {
                            if !from_response && source_name != destination {
                                continue;
                            }
                            let mut target = Headers::new();
                            insert(
                                &mut target,
                                destination.clone(),
                                HeaderValue::from_static("old first"),
                                Mode::Append,
                            );
                            insert(
                                &mut target,
                                destination.clone(),
                                HeaderValue::from_static("old second"),
                                Mode::Append,
                            );
                            insert(
                                &mut target,
                                HeaderName::from_static("x-unrelated"),
                                HeaderValue::from_static("unchanged"),
                                Mode::Append,
                            );
                            let mut expected = target.clone();
                            if let Some(value) = raw.get(&source_name) {
                                insert(&mut expected, destination.clone(), value.clone(), mode);
                            }
                            let patch = if from_response {
                                Patch::from_response(
                                    &response,
                                    source_name.clone(),
                                    destination.clone(),
                                )
                            } else {
                                Patch::from_headers(&source, source_name.clone())
                            };
                            assert_eq!(format!("{patch:?}"), "HeaderTransferPatch { .. }");
                            patch.apply(&mut target, mode);
                            // Headers equality includes CL's literal bytes, sensitivity and order.
                            assert_eq!(target, expected);
                            assert_eq!(source, import(raw.clone()));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn transfer_is_a_frozen_capture_that_outlives_its_source() {
    let mut raw = HeaderMap::new();
    raw.insert(CONTENT_LENGTH, HeaderValue::from_static(" 009 "));
    let mut source = import(raw);
    let patch = Patch::from_headers(&source, CONTENT_LENGTH);
    source.set_content_length(1);
    drop(source);
    let mut target = Headers::new();
    patch.apply(&mut target, Mode::Replace);
    let mut expected = Headers::new();
    expected.set_content_length_value(HeaderValue::from_static(" 009 "));
    assert_eq!(target, expected);

    let mut response = http::Response::new(());
    response
        .headers_mut()
        .insert(field(), HeaderValue::from_static("before"));
    let patch = Patch::from_response(&response, field(), CONTENT_LENGTH);
    response
        .headers_mut()
        .insert(field(), HeaderValue::from_static("after"));
    drop(response);
    patch.apply(&mut target, Mode::Replace);
    expected.set_content_length_value(HeaderValue::from_static("before"));
    assert_eq!(target, expected);
}

fn selected(name: HeaderName, encoding: Encoding) -> Segment {
    Segment::Field { name, encoding }
}

fn render(value: &[u8], encoding: Encoding) -> Result<String, Error> {
    let mut headers = Headers::new();
    insert(
        &mut headers,
        field(),
        HeaderValue::from_bytes(value).unwrap(),
        Mode::Replace,
    );
    Plan::new([selected(field(), encoding)]).render(&headers)
}

#[test]
fn expansion_uses_only_first_occurrence_including_literal_conflicting_cl() {
    let cases: &[(&[&[u8]], &str)] = &[
        (&[], ""),
        (&[b""], ""),
        (&[b"0"], "0"),
        (&[b" 007 ", b"7"], " 007 "),
        (&[b"1", b"2"], "1"),
        (&[b"1, 2", b"3"], "1, 2"),
        (&[b"invalid", b"4"], "invalid"),
        (&[b"18446744073709551616"], "18446744073709551616"),
        (&[b"\xff", b"later textual"], ""),
        (&["é".as_bytes(), b"later textual"], ""),
    ];
    for name in [CONTENT_LENGTH, field()] {
        for (values, expected) in cases {
            let mut raw = HeaderMap::new();
            for bytes in *values {
                let mut value = HeaderValue::from_bytes(bytes).unwrap();
                value.set_sensitive(true);
                raw.append(name.clone(), value);
            }
            let headers = import(raw);
            let before = headers.clone();
            let plan = Plan::new([
                Segment::Literal("prefix[".into()),
                selected(name.clone(), Encoding::Header),
                Segment::Literal("]suffix".into()),
            ]);
            assert_eq!(
                plan.render(&headers).unwrap(),
                format!("prefix[{expected}]suffix")
            );
            assert_eq!(headers, before);
            assert_eq!(format!("{plan:?}"), "HeaderExpansionPlan { .. }");
        }
    }
}

#[test]
fn percent_encodings_match_non_alphanumeric_not_form_or_url_path_rules() {
    for encoding in [Encoding::UrlQuery, Encoding::PathSegment] {
        assert_eq!(
            render(b"AZaz09 -._~/%?&=+:#@!", encoding).unwrap(),
            "AZaz09%20%2D%2E%5F%7E%2F%25%3F%26%3D%2B%3A%23%40%21"
        );
        assert_eq!(render(b"tab\there", encoding).unwrap(), "tab%09here");
        assert_eq!(render(b"", encoding).unwrap(), "");
        assert_eq!(render(b"\xff", encoding).unwrap(), "");
        assert_eq!(render("é".as_bytes(), encoding).unwrap(), "");
        let headers = Headers::new();
        assert_eq!(
            Plan::new([selected(CONTENT_LENGTH, encoding)])
                .render(&headers)
                .unwrap(),
            ""
        );
    }
}

#[test]
fn header_encoding_validates_without_trimming_or_leaking_text() {
    for text in ["", " padded ", "[]:/?#@", "007, 7"] {
        assert_eq!(render(text.as_bytes(), Encoding::Header).unwrap(), text);
    }
    assert_eq!(render(b"\xff", Encoding::Header).unwrap(), "");
    let err = render(b"secret\tvalue", Encoding::Header).unwrap_err();
    assert_eq!(err, Error::HeaderControlCharacter);
    assert_eq!(
        err.to_string(),
        "template header value contains a control character"
    );
    assert_eq!(format!("{err:?}"), "HeaderControlCharacter");
    // Other ASCII controls are already forbidden at HeaderValue construction.
    for byte in (0..=31).chain([127]).filter(|byte| *byte != b'\t') {
        assert!(HeaderValue::from_bytes(&[byte]).is_err());
    }
}

#[test]
fn host_encoding_preserves_existing_ip_and_hostname_validation() {
    for host in [
        "example.com",
        "EXAMPLE.Com",
        "a-b",
        "0",
        "127.0.0.1",
        "::1",
        "2001:db8::1",
        "999.999.999.999",
    ] {
        assert_eq!(render(host.as_bytes(), Encoding::Host).unwrap(), host);
    }
    // Existing semantics do not add DNS label/total-length limits.
    let long = format!(
        "{}.{}.{}",
        "a".repeat(100),
        "b".repeat(100),
        "c".repeat(100)
    );
    assert_eq!(render(long.as_bytes(), Encoding::Host).unwrap(), long);
    for host in ["", "\u{80}"] {
        assert_eq!(
            render(host.as_bytes(), Encoding::Host),
            Err(Error::EmptyHost)
        );
    }
    for host in ["a/b", "a?b", "a#b", "a@b", "a:b", "[::1]", "a:80", "a\tb"] {
        assert_eq!(
            render(host.as_bytes(), Encoding::Host),
            Err(Error::InvalidHostCharacters)
        );
    }
    for host in [
        ".", "a.", ".a", "a..b", "-a", "a-", "a_b", " a", "a ", "[host]",
    ] {
        assert_eq!(
            render(host.as_bytes(), Encoding::Host),
            Err(Error::InvalidHostName)
        );
    }
    assert_eq!(
        Plan::new([selected(CONTENT_LENGTH, Encoding::Host)]).render(&Headers::new()),
        Err(Error::EmptyHost)
    );
    let mut headers = Headers::new();
    headers.append_content_length_value(HeaderValue::from_bytes(b"\xff").unwrap());
    headers.append_content_length_value(HeaderValue::from_static("example.com"));
    assert_eq!(
        Plan::new([selected(CONTENT_LENGTH, Encoding::Host)]).render(&headers),
        Err(Error::EmptyHost)
    );
}

#[test]
fn plans_compose_only_complete_outputs_and_preserve_literals_verbatim() {
    let mut headers = Headers::new();
    insert(
        &mut headers,
        field(),
        HeaderValue::from_static("a/b"),
        Mode::Replace,
    );
    headers.set_content_length_value(HeaderValue::from_static(" 007 "));
    let plan = Plan::new([
        Segment::Literal("http://example.com/".into()),
        selected(field(), Encoding::PathSegment),
        Segment::Literal("?length=".into()),
        selected(CONTENT_LENGTH, Encoding::UrlQuery),
        Segment::Literal("\n{untouched literal}é".into()),
    ]);
    assert_eq!(
        plan.render(&headers).unwrap(),
        "http://example.com/a%2Fb?length=%20007%20\n{untouched literal}é"
    );
    assert_eq!(Plan::new([]).render(&headers).unwrap(), "");
    assert_eq!(
        format!("{:?}", Segment::Literal("context secret".into())),
        "HeaderExpansionSegment { .. }"
    );
}
