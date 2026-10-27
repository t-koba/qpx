//! External-consumer positive controls for the ownership API and codec boundary.
use http::header::{CONNECTION, CONTENT_LENGTH, HeaderName, HeaderValue};
use http::{Method, StatusCode, Version};
use qpx_core::http_content_length::{
    ContentLengthError, HeaderDiagnostic, HeaderPredicate, HeaderTextSelection,
};
use qpx_core::http_message::{Headers, OrdinaryHeaderName, Request, Response};

fn name(value: &str) -> OrdinaryHeaderName {
    OrdinaryHeaderName::try_from(value).unwrap()
}

#[test]
fn ordinary_names_cannot_select_the_declaration() {
    for value in ["content-length", "Content-Length", "CONTENT-LENGTH"] {
        assert!(OrdinaryHeaderName::try_from(value).is_err());
        assert!(
            OrdinaryHeaderName::try_from(HeaderName::from_bytes(value.as_bytes()).unwrap())
                .is_err()
        );
    }
    for value in ["", "x bad", "x\nfield"] {
        assert!(OrdinaryHeaderName::try_from(value).is_err());
    }
    assert_eq!(name("X-Trace").as_str(), "x-trace");
}

#[test]
fn ordinary_mutation_preserves_bytes_sensitivity_and_occurrence_order() {
    let mut headers = Headers::new();
    let field = name("x-opaque");
    let mut first = HeaderValue::from_bytes(b"\x80\xff").unwrap();
    first.set_sensitive(true);
    headers.insert(field.clone(), first.clone());
    headers.append(field.clone(), HeaderValue::from_static("second"));
    headers.append(field.clone(), HeaderValue::from_static("third"));
    headers.set_content_length(3);
    let values = headers.get_all(&field).collect::<Vec<_>>();
    assert_eq!(values.len(), 3);
    assert_eq!(values[0].as_bytes(), b"\x80\xff");
    assert!(values[0].is_sensitive());
    assert_eq!(values[1], "second");
    assert_eq!(values[2], "third");
    assert_eq!(headers.get(&field), Some(&first));
    assert_eq!(headers.iter().count(), 3);
    assert!(headers.iter().all(|(key, _)| key != CONTENT_LENGTH));
    assert_eq!(
        headers.insert(field.clone(), HeaderValue::from_static("new")),
        Some(first)
    );
    assert_eq!(headers.get_all(&field).count(), 1);
    assert_eq!(headers.remove(&field).unwrap(), "new");
    assert!(headers.get(&field).is_none());
    assert_eq!(headers.declared_content_length(), Ok(Some(3)));
    assert_eq!(format!("{headers:?}"), "Headers { .. }");
}

#[test]
fn request_and_response_agree_on_every_declaration_distinction() {
    use ContentLengthError::{Conflicting, InvalidHeader, InvalidValue};
    type Case<'a> = (&'a [&'a [u8]], Result<Option<u64>, ContentLengthError>);
    let cases: &[Case<'_>] = &[
        (&[], Ok(None)),
        (&[b"0"], Ok(Some(0))),
        (&[b"00, 0", b"0"], Ok(Some(0))),
        (&[b"007, 7", b"7"], Ok(Some(7))),
        (&[b"18446744073709551615"], Ok(Some(u64::MAX))),
        (&[b"18446744073709551616"], Err(InvalidValue)),
        (&[b""], Err(InvalidValue)),
        (&[b"+0"], Err(InvalidValue)),
        (&[b"-1"], Err(InvalidValue)),
        (&[b"1,"], Err(InvalidValue)),
        (&[b"1", b"2"], Err(Conflicting)),
        (&[b"2, 3"], Err(Conflicting)),
        (&[b"\xff"], Err(InvalidHeader)),
    ];
    for (values, expected) in cases {
        let mut raw_request = http::Request::new(());
        let mut raw_response = http::Response::new(());
        for value in *values {
            raw_request
                .headers_mut()
                .append(CONTENT_LENGTH, HeaderValue::from_bytes(value).unwrap());
            raw_response
                .headers_mut()
                .append(CONTENT_LENGTH, HeaderValue::from_bytes(value).unwrap());
        }
        let request = Request::from_http(raw_request);
        let response = Response::from_http(raw_response);
        assert_eq!(
            &request.headers().declared_content_length(),
            expected,
            "{values:?}"
        );
        assert_eq!(
            &response.headers().declared_content_length(),
            expected,
            "{values:?}"
        );
        assert_eq!(request.headers().iter().count(), 0);
        assert_eq!(response.headers().iter().count(), 0);
        match expected {
            Ok(length) => {
                for headers in [
                    request.into_http_for_codec().unwrap().headers(),
                    response.into_http_for_codec().unwrap().headers(),
                ] {
                    let values = headers.get_all(CONTENT_LENGTH).iter().collect::<Vec<_>>();
                    match length {
                        None => assert!(values.is_empty()),
                        Some(length) => {
                            assert_eq!(values.len(), 1);
                            assert_eq!(values[0], length.to_string().as_str());
                        }
                    }
                }
            }
            Err(error) => {
                assert_eq!(request.into_http_for_codec().unwrap_err(), *error);
                assert_eq!(response.into_http_for_codec().unwrap_err(), *error);
            }
        }
    }
}

#[test]
fn typed_edits_distinguish_removal_from_zero_and_can_replace_an_invalid_declaration() {
    let mut raw = http::Request::new(());
    raw.headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from_static("+0"));
    let mut request = Request::from_http(raw);
    request.headers_mut().set_content_length(0);
    assert_eq!(request.headers().declared_content_length(), Ok(Some(0)));
    request.headers_mut().remove_content_length();
    assert_eq!(request.headers().declared_content_length(), Ok(None));
    request.headers_mut().set_content_length(u64::MAX);
    assert_eq!(
        request.into_http_for_codec().unwrap().headers()[CONTENT_LENGTH],
        u64::MAX.to_string()
    );
}

// A deliberately non-Clone body. The header carrier must not constrain a body's
// frame, trailer or error representation, poll it, buffer it, or duplicate it.
#[derive(Debug)]
struct BodyToken {
    payload: Box<str>,
    trailers: http::HeaderMap,
    error: &'static str,
}

fn body() -> BodyToken {
    let mut trailers = http::HeaderMap::new();
    trailers.append("x-trailer", HeaderValue::from_static("first"));
    trailers.append("x-trailer", HeaderValue::from_static("second"));
    BodyToken {
        payload: "payload".into(),
        trailers,
        error: "body read error",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Extension(&'static str);

#[test]
fn request_moves_the_head_through_body_stages_without_a_raw_parts_escape() {
    let mut raw = http::Request::new(body());
    *raw.method_mut() = Method::PATCH;
    *raw.uri_mut() = "https://example.test/a?b=c".parse().unwrap();
    *raw.version_mut() = Version::HTTP_2;
    raw.extensions_mut().insert(Extension("request"));
    raw.headers_mut()
        .append(CONTENT_LENGTH, HeaderValue::from_static("007,7"));
    raw.headers_mut()
        .append(CONTENT_LENGTH, HeaderValue::from_static("7"));
    raw.headers_mut()
        .append(CONNECTION, HeaderValue::from_static("x-nominated"));
    raw.headers_mut()
        .append("x-nominated", HeaderValue::from_static("opaque"));
    let mut sensitive = HeaderValue::from_bytes(b"\xff\x80").unwrap();
    sensitive.set_sensitive(true);
    raw.headers_mut().append("x-bytes", sensitive);
    raw.headers_mut()
        .append("x-bytes", HeaderValue::from_static("second"));
    let request = Request::from_http(raw);
    let (mut head, body) = request.map_body(Some).into_head_and_body();
    assert_eq!(head.method(), Method::PATCH);
    assert_eq!(head.uri(), "https://example.test/a?b=c");
    assert_eq!(head.version(), Version::HTTP_2);
    assert_eq!(
        head.extensions().get::<Extension>(),
        Some(&Extension("request"))
    );
    *head.method_mut() = Method::POST;
    *head.uri_mut() = "/new".parse().unwrap();
    *head.version_mut() = Version::HTTP_11;
    head.extensions_mut().insert(Extension("changed"));
    head.headers_mut()
        .append(name("x-bytes"), HeaderValue::from_static("third"));
    let request = head
        .map_body(|()| body.unwrap())
        .into_http_for_codec()
        .unwrap();
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri(), "/new");
    assert_eq!(request.version(), Version::HTTP_11);
    assert_eq!(
        request.extensions().get::<Extension>(),
        Some(&Extension("changed"))
    );
    assert_eq!(request.headers()[CONTENT_LENGTH], "7");
    assert_eq!(request.headers()[CONNECTION], "x-nominated");
    assert_eq!(request.headers()["x-nominated"], "opaque");
    let values = request
        .headers()
        .get_all("x-bytes")
        .iter()
        .collect::<Vec<_>>();
    assert_eq!(values[0].as_bytes(), b"\xff\x80");
    assert!(values[0].is_sensitive());
    assert_eq!(values[1], "second");
    assert_eq!(values[2], "third");
    let body = request.into_body();
    assert_eq!(&*body.payload, "payload");
    assert_eq!(body.trailers.get_all("x-trailer").iter().count(), 2);
    assert_eq!(body.error, "body read error");
}

#[test]
fn response_moves_body_and_extensions_without_inferring_method_or_status_policy() {
    let mut raw = http::Response::new(body());
    *raw.status_mut() = StatusCode::NO_CONTENT;
    *raw.version_mut() = Version::HTTP_2;
    raw.extensions_mut().insert(Extension("response"));
    raw.headers_mut()
        .append("set-cookie", HeaderValue::from_static("a=1"));
    raw.headers_mut()
        .append("set-cookie", HeaderValue::from_static("b=2"));
    let mut response = Response::from_http(raw);
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.version(), Version::HTTP_2);
    assert_eq!(response.body().error, "body read error");
    response.body_mut().error = "changed error";
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    *response.version_mut() = Version::HTTP_11;
    response.extensions_mut().insert(Extension("changed"));
    let (head, body) = response.into_head_and_body();
    let response = head.map_body(|()| body).into_http_for_codec().unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(response.version(), Version::HTTP_11);
    assert_eq!(
        response.extensions().get::<Extension>(),
        Some(&Extension("changed"))
    );
    assert_eq!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .collect::<Vec<_>>(),
        ["a=1", "b=2"]
    );
    assert!(!response.headers().contains_key(CONTENT_LENGTH));
    assert_eq!(response.body().error, "changed error");
    assert_eq!(
        response.body().trailers.get_all("x-trailer").iter().count(),
        2
    );

    // HEAD/no-body normalization belongs to the protocol stage, not this data
    // type. It must not silently turn a selected representation length into 0.
    let mut response = Response::new(());
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    response.headers_mut().set_content_length(42);
    assert_eq!(
        response.into_http_for_codec().unwrap().headers()[CONTENT_LENGTH],
        "42"
    );
    assert!(
        Request::new(Vec::<u8>::new())
            .into_http_for_codec()
            .unwrap()
            .headers()
            .is_empty()
    );
}

#[test]
fn vary_uses_literal_pre_export_values_not_numeric_framing_equivalence() {
    let make = |value: &'static str| {
        let mut raw = http::Request::new(());
        raw.headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_static(value));
        Request::from_http(raw)
    };
    let padded = make("05");
    let plain = make("5");
    assert_eq!(
        padded.headers().declared_content_length(),
        plain.headers().declared_content_length()
    );
    assert_ne!(
        padded.headers().view().vary_selector("content-length"),
        plain.headers().view().vary_selector("content-length")
    );
    assert_eq!(
        padded.headers().view().joined_text("Content-Length"),
        HeaderTextSelection::Unrepresentable
    );
    let absent = Request::new(());
    let zero = make("0");
    assert_ne!(
        absent.headers().view().vary_selector("content-length"),
        zero.headers().view().vary_selector("content-length")
    );
    let raw = padded.into_http_for_codec().unwrap();
    assert_eq!(raw.headers()[CONTENT_LENGTH], "5");
}

#[test]
fn owner_view_redacts_content_length_trace_case_insensitively() {
    let mut headers = Headers::new();
    headers.append_content_length_value(HeaderValue::from_static("05"));
    let view = headers.view();
    let regex = regex::Regex::new("^0").unwrap();
    let miss = regex::Regex::new("^9").unwrap();
    for name in ["content-length", "Content-Length", "CONTENT-LENGTH"] {
        // Matching still observes the literal text.
        assert!(view.matches(name, HeaderPredicate::Present));
        assert!(view.matches(name, HeaderPredicate::Exact("05")));
        assert!(!view.matches(name, HeaderPredicate::Exact("5")));
        assert!(view.matches(name, HeaderPredicate::Regex(&regex)));
        assert!(!view.matches(name, HeaderPredicate::Regex(&miss)));
        // Trace preserves the boolean but never returns the text.
        for (predicate, matched) in [
            (HeaderPredicate::Present, true),
            (HeaderPredicate::Exact("05"), true),
            (HeaderPredicate::Exact("5"), false),
        ] {
            assert_eq!(
                view.trace(name, predicate),
                HeaderDiagnostic {
                    actual: None,
                    matched,
                },
                "name={name:?} matched={matched}",
            );
        }
        assert_eq!(
            view.trace(name, HeaderPredicate::Regex(&regex)),
            HeaderDiagnostic {
                actual: None,
                matched: true,
            }
        );
        assert_eq!(
            view.trace(name, HeaderPredicate::Regex(&miss)),
            HeaderDiagnostic {
                actual: None,
                matched: false,
            }
        );
        assert_eq!(view.joined_text(name), HeaderTextSelection::Unrepresentable);
    }
    // Absent declaration: redacted trace agrees with the predicate result.
    let absent_headers = Headers::new();
    let absent = absent_headers.view();
    assert_eq!(
        absent.trace("content-length", HeaderPredicate::Present),
        HeaderDiagnostic {
            actual: None,
            matched: false,
        }
    );
    assert!(!absent.matches("CONTENT-LENGTH", HeaderPredicate::Present));
    // Debug never leaks the declaration text.
    assert!(!format!("{:?}", headers.view()).contains("05"));
}

#[test]
fn owner_view_preserves_ordinary_diagnostics() {
    let mut headers = Headers::new();
    let field = name("x-trace");
    headers.insert(field.clone(), HeaderValue::from_static("alpha"));
    headers.append(field.clone(), HeaderValue::from_static("beta"));
    let view = headers.view();
    assert!(view.matches("x-trace", HeaderPredicate::Present));
    assert!(view.matches("x-trace", HeaderPredicate::Exact("beta")));
    assert!(!view.matches("x-trace", HeaderPredicate::Exact("gamma")));
    assert_eq!(
        view.trace("x-trace", HeaderPredicate::Exact("beta")),
        HeaderDiagnostic {
            actual: Some("beta".to_owned()),
            matched: true,
        }
    );
    assert_eq!(
        view.trace("X-TRACE", HeaderPredicate::Exact("gamma")),
        HeaderDiagnostic {
            actual: Some("alpha".to_owned()),
            matched: false,
        }
    );
    assert_eq!(
        view.trace("x-missing", HeaderPredicate::Present),
        HeaderDiagnostic {
            actual: None,
            matched: false,
        }
    );
    // Non-textual occurrences are skipped for matching, first textual wins.
    let mut opaque = Headers::new();
    opaque.append(field.clone(), HeaderValue::from_bytes(&[0xff]).unwrap());
    opaque.append(field.clone(), HeaderValue::from_static("plain"));
    assert!(opaque.view().matches("x-trace", HeaderPredicate::Present));
    assert_eq!(
        opaque.view().trace("x-trace", HeaderPredicate::Present),
        HeaderDiagnostic {
            actual: Some("plain".to_owned()),
            matched: true,
        }
    );
}

#[test]
fn owner_literal_values_preserve_padding_and_duplicates_until_codec_export() {
    // Padded and canonical spellings parse equally but stay Vary-distinct.
    // The literal setters return nothing, so stored text never comes back.
    let mut padded = Request::new(());
    let _: () = padded
        .headers_mut()
        .set_content_length_value(HeaderValue::from_static("05"));
    let mut plain = Request::new(());
    plain.headers_mut().set_content_length(5);
    assert_eq!(
        padded.headers().declared_content_length(),
        Ok(Some(5)),
        "padded and canonical parse numerically",
    );
    assert_eq!(plain.headers().declared_content_length(), Ok(Some(5)));
    assert_ne!(
        padded.headers().view().vary_selector("content-length"),
        plain.headers().view().vary_selector("content-length"),
        "equal padded values remain distinct for pre-export Vary",
    );
    // Duplicate equal padded values are still one numeric length pre-export.
    let mut duplicated = Request::new(());
    let _: () = duplicated
        .headers_mut()
        .append_content_length_value(HeaderValue::from_static("05"));
    let _: () = duplicated
        .headers_mut()
        .append_content_length_value(HeaderValue::from_static("05"));
    assert_eq!(duplicated.headers().declared_content_length(), Ok(Some(5)));
    assert_ne!(
        duplicated.headers().view().vary_selector("content-length"),
        padded.headers().view().vary_selector("content-length"),
    );
    assert_eq!(
        duplicated.headers().view().joined_text("content-length"),
        HeaderTextSelection::Unrepresentable,
    );
    // Zero stays distinct from absent until export.
    let mut zero = Request::new(());
    let _: () = zero
        .headers_mut()
        .set_content_length_value(HeaderValue::from_static("0"));
    assert_eq!(zero.headers().declared_content_length(), Ok(Some(0)));
    let absent_zero = Request::new(());
    assert_ne!(
        zero.headers().view().vary_selector("content-length"),
        absent_zero.headers().view().vary_selector("content-length"),
    );
    // Only the codec handoff canonicalizes to one decimal line.
    for request in [padded, duplicated, zero, plain] {
        let expected = request
            .headers()
            .declared_content_length()
            .unwrap()
            .unwrap();
        let wire = request.into_http_for_codec().unwrap();
        let values = wire
            .headers()
            .get_all(CONTENT_LENGTH)
            .iter()
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], expected.to_string().as_str());
    }
    // The response carrier agrees: padded input canonicalizes only at export.
    let mut response = Response::new(());
    response
        .headers_mut()
        .append_content_length_value(HeaderValue::from_static("007"));
    response
        .headers_mut()
        .append_content_length_value(HeaderValue::from_static("7"));
    assert_eq!(response.headers().declared_content_length(), Ok(Some(7)));
    assert_eq!(
        response.into_http_for_codec().unwrap().headers()[CONTENT_LENGTH],
        "7",
    );
    // Typed set still replaces a literal, and removal still differs from zero.
    let mut typed = Request::new(());
    typed
        .headers_mut()
        .set_content_length_value(HeaderValue::from_static("05"));
    typed.headers_mut().set_content_length(9);
    assert_eq!(typed.headers().declared_content_length(), Ok(Some(9)));
    assert_eq!(
        typed.into_http_for_codec().unwrap().headers()[CONTENT_LENGTH],
        "9",
    );
    let mut removed = Request::new(());
    removed
        .headers_mut()
        .set_content_length_value(HeaderValue::from_static("0"));
    removed.headers_mut().remove_content_length();
    assert_eq!(removed.headers().declared_content_length(), Ok(None));
}

#[test]
fn owner_literal_conflicts_and_invalid_values_still_fail_export() {
    use ContentLengthError::{Conflicting, InvalidHeader, InvalidValue};
    // Each literal shape retains the current validation result and export error.
    let cases: Vec<(Vec<&'static [u8]>, ContentLengthError)> = vec![
        (vec![b"5".as_slice(), b"6".as_slice()], Conflicting),
        (vec![b"2, 3".as_slice()], Conflicting),
        (vec![b"+0".as_slice()], InvalidValue),
        (vec![b"".as_slice()], InvalidValue),
        (vec![b"1,".as_slice()], InvalidValue),
        (vec![&[0xff]], InvalidHeader),
    ];
    for (values, expected) in cases {
        for is_response in [false, true] {
            let mut request = Request::new(());
            let mut response = Response::new(());
            let (req_headers, resp_headers) = (request.headers_mut(), response.headers_mut());
            let mut first = true;
            for value in &values {
                let header = HeaderValue::from_bytes(value).unwrap();
                if first {
                    let _: () = req_headers.set_content_length_value(header.clone());
                    let _: () = resp_headers.set_content_length_value(header);
                    first = false;
                } else {
                    let _: () = req_headers.append_content_length_value(header.clone());
                    let _: () = resp_headers.append_content_length_value(header);
                }
            }
            assert_eq!(request.headers().declared_content_length(), Err(expected));
            assert_eq!(response.headers().declared_content_length(), Err(expected));
            if is_response {
                assert_eq!(response.into_http_for_codec().unwrap_err(), expected);
            } else {
                assert_eq!(request.into_http_for_codec().unwrap_err(), expected);
            }
        }
    }
}

#[test]
fn literal_presence_does_not_resolve_or_hide_invalid_declarations() {
    let mut headers = Headers::new();
    let ordinary = name("x-bin");
    assert!(!headers.contains_content_length());
    assert!(!headers.contains_key(&ordinary));
    assert_eq!(headers.declared_content_length(), Ok(None));
    for value in ["", "bad", "5, 6"] {
        headers.set_content_length_value(HeaderValue::from_str(value).unwrap());
        assert!(headers.contains_content_length());
        assert!(headers.declared_content_length().is_err());
    }
    headers.set_content_length(0);
    assert!(headers.contains_content_length());
    assert_eq!(headers.declared_content_length(), Ok(Some(0)));
    headers.append_content_length_value(HeaderValue::from_static("1"));
    assert!(headers.contains_content_length());
    assert_eq!(
        headers.declared_content_length(),
        Err(ContentLengthError::Conflicting)
    );
    headers.remove_content_length();
    assert!(!headers.contains_content_length());
    headers.insert(ordinary.clone(), HeaderValue::from_bytes(b"\xff").unwrap());
    assert!(headers.contains_key(&ordinary));
}

#[test]
fn frozen_equality_is_literal_ordered_and_sensitivity_aware_for_every_field() {
    let mut headers = Headers::new();
    headers.set_content_length_value(HeaderValue::from_static(" 5 "));
    headers.append_content_length_value(HeaderValue::from_static("5"));
    headers.insert(name("x-bin"), HeaderValue::from_bytes(b"\xff").unwrap());
    headers.append(name("x-bin"), HeaderValue::from_static("second"));
    let frozen = headers.clone();
    assert_eq!(headers, frozen);

    let mut changed = headers.clone();
    changed.set_content_length(5);
    assert_eq!(
        changed.declared_content_length(),
        frozen.declared_content_length()
    );
    assert_ne!(changed, frozen); // not just the parsed length or ordinary fields
    changed.append_content_length_value(HeaderValue::from_static(" 5 "));
    assert_ne!(changed, frozen); // same number/count but reversed occurrence order
    changed.set_content_length_value(HeaderValue::from_static(" 5 "));
    changed.append_content_length_value(HeaderValue::from_static("5"));
    assert_eq!(changed, frozen);
    let mut sensitive = HeaderValue::from_static("5");
    sensitive.set_sensitive(true);
    changed.set_content_length_value(HeaderValue::from_static(" 5 "));
    changed.append_content_length_value(sensitive);
    assert_ne!(changed, frozen); // sensitivity of a non-first CL occurrence
    let mut changed = headers.clone();
    let mut sensitive = HeaderValue::from_static("second");
    sensitive.set_sensitive(true);
    changed.insert(name("x-bin"), HeaderValue::from_bytes(b"\xff").unwrap());
    changed.append(name("x-bin"), sensitive);
    assert_ne!(changed, frozen); // ordinary sensitivity too
    changed.remove(&name("x-bin"));
    changed.insert(name("x-bin"), HeaderValue::from_static("second"));
    changed.append(name("x-bin"), HeaderValue::from_bytes(b"\xff").unwrap());
    assert_ne!(changed, frozen);
    assert_eq!(headers, frozen); // a frozen clone is independent of later edits

    let mut left = Headers::new();
    left.insert(name("x-a"), HeaderValue::from_static("a"));
    left.set_content_length_value(HeaderValue::from_static("bad"));
    let mut right = Headers::new();
    right.set_content_length_value(HeaderValue::from_static("bad"));
    right.insert(name("x-a"), HeaderValue::from_static("a"));
    assert_eq!(left, right); // distinct-name insertion order is not meaningful
    right.set_content_length_value(HeaderValue::from_static("worse"));
    assert_ne!(left, right); // even two malformed declarations differ literally
}

fn identity_headers(name: &HeaderName, values: &[&[u8]]) -> Headers {
    let mut request = http::Request::new(());
    for value in values {
        request
            .headers_mut()
            .append(name, HeaderValue::from_bytes(value).unwrap());
    }
    Request::from_http(request).headers().clone()
}

#[test]
fn identity_selections_preserve_literal_occurrence_and_member_order() {
    // Both configured ordinary fields and Content-Length have the same literal
    // extraction domain. None of these selections resolves framing.
    for field in [HeaderName::from_static("x-identity"), CONTENT_LENGTH] {
        let headers = identity_headers(
            &field,
            &[b"\xff", b" \t", b" 007, 7, 007, A, a ", b" a, 0, A "],
        );
        assert_eq!(
            headers.identity_text(&field).as_deref(),
            Some("007, 7, 007, A, a")
        );
        assert_eq!(
            headers.identity_members(&field),
            ["007", "7", "A", "a", "0"]
        );
        assert_eq!(
            headers.identity_assertion(&field, None),
            Some("007, 7, 007, A, a")
        );
        assert_eq!(
            headers.identity_assertion(&field, Some("007,")),
            Some("7, 007, A, a")
        );
        assert_eq!(format!("{headers:?}"), "Headers { .. }");
    }
}

#[test]
fn identity_content_length_is_not_parsed_or_canonicalized() {
    for (values, scalar, members) in [
        (vec![], None, vec![]),
        (vec![&b""[..], b" \t"], None, vec![]),
        (vec![&b" 000 "[..], b"0"], Some("000"), vec!["000", "0"]),
        (
            vec![&b" 007, 7 "[..], b"8"],
            Some("007, 7"),
            vec!["007", "7", "8"],
        ),
        (
            vec![&b" invalid "[..], b"9"],
            Some("invalid"),
            vec!["invalid", "9"],
        ),
        (vec![&b"\xff"[..], b" 5 "], Some("5"), vec!["5"]),
    ] {
        let headers = identity_headers(&CONTENT_LENGTH, &values);
        assert_eq!(headers.identity_text(&CONTENT_LENGTH).as_deref(), scalar);
        assert_eq!(headers.identity_members(&CONTENT_LENGTH), members);
        assert_eq!(headers.identity_assertion(&CONTENT_LENGTH, None), scalar);
        // Selection leaves all bytes/occurrences unchanged inside the owner.
        assert_eq!(headers, identity_headers(&CONTENT_LENGTH, &values));
    }
}

#[test]
fn identity_assertion_selects_first_eligible_literal_prefix() {
    for field in [HeaderName::from_static("x-assertion"), CONTENT_LENGTH] {
        let headers = identity_headers(
            &field,
            &[
                b"\xff",
                b" ",
                b"token wrong-case",
                b"Token ",
                b"  Token   first  ",
                b"Token second",
            ],
        );
        assert_eq!(
            headers.identity_assertion(&field, Some("Token ")),
            Some("first")
        );
        assert_eq!(
            headers.identity_assertion(&field, None),
            Some("token wrong-case")
        );
        assert_eq!(headers.identity_assertion(&field, Some("missing ")), None);
        assert_eq!(
            headers.identity_assertion(&field, Some("")),
            Some("token wrong-case")
        );
    }
}

#[test]
fn identity_authorization_preserves_exact_one_and_malformed_distinctions() {
    use qpx_core::http_message::IdentityAuthorizationError::*;
    // Even a configured Content-Length credential source must select literals.
    for field in [http::header::AUTHORIZATION, CONTENT_LENGTH] {
        let cases: &[(&[&[u8]], _)] = &[
            (&[], Ok(None)),
            (&[b""], Err(MalformedBearer)),
            (&[b"\xff"], Err(NonTextual)),
            (&[b"", b"Bearer valid"], Err(Duplicate)),
            (&[b"\xff", b"Bearer valid"], Err(Duplicate)),
            (&[b"Bearer same", b"Bearer same"], Err(Duplicate)),
            (&[b"Bearer"], Err(MalformedBearer)),
            (&[b"Bearer "], Err(MalformedBearer)),
            (&[b"Bearer  token"], Err(MalformedBearer)),
            (&[b"Bearer a\tb"], Err(MalformedBearer)),
            (&[b"Bearer a, Bearer b"], Err(MalformedBearer)),
            (&[b"Basic token"], Err(MalformedAuthorization)),
            (&[b"  bEaReR token \t"], Ok(Some(("token", false)))),
            (&[b"DPoP proof"], Ok(Some(("proof", true)))),
        ];
        for (values, expected) in cases {
            let headers = identity_headers(&field, values);
            assert_eq!(headers.identity_authorization(&field, true), *expected);
        }
        assert_eq!(
            identity_headers(&field, &[b"DPoP proof"]).identity_authorization(&field, false),
            Err(DpopDisabled)
        );
    }
}

#[test]
fn field_count_includes_duplicate_framing_fields_without_reading_them() {
    let mut headers = Headers::new();
    headers.append(name("cookie"), HeaderValue::from_static("a=1"));
    headers.append(name("cookie"), HeaderValue::from_static("b=2"));
    headers.append_content_length_value(HeaderValue::from_static("invalid"));
    headers.append_content_length_value(HeaderValue::from_static("000"));
    assert_eq!(headers.field_count(), 4);
    assert_eq!(headers.iter().count(), 2);
}

#[test]
fn field_bytes_include_all_occurrences_and_trim_only_http_ows() {
    let mut headers = Headers::new();
    headers.append_content_length_value(HeaderValue::from_static(" 01 "));
    headers.append_content_length_value(HeaderValue::from_static("1"));
    let field = name("x-test");
    headers.append(field.clone(), HeaderValue::from_bytes(b" \t\xff ").unwrap());
    headers.append(field, HeaderValue::from_static("\t  "));
    assert_eq!(headers.field_count(), 4);
    assert_eq!(
        headers.field_bytes(false),
        (14 + 4) + (14 + 1) + (6 + 4) + (6 + 3)
    );
    assert_eq!(headers.field_bytes(true), (14 + 2) + (14 + 1) + (6 + 1) + 6);
}

#[test]
fn request_policy_cookie_view_matches_legacy_decoder_without_mutation() {
    use qpx_core::http_content_length::HeaderView;

    // Expected values are the old decoders' logical field, not a mutation of
    // the input. None denotes an absent field; opaque values stay opaque.
    type Case<'a> = (&'a [&'a [u8]], Option<&'a [u8]>, Option<&'a [u8]>);
    let cases: &[Case<'_>] = &[
        (&[], None, None),
        (&[b""], Some(b""), Some(b"")),
        (&[b"a=1"], Some(b"a=1"), Some(b"a=1")),
        (&[b"", b""], None, Some(b"; ")),
        (&[b"", b"a=1", b""], Some(b"a=1; "), Some(b"; a=1; ")),
        (
            &[b"a=1", b"", b"b=2"],
            Some(b"a=1; ; b=2"),
            Some(b"a=1; ; b=2"),
        ),
        (&[b"a=1", b"b=2"], Some(b"a=1; b=2"), Some(b"a=1; b=2")),
        (&[b"\xff"], Some(b"\xff"), Some(b"\xff")),
        (&[b"a=1", b"\xff"], Some(b"a=1; \xff"), Some(b"a=1; \xff")),
        (&[b"\xff", b"a=1"], Some(b"\xff; a=1"), Some(b"\xff; a=1")),
    ];
    let regex = regex::Regex::new("a=1.*b=2").unwrap();
    let predicates = [
        HeaderPredicate::Present,
        HeaderPredicate::Exact(""),
        HeaderPredicate::Exact("a=1"),
        HeaderPredicate::Exact("a=1; b=2"),
        HeaderPredicate::Exact("; "),
        HeaderPredicate::Regex(&regex),
    ];
    for (fields, h2, h3) in cases {
        let mut headers = Headers::new();
        for (index, value) in fields.iter().enumerate() {
            let mut field = HeaderValue::from_bytes(value).unwrap();
            field.set_sensitive(index % 2 == 0);
            headers.append(name("cookie"), field);
        }
        headers.append(name("set-cookie"), HeaderValue::from_static("one"));
        headers.append(name("set-cookie"), HeaderValue::from_static("two"));
        headers.set_content_length(7);
        let original: Vec<_> = headers
            .get_all(&name("cookie"))
            .map(|v| (v.as_bytes().to_vec(), v.is_sensitive()))
            .collect();
        for (version, expected) in [(Version::HTTP_2, h2), (Version::HTTP_3, h3)] {
            let mut legacy = http::HeaderMap::new();
            if let Some(value) = expected {
                legacy.append("cookie", HeaderValue::from_bytes(value).unwrap());
            }
            let expected_view = HeaderView::new(&legacy);
            let view = headers.request_policy_view(version);
            for predicate in predicates {
                assert_eq!(
                    view.matches("CoOkIe", predicate),
                    expected_view.matches("cookie", predicate),
                    "{version:?} {fields:?}"
                );
                assert_eq!(
                    view.trace("CoOkIe", predicate),
                    expected_view.trace("cookie", predicate),
                    "{version:?} {fields:?}"
                );
            }
            assert!(view.matches("set-cookie", HeaderPredicate::Exact("two")));
            assert_eq!(
                view.trace("CONTENT-LENGTH", HeaderPredicate::Exact("7")),
                HeaderDiagnostic {
                    actual: None,
                    matched: true
                }
            );
            assert_eq!(
                view.joined_text("cookie"),
                headers.view().joined_text("cookie")
            );
            assert_eq!(
                view.vary_selector("cookie"),
                headers.view().vary_selector("cookie")
            );
        }
        let after: Vec<_> = headers
            .get_all(&name("cookie"))
            .map(|v| (v.as_bytes().to_vec(), v.is_sensitive()))
            .collect();
        assert_eq!(original, after);
        for predicate in predicates {
            assert_eq!(
                headers
                    .request_policy_view(Version::HTTP_11)
                    .trace("cookie", predicate),
                headers.view().trace("cookie", predicate)
            );
        }
    }
}
