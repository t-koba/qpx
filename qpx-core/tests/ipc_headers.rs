#![cfg(feature = "ipc-support")]

use http::{Response, Uri};
use qpx_core::http_content_length::ContentLengthError;
use qpx_core::ipc::meta::{IpcRequestHeaders, IpcRequestMeta, IpcResponseHeaders, IpcResponseMeta};

fn request_headers(pairs: &[(&str, &str)]) -> IpcRequestHeaders {
    IpcRequestHeaders::from_pairs(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

#[test]
fn request_wire_is_exact_and_round_trips_ordered_duplicates() {
    let wire = r#"{"method":"POST","uri":"/app","server_protocol":"HTTP/1.1","headers":[["X-Dup","first"],["x-dup","second"],["X-Dup","third"]],"params":{}}"#;
    let mut meta: IpcRequestMeta = serde_json::from_str(wire).unwrap();
    assert_eq!(serde_json::to_string(&meta).unwrap(), wire);
    meta.headers = request_headers(&[("X-Dup", "first"), ("x-dup", "second")]);
    meta.headers.push(("X-Dup".into(), "third".into()));
    let encoded = serde_json::to_string(&meta).unwrap();
    assert_eq!(encoded, wire);
    let decoded: IpcRequestMeta = serde_json::from_str(&encoded).unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);
    assert_eq!(format!("{:?}", meta.headers), "IpcRequestHeaders { .. }");
}

#[test]
fn response_wire_is_exact_and_round_trips_ordered_duplicates() {
    let wire = r#"{"status":201,"headers":[["Set-Cookie","a=1"],["set-cookie","b=2"],["Set-Cookie","c=3"]]}"#;
    let mut meta: IpcResponseMeta = serde_json::from_str(wire).unwrap();
    assert_eq!(serde_json::to_string(&meta).unwrap(), wire);
    meta.headers = IpcResponseHeaders::from_pairs(vec![
        ("Set-Cookie".into(), "a=1".into()),
        ("set-cookie".into(), "b=2".into()),
    ]);
    meta.headers.push(("Set-Cookie".into(), "c=3".into()));
    let encoded = serde_json::to_string(&meta).unwrap();
    assert_eq!(encoded, wire);
    let decoded: IpcResponseMeta = serde_json::from_str(&encoded).unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);
    assert_eq!(format!("{:?}", meta.headers), "IpcResponseHeaders { .. }");
}

#[test]
fn first_host_and_content_type_win_case_insensitively() {
    let uri: Uri = "https://uri.test:8443/app".parse().unwrap();
    for (host, expected_name, expected_port) in [
        ("  First.test:8080  ", "First.test", 8080),
        ("[::1]:9090", "::1", 9090),
        ("first.test:invalid", "first.test", 80),
        ("first.test", "first.test", 80),
    ] {
        let headers = request_headers(&[
            ("hOsT", host),
            ("Host", "ignored.test:99"),
            ("CONTENT-TYPE", "text/plain"),
            ("content-type", "ignored/type"),
        ]);
        assert_eq!(headers.route_host(&uri).as_deref(), Some(expected_name));
        assert_eq!(
            headers.server_name_and_port(&uri),
            (expected_name.into(), expected_port)
        );
        assert_eq!(headers.content_type(), "text/plain");
    }
}

#[test]
fn host_fallback_keeps_routing_distinct_from_server_selection() {
    let uri: Uri = "https://uri.test:8443/app".parse().unwrap();
    let empty = IpcRequestHeaders::default();
    assert_eq!(empty.route_host(&uri).as_deref(), Some("uri.test"));
    assert_eq!(empty.server_name_and_port(&uri), ("uri.test".into(), 8443));
    assert_eq!(empty.content_type(), "");
    let relative: Uri = "/app".parse().unwrap();
    assert_eq!(empty.route_host(&relative), None);
    assert_eq!(
        empty.server_name_and_port(&relative),
        ("localhost".into(), 80)
    );
    for malformed in ["", "  ", "[broken"] {
        let headers = request_headers(&[("host", malformed), ("host", "ignored.test")]);
        assert_eq!(headers.route_host(&uri).as_deref(), Some("uri.test"));
        assert_eq!(headers.server_name_and_port(&uri), ("localhost".into(), 80));
        assert_eq!(headers.route_host(&relative), None);
    }
    let empty_type = request_headers(&[("Content-Type", ""), ("content-type", "ignored")]);
    assert_eq!(empty_type.content_type(), "");
}

#[test]
fn declared_length_uses_owner_and_preserves_absent_zero_and_u64() {
    assert_eq!(
        IpcRequestHeaders::default()
            .declared_content_length()
            .unwrap(),
        None
    );
    for (value, expected) in [
        ("0", 0),
        (" 5, 005 ", 5),
        ("18446744073709551615", u64::MAX),
    ] {
        let headers = request_headers(&[("CONTENT-LENGTH", value), ("content-length", value)]);
        assert_eq!(headers.declared_content_length().unwrap(), Some(expected));
    }
    let conflicting = request_headers(&[("Content-Length", "5"), ("content-length", "6")]);
    assert!(matches!(
        conflicting.declared_content_length(),
        Err(ContentLengthError::Conflicting)
    ));
    for invalid in ["", "+5", "-1", "nope", "5,", "18446744073709551616"] {
        assert!(
            request_headers(&[("content-length", invalid)])
                .declared_content_length()
                .is_err(),
            "{invalid}"
        );
    }
    assert!(
        request_headers(&[("content-length", "5, 6")])
            .declared_content_length()
            .is_err()
    );
}

#[test]
fn response_builder_appends_duplicates_and_defers_invalid_fields() {
    let meta: IpcResponseMeta = serde_json::from_str(
        r#"{"status":200,"headers":[["Set-Cookie","a=1"],["set-cookie","b=2"],["X-Dup","first"],["x-dup","second"]]}"#,
    ).unwrap();
    let response = meta
        .headers
        .apply_to_response(Response::builder().header("set-cookie", "prior=0"))
        .body(())
        .unwrap();
    assert_eq!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["prior=0", "a=1", "b=2"]
    );
    assert_eq!(
        response
            .headers()
            .get_all("x-dup")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    for (name, value) in [("bad name", "value"), ("x-good", "bad\r\nvalue")] {
        let fields = IpcResponseHeaders::from_pairs(vec![(name.into(), value.into())]);
        let builder = fields.apply_to_response(Response::builder());
        assert!(builder.body(()).is_err());
    }
    let fields = IpcResponseHeaders::default();
    assert!(
        fields
            .apply_to_response(Response::builder().status(0))
            .body(())
            .is_err()
    );
}
