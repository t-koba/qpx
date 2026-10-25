//! Public response API: write-only construction and complete terminal artifacts.
use bytes::Bytes;
use qpxf::executor::{CgiResponse, CgiResponseHeaders};

#[test]
fn construction_preserves_ordered_duplicates_and_binary_body() {
    let mut headers = CgiResponseHeaders::from_pairs(vec![
        ("Set-Cookie".into(), "a=1".into()),
        ("set-cookie".into(), "b=2".into()),
    ]);
    headers.push(("Set-Cookie".into(), "c=3".into()));
    assert_eq!(format!("{headers:?}"), "CgiResponseHeaders { .. }");
    let mut response = CgiResponse {
        status: 201,
        headers,
        body: Bytes::from_static(b"\0\xffbody"),
    };
    assert_eq!(
        response.to_cgi_output().as_ref(),
        b"Status: 201\r\nSet-Cookie: a=1\r\nset-cookie: b=2\r\nSet-Cookie: c=3\r\n\r\n\0\xffbody"
    );
    // Status and body remain independently accessible and mutable.
    response.status = 202;
    response.body = Bytes::from_static(b"changed");
    assert_eq!(response.clone().status, 202);
    assert_eq!(response.body.as_ref(), b"changed");
}

#[test]
fn parsing_and_ipc_transfer_preserve_pairs_without_http_value_validation() {
    let headers = b" Status : 201 Created\r\n Set-Cookie : a=1 \r\nset-cookie: b=2\r\nsTaTuS: 202 Accepted extra tokens\r\nSet-Cookie: c=3\r\nContent-Length: not-a-number\r\ncontent-length: 7\r\nX-Control: a\x01b\r\nX-Unicode: \x63af\xc3\xa9\r\n\r\n";
    let body = b"\xff\0body\n\n";
    let data = [headers.as_slice(), body].concat();
    let head = CgiResponse::parse_cgi_head(&data).unwrap();
    assert_eq!(head.body_offset(), headers.len());
    let (meta, offset) = head.into_ipc_response();
    assert_eq!(offset, headers.len());
    let wire = r#"{"status":202,"headers":[["Set-Cookie","a=1"],["set-cookie","b=2"],["Set-Cookie","c=3"],["Content-Length","not-a-number"],["content-length","7"],["X-Control","a\u0001b"],["X-Unicode","café"]]}"#;
    assert_eq!(serde_json::to_string(&meta).unwrap(), wire);

    let response = CgiResponse::parse_cgi_output(&data).unwrap();
    assert_eq!(response.status, meta.status);
    assert_eq!(response.body.as_ref(), &data[offset..]);
    let normalized = response.to_cgi_output();
    assert_eq!(
        normalized.as_ref(),
        [
            b"Status: 202\r\nSet-Cookie: a=1\r\nset-cookie: b=2\r\nSet-Cookie: c=3\r\nContent-Length: not-a-number\r\ncontent-length: 7\r\nX-Control: a\x01b\r\nX-Unicode: \x63af\xc3\xa9\r\n\r\n".as_slice(),
            body,
        ].concat()
    );
    let (normalized_meta, _) = CgiResponse::parse_cgi_head(&normalized)
        .unwrap()
        .into_ipc_response();
    assert_eq!(serde_json::to_string(&normalized_meta).unwrap(), wire);
}

#[test]
fn earliest_terminator_offsets_and_full_parse_agree() {
    for (headers, body) in [
        (
            b"X-Test: yes\r\n\r\n".as_slice(),
            b"body\n\nlater".as_slice(),
        ),
        (
            b"X-Test: yes\n\n".as_slice(),
            b"body\r\n\r\nlater".as_slice(),
        ),
        (b"\r\n\r\n".as_slice(), b"\xff\n\n".as_slice()),
        (b"\n\n".as_slice(), b"\xff\r\n\r\n".as_slice()),
    ] {
        // Head parsing has the same offset whether or not body bytes are present.
        for data in [headers.to_vec(), [headers, body].concat()] {
            let head = CgiResponse::parse_cgi_head(&data).unwrap();
            assert_eq!(head.body_offset(), headers.len());
            let (meta, offset) = head.into_ipc_response();
            assert_eq!(offset, headers.len());
            assert_eq!(meta.status, 200);
            let response = CgiResponse::parse_cgi_output(&data).unwrap();
            assert_eq!(response.status, meta.status);
            assert_eq!(response.body.as_ref(), &data[offset..]);
            let (full_meta, _) = CgiResponse::parse_cgi_head(&response.to_cgi_output())
                .unwrap()
                .into_ipc_response();
            assert_eq!(
                serde_json::to_string(&full_meta).unwrap(),
                serde_json::to_string(&meta).unwrap()
            );
        }
    }
}

#[test]
fn status_token_parsing_and_boundaries_are_unchanged() {
    for (input, expected) in [
        ("Status: 100 Continue\n\n", 100),
        ("STATUS: 599 anything\n\n", 599),
        ("Status: +201 reason words ignored\n\n", 201),
        ("Status: 201\nsTaTuS: 204\n\n", 204),
    ] {
        let response = CgiResponse::parse_cgi_output(input.as_bytes()).unwrap();
        assert_eq!(response.status, expected);
        assert_eq!(
            response.to_cgi_output().as_ref(),
            format!("Status: {expected}\r\n\r\n").as_bytes()
        );
    }
}

#[test]
fn head_and_full_parse_reject_the_same_malformed_input() {
    for (data, error) in [
        (b"X: y".as_slice(), "missing header terminator"),
        (b"not a header\n\n".as_slice(), "malformed header line"),
        (b": value\n\n".as_slice(), "invalid header name"),
        (b"bad name: value\n\n".as_slice(), "invalid header name"),
        (b"X: \xff\n\n".as_slice(), "invalid utf-8"),
        (b"Status: \n\n".as_slice(), "Status header is empty"),
        (b"Status: nope\n\n".as_slice(), "invalid digit"),
        (b"Status: 99\n\n".as_slice(), "out of range"),
        (b"Status: 600\n\n".as_slice(), "out of range"),
        (b"Status: 65536\n\n".as_slice(), "too large"),
        // An invalid earlier Status still errors before a later valid Status.
        (b"Status: nope\nStatus: 200\n\n".as_slice(), "invalid digit"),
    ] {
        let head_error = CgiResponse::parse_cgi_head(data).err().unwrap().to_string();
        let full_error = CgiResponse::parse_cgi_output(data).unwrap_err().to_string();
        assert!(
            head_error.contains(error),
            "{head_error:?}, expected {error:?}"
        );
        assert_eq!(full_error, head_error);
    }
}
