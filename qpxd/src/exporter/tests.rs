use super::*;
use qpx_core::config::CaptureRedactionConfig;

#[test]
fn redacts_plaintext_headers_and_query_keys() {
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: vec![
            "authorization".to_string(),
            "cookie".to_string(),
            "set-cookie".to_string(),
        ],
        query_keys: vec!["token".to_string()],
        json_paths: vec![
            "$.password".to_string(),
            "$.nested.access_token".to_string(),
        ],
    });
    let out = redaction.redact_plaintext(
        b"POST /api?token=secret&ok=yes HTTP/1.1\r\nauthorization: bearer secret\r\ncookie: sid=secret\r\nset-cookie: sid=secret\r\nhost: example.com\r\ncontent-type: application/json\r\n\r\n{\"password\":\"secret\",\"nested\":{\"access_token\":\"abc\"},\"ok\":true}",
    );
    let text = String::from_utf8(out.into_owned()).expect("utf8");
    assert!(text.contains("token=<redacted>"));
    assert!(text.contains("authorization: <redacted>"));
    assert!(text.contains("cookie: <redacted>"));
    assert!(text.contains("set-cookie: <redacted>"));
    assert!(text.contains("host: example.com"));
    assert!(!text.contains("bearer secret"));
    assert!(text.contains("\"password\":\"<redacted>\""));
    assert!(text.contains("\"access_token\":\"<redacted>\""));
    assert!(!text.contains("\"secret\""));
    assert!(!text.contains("\"abc\""));
}

#[test]
fn redacts_percent_encoded_query_keys_without_rewriting_key_spelling() {
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: Vec::new(),
        query_keys: vec!["token".to_string(), "access_token".to_string()],
        json_paths: Vec::new(),
    });
    let out = redaction.redact_plaintext(
        b"GET /api?t%6fken=secret&access%5Ftoken=abc&ok=yes HTTP/1.1\r\nhost: example.com\r\n\r\n",
    );
    let text = String::from_utf8(out.into_owned()).expect("utf8");
    assert!(text.contains("t%6fken=<redacted>"));
    assert!(text.contains("access%5Ftoken=<redacted>"));
    assert!(text.contains("ok=yes"));
    assert!(!text.contains("secret"));
    assert!(!text.contains("abc"));
}

#[test]
fn redacts_partial_request_line_before_truncation_can_leak_query() {
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: Vec::new(),
        query_keys: vec!["token".to_string()],
        json_paths: Vec::new(),
    });
    let out = redaction.redact_plaintext(b"GET /cb?token=secret");
    let text = String::from_utf8(out.into_owned()).expect("utf8");
    assert_eq!(text, "GET /cb?token=<redacted>");
    assert!(!text.contains("secret"));
}

#[test]
fn redacts_uri_query_keys_inside_response_uri_headers() {
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: Vec::new(),
        query_keys: vec!["access_token".to_string(), "code".to_string()],
        json_paths: Vec::new(),
    });
    let out = redaction.redact_plaintext(
        b"HTTP/1.1 302 Found\r\nLocation: https://idp.example/cb?access_token=secret&ok=yes\r\nContent-Location: /done?code=abc\r\nRefresh: 0; URL \t= \"https://idp.example/next#access_token=refresh\"\r\nLink: <https://idp.example/a#code=link>; rel=\"next\"\r\n\r\n",
    );
    let text = String::from_utf8(out.into_owned()).expect("utf8");
    assert!(text.contains("access_token=<redacted>"));
    assert!(text.contains("code=<redacted>"));
    assert!(text.contains("ok=yes"));
    assert!(!text.contains("secret"));
    assert!(!text.contains("abc"));
    assert!(!text.contains("refresh"));
    assert!(!text.contains("code=link"));
}

#[test]
fn redacts_body_only_json_plaintext_samples() {
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: Vec::new(),
        query_keys: Vec::new(),
        json_paths: vec!["$.password".to_string()],
    });
    let out = redaction.redact_plaintext(br#"{"password":"secret","ok":true}"#);
    let text = String::from_utf8(out.into_owned()).expect("utf8");
    assert!(text.contains("\"password\":\"<redacted>\""));
    assert!(!text.contains("secret"));
}

#[test]
fn redacts_unparsable_json_samples_fail_closed() {
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: Vec::new(),
        query_keys: Vec::new(),
        json_paths: vec!["$.password".to_string()],
    });
    let out = redaction.redact_plaintext(br#"{"password":"secret","x":"#);
    let text = String::from_utf8(out.into_owned()).expect("utf8");
    assert_eq!(text, "<redacted>");
    assert!(!text.contains("secret"));
}

#[test]
fn redacts_non_utf8_plaintext_fail_closed_when_redaction_is_enabled() {
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: vec!["authorization".to_string()],
        query_keys: Vec::new(),
        json_paths: Vec::new(),
    });
    let out = redaction.redact_plaintext(b"\xffauthorization=secret");
    assert_eq!(out.as_ref(), b"<redacted>");
}

#[test]
fn redacts_structured_json_content_types() {
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: Vec::new(),
        query_keys: Vec::new(),
        json_paths: vec!["$.detail.secret".to_string()],
    });
    let out = redaction.redact_plaintext(
        b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/problem+json; charset=utf-8\r\n\r\n{\"detail\":{\"secret\":\"leak\"},\"status\":400}",
    );
    let text = String::from_utf8(out.into_owned()).expect("utf8");
    assert!(text.contains("\"secret\":\"<redacted>\""));
    assert!(!text.contains("leak"));
}

#[test]
fn plaintext_export_emits_only_redacted_and_truncated_payload() {
    let (tx, mut rx) = mpsc::channel(1);
    let session = ExportSession {
        tx,
        session_id: "test-session".to_string(),
        client: "client".to_string(),
        server: "server".to_string(),
        capture_plaintext: true,
        capture_encrypted: false,
        max_plaintext_bytes: Some(80),
        max_chunk_bytes: 1024,
        redaction: Arc::new(CaptureRedaction::from_config(&CaptureRedactionConfig {
            headers: vec!["authorization".to_string()],
            query_keys: vec!["token".to_string()],
            json_paths: vec!["$.password".to_string()],
        })),
    };

    session.emit_plaintext(
        true,
        b"POST /api?token=secret HTTP/1.1\r\nauthorization: bearer secret\r\ncontent-type: application/json\r\n\r\n{\"password\":\"secret\",\"extra\":\"this text must be truncated\"}",
    );

    let event = rx.try_recv().expect("redacted event");
    let text = String::from_utf8(event.payload.to_vec()).expect("utf8");
    assert_eq!(event.plane, CapturePlane::ClientServerPlaintext);
    assert!(text.len() <= 80);
    assert!(text.contains("token=<redacted>"));
    assert!(text.contains("authorization: <redacted>"));
    assert!(!text.contains("bearer secret"));
    assert!(!text.contains("token=secret"));
}

#[test]
fn plaintext_export_redacts_full_payload_before_truncating() {
    let (tx, mut rx) = mpsc::channel(1);
    let session = ExportSession {
        tx,
        session_id: "test-session".to_string(),
        client: "client".to_string(),
        server: "server".to_string(),
        capture_plaintext: true,
        capture_encrypted: false,
        max_plaintext_bytes: Some(24),
        max_chunk_bytes: 1024,
        redaction: Arc::new(CaptureRedaction::from_config(&CaptureRedactionConfig {
            headers: Vec::new(),
            query_keys: vec!["token".to_string()],
            json_paths: Vec::new(),
        })),
    };

    session.emit_plaintext(
        true,
        b"GET /cb?token=secret HTTP/1.1\r\nhost: example\r\n\r\n",
    );

    let event = rx.try_recv().expect("event");
    let text = String::from_utf8(event.payload.to_vec()).expect("utf8");
    assert!(text.len() <= 24);
    assert!(text.starts_with("GET /cb?token=<redact"));
    assert!(!text.contains("secret"));
}

#[test]
fn plaintext_export_drops_before_redaction_when_queue_is_full() {
    let (tx, mut rx) = mpsc::channel(1);
    let session = ExportSession {
        tx: tx.clone(),
        session_id: "test-session".to_string(),
        client: "client".to_string(),
        server: "server".to_string(),
        capture_plaintext: true,
        capture_encrypted: false,
        max_plaintext_bytes: None,
        max_chunk_bytes: 1024,
        redaction: Arc::new(CaptureRedaction::from_config(&CaptureRedactionConfig {
            headers: Vec::new(),
            query_keys: Vec::new(),
            json_paths: vec!["$.password".to_string()],
        })),
    };

    tx.try_send(CaptureEvent::new(
        "queued".to_string(),
        CapturePlane::ClientServerPlaintext,
        CaptureDirection::ClientToServer,
        "client".to_string(),
        "server".to_string(),
        b"queued",
    ))
    .expect("fill queue");

    session.emit_plaintext(true, br#"{"password":"secret"}"#);

    let event = rx.try_recv().expect("queued event remains");
    assert_eq!(event.session_id, "queued");
    assert!(rx.try_recv().is_err());
}

#[test]
fn scoped_session_can_enable_targeted_capture() {
    let (tx, _rx) = mpsc::channel(1);
    let sink = ExporterSink {
        tx,
        session_counter: Arc::new(AtomicU64::new(1)),
        capture_plaintext: false,
        capture_encrypted: false,
        max_chunk_bytes: 1024,
        redaction: Arc::new(CaptureRedaction::from_config(
            &CaptureRedactionConfig::default(),
        )),
    };

    let capture = crate::runtime::CompiledCapturePlan {
        encrypted: false,
        plaintext: Some(crate::runtime::CompiledPlaintextCapturePlan {
            headers: true,
            body: qpx_core::config::CaptureBodyMode::Full,
            body_sample_bytes: None,
            sample_percent: Some(100),
            max_body_bytes: Some(4),
            redact: CaptureRedactionConfig {
                headers: vec!["x-secret".to_string()],
                query_keys: Vec::new(),
                json_paths: Vec::new(),
            },
        }),
    };
    let session = sink.session_with_capture("client", "server", &capture);

    assert!(session.capture_plaintext);
    assert!(!session.capture_encrypted);
    assert_eq!(session.max_plaintext_bytes, Some(4));
    assert!(
        session
            .redaction
            .headers
            .iter()
            .any(|header| header == "x-secret")
    );
}

#[test]
fn scoped_session_respects_zero_percent_sampling() {
    let (tx, _rx) = mpsc::channel(1);
    let sink = ExporterSink {
        tx,
        session_counter: Arc::new(AtomicU64::new(1)),
        capture_plaintext: false,
        capture_encrypted: false,
        max_chunk_bytes: 1024,
        redaction: Arc::new(CaptureRedaction::from_config(
            &CaptureRedactionConfig::default(),
        )),
    };
    let capture = crate::runtime::CompiledCapturePlan {
        encrypted: false,
        plaintext: Some(crate::runtime::CompiledPlaintextCapturePlan {
            headers: true,
            body: qpx_core::config::CaptureBodyMode::Disabled,
            body_sample_bytes: None,
            sample_percent: Some(0),
            max_body_bytes: None,
            redact: CaptureRedactionConfig::default(),
        }),
    };

    let session = sink.session_with_capture("client", "server", &capture);

    assert!(!session.capture_plaintext);
}

#[test]
fn redacts_standalone_json_with_blank_lines() {
    for sample in [
        "{\n\n  \"password\": \"synthetic-marker\"\n}",
        "{\r\n\r\n  \"password\": \"synthetic-marker\"\r\n}",
    ] {
        // The sample must be valid JSON for this regression to be meaningful.
        let parsed: serde_json::Value =
            serde_json::from_str(sample).expect("regression sample is valid JSON");
        assert!(parsed.get("password").is_some());
        let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
            headers: Vec::new(),
            query_keys: Vec::new(),
            json_paths: vec!["$.password".to_string()],
        });
        let out = redaction.redact_plaintext(sample.as_bytes());
        let text = String::from_utf8(out.into_owned()).expect("utf8");
        assert!(
            text.contains("\"password\":\"<redacted>\""),
            "blank-line sample was not redacted: {text:?}"
        );
        assert!(!text.contains("synthetic-marker"));
    }
}

#[test]
fn redacting_content_type_preserves_json_body_redaction() {
    for content_type in ["application/json", "application/problem+json"] {
        let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
            headers: vec!["content-type".to_string()],
            query_keys: Vec::new(),
            json_paths: vec!["$.password".to_string()],
        });
        let raw = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\n\r\n{{\"password\":\"synthetic-marker\",\"ok\":true}}"
        );
        let out = redaction.redact_plaintext(raw.as_bytes());
        let text = String::from_utf8(out.into_owned()).expect("utf8");
        assert!(
            text.contains("content-type: <redacted>"),
            "content-type header was not redacted for {content_type}: {text:?}"
        );
        assert!(
            text.contains("\"password\":\"<redacted>\""),
            "JSON body redaction was disabled by content-type redaction for {content_type}: {text:?}"
        );
        assert!(!text.contains("synthetic-marker"));
    }
}

#[test]
fn saturated_queue_drops_multi_chunk_suffix_after_first_chunk() {
    // The proxy-side queue is always non-blocking: once saturated, only
    // whole chunks that still fit are kept; the suffix is dropped even
    // though no backpressure reaches the proxy pipeline.
    let (tx, mut rx) = mpsc::channel(2);
    let session = ExportSession {
        tx: tx.clone(),
        session_id: "test-session".to_string(),
        client: "client".to_string(),
        server: "server".to_string(),
        capture_plaintext: true,
        capture_encrypted: false,
        max_plaintext_bytes: None,
        max_chunk_bytes: 1,
        redaction: Arc::new(CaptureRedaction::from_config(&CaptureRedactionConfig {
            headers: Vec::new(),
            query_keys: Vec::new(),
            json_paths: Vec::new(),
        })),
    };

    tx.try_send(CaptureEvent::new(
        "queued".to_string(),
        CapturePlane::ClientServerPlaintext,
        CaptureDirection::ClientToServer,
        "client".to_string(),
        "server".to_string(),
        b"queued",
    ))
    .expect("fill queue");

    session.emit_plaintext(true, b"abcdef");

    let first = rx.try_recv().expect("filler remains");
    assert_eq!(first.session_id, "queued");
    let second = rx.try_recv().expect("first chunk fits");
    assert_eq!(second.payload_bytes(), b"a");
    assert!(
        rx.try_recv().is_err(),
        "saturated queue drops the chunk suffix"
    );
}

#[test]
fn userinfo_redacted_from_captures_and_exports_even_without_configured_redaction() {
    let empty = CaptureRedactionConfig {
        headers: vec![],
        query_keys: vec![],
        json_paths: vec![],
    };
    for scheme in ["ftp", "http", "https", "custom"] {
        let raw = format!(
            "GET {scheme}://synthetic-user:synthetic-pass@host/file HTTP/1.1\r\nHost: host\r\nReferer: {scheme}://synthetic-user:synthetic-pass@host/\r\nLocation: {scheme}://synthetic-user:synthetic-pass@host/\r\nContent-Location: {scheme}://synthetic-user@host/\r\nContent-Base: {scheme}://synthetic-user:synthetic-pass@host/base\r\nDestination: {scheme}://synthetic-user:synthetic-pass@host/destination\r\nURI: {scheme}://synthetic-user:synthetic-pass@host/uri\r\nOrigin: {scheme}://synthetic-user:synthetic-pass@host {scheme}://synthetic-user:synthetic-pass@other/\r\nAccess-Control-Allow-Origin: {scheme}://synthetic-user:synthetic-pass@host\r\nRefresh: 0; url={scheme}://synthetic-user:synthetic-pass@host/\r\nLink: <{scheme}://synthetic-user:synthetic-pass@host/>; rel=next\r\n\r\n"
        );
        let redaction = CaptureRedaction::from_config(&empty);
        let captured = redaction.redact_plaintext(raw.as_bytes());
        let captured = std::str::from_utf8(&captured).unwrap();
        assert!(captured.contains(&format!("GET {scheme}://host/file HTTP/1.1")));
        assert!(!captured.contains("synthetic-user"), "{captured:?}");
        assert!(!captured.contains("synthetic-pass"), "{captured:?}");
        for cap in [None, Some(24)] {
            for bytes_api in [false, true] {
                let (tx, mut rx) = mpsc::channel(32);
                let session = ExportSession {
                    tx,
                    session_id: "test-session".into(),
                    client: "client".into(),
                    server: "server".into(),
                    capture_plaintext: true,
                    capture_encrypted: false,
                    max_plaintext_bytes: cap,
                    max_chunk_bytes: 16,
                    redaction: Arc::new(CaptureRedaction::from_config(&empty)),
                };
                if bytes_api {
                    session.emit_plaintext_bytes(true, Bytes::from(raw.clone()));
                } else {
                    session.emit_plaintext(true, raw.as_bytes());
                }
                let mut exported = Vec::new();
                while let Ok(event) = rx.try_recv() {
                    exported.extend_from_slice(&event.payload);
                }
                assert!(!exported.is_empty());
                let text = String::from_utf8(exported).unwrap();
                assert!(!text.contains("synthetic-user"));
                assert!(!text.contains("synthetic-pass"));
                assert!(cap.is_none_or(|max| text.len() <= max));
            }
        }
        let partial = format!("GET {scheme}://synthetic-user:synthetic-pass");
        assert!(
            !String::from_utf8(redaction.redact_plaintext(partial.as_bytes()).into_owned())
                .unwrap()
                .contains("synthetic-")
        );
    }
}

#[test]
fn non_utf8_plaintext_bytes_export_uses_redacted_marker_not_input_prefix() {
    let (tx, mut rx) = mpsc::channel(1);
    let session = ExportSession {
        tx,
        session_id: "test-session".into(),
        client: "client".into(),
        server: "server".into(),
        capture_plaintext: true,
        capture_encrypted: false,
        max_plaintext_bytes: None,
        max_chunk_bytes: 1024,
        redaction: Arc::new(CaptureRedaction::from_config(&CaptureRedactionConfig {
            headers: vec![],
            query_keys: vec![],
            json_paths: vec![],
        })),
    };
    for payload in [
        &b"opaque\xffbody"[..],
        &b"GET http://synthetic-user:synthetic-pass@host/ HTTP/1.1\r\n\r\n\xff"[..],
    ] {
        session.emit_plaintext_bytes(true, Bytes::copy_from_slice(payload));
        assert_eq!(rx.try_recv().unwrap().payload.as_ref(), b"<redacted>");
    }
}

#[tokio::test]
async fn rejected_http_userinfo_request_is_captured_redacted() {
    let req = Request::builder()
        .uri("http://synthetic-user@host/file")
        .header("host", "host")
        .body(Body::empty())
        .unwrap();
    let raw = format!("GET {} HTTP/1.1\r\nHost: host\r\n\r\n", req.uri());
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: vec![],
        query_keys: vec![],
        json_paths: vec![],
    });
    assert_eq!(
        redaction.redact_plaintext(raw.as_bytes()).as_ref(),
        b"GET http://host/file HTTP/1.1\r\nHost: host\r\n\r\n"
    );
    let config = serde_yaml::from_str(
        r#"
state_dir: null
edges:
- kind: forward
  name: test
  listen: 127.0.0.1:0
  default_action: {type: direct}
"#,
    )
    .unwrap();
    let response = crate::forward::handle_request_inner(
        req,
        crate::runtime::Runtime::new(config).unwrap(),
        "test",
        "127.0.0.1:12345".parse().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
}

#[test]
fn ambiguous_uri_headers_and_truncated_authorities_are_safe_before_export_caps() {
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: vec![],
        query_keys: vec![],
        json_paths: vec![],
    });
    for header in [
        "Refresh: 0; url='ftp://synthetic-user:synthetic-pass@host/file'",
        "Refresh: 0; url='//synthetic-user:synthetic-pass",
        "Refresh: ftp://synthetic-user:synthetic-pass@host/; url=ftp://host/",
        "Refresh: 0; url=ftp://synthetic-user:synthetic-pass@host/; url=ftp://synthetic-user@host/",
        "Link: <ftp://synthetic-user:synthetic-pass@host/file",
        "Link: <//synthetic-user:synthetic-pass",
        "Link: ftp://synthetic-user:synthetic-pass@host/file",
        "Host: '1bad://synthetic-user:synthetic-pass@host'",
        "Host: /foo://synthetic-user:synthetic-pass@host",
    ] {
        let raw = format!("HTTP/1.1 302 Found\r\n{header}\r\n\r\n");
        let safe = redaction.redact_plaintext(raw.as_bytes());
        assert!(
            !String::from_utf8_lossy(&safe).contains("synthetic-"),
            "{header}"
        );
        // Check caps on either side of every authority/userinfo boundary.
        for cap in 0..=raw.len() {
            assert_eq!(
                redaction
                    .redact_plaintext_for_export(raw.as_bytes(), Some(cap))
                    .as_ref(),
                &safe[..safe.len().min(cap)]
            );
        }
    }
    for target in [
        "ftp://synthetic-user:synthetic-pass",
        "//synthetic-user:synthetic-pass",
        "synthetic-user:synthetic-pass",
        "//synthetic-user:synthetic-pass@host/file",
        "synthetic-user:synthetic-pass@host:21",
    ] {
        let raw = format!("CONNECT {target}");
        let safe = redaction.redact_plaintext(raw.as_bytes());
        assert!(
            !String::from_utf8_lossy(&safe).contains("synthetic-"),
            "{target}"
        );
        for cap in 0..=raw.len() {
            assert_eq!(
                redaction
                    .redact_plaintext_for_export(raw.as_bytes(), Some(cap))
                    .as_ref(),
                &safe[..safe.len().min(cap)]
            );
        }
    }
    let raw = b"HTTP/1.1 200 OK\r\nRefresh: 0; url='ftp://synthetic-user@host/file'\r\n\r\n";
    assert!(
        String::from_utf8_lossy(&redaction.redact_plaintext(raw))
            .contains("Refresh: 0; url='ftp://host/file'")
    );
}

#[test]
fn incomplete_uri_headers_do_not_export_an_authority_prefix() {
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: vec![],
        query_keys: vec![],
        json_paths: vec![],
    });
    for name in [
        "Location",
        "Content-Location",
        "Referer",
        "Host",
        "Link",
        "Refresh",
    ] {
        let raw = format!("HTTP/1.1 302 Found\r\n{name}: //synthetic-user:synthetic-pass");
        for cap in 0..=raw.len() {
            let safe = redaction.redact_plaintext_for_export(raw.as_bytes(), Some(cap));
            assert!(!String::from_utf8_lossy(&safe).contains("synthetic-"));
        }
    }
    // Ordinary origin paths are not authorities even in request previews.
    let raw = b"GET /foo://user@host";
    assert_eq!(redaction.redact_plaintext(raw).as_ref(), raw);
}

#[test]
fn uri_body_text_is_not_subject_to_userinfo_dlp() {
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: vec![],
        query_keys: vec![],
        json_paths: vec![],
    });
    let raw =
        b"POST /upload HTTP/1.1\r\nHost: host\r\n\r\nftp://synthetic-user:synthetic-pass@host/file";
    assert_eq!(redaction.redact_plaintext(raw).as_ref(), raw);
}

#[test]
fn opaque_and_relative_uri_headers_are_preserved_but_authorities_are_redacted() {
    let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
        headers: vec![],
        query_keys: vec![],
        json_paths: vec![],
    });
    for uri in [
        "mailto:alice@example.com",
        "urn:example:person@domain",
        "urn:example:ftp://user@host",
        "relative/alice@example.com",
        "alice@example.com",
    ] {
        let raw = format!(
            "HTTP/1.1 302 Found\r\nLocation: {uri}\r\nLink: <{uri}>; rel=next\r\nOrigin: {uri}\r\n\r\n"
        );
        assert_eq!(
            redaction.redact_plaintext(raw.as_bytes()).as_ref(),
            raw.as_bytes()
        );
    }
    let raw = b"CONNECT synthetic-user:synthetic-pass@host:443 HTTP/1.1\r\nHost: synthetic-user:synthetic-pass@host:443\r\n\r\n";
    let safe = redaction.redact_plaintext(raw);
    assert_eq!(
        safe.as_ref(),
        b"CONNECT host:443 HTTP/1.1\r\nHost: host:443\r\n\r\n"
    );
    let extended_path = b"CONNECT /chat/@alice?room=general HTTP/1.1\r\n\r\n";
    assert_eq!(
        redaction.redact_plaintext(extended_path).as_ref(),
        extended_path
    );
    for cap in 0..=raw.len() {
        assert_eq!(
            redaction
                .redact_plaintext_for_export(raw, Some(cap))
                .as_ref(),
            &safe[..safe.len().min(cap)]
        );
    }
    for scheme in ["ftp", "http"] {
        let raw = format!(
            "HTTP/1.1 302 Found\r\nLocation: {scheme}://synthetic-user:synthetic-pass@host/file\r\nLink: <{scheme}://synthetic-user:synthetic-pass@host/file>; rel=next\r\nOrigin: {scheme}://synthetic-user:synthetic-pass@host\r\n\r\n"
        );
        let safe = redaction.redact_plaintext(raw.as_bytes());
        let safe = String::from_utf8_lossy(&safe);
        assert!(!safe.contains("synthetic-"));
        assert!(safe.contains(&format!("Location: {scheme}://host/file")));
        assert!(safe.contains(&format!("Link: <{scheme}://host/file>")));
        assert!(safe.contains(&format!("Origin: {scheme}://host\r\n")));
    }
}
