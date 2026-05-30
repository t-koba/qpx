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
