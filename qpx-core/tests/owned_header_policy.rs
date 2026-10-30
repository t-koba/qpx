//! External-consumer controls for owner-backed policy, without map export.
use http::header::HeaderValue;
use qpx_core::config::{
    ActionConfig, ActionKind, HeaderControl, HeaderMatch, MatchConfig, RegexReplace,
    RpcMatchConfig, RuleConfig,
};
use qpx_core::http_content_length::{ContentLengthError, HeaderView};
use qpx_core::http_message::{Headers, OrdinaryHeaderName};
use qpx_core::matchers::{CompiledMatch, MatchReason};
use qpx_core::prefilter::StringInterner;
use qpx_core::rules::{CompiledHeaderControl, RuleEngine, RuleMatchContext};

fn name(value: &str) -> OrdinaryHeaderName {
    value.try_into().unwrap()
}

fn replace(header: &str, pattern: &str, replacement: &str) -> RegexReplace {
    RegexReplace {
        header: header.into(),
        pattern: pattern.into(),
        replace: replacement.into(),
    }
}

fn request_control(raw: HeaderControl) -> CompiledHeaderControl {
    CompiledHeaderControl::compile(&raw).unwrap()
}

#[test]
fn literal_set_add_remove_and_request_response_isolation() {
    let control = request_control(HeaderControl {
        request_set: [("Content-Length".into(), " 005 ".into())].into(),
        request_add: [("content-length".into(), "5".into())].into(),
        response_set: [("content-length".into(), "bad".into())].into(),
        ..Default::default()
    });
    let mut headers = Headers::new();
    assert!(control.apply_request_owned(&mut headers).is_empty());
    let mut expected = Headers::new();
    expected.set_content_length_value(HeaderValue::from_static(" 005 "));
    expected.append_content_length_value(HeaderValue::from_static("5"));
    assert_eq!(headers, expected); // compare literal bytes and duplicates
    assert_eq!(headers.declared_content_length(), Ok(Some(5)));
    assert!(control.apply_response_owned(&mut headers).is_empty());
    expected.set_content_length_value(HeaderValue::from_static("bad"));
    assert_eq!(headers, expected);
    assert!(headers.contains_content_length());
    assert_eq!(
        headers.declared_content_length(),
        Err(ContentLengthError::InvalidValue)
    );
    let remove = request_control(HeaderControl {
        request_remove: vec!["Content-Length".into()],
        ..Default::default()
    });
    assert!(remove.apply_request_owned(&mut headers).is_empty());
    assert!(!headers.contains_content_length());
}

#[test]
fn merged_owner_plan_preserves_stage_order_and_literal_regex_selection() {
    let base = request_control(HeaderControl {
        request_set: [("x-remove".into(), "set".into())].into(),
        request_add: [
            ("content-length".into(), "99".into()),
            ("x-stage".into(), "base-add".into()),
            ("x-remove".into(), "add".into()),
        ]
        .into(),
        request_remove: vec!["x-remove".into()],
        request_regex_replace: vec![
            replace("Content-Length", "^ 005 $", "7"),
            replace("x-stage", "set", "regex"),
            replace("x-remove", ".*", "resurrected"),
        ],
        ..Default::default()
    });
    let extra = request_control(HeaderControl {
        request_set: [
            ("content-length".into(), " 005 ".into()),
            ("x-stage".into(), "extra-set".into()),
        ]
        .into(),
        request_regex_replace: vec![replace("content-length", "7", "8")],
        ..Default::default()
    });
    let control = base.merged(&extra);
    let mut headers = Headers::new();
    headers.set_content_length(123);
    assert!(control.apply_request_owned(&mut headers).is_empty());
    let mut expected = Headers::new();
    expected.set_content_length(8); // regex saw literal first value, then collapsed duplicates
    expected.insert(name("x-stage"), HeaderValue::from_static("extra-regex"));
    assert_eq!(headers, expected);
    assert!(!headers.contains_key(&name("x-remove")));
}

#[test]
fn regex_diagnostics_preserve_names_repetitions_and_unchanged_values() {
    let control = request_control(HeaderControl {
        response_regex_replace: vec![
            replace("content-length", "^ 5 $", "bad\nvalue"),
            replace("x-bad", "ok", "bad\rvalue"),
            replace("Content-Length", "5", "bad\nagain"),
            replace("x-opaque", ".*", "bad\nvalue"),
            replace("x-missing", ".*", "bad\nvalue"),
            replace("x-good", "ok", "done"),
        ],
        ..Default::default()
    });
    let mut headers = Headers::new();
    let mut sensitive = HeaderValue::from_static(" 5 ");
    sensitive.set_sensitive(true);
    headers.set_content_length_value(sensitive);
    headers.append_content_length_value(HeaderValue::from_static("5"));
    headers.insert(name("x-bad"), HeaderValue::from_static("ok"));
    headers.append(name("x-bad"), HeaderValue::from_static("other"));
    headers.insert(name("x-opaque"), HeaderValue::from_bytes(b"\xff").unwrap());
    headers.append(name("x-opaque"), HeaderValue::from_static("ok"));
    let mut expected = headers.clone();
    headers.insert(name("x-good"), HeaderValue::from_static("ok"));
    expected.insert(name("x-good"), HeaderValue::from_static("done"));
    let diagnostics = control.apply_response_owned(&mut headers);
    assert_eq!(
        diagnostics.iter().map(|n| n.as_str()).collect::<Vec<_>>(),
        ["content-length", "x-bad", "content-length"]
    );
    assert_eq!(headers, expected); // failed/opaque operations preserve every occurrence/sensitivity
}

#[test]
fn regex_skips_nontextual_first_content_length_and_collapses_on_no_match() {
    let control = request_control(HeaderControl {
        request_regex_replace: vec![replace("content-length", "never", "\n")],
        ..Default::default()
    });
    let mut headers = Headers::new();
    headers.set_content_length_value(HeaderValue::from_bytes(b"\xff").unwrap());
    headers.append_content_length_value(HeaderValue::from_static("5"));
    let frozen = headers.clone();
    assert!(control.apply_request_owned(&mut headers).is_empty());
    assert_eq!(headers, frozen); // does not seek a later textual occurrence
    let mut sensitive = HeaderValue::from_static("bad");
    sensitive.set_sensitive(true);
    headers.set_content_length_value(sensitive);
    headers.append_content_length_value(HeaderValue::from_static("5"));
    assert!(control.apply_request_owned(&mut headers).is_empty());
    let mut expected = Headers::new();
    expected.set_content_length_value(HeaderValue::from_static("bad"));
    assert_eq!(headers, expected); // successful no-match still collapses, resets sensitivity
    assert!(headers.declared_content_length().is_err()); // no implicit validation/canonicalization
}

#[test]
fn request_and_response_controls_preserve_literal_length_outcomes() {
    let raw_control = HeaderControl {
        request_set: [("x-stage".into(), "set".into())].into(),
        request_add: [("x-stage".into(), "add".into())].into(),
        request_remove: vec!["x-remove".into()],
        request_regex_replace: vec![
            replace("x-stage", "set", "done"),
            replace("content-length", "5", "6"),
            replace("content-length", "6", "bad\nvalue"),
            replace("x-opaque", ".*", "new"),
        ],
        ..Default::default()
    };
    let control = request_control(HeaderControl {
        response_set: raw_control.request_set.clone(),
        response_add: raw_control.request_add.clone(),
        response_remove: raw_control.request_remove.clone(),
        response_regex_replace: raw_control.request_regex_replace.clone(),
        ..raw_control
    });
    for (values, expected_length, fails) in [
        (vec![], None, false),
        (vec!["5"], Some("6"), true),
        (vec![" 5 ", "99"], Some(" 6 "), true),
        (vec!["bad", "5"], Some("bad"), false),
        (vec!["", "5"], Some(""), false),
    ] {
        let mut headers = Headers::new();
        for value in values {
            headers.append_content_length_value(HeaderValue::from_str(value).unwrap());
        }
        headers.insert(name("x-remove"), HeaderValue::from_static("gone"));
        let opaque = HeaderValue::from_bytes(b"\xff").unwrap();
        headers.insert(name("x-opaque"), opaque.clone());
        let mut response = headers.clone();
        let diagnostics = if fails {
            vec!["content-length"]
        } else {
            vec![]
        };
        assert_eq!(control.apply_request_owned(&mut headers), diagnostics);
        assert_eq!(control.apply_response_owned(&mut response), diagnostics);
        let mut expected = Headers::new();
        if let Some(value) = expected_length {
            expected.set_content_length_value(HeaderValue::from_str(value).unwrap());
        }
        expected.insert(name("x-stage"), HeaderValue::from_static("done"));
        expected.insert(name("x-opaque"), opaque);
        assert_eq!(headers, expected);
        assert_eq!(response, expected);
    }
}

fn matcher(config: &MatchConfig) -> CompiledMatch {
    CompiledMatch::compile(config, &mut StringInterner::default())
        .unwrap()
        .0
}

#[test]
fn owner_context_matches_and_redacts_only_content_length_actual() {
    let config = MatchConfig {
        headers: vec![
            HeaderMatch {
                name: "Content-Length".into(),
                value: None,
                regex: None,
            },
            HeaderMatch {
                name: "content-length".into(),
                value: Some("5".into()),
                regex: None,
            },
            HeaderMatch {
                name: "CONTENT-LENGTH".into(),
                value: None,
                regex: Some("^ 5 $".into()),
            },
            HeaderMatch {
                name: "x-bin".into(),
                value: Some("ok".into()),
                regex: None,
            },
        ],
        ..Default::default()
    };
    let compiled = matcher(&config);
    let mut headers = Headers::new();
    headers.set_content_length_value(HeaderValue::from_static(" 5 "));
    headers.append_content_length_value(HeaderValue::from_static("5"));
    headers.insert(name("x-bin"), HeaderValue::from_bytes(b"\xff").unwrap());
    headers.append(name("x-bin"), HeaderValue::from_static("ok"));
    let ctx = RuleMatchContext {
        owned_headers: Some(headers.view()),
        ..Default::default()
    };
    assert!(compiled.matches(&ctx));
    assert!(compiled.matches_without_request_body_observation(&ctx));
    assert!(compiled.matches_without_response_body_observation(&ctx));
    let trace = compiled.matches_with_trace(&ctx);
    assert!(trace.result);
    for reason in trace.reasons {
        if let MatchReason::Header {
            name,
            actual,
            result,
            ..
        } = reason
        {
            assert!(result);
            if name.eq_ignore_ascii_case("content-length") {
                assert_eq!(actual, None);
            } else {
                assert_eq!(actual.as_deref(), Some("ok"));
            }
        }
    }
    let action = |kind| ActionConfig {
        kind,
        upstream: None,
        local_response: None,
    };
    let engine = RuleEngine::new(
        vec![RuleConfig {
            name: "owned".into(),
            r#match: Some(config),
            auth: None,
            action: Some(action(ActionKind::Block)),
            headers: None,
            rate_limit: None,
        }],
        action(ActionKind::Direct),
    )
    .unwrap();
    assert_eq!(engine.evaluate_ref(&ctx).matched_rule, Some("owned"));
    assert_eq!(engine.first_matcher(&ctx).unwrap().name(), "owned");
    assert_eq!(engine.matcher_candidate_indices(&ctx), vec![0]);

    let mismatch = matcher(&MatchConfig {
        headers: vec![HeaderMatch {
            name: "Content-Length".into(),
            value: Some("not-five".into()),
            regex: None,
        }],
        ..Default::default()
    })
    .matches_with_trace(&ctx);
    assert!(!mismatch.result);
    assert!(matches!(
        &mismatch.reasons[0],
        MatchReason::Header {
            actual: None,
            result: false,
            ..
        }
    ));

    // An owner source is authoritative when a transitional source is also set.
    let raw = http::HeaderMap::new();
    let both = RuleMatchContext {
        headers: Some(HeaderView::new(&raw)),
        ..ctx
    };
    assert!(compiled.matches(&both));
    let absent = RuleMatchContext {
        owned_headers: None,
        ..both
    };
    assert!(!compiled.matches(&absent));
    let failure = compiled.matches_with_trace(&absent);
    assert!(!failure.result);
}

#[test]
fn owner_rpc_trailers_use_the_same_closed_matching_path() {
    let compiled = matcher(&MatchConfig {
        rpc: Some(RpcMatchConfig {
            trailers: vec![HeaderMatch {
                name: "Content-Length".into(),
                value: Some("bad".into()),
                regex: None,
            }],
            ..Default::default()
        }),
        ..Default::default()
    });
    let mut trailers = Headers::new();
    trailers.set_content_length_value(HeaderValue::from_bytes(b"\xff").unwrap());
    trailers.append_content_length_value(HeaderValue::from_static("bad"));
    let ctx = RuleMatchContext {
        owned_rpc_trailers: Some(trailers.view()),
        ..Default::default()
    };
    assert!(compiled.matches(&ctx));
    assert!(compiled.matches_with_trace(&ctx).result);
    let absent = RuleMatchContext {
        owned_rpc_trailers: None,
        ..ctx
    };
    assert!(!compiled.matches(&absent));
}
