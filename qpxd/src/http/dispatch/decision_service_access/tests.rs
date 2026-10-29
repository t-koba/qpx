use super::*;
use crate::http::dispatch::{DispatchError, ProxyKind};
use crate::http::protocol::l7::finalize_response_with_headers;
use http::{StatusCode, Version};
use qpx_core::config::{HeaderControl, LocalResponseConfig};
use qpx_core::http_message::OrdinaryHeaderName;
use qpx_observability::access_log::RequestLogContext;

fn control(yaml: &str) -> Arc<CompiledHeaderControl> {
    Arc::new(
        CompiledHeaderControl::compile(&serde_yaml::from_str::<HeaderControl>(yaml).unwrap())
            .unwrap(),
    )
}

#[tokio::test]
async fn denied_responses_stay_owned_through_controls_audit_limit_and_error() {
    let mut config = serde_yaml::from_str::<qpx_core::config::Config>("edges: []").unwrap();
    config.telemetry.access_log.output.enabled = true;
    let state = crate::runtime::Runtime::new(config).unwrap().state();
    let base = control(
        r#"
response_set:
  date: Thu, 01 Jan 1970 00:00:00 GMT
  x-phase: base
  x-invalid: unchanged
response_add:
  set-cookie: base=1
response_regex_replace:
- { header: x-phase, pattern: base, replace: intermediate }
- { header: x-invalid, pattern: unchanged, replace: "bad\r\nvalue" }
"#,
    );
    let extra = control(
        r#"
response_add:
  set-cookie: deny=2
response_regex_replace:
- { header: x-phase, pattern: intermediate, replace: deny }
"#,
    );
    let merged = merge_header_controls(Some(base.clone()), Some(extra.clone())).unwrap();
    for max_bytes in [4, 8] {
        for method in [Method::GET, Method::HEAD] {
            for version in [Version::HTTP_11, Version::HTTP_2] {
                // Default deny, local override, and local no-body statuses.
                for status in [None, Some(418), Some(204), Some(304)] {
                    let local = status.map(|status| LocalResponseConfig {
                        status,
                        body: "payload".into(),
                        content_type: Some("text/custom".into()),
                        headers: [
                            ("content-length".into(), "0007".into()),
                            ("connection".into(), "x-hop".into()),
                            ("x-hop".into(), "remove".into()),
                            ("x-exact".into(), "unchanged\tbytes".into()),
                        ]
                        .into(),
                        rpc: None,
                    });
                    let audit = DispatchAuditContext::new(
                        Some(state.clone()),
                        ProxyKind::Forward,
                        Some("edge".into()),
                        "127.0.0.1:1234".parse().unwrap(),
                        method.clone(),
                        Some("/".into()),
                        RequestLogContext {
                            subject: Some("test-subject".into()),
                            policy_tags: vec!["decision-tag".into()],
                            ..Default::default()
                        },
                    );
                    let raw = match &local {
                        Some(local) => {
                            crate::http::local_response::build_local_response(local).unwrap()
                        }
                        None => crate::http::protocol::common::forbidden_response("payload"),
                    };
                    // Reference is the pre-migration standard-response finalization.
                    let mut expected = finalize_response_with_headers(
                        &method,
                        version,
                        "qpx-test",
                        raw,
                        Some(&merged),
                        false,
                    );
                    let outcome = if local.is_some() {
                        DispatchOutcome::DecisionServiceLocalResponse
                    } else {
                        DispatchOutcome::DecisionServiceDeny
                    };
                    annotate_dispatch_response(&mut expected, &audit, outcome, &[]);
                    let actual =
                        apply_decision_service_http_access(DecisionServiceHttpAccessInput {
                            enforcement: DecisionServiceEnforcement::Deny(DecisionServiceDeny {
                                headers: Some(extra.clone()),
                                local_response: local,
                                ..Default::default()
                            }),
                            mode: DecisionServiceMode::ForwardHttp,
                            base_headers: Some(base.clone()),
                            request_limit: None,
                            request_head: (&method, version),
                            proxy_name: "qpx-test",
                            default_deny_body: "payload",
                            audit: &audit,
                        })
                        .unwrap();
                    let DecisionServiceHttpAccessOutcome::Blocked(mut actual) = actual else {
                        panic!("deny must produce an owner response, not a rate-limit response");
                    };
                    assert_eq!(actual.status().as_u16(), status.unwrap_or(403));
                    assert_eq!(actual.version(), expected.version());
                    let fields: Vec<_> = actual
                        .headers()
                        .iter()
                        .map(|(n, v)| (n.as_str(), v.as_bytes(), v.is_sensitive()))
                        .collect();
                    let expected_fields: Vec<_> = expected
                        .headers()
                        .iter()
                        .filter(|(n, _)| *n != http::header::CONTENT_LENGTH)
                        .map(|(n, v)| (n.as_str(), v.as_bytes(), v.is_sensitive()))
                        .collect();
                    assert_eq!(fields, expected_fields);
                    assert_eq!(
                        actual.headers().declared_content_length(),
                        qpx_core::http_content_length::declared_content_length(expected.headers())
                    );
                    assert_eq!(
                        actual
                            .headers()
                            .get(&OrdinaryHeaderName::try_from("x-phase").unwrap())
                            .unwrap(),
                        "deny"
                    );
                    assert_eq!(
                        actual
                            .headers()
                            .get(&OrdinaryHeaderName::try_from("x-invalid").unwrap())
                            .unwrap(),
                        "unchanged"
                    );
                    assert_eq!(
                        actual
                            .headers()
                            .get_all(&OrdinaryHeaderName::try_from("set-cookie").unwrap())
                            .map(|v| v.to_str().unwrap())
                            .collect::<Vec<_>>(),
                        ["base=1", "deny=2"]
                    );
                    assert_eq!(
                        actual.body().trailers_are_sanitized(),
                        expected.body().trailers_are_sanitized()
                    );
                    assert_eq!(
                        format!(
                            "{:?}",
                            actual.extensions().get::<RequestLogContext>().unwrap()
                        ),
                        format!(
                            "{:?}",
                            expected.extensions().get::<RequestLogContext>().unwrap()
                        )
                    );

                    // Exercise the same owner-preserving limiter and error extraction
                    // used by forward dispatch, including arbitrary extension retention.
                    actual.extensions_mut().insert(42_u32);
                    expected.extensions_mut().insert(42_u32);
                    crate::http::capture::stream::limit_response_body_to_max_bytes(
                        &mut actual,
                        max_bytes,
                    );
                    crate::http::capture::stream::limit_response_body_to_max_bytes(
                        &mut expected,
                        max_bytes,
                    );
                    let actual = DispatchError::DecisionServiceDenied {
                        response: Box::new(actual),
                    }
                    .into_response_result()
                    .unwrap();
                    let _: &OwnerResponse<Body> = &actual;
                    assert_eq!(actual.extensions().get::<u32>(), Some(&42));
                    assert_eq!(
                        actual
                            .extensions()
                            .get::<RequestLogContext>()
                            .unwrap()
                            .policy_tags,
                        ["decision-tag"]
                    );
                    assert_eq!(
                        actual.headers().declared_content_length(),
                        qpx_core::http_content_length::declared_content_length(expected.headers())
                    );
                    let actual = qpx_http::body::to_bytes(actual.into_head_and_body().1).await;
                    let expected = qpx_http::body::to_bytes(expected.into_body()).await;
                    match (actual, expected) {
                        (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
                        (Err(actual), Err(expected)) => {
                            assert!(actual.to_string().contains("response body limit exceeded"));
                            assert_eq!(actual.to_string(), expected.to_string());
                        }
                        other => panic!("body limit parity: {other:?}"),
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn decision_profile_rate_limit_remains_a_standard_response() {
    let config = serde_yaml::from_str::<qpx_core::config::RateLimitProfileConfig>(
        r#"
name: decision-limit
enabled: true
key: global
apply_to: [request]
requests:
  quota: { amount: 1, interval_secs: 3600 }
"#,
    )
    .unwrap();
    let limiters = RateLimiters::from_config(
        std::iter::empty::<&qpx_core::config::IngressEdgeConfig>(),
        std::slice::from_ref(&config),
    );
    let audit = DispatchAuditContext::new(
        None,
        ProxyKind::Forward,
        None,
        "127.0.0.1:1234".parse().unwrap(),
        Method::GET,
        None,
        Default::default(),
    );
    let context = RateLimitContext::default();
    let run = || {
        let mut limits = AppliedRateLimits::default();
        apply_decision_service_http_access(DecisionServiceHttpAccessInput {
            enforcement: DecisionServiceEnforcement::Continue(DecisionServiceAllow {
                rate_limit_profile: Some("decision-limit".into()),
                ..Default::default()
            }),
            mode: DecisionServiceMode::ForwardHttp,
            base_headers: None,
            request_limit: Some((&mut limits, &context, &limiters)),
            request_head: (&Method::GET, Version::HTTP_11),
            proxy_name: "qpx-test",
            default_deny_body: "denied",
            audit: &audit,
        })
        .unwrap()
    };
    assert!(matches!(
        run(),
        DecisionServiceHttpAccessOutcome::Continue(_)
    ));
    let DecisionServiceHttpAccessOutcome::RateLimited(response) = run() else {
        panic!("second request must be rate limited");
    };
    let _: &OwnerResponse<Body> = &response;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response
            .headers()
            .contains_key(&"retry-after".try_into().unwrap())
    );
    let response = DispatchError::RateLimited {
        response: Box::new(response),
    }
    .into_response_result()
    .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        !qpx_http::body::to_bytes(response.into_head_and_body().1)
            .await
            .unwrap()
            .is_empty()
    );
}
