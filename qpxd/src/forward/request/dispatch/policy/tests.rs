use super::*;
use crate::destination::DestinationMetadata;
use crate::policy_context::ResolvedIdentity;
use crate::runtime::auth::AuthChallenge;
use http::{StatusCode, Version};
use http_body_util::BodyExt;
use qpx_core::http_message::{OrdinaryHeaderMut, OrdinaryHeaderName};
use qpx_observability::access_log::RequestLogContext;

fn challenge(values: &[&str]) -> AuthChallenge {
    AuthChallenge {
        header_values: values.iter().map(|value| (*value).to_owned()).collect(),
        stale: false,
    }
}

// The standard-response constructor used before this migration, including its
// all-or-nothing fallback when any challenge field cannot be encoded.
fn raw_challenge(values: &[&str]) -> http::Response<Body> {
    let mut builder = http::Response::builder().status(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    for value in values {
        builder = builder.header("Proxy-Authenticate", *value);
    }
    builder
        .body(Body::from("payload"))
        .unwrap_or_else(|_| http::Response::new(Body::empty()))
}

#[tokio::test]
async fn auth_policy_challenge_constructor_parity() {
    for values in [
        vec![],
        vec![
            "Digest realm=\"edge\", stale=true",
            "Basic realm=\"edge\"",
            "Basic realm=\"edge\"",
        ],
        vec!["  Basic realm=\"edge\"\t", "opaque-\u{e9}"],
        vec![
            "Basic realm=\"edge\"",
            "bad\r\nvalue",
            "Digest realm=\"edge\"",
        ],
    ] {
        let actual = proxy_auth_required(challenge(&values), "payload").into_http_for_library();
        let expected = raw_challenge(&values);
        assert_eq!(actual.status(), expected.status());
        assert_eq!(actual.version(), expected.version());
        assert_eq!(actual.headers(), expected.headers());
        assert_eq!(
            actual
                .headers()
                .get_all("proxy-authenticate")
                .iter()
                .collect::<Vec<_>>(),
            expected
                .headers()
                .get_all("proxy-authenticate")
                .iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            actual.into_body().collect().await.unwrap().to_bytes(),
            expected.into_body().collect().await.unwrap().to_bytes()
        );
    }
}

#[tokio::test]
async fn auth_policy_finalization_and_owner_error_handoff_parity() {
    let mut config = serde_yaml::from_str::<qpx_core::config::Config>("edges: []").unwrap();
    config.telemetry.access_log.output.enabled = true;
    let state = crate::runtime::Runtime::new(config).unwrap().state();
    let identity = ResolvedIdentity {
        user: Some("test-user".into()),
        ..Default::default()
    };
    let destination = DestinationMetadata {
        category_trace: Some("test-destination".into()),
        ..Default::default()
    };
    let values = [
        "Digest realm=\"edge\", stale=true",
        "Basic realm=\"edge\"",
        "Basic realm=\"edge\"",
    ];
    for method in [Method::GET, Method::HEAD, Method::CONNECT] {
        for version in [
            Version::HTTP_10,
            Version::HTTP_11,
            Version::HTTP_2,
            Version::HTTP_3,
        ] {
            for is_challenge in [false, true] {
                let (mut actual, mut expected, outcome) = if is_challenge {
                    (
                        proxy_auth_required(challenge(&values), "payload"),
                        raw_challenge(&values),
                        DispatchOutcome::Challenge,
                    )
                } else {
                    (
                        forbidden("payload"),
                        http::Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from("payload"))
                            .unwrap(),
                        DispatchOutcome::Forbidden,
                    )
                };
                // Stable Date plus a nominated field exercise sanitization order;
                // Proxy-Authenticate must survive even when Connection names it.
                for (name, value) in [
                    ("date", "Thu, 01 Jan 1970 00:00:00 GMT"),
                    ("connection", "x-private, proxy-authenticate"),
                    ("x-private", "remove"),
                ] {
                    actual.headers_mut().ordinary_insert(
                        OrdinaryHeaderName::try_from(name).unwrap(),
                        value.parse().unwrap(),
                    );
                    expected.headers_mut().insert(
                        http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                        value.parse().unwrap(),
                    );
                }
                actual.extensions_mut().insert(42_u32);
                let actual = finalize_forward_policy_response(
                    ForwardPolicyResponseInput {
                        state: &state,
                        identity: &identity,
                        destination: &destination,
                        proxy_name: "qpx-test",
                        listener_name: "test-edge",
                        remote_addr: "127.0.0.1:1234".parse().unwrap(),
                        host: "example.test",
                        request_method: &method,
                        request_version: version,
                        path: Some("/"),
                    },
                    actual,
                    outcome,
                );
                let error = if is_challenge {
                    DispatchError::AuthRequired {
                        method: "proxy".into(),
                        response: Box::new(actual),
                    }
                } else {
                    DispatchError::PolicyDenied {
                        reason: "authentication denied".into(),
                        response: Box::new(actual),
                    }
                };
                let actual: Response<Body> = error.into_response_result().unwrap();
                let mut expected =
                    finalize_response_for_request(&method, version, "qpx-test", expected, false);
                let mut log_context = identity.to_log_context(None, None, None);
                attach_destination_trace(&mut log_context, &destination);
                attach_log_context(&state, &mut expected, &log_context);
                assert_eq!(actual.extensions().get::<u32>(), Some(&42));
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
                assert_eq!(
                    actual.body().trailers_are_sanitized(),
                    expected.body().trailers_are_sanitized()
                );
                let actual = actual.into_http_for_codec().unwrap();
                assert_eq!(actual.status(), expected.status());
                assert_eq!(actual.version(), expected.version());
                assert_eq!(actual.headers(), expected.headers());
                assert_eq!(
                    actual
                        .headers()
                        .get_all("proxy-authenticate")
                        .iter()
                        .collect::<Vec<_>>(),
                    expected
                        .headers()
                        .get_all("proxy-authenticate")
                        .iter()
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    actual.into_body().collect().await.unwrap().to_bytes(),
                    expected.into_body().collect().await.unwrap().to_bytes()
                );
            }
        }
    }
}
