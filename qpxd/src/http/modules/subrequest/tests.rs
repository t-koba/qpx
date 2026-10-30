use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use qpx_core::config::{SubrequestModuleConfig, SubrequestPhase};
use tokio::time::Duration;

use super::ssrf::{redirect_host_is_private_ip, redirect_ip_is_private};
use super::*;

#[test]
fn wildcard_allowed_host_requires_label_boundary() {
    assert!(allowed_host_matches("*.example.com", "api.example.com"));
    assert!(allowed_host_matches(
        "*.example.com",
        "deep.api.example.com"
    ));
    assert!(!allowed_host_matches("*.example.com", "example.com"));
    assert!(!allowed_host_matches("*.example.com", "badexample.com"));
    assert!(!allowed_host_matches("*.example.com", "evil-example.com"));
}

#[test]
fn private_redirect_detection_handles_ipv4_mapped_ipv6() {
    assert!(redirect_host_is_private_ip("::ffff:127.0.0.1"));
    assert!(redirect_host_is_private_ip("[::ffff:10.0.0.1]"));
    assert!(!redirect_host_is_private_ip("::ffff:8.8.8.8"));
}

#[test]
fn private_redirect_detection_handles_nat64_embedded_ipv4() {
    assert!(redirect_ip_is_private(IpAddr::V6(
        "64:ff9b::7f00:1".parse().unwrap()
    )));
    assert!(redirect_ip_is_private(IpAddr::V6(
        "64:ff9b:1::0a00:1".parse().unwrap()
    )));
    assert!(redirect_ip_is_private(IpAddr::V6(
        "64:ff9b::0808:0808".parse().unwrap()
    )));
}

#[test]
fn private_redirect_detection_rejects_non_global_special_ranges() {
    assert!(redirect_ip_is_private(IpAddr::V4(Ipv4Addr::new(
        100, 64, 0, 1
    ))));
    assert!(redirect_ip_is_private(IpAddr::V4(Ipv4Addr::new(
        198, 18, 0, 1
    ))));
    assert!(redirect_ip_is_private(IpAddr::V4(Ipv4Addr::new(
        224, 0, 0, 1
    ))));
    assert!(redirect_ip_is_private(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(redirect_ip_is_private(IpAddr::V6(
        "2001:db8::1".parse().unwrap()
    )));
    assert!(redirect_ip_is_private(IpAddr::V6(
        "100::1".parse().unwrap()
    )));
    assert!(redirect_ip_is_private(IpAddr::V6(
        "2001:1::1".parse().unwrap()
    )));
    assert!(redirect_ip_is_private(IpAddr::V6(
        "2002:0a00:0001::1".parse().unwrap()
    )));
    assert!(!redirect_ip_is_private(IpAddr::V6(
        "2606:4700:4700::1111".parse().unwrap()
    )));
    assert!(!redirect_ip_is_private(IpAddr::V4(Ipv4Addr::new(
        8, 8, 8, 8
    ))));
}

#[tokio::test]
async fn initial_subrequest_private_ip_check_rejects_loopback_target() {
    let module = SubrequestModule::new(SubrequestModuleConfig {
        name: "authz".to_string(),
        phase: SubrequestPhase::RequestHeaders,
        method: None,
        url: "http://127.0.0.1/check".to_string(),
        timeout_ms: Some(100),
        max_response_bytes: Some(1024),
        allowed_schemes: vec!["http".to_string()],
        allowed_hosts: vec!["*".to_string()],
        deny_redirects: false,
        deny_private_ip_redirects: true,
        pass_headers: Vec::new(),
        request_headers: Default::default(),
        copy_response_headers_to_request: Vec::new(),
        copy_response_headers_to_response: Vec::new(),
        response_mode: None,
    })
    .expect("module");
    let uri: http::Uri = "http://127.0.0.1/check".parse().expect("uri");
    let err = module
        .resolve_public_target_addr(&uri, Duration::from_millis(100))
        .await
        .expect_err("loopback target should be rejected");
    assert!(err.to_string().contains("private IP"));
}

#[test]
fn the_declared_response_length_is_read_through_the_owner() {
    // A comma list of equal members is one length, so a response that
    // declares a length over the limit is over it.
    let mut headers = Headers::new();
    headers.append_content_length_value(http::HeaderValue::from_static("100, 100"));
    assert!(response_exceeds_max_response_bytes(&headers, 64));

    // A declaration the owner refuses names no length, so the check does
    // not fire and the body is cut to the limit instead.
    let mut headers = Headers::new();
    headers.append_content_length_value(http::HeaderValue::from_static("+100"));
    assert!(!response_exceeds_max_response_bytes(&headers, 64));

    // A declared length within the limit is not over it.
    let mut headers = Headers::new();
    headers.append_content_length_value(http::HeaderValue::from_static("64"));
    assert!(!response_exceeds_max_response_bytes(&headers, 64));
}

#[test]
fn owned_subresponse_copies_first_literal_field_and_preserves_pending_order() {
    let module = SubrequestModule::new(
        serde_yaml::from_str(
            r#"
name: capture
phase: request_headers
url: https://auth.example.com/check
allowed_schemes: [https]
allowed_hosts: [auth.example.com]
max_response_bytes: 1024
copy_response_headers_to_request:
  - {from: content-length, to: x-length}
  - {from: x-opaque, to: content-length}
  - {from: x-missing, to: x-keep}
copy_response_headers_to_response:
  - {from: content-length, to: x-length}
  - {from: x-opaque, to: content-length}
  - {from: x-missing, to: x-keep}
"#,
        )
        .unwrap(),
    )
    .unwrap();
    let mut source = hyper::Response::new(Body::empty());
    let mut length = HeaderValue::from_static("0007");
    length.set_sensitive(true);
    source
        .headers_mut()
        .append(http::header::CONTENT_LENGTH, length);
    source
        .headers_mut()
        .append(http::header::CONTENT_LENGTH, HeaderValue::from_static("8"));
    let mut opaque = HeaderValue::from_bytes(b"\x80opaque").unwrap();
    opaque.set_sensitive(true);
    source.headers_mut().insert("x-opaque", opaque.clone());
    let source = Response::from_http(source); // Simulated subrequest client ingress.
    let mut ctx = crate::http::modules::tests::module_test_context();
    let mut request = OwnerRequest::new(Body::empty());
    request.headers_mut().insert(
        OrdinaryHeaderName::try_from("x-keep").unwrap(),
        HeaderValue::from_static("keep"),
    );
    ctx.sync_frozen_request(&request);
    ctx.queue_response_header(
        HeaderName::from_static("x-length"),
        HeaderValue::from_static("before"),
    );
    module.apply_request_response_headers(
        &source,
        &mut ctx,
        &mut HttpModuleRequest::new(&mut request),
    );
    let frozen = &ctx.session.request.as_ref().unwrap().headers;
    let copied = frozen
        .get(&OrdinaryHeaderName::try_from("x-length").unwrap())
        .unwrap();
    assert_eq!(copied, "0007");
    assert!(copied.is_sensitive());
    assert!(frozen.declared_content_length().is_err());
    assert_eq!(request.headers(), frozen);

    // Captured fields and caller-supplied literals share the same ordered queue.
    ctx.queue_response_header(
        HeaderName::from_static("x-length"),
        HeaderValue::from_static("after"),
    );
    let mut response =
        HttpModuleResponse::new(http::StatusCode::OK, crate::http::modules::Body::empty());
    response.set_header(
        HeaderName::from_static("x-keep"),
        HeaderValue::from_static("keep"),
    );
    ctx.apply_pending_response_headers(response.as_owner_mut());
    let raw = response.into_owner().into_http_for_library(); // Assertion boundary only.
    assert_eq!(raw.headers()["x-length"], "after");
    assert_eq!(raw.headers()["x-keep"], "keep");
    assert_eq!(raw.headers()[http::header::CONTENT_LENGTH], opaque);
    assert!(raw.headers()[http::header::CONTENT_LENGTH].is_sensitive());

    let mut response = HttpModuleResponse::new(
        http::StatusCode::ACCEPTED,
        crate::http::modules::Body::empty(),
    );
    response.set_header(
        HeaderName::from_static("x-keep"),
        HeaderValue::from_static("keep"),
    );
    module.apply_subrequest_response_headers(&source, &mut ctx, &mut response);
    let raw = response.into_owner().into_http_for_library();
    assert_eq!(raw.status(), http::StatusCode::ACCEPTED);
    assert_eq!(raw.headers()["x-length"], "0007");
    assert!(raw.headers()["x-length"].is_sensitive());
    assert_eq!(raw.headers()[http::header::CONTENT_LENGTH], opaque);
    assert!(raw.headers()[http::header::CONTENT_LENGTH].is_sensitive());
    assert_eq!(raw.headers()["x-keep"], "keep");
}
