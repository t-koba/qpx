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
