use super::*;
use crate::forward::h3::connect::parse::{
    parse_connect_authority_with_default, parse_connect_udp_target,
};

#[test]
fn connect_authority_requires_explicit_port() {
    assert!(parse_connect_authority_with_default("example.com", None).is_err());
    let (host, port) =
        parse_connect_authority_with_default("example.com:8443", None).expect("valid");
    assert_eq!(host, "example.com");
    assert_eq!(port, 8443);
}

#[test]
fn extended_connect_authority_accepts_default_port() {
    let (host, port) =
        parse_connect_authority_with_default("example.com", Some(443)).expect("valid");
    assert_eq!(host, "example.com");
    assert_eq!(port, 443);
}

#[test]
fn connect_authority_rejects_userinfo_and_absolute_form() {
    assert!(parse_connect_authority_with_default("user@example.com:443", Some(443)).is_err());
    assert!(parse_connect_authority_with_default("https://example.com:443", Some(443)).is_err());
    assert!(parse_connect_authority_with_default("example.com:443/path", Some(443)).is_err());
}

#[test]
fn connect_udp_target_from_well_known_path() {
    let uri = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/.well-known/masque/udp/192.0.2.6/443/")
        .build()
        .unwrap();
    let (host, port) = parse_connect_udp_target(&uri, None).expect("valid");
    assert_eq!(host, "192.0.2.6");
    assert_eq!(port, 443);

    let uri = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/.well-known/masque/udp/2001%3Adb8%3A%3A42/8443/")
        .build()
        .unwrap();
    let (host, port) = parse_connect_udp_target(&uri, None).expect("valid");
    assert_eq!(host, "2001:db8::42");
    assert_eq!(port, 8443);

    let repeated_slashes = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("//.well-known/masque/udp/192.0.2.6/443/")
        .build()
        .unwrap();
    assert!(parse_connect_udp_target(&repeated_slashes, None).is_err());

    let suffix = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/.well-known/masque/udp/192.0.2.6/443/extra")
        .build()
        .unwrap();
    assert!(parse_connect_udp_target(&suffix, None).is_err());
}

#[test]
fn connect_udp_target_from_query() {
    let uri = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/masque?h=example.com&p=8443")
        .build()
        .unwrap();
    let (host, port) = parse_connect_udp_target(&uri, None).expect("valid");
    assert_eq!(host, "example.com");
    assert_eq!(port, 8443);
}

#[test]
fn connect_udp_target_rejects_invalid_host_syntax() {
    let uri = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/masque?h=bad%20host&p=8443")
        .build()
        .unwrap();
    assert!(parse_connect_udp_target(&uri, None).is_err());

    let uri = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/.well-known/masque/udp/user%40example.com/443/")
        .build()
        .unwrap();
    assert!(parse_connect_udp_target(&uri, None).is_err());
}

#[test]
fn connect_udp_target_normalizes_bracketed_ipv6_literal() {
    let uri = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/.well-known/masque/udp/[::1]/443/")
        .build()
        .expect("uri");
    let (host, port) = parse_connect_udp_target(&uri, None).expect("target");
    assert_eq!(host, "::1");
    assert_eq!(port, 443);
}

#[test]
fn connect_udp_target_from_custom_template_path() {
    let uri = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/masque/udp/example.com/8443")
        .build()
        .unwrap();
    let template = "https://proxy.example/masque/udp/{target_host}/{target_port}";
    let (host, port) = parse_connect_udp_target(&uri, Some(template)).expect("valid");
    assert_eq!(host, "example.com");
    assert_eq!(port, 8443);
}

#[test]
fn connect_udp_target_from_absolute_template_enforces_scheme_and_authority() {
    let template = "https://proxy.example/masque/udp/{target_host}/{target_port}";

    let uri = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example:443")
        .path_and_query("/masque/udp/example.com/8443")
        .build()
        .unwrap();
    let (host, port) = parse_connect_udp_target(&uri, Some(template)).expect("valid");
    assert_eq!(host, "example.com");
    assert_eq!(port, 8443);

    let wrong_scheme = ::http::Uri::builder()
        .scheme("http")
        .authority("proxy.example")
        .path_and_query("/masque/udp/example.com/8443")
        .build()
        .unwrap();
    assert!(parse_connect_udp_target(&wrong_scheme, Some(template)).is_err());

    let wrong_authority = ::http::Uri::builder()
        .scheme("https")
        .authority("other-proxy.example")
        .path_and_query("/masque/udp/example.com/8443")
        .build()
        .unwrap();
    assert!(parse_connect_udp_target(&wrong_authority, Some(template)).is_err());
}

#[test]
fn connect_udp_target_from_template_requires_exact_path_structure() {
    let template = "https://proxy.example/masque/udp/{target_host}/{target_port}/";

    let repeated_slashes = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("//masque//udp/example.com/8443/")
        .build()
        .unwrap();
    assert!(parse_connect_udp_target(&repeated_slashes, Some(template)).is_err());

    let missing_trailing_slash = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/masque/udp/example.com/8443")
        .build()
        .unwrap();
    assert!(parse_connect_udp_target(&missing_trailing_slash, Some(template)).is_err());
}

#[test]
fn connect_udp_target_from_template_enforces_literal_query() {
    let template = "https://proxy.example/masque?mode=udp&h={target_host}&p={target_port}";
    let uri = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/masque?mode=udp&h=example.com&p=8443")
        .build()
        .unwrap();
    let (host, port) = parse_connect_udp_target(&uri, Some(template)).expect("valid");
    assert_eq!(host, "example.com");
    assert_eq!(port, 8443);

    let wrong_literal = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/masque?mode=tcp&h=example.com&p=8443")
        .build()
        .unwrap();
    assert!(parse_connect_udp_target(&wrong_literal, Some(template)).is_err());

    let extra_query = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/masque?mode=udp&h=example.com&p=8443&extra=1")
        .build()
        .unwrap();
    assert!(parse_connect_udp_target(&extra_query, Some(template)).is_err());
}

#[test]
fn connect_udp_target_from_template_supports_rfc6570_operators() {
    let template =
        "https://proxy.example/masque{/target_host}{;target_port}{?target_host,target_port}";
    let uri = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query(
            "/masque/example.com;target_port=8443?target_host=example.com&target_port=8443",
        )
        .build()
        .unwrap();
    let (host, port) = parse_connect_udp_target(&uri, Some(template)).expect("valid");
    assert_eq!(host, "example.com");
    assert_eq!(port, 8443);
}

#[test]
fn normalize_h3_upstream_connect_headers_strips_proxy_auth_and_adds_via() {
    let uri = ::http::Uri::builder()
        .scheme("https")
        .authority("proxy.example")
        .path_and_query("/chat")
        .build()
        .unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::HeaderName::from_static("proxy-authorization"),
        http::HeaderValue::from_static("Basic dGVzdA=="),
    );
    headers.insert(
        http::header::HeaderName::from_static("connection"),
        http::HeaderValue::from_static("proxy-authorization"),
    );
    headers.insert(
        http::header::HeaderName::from_static("x-custom"),
        http::HeaderValue::from_static("ok"),
    );

    let normalized = normalize_h3_upstream_connect_headers(&uri, &headers, "qpx").expect("headers");
    assert!(normalized.get("proxy-authorization").is_none());
    assert_eq!(
        normalized.get("host").and_then(|v| v.to_str().ok()),
        Some("proxy.example")
    );
    assert_eq!(
        normalized.get("via").and_then(|v| v.to_str().ok()),
        Some("3 qpx")
    );
    assert_eq!(
        normalized.get("x-custom").and_then(|v| v.to_str().ok()),
        Some("ok")
    );
}
