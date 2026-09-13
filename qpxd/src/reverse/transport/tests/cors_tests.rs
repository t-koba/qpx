use super::*;
use http::{StatusCode, Version};
use std::io::Write as _;

const ALLOWED_ORIGIN: &str = "https://app.example";

fn build_reverse(config: &[u8]) -> crate::reverse::ReloadableReverse {
    let mut file = tempfile::NamedTempFile::new().expect("temporary CORS config");
    file.write_all(config).expect("write CORS config");
    let config = qpx_core::config::load_config(file.path()).expect("load CORS config");
    let reverse_config = config.reverse_edge_configs()[0].clone();
    let runtime = Runtime::new(config).expect("CORS runtime");
    crate::reverse::ReloadableReverse::new(
        reverse_config,
        runtime,
        StdArc::<str>::from("reverse_upstreams_unhealthy"),
    )
    .expect("CORS reverse")
}

fn build_cors_reverse() -> crate::reverse::ReloadableReverse {
    build_reverse(
        br#"edges:
- kind: reverse
  name: cors-origin
  listen: 127.0.0.1:19080
  routes:
  - name: api
    match:
      method: [PUT]
      path: [/api/**]
    headers:
      response_set:
        Access-Control-Allow-Origin: https://route-header.example
    http:
      cors:
        allowed_origins: [https://app.example]
        allowed_methods: [PUT]
        allowed_headers: [content-type, x-request-id]
        expose_headers: [etag]
        allow_credentials: true
        max_age_seconds: 600
        allow_private_network: true
    target:
      type: local_response
      response:
        status: 200
        content_type: text/plain
        body: origin
        headers:
          Access-Control-Allow-Origin: https://target-header.example
          ETag: '"qpx"'
"#,
    )
}

fn connection() -> ReverseConnInfo {
    ReverseConnInfo::plain(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
        19080,
    )
}

fn preflight_request(version: Version, origin: &str) -> Request<Body> {
    Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/item")
        .version(version)
        .header("host", "api.example")
        .header("origin", origin)
        .header("access-control-request-method", "PUT")
        .header(
            "access-control-request-headers",
            "Content-Type, X-Request-Id",
        )
        .header("access-control-request-private-network", "true")
        .body(Body::empty())
        .expect("preflight request")
}

#[tokio::test]
async fn cors_preflight_selects_actual_method_route_for_all_http_versions() {
    let reverse = build_cors_reverse();
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        let (_, response) = handle_request_with_interim(
            preflight_request(version, ALLOWED_ORIGIN),
            reverse.clone(),
            connection(),
        )
        .await
        .expect("preflight response");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            ALLOWED_ORIGIN
        );
        assert_eq!(
            response.headers()["access-control-allow-credentials"],
            "true"
        );
        assert_eq!(response.headers()["access-control-allow-methods"], "PUT");
        assert_eq!(
            response.headers()["access-control-allow-headers"],
            "content-type, x-request-id"
        );
        assert_eq!(response.headers()["access-control-max-age"], "600");
        assert_eq!(
            response.headers()["access-control-allow-private-network"],
            "true"
        );
        let vary = response
            .headers()
            .get_all(http::header::VARY)
            .iter()
            .map(|value| value.to_str().expect("Vary field"))
            .collect::<Vec<_>>();
        assert!(vary.contains(&"Origin"));
        assert!(vary.contains(&"access-control-request-method"));
        assert!(vary.contains(&"access-control-request-headers"));
        assert!(vary.contains(&"access-control-request-private-network"));
        assert_eq!(to_bytes(response.into_body()).await.expect("body"), "");
    }
}

#[tokio::test]
async fn cors_actual_response_overrides_target_and_route_cors_fields() {
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/api/item")
        .header("host", "api.example")
        .header("origin", ALLOWED_ORIGIN)
        .body(Body::from("payload"))
        .expect("actual request");
    let (_, response) = handle_request_with_interim(request, build_cors_reverse(), connection())
        .await
        .expect("actual response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        ALLOWED_ORIGIN
    );
    assert_eq!(
        response.headers()["access-control-allow-credentials"],
        "true"
    );
    assert_eq!(response.headers()["access-control-expose-headers"], "etag");
    assert_eq!(response.headers()[http::header::ETAG], "\"qpx\"");
    assert_eq!(
        to_bytes(response.into_body()).await.expect("response body"),
        "origin"
    );
}

#[tokio::test]
async fn cors_denial_returns_problem_without_allow_fields() {
    let (_, response) = handle_request_with_interim(
        preflight_request(Version::HTTP_11, "https://evil.example"),
        build_cors_reverse(),
        connection(),
    )
    .await
    .expect("denied preflight response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()[http::header::CONTENT_TYPE],
        qpx_http::problem::PROBLEM_JSON
    );
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-origin")
    );
    let body = to_bytes(response.into_body()).await.expect("problem body");
    assert!(
        body.windows("CORS origin is not allowed".len())
            .any(|window| { window == "CORS origin is not allowed".as_bytes() })
    );
}

#[tokio::test]
async fn cors_disallowed_actual_origin_strips_target_allow_fields() {
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/api/item")
        .header("host", "api.example")
        .header("origin", "https://evil.example")
        .body(Body::empty())
        .expect("actual request");
    let (_, response) = handle_request_with_interim(request, build_cors_reverse(), connection())
        .await
        .expect("actual response");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-origin")
    );
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    assert!(
        !response
            .headers()
            .contains_key("access-control-expose-headers")
    );
}

#[tokio::test]
async fn malformed_cors_request_is_rejected_explicitly() {
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/api/item")
        .header("host", "api.example")
        .header("origin", ALLOWED_ORIGIN)
        .header("origin", "https://other.example")
        .body(Body::empty())
        .expect("malformed request");
    let (_, response) = handle_request_with_interim(request, build_cors_reverse(), connection())
        .await
        .expect("malformed CORS response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers()[http::header::CONTENT_TYPE],
        qpx_http::problem::PROBLEM_JSON
    );
}

#[tokio::test]
async fn cors_is_applied_to_generated_upstream_failure_response() {
    let config = br#"edges:
- kind: reverse
  name: cors-upstream
  listen: 127.0.0.1:19080
  routes:
  - match:
      method: [PUT]
      path: [/api/**]
    http:
      cors:
        allowed_origins: [https://app.example]
        allowed_methods: [PUT]
        allow_credentials: true
    target:
      type: upstream
      upstreams: [http://127.0.0.1:0]
"#;
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/api/item")
        .header("host", "api.example")
        .header("origin", ALLOWED_ORIGIN)
        .body(Body::empty())
        .expect("actual request");
    let (_, response) = handle_request_with_interim(request, build_reverse(config), connection())
        .await
        .expect("gateway error response");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        ALLOWED_ORIGIN
    );
    assert_eq!(
        response.headers()["access-control-allow-credentials"],
        "true"
    );
}
