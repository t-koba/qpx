use super::*;
use http::{StatusCode, Version};
use std::io::Write as _;

fn ordinary(name: &str) -> qpx_core::http_message::OrdinaryHeaderName {
    qpx_core::http_message::OrdinaryHeaderName::try_from(name).expect("ordinary field")
}

fn field(
    response: &qpx_core::http_message::Response<Body>,
    name: impl AsRef<str>,
) -> &http::HeaderValue {
    response
        .headers()
        .get(&ordinary(name.as_ref()))
        .expect("field")
}

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
    Request::from_http(
        http::Request::builder()
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
            .expect("preflight request"),
    )
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
            field(&response, "access-control-allow-origin"),
            ALLOWED_ORIGIN
        );
        assert_eq!(field(&response, "access-control-allow-credentials"), "true");
        assert_eq!(field(&response, "access-control-allow-methods"), "PUT");
        assert_eq!(
            field(&response, "access-control-allow-headers"),
            "content-type, x-request-id"
        );
        assert_eq!(field(&response, "access-control-max-age"), "600");
        assert_eq!(
            field(&response, "access-control-allow-private-network"),
            "true"
        );
        let vary = response
            .headers()
            .get_all(&ordinary("vary"))
            .map(|value| value.to_str().expect("Vary field"))
            .collect::<Vec<_>>();
        assert!(vary.contains(&"Origin"));
        assert!(vary.contains(&"access-control-request-method"));
        assert!(vary.contains(&"access-control-request-headers"));
        assert!(vary.contains(&"access-control-request-private-network"));
        assert_eq!(
            to_bytes(response.into_head_and_body().1)
                .await
                .expect("body"),
            ""
        );
    }
}

#[tokio::test]
async fn cors_actual_response_overrides_target_and_route_cors_fields() {
    let request = Request::from_http(
        http::Request::builder()
            .method(Method::PUT)
            .uri("/api/item")
            .header("host", "api.example")
            .header("origin", ALLOWED_ORIGIN)
            .body(Body::from("payload"))
            .expect("actual request"),
    );
    let (_, response) = handle_request_with_interim(request, build_cors_reverse(), connection())
        .await
        .expect("actual response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        field(&response, "access-control-allow-origin"),
        ALLOWED_ORIGIN
    );
    assert_eq!(field(&response, "access-control-allow-credentials"), "true");
    assert_eq!(field(&response, "access-control-expose-headers"), "etag");
    assert_eq!(field(&response, http::header::ETAG), "\"qpx\"");
    assert_eq!(
        to_bytes(response.into_head_and_body().1)
            .await
            .expect("response body"),
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
        field(&response, http::header::CONTENT_TYPE),
        qpx_http::problem::PROBLEM_JSON
    );
    assert!(
        !response
            .headers()
            .contains_key(&ordinary("access-control-allow-origin"))
    );
    let body = to_bytes(response.into_head_and_body().1)
        .await
        .expect("problem body");
    assert!(
        body.windows("CORS origin is not allowed".len())
            .any(|window| { window == "CORS origin is not allowed".as_bytes() })
    );
}

#[tokio::test]
async fn cors_disallowed_actual_origin_strips_target_allow_fields() {
    let request = Request::from_http(
        http::Request::builder()
            .method(Method::PUT)
            .uri("/api/item")
            .header("host", "api.example")
            .header("origin", "https://evil.example")
            .body(Body::empty())
            .expect("actual request"),
    );
    let (_, response) = handle_request_with_interim(request, build_cors_reverse(), connection())
        .await
        .expect("actual response");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !response
            .headers()
            .contains_key(&ordinary("access-control-allow-origin"))
    );
    assert!(
        !response.headers().contains_key(
            &qpx_core::http_message::OrdinaryHeaderName::try_from(
                "access-control-allow-credentials"
            )
            .unwrap()
        )
    );
    assert!(
        !response
            .headers()
            .contains_key(&ordinary("access-control-expose-headers"))
    );
}

#[tokio::test]
async fn malformed_cors_request_is_rejected_explicitly() {
    let request = Request::from_http(
        http::Request::builder()
            .method(Method::PUT)
            .uri("/api/item")
            .header("host", "api.example")
            .header("origin", ALLOWED_ORIGIN)
            .header("origin", "https://other.example")
            .body(Body::empty())
            .expect("malformed request"),
    );
    let (_, response) = handle_request_with_interim(request, build_cors_reverse(), connection())
        .await
        .expect("malformed CORS response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        field(&response, http::header::CONTENT_TYPE),
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
    let request = Request::from_http(
        http::Request::builder()
            .method(Method::PUT)
            .uri("/api/item")
            .header("host", "api.example")
            .header("origin", ALLOWED_ORIGIN)
            .body(Body::empty())
            .expect("actual request"),
    );
    let (_, response) = handle_request_with_interim(request, build_reverse(config), connection())
        .await
        .expect("gateway error response");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        field(&response, "access-control-allow-origin"),
        ALLOWED_ORIGIN
    );
    assert_eq!(field(&response, "access-control-allow-credentials"), "true");
}

#[tokio::test]
async fn cors_preflight_does_not_grant_later_route_permission_for_earlier_owner() {
    // Ordinary route precedence: the preflight authorizes the route the
    // actual request would select. The earlier route owns PUT /api/** and
    // carries no edge CORS policy, so the later route's permission must not
    // be granted for it; the preflight falls back to ordinary handling and
    // the browser never sends the cross-origin PUT.
    let reverse = build_reverse(
        br#"edges:
- kind: reverse
  name: overlap
  listen: 127.0.0.1:19080
  routes:
  - name: ordinary
    match:
      method: [PUT]
      path: [/api/**]
    target:
      type: local_response
      response:
        status: 200
        content_type: text/plain
        body: ordinary
  - name: cors
    match:
      method: [PUT]
      path: [/api/**]
    http:
      cors:
        allowed_origins: [https://app.example]
        allowed_methods: [PUT]
    target:
      type: local_response
      response:
        status: 200
        content_type: text/plain
        body: cors
"#,
    );
    let preflight = Request::from_http(
        http::Request::builder()
            .method(Method::OPTIONS)
            .uri("/api/item")
            .header("host", "api.example")
            .header("origin", ALLOWED_ORIGIN)
            .header("access-control-request-method", "PUT")
            .body(Body::empty())
            .expect("preflight request"),
    );
    let (_, preflight_response) =
        handle_request_with_interim(preflight, reverse.clone(), connection())
            .await
            .expect("preflight response");
    assert_ne!(preflight_response.status(), StatusCode::NO_CONTENT);
    assert!(
        !preflight_response
            .headers()
            .contains_key(&ordinary("access-control-allow-origin")),
        "later route permission must not authorize the earlier owner's request"
    );

    // The actual request still selects the earlier route, without edge CORS.
    let actual = Request::from_http(
        http::Request::builder()
            .method(Method::PUT)
            .uri("/api/item")
            .header("host", "api.example")
            .header("origin", ALLOWED_ORIGIN)
            .body(Body::empty())
            .expect("actual request"),
    );
    let (_, actual_response) = handle_request_with_interim(actual, reverse, connection())
        .await
        .expect("actual response");
    assert_eq!(actual_response.status(), StatusCode::OK);
    assert!(
        !actual_response
            .headers()
            .contains_key(&ordinary("access-control-allow-origin"))
    );
    assert_eq!(
        to_bytes(actual_response.into_head_and_body().1)
            .await
            .expect("response body"),
        "ordinary"
    );
}

#[tokio::test]
async fn reverse_terminal_metadata_preserves_policy_effects_for_h1_and_h2() {
    let reverse = build_reverse(
        br#"edges:
- kind: reverse
  name: terminal-metadata
  listen: 127.0.0.1:19080
  routes:
  - match:
      path: [/api/**]
    headers:
      response_set:
        Referrer-Policy: unsafe-url
        Access-Control-Allow-Origin: https://route.example
    http:
      api_metadata:
        deprecation_unix_seconds: 0
        links:
        - target: /docs
          relation: deprecation
      hsts:
        max_age_seconds: 60
        include_subdomains: true
      cors:
        allowed_origins: [https://app.example]
        allowed_methods: [GET]
        allow_credentials: true
      cookies:
        require_secure: false
        require_http_only: true
        same_site: lax
      fetch_metadata:
        allowed_sites: [same-origin]
        allow_missing: true
      browser_security:
        referrer_policy: same-origin
        x_content_type_options: nosniff
    target:
      type: local_response
      response:
        status: 201
        content_type: text/plain
        body: terminal
        headers:
          Link: '</first>; rel=alternate'
          Set-Cookie: 'session=1; Path=/'
          Vary: Accept-Encoding
"#,
    );
    for version in [Version::HTTP_11, Version::HTTP_2] {
        for secure in [false, true] {
            let mut conn = connection();
            conn.tls_terminated = secure;
            conn.tls_sni = secure.then(|| StdArc::from("api.example"));
            let req = Request::from_http(
                http::Request::builder()
                    .method(Method::GET)
                    .uri("/api/item")
                    .version(version)
                    .header("host", "api.example")
                    .header("origin", ALLOWED_ORIGIN)
                    .body(Body::empty())
                    .unwrap(),
            );
            let (interim, response) = handle_request_with_interim(req, reverse.clone(), conn)
                .await
                .unwrap();
            assert!(interim.is_empty());
            // The successful response reaches the service boundary already owned.
            let response: qpx_core::http_message::Response<Body> = response;
            assert_eq!(response.status(), StatusCode::CREATED);
            // Local response heads retain their constructed version; the codec
            // selects the actual downstream protocol, as before adoption.
            assert_eq!(response.version(), Version::HTTP_11);
            assert_eq!(response.headers().declared_content_length().unwrap(), None);
            assert_eq!(field(&response, "deprecation"), "@0");
            assert_eq!(
                field(&response, "access-control-allow-origin"),
                ALLOWED_ORIGIN
            );
            assert_eq!(field(&response, "access-control-allow-credentials"), "true");
            assert_eq!(
                field(&response, "set-cookie"),
                "session=1; Path=/; HttpOnly; SameSite=Lax"
            );
            assert_eq!(field(&response, "referrer-policy"), "same-origin");
            assert_eq!(field(&response, "x-content-type-options"), "nosniff");
            assert_eq!(
                response
                    .headers()
                    .contains_key(&ordinary("strict-transport-security")),
                secure
            );
            if secure {
                assert_eq!(
                    field(&response, "strict-transport-security"),
                    "max-age=60; includeSubDomains"
                );
            }
            assert_eq!(
                response
                    .headers()
                    .get_all(&ordinary("link"))
                    .map(|v| v.to_str().unwrap())
                    .collect::<Vec<_>>(),
                ["</first>; rel=alternate", "</docs>; rel=\"deprecation\""]
            );
            assert_eq!(
                field(&response, "vary"),
                "Accept-Encoding, Origin, sec-fetch-site, sec-fetch-mode, sec-fetch-dest"
            );
            assert_eq!(
                to_bytes(response.into_head_and_body().1).await.unwrap(),
                "terminal"
            );
        }
    }
}
