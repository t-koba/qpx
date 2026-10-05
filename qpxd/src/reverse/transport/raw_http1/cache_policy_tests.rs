use super::*;

fn configure_policy(config: &mut qpx_core::config::Config, burst: u64) {
    config.http = serde_yaml::from_str(
        r#"
guard_profiles:
- name: head-only
  normalize: {path: true, query: true, headers: true}
  limits: {path_bytes: 32, query_pairs: 2, header_count: 8, header_bytes: 1024}
"#,
    )
    .expect("guard configuration");
    let qpx_core::config::EdgeConfig::Reverse(edge) = &mut config.edges[0] else {
        panic!("reverse edge is required");
    };
    let route = &mut edge.routes[0];
    route.http_guard_profile = Some("head-only".into());
    route.headers = Some(
        serde_yaml::from_str(
            r#"
request_set: {Host: transformed.local, X-Request-Policy: applied}
request_add: {X-Forwarded-By: qpx}
request_remove: [X-Internal-Only]
response_set: {X-Content-Type-Options: nosniff}
response_add: {X-Qpx-Feature-Set: rich}
"#,
        )
        .expect("header configuration"),
    );
    route.http = Some(
        serde_yaml::from_str(
            r#"
forwarded:
  trusted_peers: [127.0.0.1/32]
  by: qpx-rich
  untrusted_chain: discard
api_metadata:
  deprecation_unix_seconds: 2000000000
  sunset_unix_seconds: 2000003600
  links:
  - {target: 'https://bench.local/migration', relation: successor-version, media_type: text/html}
"#,
        )
        .expect("HTTP policy"),
    );
    route.http_modules = serde_yaml::from_str(
        r#"
- type: cache_purge
  settings: {methods: [PURGE], require_identity: false, allowed_peers: [127.0.0.1/32]}
- type: response_compression
  settings: {min_body_bytes: 1, max_body_bytes: 2097152, gzip: true, brotli: true, zstd: true}
"#,
    )
    .expect("module configuration");
    route.rate_limit = Some(
        serde_yaml::from_str(&format!(
            "enabled: true\nrequests: {{rps: 1, burst: {burst}}}"
        ))
        .expect("rate configuration"),
    );
}

fn prepare<'a>(
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
    cache: &'a mut RawHttp1ConnectionCache,
    raw: &[u8],
) -> &'a PreparedRawHttp1Request {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    assert!(request.parse(raw).expect("raw request").is_complete());
    prepare_raw_http1_request(
        reverse,
        conn,
        RawHttp1RequestView {
            raw_head: raw,
            method: request.method.expect("method"),
            target: request.path.expect("target"),
            version: request.version.expect("version"),
            headers: request.headers,
        },
        cache,
    )
    .expect("prepared request")
}

async fn fixture(burst: u64) -> (tempfile::TempDir, ReloadableReverse, ReverseConnInfo) {
    let upstream = crate::test_util::spawn_static_http_server(
        "200 OK",
        vec![("Cache-Control", "max-age=600".into())],
        "policy-payload".into(),
        1,
    )
    .await;
    let dir = tempfile::tempdir().expect("cache directory");
    let path = std::fs::canonicalize(dir.path()).expect("real cache directory");
    let reverse = super::tests::build_cache_hit_reverse_fixture_with_configuration(
        upstream,
        &path,
        Default::default(),
        |config| configure_policy(config, burst),
    );
    (
        dir,
        reverse,
        ReverseConnInfo::plain(([127, 0, 0, 1], 4242).into(), 18080),
    )
}

async fn publish(
    prepared: &PreparedRawHttp1Request,
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
) {
    let (_, response) = super::super::handle_request_with_interim_ref(
        prepared.generic_request().expect("generic request"),
        reverse,
        conn,
    )
    .await
    .expect("real origin dispatch");
    assert_eq!(response.status(), StatusCode::OK);
    let body = qpx_http::body::to_bytes(response.into_body())
        .await
        .expect("origin body");
    assert_eq!(body.as_ref(), b"policy-payload");
    let fast = prepared.cache_hit.as_ref().expect("prepared cache path");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if try_raw_cache_hit_response(fast).is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("disk writeback publication");
}

async fn response_parts(response: PreparedRawHttp1Response) -> (StatusCode, HeaderMap, Bytes) {
    match response {
        PreparedRawHttp1Response::InMemory {
            status,
            headers,
            body,
        } => (status, headers, body),
        PreparedRawHttp1Response::Generic(_, response) => {
            let (parts, body) = response.into_parts();
            (
                parts.status,
                parts.headers,
                qpx_http::body::to_bytes(body).await.expect("response body"),
            )
        }
        PreparedRawHttp1Response::Direct(_) => panic!("cache hit cannot relay an origin"),
    }
}

const HEAD: &[u8] = b"GET /bench-1 HTTP/1.1\r\nHost: bench.local\r\n\r\n";

#[tokio::test]
async fn prepared_cache_hit_preserves_policy_and_generic_response() {
    let (_dir, reverse, conn) = fixture(100).await;
    let mut cache = RawHttp1ConnectionCache::default();
    let prepared = prepare(&reverse, &conn, &mut cache, HEAD);
    assert!(
        prepared
            .cache_hit
            .as_ref()
            .expect("eligible head policy")
            .policy
            .is_some()
    );
    publish(prepared, &reverse, &conn).await;
    let actual = prepared
        .try_serving_cache_hit()
        .expect("cache policy execution")
        .expect("published hot hit");
    let (status, headers, body) = response_parts(actual).await;
    let (_, expected) = super::super::handle_request_with_interim_ref(
        prepared.generic_request().expect("reference request"),
        &reverse,
        &conn,
    )
    .await
    .expect("generic hot hit");
    let (parts, expected_body) = expected.into_parts();
    assert_eq!(status, parts.status);
    assert_eq!(
        body,
        qpx_http::body::to_bytes(expected_body)
            .await
            .expect("reference body")
    );
    for name in [
        "x-content-type-options",
        "x-qpx-feature-set",
        "deprecation",
        "sunset",
        "link",
        "content-length",
        "cache-control",
        "cache-status",
        "server",
        "via",
        "proxy-status",
    ] {
        assert_eq!(
            headers.get_all(name),
            parts.headers.get_all(name),
            "header {name}"
        );
    }
    assert_eq!(headers["x-qpx-feature-set"], "rich");
    assert!(headers.contains_key("deprecation"));
}

#[tokio::test]
async fn prepared_cache_hit_consumes_each_admission_token_once() {
    let (_dir, reverse, conn) = fixture(2).await;
    let mut cache = RawHttp1ConnectionCache::default();
    let prepared = prepare(&reverse, &conn, &mut cache, HEAD);
    assert!(
        prepared
            .try_serving_cache_hit()
            .expect("cold lookup")
            .is_none()
    );
    publish(prepared, &reverse, &conn).await;
    let hit = prepared
        .try_serving_cache_hit()
        .expect("second admission")
        .expect("hot hit");
    assert_eq!(response_parts(hit).await.0, StatusCode::OK);
    let denied = prepared
        .try_serving_cache_hit()
        .expect("third admission")
        .expect("rate response");
    let (status, headers, _) = response_parts(denied).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.contains_key(http::header::RETRY_AFTER));
    assert!(headers.contains_key("deprecation"));
}

#[tokio::test]
async fn prepared_cache_hit_preserves_guard_rejection_and_active_modules() {
    let (_dir, reverse, conn) = fixture(100).await;
    for (raw, status) in [
        (&b"GET /path-that-is-longer-than-thirty-two-bytes HTTP/1.1\r\nHost: bench.local\r\n\r\n"[..], Some(StatusCode::PAYLOAD_TOO_LARGE)),
        (&b"GET /bench-1?a=1&b=2&c=3 HTTP/1.1\r\nHost: bench.local\r\n\r\n"[..], Some(StatusCode::BAD_REQUEST)),
        (&b"GET /bench-1 HTTP/1.1\r\nHost: bench.local\r\nAccept-Encoding: gzip\r\n\r\n"[..], None),
        (&b"GET /bench-1 HTTP/1.1\r\nHost: bench.local\r\nCache-Control: no-cache\r\n\r\n"[..], None),
    ] {
        let mut cache = RawHttp1ConnectionCache::default();
        let prepared = prepare(&reverse, &conn, &mut cache, raw);
        assert!(prepared.cache_hit.is_none());
        if let Some(status) = status {
            let (_, response) = super::super::handle_request_with_interim_ref(
                prepared.generic_request().expect("rejected request"), &reverse, &conn,
            ).await.expect("guard dispatch");
            assert_eq!(response.status(), status);
        }
    }
}

#[tokio::test]
async fn prepared_cache_hit_checks_transformed_request_headers() {
    let dir = tempfile::tempdir().expect("cache directory");
    let path = std::fs::canonicalize(dir.path()).expect("real cache directory");
    let origin = crate::test_util::spawn_static_http_server(
        "200 OK",
        Vec::new(),
        "policy-payload".into(),
        1,
    )
    .await;
    let conn = ReverseConnInfo::plain(([127, 0, 0, 1], 4242).into(), 18080);
    for (name, value) in [
        ("Accept-Encoding", "gzip"),
        ("Cache-Control", "no-cache"),
        ("If-None-Match", "\"etag\""),
        ("Range", "bytes=0-3"),
        ("Upgrade", "websocket"),
        ("Expect", "100-continue"),
        ("Transfer-Encoding", "chunked"),
        ("Content-Length", "1"),
    ] {
        let reverse = super::tests::build_cache_hit_reverse_fixture_with_configuration(
            origin,
            &path,
            Default::default(),
            |config| {
                configure_policy(config, 100);
                let qpx_core::config::EdgeConfig::Reverse(edge) = &mut config.edges[0] else {
                    panic!("reverse edge is required");
                };
                edge.routes[0]
                    .headers
                    .as_mut()
                    .expect("header control")
                    .request_set
                    .insert(name.into(), value.into());
            },
        );
        let mut cache = RawHttp1ConnectionCache::default();
        let prepared = prepare(&reverse, &conn, &mut cache, HEAD);
        assert!(
            prepared.cache_hit.is_none(),
            "transformed {name} must use generic dispatch"
        );
    }
}

#[tokio::test]
async fn prepared_cache_hit_is_invalidated_by_policy_reload() {
    let (_dir, reverse, conn) = fixture(100).await;
    let mut cache = RawHttp1ConnectionCache::default();
    let prepared = prepare(&reverse, &conn, &mut cache, HEAD);
    assert!(prepared.cache_hit.is_some());
    assert_eq!(cache.cached_prefix_len(&reverse, HEAD), Some(HEAD.len()));
    let mut config = (*reverse.runtime.state().resources.operational).clone();
    config.http.guard_profiles[0].limits.path_bytes = Some(2);
    let new_state = crate::runtime::RuntimeState::build(config).expect("new policy runtime");
    reverse.runtime.swap(new_state);
    assert!(cache.cached_prefix_len(&reverse, HEAD).is_none());
    let mut new_cache = RawHttp1ConnectionCache::default();
    // Recompile the router against the new immutable runtime before preparing.
    let config = &reverse.runtime.state().resources.operational;
    let qpx_core::config::EdgeConfig::Reverse(edge) = &config.edges[0] else {
        panic!("reverse edge is required");
    };
    let reloaded = ReloadableReverse::new(
        edge.clone(),
        reverse.runtime.clone(),
        Arc::from("reverse_upstreams_unhealthy"),
    )
    .expect("reloaded reverse");
    let prepared = prepare(&reloaded, &conn, &mut new_cache, HEAD);
    assert!(prepared.cache_hit.is_none());
    let (_, response) = super::super::handle_request_with_interim_ref(
        prepared.generic_request().expect("reloaded request"),
        &reloaded,
        &conn,
    )
    .await
    .expect("reloaded guard dispatch");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn prepared_cache_hit_preserves_persistent_reads_after_restart() {
    let (dir, reverse, conn) = fixture(100).await;
    let mut cache = RawHttp1ConnectionCache::default();
    let prepared = prepare(&reverse, &conn, &mut cache, HEAD);
    publish(prepared, &reverse, &conn).await;
    let config = (*reverse.runtime.state().resources.operational).clone();
    let qpx_core::config::EdgeConfig::Reverse(edge) = config.edges[0].clone() else {
        panic!("reverse edge is required");
    };
    drop(cache);
    drop(reverse);
    let runtime = crate::runtime::Runtime::new(config).expect("restart runtime");
    let restarted = ReloadableReverse::new(edge, runtime, Arc::from("reverse_upstreams_unhealthy"))
        .expect("restart reverse");
    let mut cache = RawHttp1ConnectionCache::default();
    let prepared = prepare(&restarted, &conn, &mut cache, HEAD);
    let response = if let Some(response) = prepared.try_serving_cache_hit().expect("restart probe")
    {
        response
    } else {
        let (interim, response) = super::super::handle_request_with_interim_ref(
            prepared.generic_request().expect("restart request"),
            &restarted,
            &conn,
        )
        .await
        .expect("persistent lookup");
        PreparedRawHttp1Response::Generic(interim, response)
    };
    let (status, headers, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"policy-payload");
    assert!(
        headers["cache-status"]
            .to_str()
            .expect("cache status")
            .contains("hit")
    );
    assert_eq!(headers["x-qpx-feature-set"], "rich");
    assert!(dir.path().exists());
}

#[tokio::test]
async fn prepared_cache_hit_keeps_vary_negotiation_on_generic_path() {
    let origin = crate::test_util::spawn_static_http_server(
        "200 OK",
        vec![
            ("Cache-Control", "max-age=600".into()),
            ("Vary", "Accept-Language".into()),
        ],
        "policy-payload".into(),
        1,
    )
    .await;
    let dir = tempfile::tempdir().expect("cache directory");
    let path = std::fs::canonicalize(dir.path()).expect("real cache directory");
    let reverse = super::tests::build_cache_hit_reverse_fixture_with_configuration(
        origin,
        &path,
        Default::default(),
        |config| configure_policy(config, 100),
    );
    let conn = ReverseConnInfo::plain(([127, 0, 0, 1], 4242).into(), 18080);
    let mut cache = RawHttp1ConnectionCache::default();
    let prepared = prepare(&reverse, &conn, &mut cache, HEAD);
    let (_, response) = super::super::handle_request_with_interim_ref(
        prepared.generic_request().expect("origin request"),
        &reverse,
        &conn,
    )
    .await
    .expect("vary origin dispatch");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        qpx_http::body::to_bytes(response.into_body())
            .await
            .expect("vary body")
            .as_ref(),
        b"policy-payload"
    );
    let fast = prepared.cache_hit.as_ref().expect("prepared policy");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if fast
                .backend
                .get(
                    &fast.namespace,
                    fast.key.primary_index_storage_key().as_ref(),
                )
                .await
                .expect("persistent variant index")
                .is_some()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("variant index publication");
    assert!(
        prepared
            .try_serving_cache_hit()
            .expect("vary probe")
            .is_none()
    );
    let (_, response) = super::super::handle_request_with_interim_ref(
        prepared.generic_request().expect("vary reference"),
        &reverse,
        &conn,
    )
    .await
    .expect("generic variant lookup");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["cache-status"]
            .to_str()
            .expect("cache status")
            .contains("hit")
    );
    assert_eq!(
        qpx_http::body::to_bytes(response.into_body())
            .await
            .expect("cached variant")
            .as_ref(),
        b"policy-payload"
    );
}
