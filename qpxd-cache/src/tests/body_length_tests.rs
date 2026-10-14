use super::*;

// Leave one writeback slot available, then wait for it to be released. This
// observes completion of both successful and rejected asynchronous stores.
async fn store_length_case(
    request: &Request<Body>,
    response: Response<Body>,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Response<Body> {
    let key = CacheRequestKey::for_lookup(request, "http")
        .expect("key")
        .expect("some key");
    let admission = test_writeback_admission();
    let mut reserved = Vec::new();
    while let Some(permit) = admission.try_acquire() {
        reserved.push(permit);
    }
    drop(reserved.pop());
    let response = maybe_store(
        request.method(),
        request.headers(),
        &key,
        &policy(),
        response,
        CacheStoreContext {
            timing: CacheStoreTiming {
                response_delay_secs: 0,
                body_read_timeout: Duration::from_secs(1),
                request_collapse_guard: None,
            },
            writeback_admission: &admission,
            backends,
        },
    )
    .await
    .expect("client response");
    let (parts, body) = response.into_parts();
    let bytes = qpx_http::body::to_bytes(body)
        .await
        .expect("client body must not be aborted by cache validation");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(permit) = admission.try_acquire() {
                break permit;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("writeback must finish");
    Response::from_parts(parts, Body::from(bytes))
}

async fn lookup_length_case(
    request: &Request<Body>,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> LookupOutcome {
    let key = CacheRequestKey::for_lookup(request, "http")
        .expect("key")
        .expect("some key");
    lookup(
        request.method(),
        request.headers(),
        &key,
        &policy(),
        backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup")
}

#[tokio::test]
async fn mismatched_get_body_reaches_client_but_publishes_nothing() {
    // Cover early EOF (including an empty body), overrun (including declared
    // zero), and a short stream ending in trailers rather than plain EOF.
    for (declared, payload, trailers) in [
        (7, "hello", None),
        (7, "", None),
        (3, "hello", None),
        (0, "hello", None),
        (7, "hello", Some(http::HeaderMap::new())),
    ] {
        for vary in [false, true] {
            let req = make_get_request("/body-length");
            let backend = Arc::new(MockBackend::new());
            let backends =
                HashMap::from([("b".to_string(), backend.clone() as Arc<dyn CacheBackend>)]);
            let mut response = Response::builder()
                .header(CACHE_CONTROL, "public, max-age=60")
                .header(CONTENT_LENGTH, declared.to_string());
            if vary {
                response = response.header(VARY, "accept-language");
            }
            let response = response
                .body(Body::replay_chunks(
                    payload
                        .as_bytes()
                        .chunks(2)
                        .map(Bytes::copy_from_slice)
                        .collect(),
                    trailers.clone(),
                ))
                .expect("response");
            let client = store_length_case(&req, response, &backends).await;
            assert_eq!(client.headers()[CONTENT_LENGTH], declared.to_string());
            assert_eq!(
                qpx_http::body::to_bytes(client.into_body())
                    .await
                    .expect("body"),
                payload
            );
            assert!(
                backend.map.lock().expect("map").is_empty(),
                "must publish no body, metadata, or index: declared={declared}, vary={vary}"
            );
            assert!(matches!(
                lookup_length_case(&req, &backends).await,
                LookupOutcome::Miss
            ));
        }
    }
}

#[tokio::test]
async fn malformed_content_length_bypasses_storage_not_client() {
    for values in [
        vec!["+5"],
        vec!["-5"],
        vec![""],
        vec!["5,"],
        vec!["5, 6"],
        vec!["5", "6"],
        vec!["18446744073709551616"],
        vec!["invalid"],
        vec!["\u{80}"],
    ] {
        let req = make_get_request("/malformed-length");
        let backend = Arc::new(MockBackend::new());
        let backends = HashMap::from([("b".to_string(), backend.clone() as Arc<dyn CacheBackend>)]);
        let mut response = make_response(StatusCode::OK, "public, max-age=60", "hello");
        response.headers_mut().remove(CONTENT_LENGTH);
        for value in &values {
            response.headers_mut().append(
                CONTENT_LENGTH,
                http::HeaderValue::from_str(value).expect("header"),
            );
        }
        let client = store_length_case(&req, response, &backends).await;
        assert_eq!(
            client
                .headers()
                .get_all(CONTENT_LENGTH)
                .iter()
                .collect::<Vec<_>>(),
            values
                .iter()
                .map(|v| http::HeaderValue::from_str(v).unwrap())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            qpx_http::body::to_bytes(client.into_body())
                .await
                .expect("body"),
            "hello"
        );
        assert!(backend.map.lock().expect("map").is_empty());
        assert!(matches!(
            lookup_length_case(&req, &backends).await,
            LookupOutcome::Miss
        ));
    }
}

#[tokio::test]
async fn matching_duplicate_lengths_and_unspecified_length_are_stored() {
    for values in [vec![], vec!["5"], vec!["5, 005", " 5 "], vec!["0", "0, 0"]] {
        let payload = if values.first() == Some(&"0") {
            ""
        } else {
            "hello"
        };
        let req = make_get_request("/matching-length");
        let backends = backend_map();
        let mut response = make_response(StatusCode::OK, "public, max-age=60", payload);
        response.headers_mut().remove(CONTENT_LENGTH);
        for value in values {
            response
                .headers_mut()
                .append(CONTENT_LENGTH, value.parse().expect("header"));
        }
        store_length_case(&req, response, &backends).await;
        let LookupOutcome::Hit(hit) = lookup_length_case(&req, &backends).await else {
            panic!("matching body must be stored");
        };
        assert_eq!(
            qpx_http::body::to_bytes(hit.into_body())
                .await
                .expect("body"),
            payload
        );
    }
}

#[tokio::test]
async fn head_and_body_forbidden_statuses_do_not_compare_get_length() {
    for (method, status) in [
        (Method::HEAD, StatusCode::OK),
        (Method::GET, StatusCode::NO_CONTENT),
        (Method::GET, StatusCode::RESET_CONTENT),
        (Method::GET, StatusCode::NOT_MODIFIED),
    ] {
        let mut req = make_get_request("/no-body-length");
        *req.method_mut() = method;
        let backends = backend_map();
        let response = Response::builder()
            .status(status)
            .header(CACHE_CONTROL, "public, max-age=60")
            .header(CONTENT_LENGTH, "123")
            .body(Body::empty())
            .expect("response");
        let client = store_length_case(&req, response, &backends).await;
        assert_eq!(client.status(), status);
        assert_eq!(client.headers()[CONTENT_LENGTH], "123");
        assert!(matches!(
            lookup_length_case(&req, &backends).await,
            LookupOutcome::Hit(_)
        ));
    }
}
