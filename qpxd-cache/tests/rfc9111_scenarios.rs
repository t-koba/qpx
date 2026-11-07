use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http::header::{AGE, CACHE_CONTROL, ETAG, HOST, HeaderValue, VARY};
use hyper::{Method, Response, StatusCode};
use qpx_core::config::{CacheBackendConfig, CachePolicyConfig};
use qpx_core::http_message::{OrdinaryHeaderName, Request as OwnerRequest};
use qpx_http::body::Body;
use qpxd_cache::{
    CacheBackend, CacheRequestKey, CacheStoreContext, CacheStoreTiming, CacheWritebackAdmission,
    CachedBody, CachedBodyStream, InFlightRevalidations, LookupOutcome,
    attach_revalidation_headers, build_backends, lookup, maybe_store, revalidate_not_modified,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct MemoryBackend {
    objects: Mutex<HashMap<String, Bytes>>,
}

#[async_trait]
impl CacheBackend for MemoryBackend {
    async fn get(&self, namespace: &str, key: &str) -> Result<Option<Bytes>> {
        Ok(self
            .objects
            .lock()
            .expect("lock")
            .get(&slot(namespace, key))
            .cloned())
    }

    async fn get_many(&self, namespace: &str, keys: &[String]) -> Result<Vec<Option<Bytes>>> {
        let mut values = Vec::with_capacity(keys.len());
        for key in keys {
            values.push(self.get(namespace, key).await?);
        }
        Ok(values)
    }

    async fn put(&self, namespace: &str, key: &str, value: &[u8], _ttl_secs: u64) -> Result<()> {
        self.objects
            .lock()
            .expect("lock")
            .insert(slot(namespace, key), Bytes::copy_from_slice(value));
        Ok(())
    }

    async fn put_object(
        &self,
        namespace: &str,
        key: &str,
        body: &CachedBody,
        ttl_secs: u64,
    ) -> Result<()> {
        let mut stream = match body {
            CachedBody::Memory(bytes) => Body::from(bytes.clone()),
            CachedBody::File(_) => Body::empty(),
        };
        let bytes = collect_body(&mut stream).await?;
        self.put(namespace, key, bytes.as_ref(), ttl_secs).await
    }

    async fn put_object_stream(
        &self,
        namespace: &str,
        key: &str,
        mut body: Body,
        max_body_bytes: usize,
        body_read_timeout: Duration,
        ttl_secs: u64,
    ) -> Result<u64> {
        let mut out = Vec::new();
        while let Some(chunk) = tokio::time::timeout(body_read_timeout, body.data()).await? {
            let chunk = chunk?;
            let next = out
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| anyhow::anyhow!("cache object length overflow"))?;
            if next > max_body_bytes {
                return Err(anyhow::anyhow!(
                    "cache object exceeds configured limit: {} bytes",
                    max_body_bytes
                ));
            }
            out.extend_from_slice(chunk.as_ref());
        }
        let len = out.len() as u64;
        self.put(namespace, key, &out, ttl_secs).await?;
        Ok(len)
    }

    async fn get_object_stream(
        &self,
        namespace: &str,
        key: &str,
        expected_len: u64,
        range: Option<(u64, u64)>,
    ) -> Result<Option<CachedBodyStream>> {
        let Some(bytes) = self.get(namespace, key).await? else {
            return Ok(None);
        };
        if bytes.len() as u64 != expected_len {
            return Ok(None);
        }
        let (len, body) = match range {
            Some((start, end)) => {
                let start = start as usize;
                let end = end as usize + 1;
                let slice = bytes.slice(start..end.min(bytes.len()));
                (slice.len() as u64, Body::from(slice))
            }
            None => (bytes.len() as u64, Body::from(bytes)),
        };
        Ok(Some(CachedBodyStream::from_body_for_backend(len, body)))
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        self.objects
            .lock()
            .expect("lock")
            .remove(&slot(namespace, key));
        Ok(())
    }
}

fn slot(namespace: &str, key: &str) -> String {
    format!("{namespace}::{key}")
}

fn policy() -> CachePolicyConfig {
    policy_for_backend("mem")
}

fn policy_for_backend(backend: &str) -> CachePolicyConfig {
    CachePolicyConfig {
        enabled: true,
        backend: backend.to_string(),
        namespace: Some("rfc9111".to_string()),
        default_ttl_secs: Some(30),
        max_object_bytes: 64 * 1024,
        allow_set_cookie_store: false,
        allow_authorization_without_vary_store: false,
    }
}

fn backends() -> HashMap<String, Arc<dyn CacheBackend>> {
    let backend = Arc::new(MemoryBackend::default()) as Arc<dyn CacheBackend>;
    HashMap::from([("mem".to_string(), backend)])
}

struct BackendCase {
    name: String,
    policy: CachePolicyConfig,
    backends: HashMap<String, Arc<dyn CacheBackend>>,
    cleanup: Option<PathBuf>,
}

impl Drop for BackendCase {
    fn drop(&mut self) {
        if let Some(path) = self.cleanup.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(name: &str) -> PathBuf {
    let base = if std::path::Path::new("/private/tmp").is_dir() {
        PathBuf::from("/private/tmp")
    } else {
        std::env::temp_dir()
    };
    let path = base.join(format!(
        "qpx-rfc9111-{name}-{}-{}",
        std::process::id(),
        TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).expect("create cache test dir");
    path
}

fn backend_cases(name: &str) -> Vec<BackendCase> {
    let disk_path = temp_dir(name);
    let disk_cfg = CacheBackendConfig {
        writer_mode: Default::default(),
        commit_lock_stripes: 64,
        name: "disk".to_string(),
        kind: "disk".to_string(),
        endpoint: String::new(),
        path: Some(disk_path.display().to_string()),
        max_bytes: Some(1024 * 1024),
        sweep_interval_secs: 1,
        timeout_ms: 500,
        max_object_bytes: 1024 * 1024,
        auth_header_env: None,
    };
    vec![
        BackendCase {
            name: "memory".to_string(),
            policy: policy(),
            backends: backends(),
            cleanup: None,
        },
        BackendCase {
            name: "disk".to_string(),
            policy: policy_for_backend("disk"),
            backends: build_backends(&[disk_cfg], None).expect("disk backend"),
            cleanup: Some(disk_path),
        },
    ]
}

fn revalidations() -> Arc<InFlightRevalidations> {
    Arc::new(InFlightRevalidations::with_default_shards())
}

fn request(path: &str) -> OwnerRequest<()> {
    OwnerRequest::from_http(
        http::Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(HOST, "cache.example")
            .body(())
            .expect("request"),
    )
}

fn ord(name: &str) -> OrdinaryHeaderName {
    OrdinaryHeaderName::try_from(name).expect("ordinary header name")
}

fn response(body: &'static str, headers: &[(&str, &str)]) -> Response<Body> {
    let mut builder = Response::builder().status(StatusCode::OK);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::from(body)).expect("response")
}

async fn collect_body(body: &mut Body) -> Result<Bytes> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        out.extend_from_slice(chunk?.as_ref());
    }
    Ok(Bytes::from(out))
}

async fn store_and_drain(
    req: &OwnerRequest<()>,
    key: &CacheRequestKey,
    response: Response<Body>,
    policy: &CachePolicyConfig,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<()> {
    let writeback_admission = CacheWritebackAdmission::with_default_capacity();
    let mut stored = maybe_store(
        req,
        key,
        policy,
        qpx_core::http_message::Response::from_http(response),
        CacheStoreContext {
            timing: CacheStoreTiming {
                response_delay_secs: 0,
                body_read_timeout: Duration::from_secs(1),
                request_collapse_guard: None,
            },
            writeback_admission: &writeback_admission,
            backends,
        },
    )
    .await?;
    let _ = collect_body(stored.body_mut()).await?;
    Ok(())
}

async fn wait_for_cached_outcome(
    req: &OwnerRequest<()>,
    key: &CacheRequestKey,
    policy: &CachePolicyConfig,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<LookupOutcome> {
    for _ in 0..50 {
        let outcome = lookup(req, key, policy, backends, &revalidations()).await?;
        if !matches!(
            outcome,
            LookupOutcome::Miss | LookupOutcome::OnlyIfCachedMiss
        ) {
            return Ok(outcome);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    lookup(req, key, policy, backends, &revalidations()).await
}

#[tokio::test]
async fn freshness_serves_a_fresh_public_response() -> Result<()> {
    for case in backend_cases("fresh") {
        let policy = &case.policy;
        let backends = &case.backends;
        let req = request("/fresh");
        let key = CacheRequestKey::for_lookup(&req, "http")?.expect("cache key");
        store_and_drain(
            &req,
            &key,
            response(
                "fresh body",
                &[(CACHE_CONTROL.as_str(), "public, max-age=60")],
            ),
            policy,
            backends,
        )
        .await?;

        let LookupOutcome::Hit(mut hit) =
            wait_for_cached_outcome(&req, &key, policy, backends).await?
        else {
            panic!("fresh response should be a cache hit for {}", case.name);
        };
        assert_eq!(hit.status(), StatusCode::OK);
        assert_eq!(
            collect_body(hit.body_mut()).await?,
            Bytes::from_static(b"fresh body")
        );
    }
    Ok(())
}

#[tokio::test]
async fn vary_selects_the_matching_request_variant() -> Result<()> {
    for case in backend_cases("vary") {
        let policy = &case.policy;
        let backends = &case.backends;
        let mut en = request("/vary");
        en.headers_mut()
            .insert(ord("accept-language"), HeaderValue::from_static("en"));
        let mut ja = request("/vary");
        ja.headers_mut()
            .insert(ord("accept-language"), HeaderValue::from_static("ja"));
        let en_key = CacheRequestKey::for_lookup(&en, "http")?.expect("cache key");
        let ja_key = CacheRequestKey::for_lookup(&ja, "http")?.expect("cache key");

        store_and_drain(
            &en,
            &en_key,
            response(
                "hello",
                &[
                    (CACHE_CONTROL.as_str(), "public, max-age=60"),
                    (VARY.as_str(), "accept-language"),
                ],
            ),
            policy,
            backends,
        )
        .await?;
        let _ = wait_for_cached_outcome(&en, &en_key, policy, backends).await?;
        store_and_drain(
            &ja,
            &ja_key,
            response(
                "konnichiwa",
                &[
                    (CACHE_CONTROL.as_str(), "public, max-age=60"),
                    (VARY.as_str(), "accept-language"),
                ],
            ),
            policy,
            backends,
        )
        .await?;
        let _ = wait_for_cached_outcome(&ja, &ja_key, policy, backends).await?;

        let LookupOutcome::Hit(mut en_hit) =
            wait_for_cached_outcome(&en, &en_key, policy, backends).await?
        else {
            panic!("en variant should hit for {}", case.name);
        };
        let LookupOutcome::Hit(mut ja_hit) =
            wait_for_cached_outcome(&ja, &ja_key, policy, backends).await?
        else {
            panic!("ja variant should hit for {}", case.name);
        };
        assert_eq!(
            collect_body(en_hit.body_mut()).await?,
            Bytes::from_static(b"hello")
        );
        assert_eq!(
            collect_body(ja_hit.body_mut()).await?,
            Bytes::from_static(b"konnichiwa")
        );
    }
    Ok(())
}

#[tokio::test]
async fn stale_while_revalidate_serves_stale_and_returns_revalidation_state() -> Result<()> {
    for case in backend_cases("swr") {
        let policy = &case.policy;
        let backends = &case.backends;
        let req = request("/swr");
        let key = CacheRequestKey::for_lookup(&req, "http")?.expect("cache key");
        store_and_drain(
            &req,
            &key,
            response(
                "stale body",
                &[
                    (
                        CACHE_CONTROL.as_str(),
                        "public, max-age=0, stale-while-revalidate=60",
                    ),
                    (AGE.as_str(), "1"),
                ],
            ),
            policy,
            backends,
        )
        .await?;

        let LookupOutcome::StaleWhileRevalidate(mut hit, state) =
            wait_for_cached_outcome(&req, &key, policy, backends).await?
        else {
            panic!(
                "stale response should use stale-while-revalidate for {}",
                case.name
            );
        };
        assert!(state.begin_background_revalidation().is_some());
        assert_eq!(
            collect_body(hit.body_mut()).await?,
            Bytes::from_static(b"stale body")
        );
    }
    Ok(())
}

#[tokio::test]
async fn conditional_requests_return_not_modified_or_attach_revalidation_headers() -> Result<()> {
    for case in backend_cases("conditional") {
        let policy = &case.policy;
        let backends = &case.backends;
        let req = request("/conditional");
        let key = CacheRequestKey::for_lookup(&req, "http")?.expect("cache key");
        store_and_drain(
            &req,
            &key,
            response(
                "etag body",
                &[
                    (CACHE_CONTROL.as_str(), "public, max-age=60"),
                    (ETAG.as_str(), "\"v1\""),
                ],
            ),
            policy,
            backends,
        )
        .await?;
        let mut conditional = request("/conditional");
        conditional
            .headers_mut()
            .insert(ord("if-none-match"), HeaderValue::from_static("\"v1\""));
        let conditional_key =
            CacheRequestKey::for_lookup(&conditional, "http")?.expect("cache key");
        let LookupOutcome::Hit(not_modified) =
            wait_for_cached_outcome(&conditional, &conditional_key, policy, backends).await?
        else {
            panic!(
                "matching If-None-Match should be answered from cache for {}",
                case.name
            );
        };
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

        let stale_req = request("/conditional-stale");
        let stale_key = CacheRequestKey::for_lookup(&stale_req, "http")?.expect("cache key");
        store_and_drain(
            &stale_req,
            &stale_key,
            response(
                "stale etag body",
                &[
                    (CACHE_CONTROL.as_str(), "public, max-age=0"),
                    (AGE.as_str(), "1"),
                    (ETAG.as_str(), "\"stale-v1\""),
                ],
            ),
            policy,
            backends,
        )
        .await?;
        let LookupOutcome::Revalidate(state) =
            wait_for_cached_outcome(&stale_req, &stale_key, policy, backends).await?
        else {
            panic!(
                "stale response without stale allowance should revalidate for {}",
                case.name
            );
        };
        let mut headers = qpx_core::http_message::Headers::new();
        assert!(attach_revalidation_headers(&mut headers, &state));
        assert_eq!(
            headers.get(&ord("if-none-match")),
            Some(&HeaderValue::from_static("\"stale-v1\""))
        );
    }
    Ok(())
}

// Delivery schedules metadata work rather than awaiting it on the response
// path. Observe that mutation before asserting subsequent lookup behavior.
async fn wait_for_revalidated_outcome(
    req: &OwnerRequest<()>,
    key: &CacheRequestKey,
    policy: &CachePolicyConfig,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
    expect_hit: bool,
) -> Result<LookupOutcome> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let outcome = lookup(req, key, policy, backends, &revalidations()).await?;
            if matches!(&outcome, LookupOutcome::Hit(_)) && expect_hit
                || matches!(&outcome, LookupOutcome::Miss) && !expect_hit
            {
                return Ok::<_, anyhow::Error>(outcome);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?
}

#[tokio::test]
async fn foreground_304_replays_persisted_body() -> Result<()> {
    for case in backend_cases("foreground-304") {
        for (index, (method, range, control, status, expected)) in [
            (
                Method::GET,
                None,
                "public, max-age=300",
                StatusCode::OK,
                "cached body",
            ),
            (
                Method::HEAD,
                None,
                "public, max-age=300",
                StatusCode::OK,
                "",
            ),
            (
                Method::GET,
                Some("bytes=2-5"),
                "public, max-age=300",
                StatusCode::PARTIAL_CONTENT,
                "ched",
            ),
            (
                Method::GET,
                Some("bytes=99-"),
                "public, max-age=300",
                StatusCode::RANGE_NOT_SATISFIABLE,
                "",
            ),
            (Method::GET, None, "no-store", StatusCode::OK, "cached body"),
        ]
        .into_iter()
        .enumerate()
        {
            let path = format!("/foreground-304/{index}");
            let mut req = request(&path);
            let key = CacheRequestKey::for_lookup(&req, "http")?.expect("cache key");
            store_and_drain(
                &req,
                &key,
                response(
                    "cached body",
                    &[
                        (CACHE_CONTROL.as_str(), "public, no-cache, max-age=60"),
                        (ETAG.as_str(), "\"v1\""),
                        ("content-length", "11"),
                    ],
                ),
                &case.policy,
                &case.backends,
            )
            .await?;
            *req.method_mut() = method.clone();
            if let Some(range) = range {
                req.headers_mut()
                    .insert(ord("range"), HeaderValue::from_static(range));
            }
            let lookup_key = CacheRequestKey::for_lookup(&req, "http")?.expect("cache key");
            let LookupOutcome::Revalidate(state) =
                wait_for_cached_outcome(&req, &lookup_key, &case.policy, &case.backends).await?
            else {
                panic!("expected metadata-backed revalidation for {}", case.name)
            };
            let not_modified = Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(CACHE_CONTROL, control)
                .header("content-length", "999")
                .header("x-refreshed", "yes")
                .body(Body::empty())?;
            let mut refreshed = revalidate_not_modified(
                &req,
                &case.policy,
                qpx_core::http_message::Response::from_http(not_modified),
                state,
                0,
                Duration::from_secs(1),
                &case.backends,
            )
            .await?;
            assert_eq!(refreshed.status(), status);
            assert_eq!(
                refreshed.headers().declared_content_length()?,
                Some(if method == Method::HEAD {
                    11
                } else {
                    expected.len() as u64
                })
            );
            assert_eq!(
                refreshed.headers().get(&ord("x-refreshed")),
                Some(&HeaderValue::from_static("yes"))
            );
            assert_eq!(
                collect_body(refreshed.body_mut()).await?.as_ref(),
                expected.as_bytes()
            );
            // Metadata refresh must leave the complete representation available.
            let get = request(&path);
            match wait_for_revalidated_outcome(
                &get,
                &key,
                &case.policy,
                &case.backends,
                control != "no-store",
            )
            .await?
            {
                LookupOutcome::Hit(mut hit) if control != "no-store" => {
                    assert_eq!(hit.headers().declared_content_length()?, Some(11));
                    assert_eq!(collect_body(hit.body_mut()).await?.as_ref(), b"cached body");
                }
                LookupOutcome::Miss if control == "no-store" => {}
                _ => panic!("unexpected outcome after 304 for {}", case.name),
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn foreground_304_vary_changes_evict_incoherent_selectors() -> Result<()> {
    for case in backend_cases("foreground-304-vary") {
        for (index, (updated_vary, expect_hit)) in
            [("accept-language", true), ("x-region", false), ("*", false)]
                .into_iter()
                .enumerate()
        {
            let path = format!("/foreground-304-vary/{index}");
            let mut req = request(&path);
            req.headers_mut()
                .insert(ord("accept-language"), HeaderValue::from_static("en"));
            req.headers_mut()
                .insert(ord("x-region"), HeaderValue::from_static("us"));
            let key = CacheRequestKey::for_lookup(&req, "http")?.expect("cache key");
            store_and_drain(
                &req,
                &key,
                response(
                    "cached vary body",
                    &[
                        (CACHE_CONTROL.as_str(), "public, no-cache, max-age=60"),
                        (VARY.as_str(), "accept-language"),
                        (ETAG.as_str(), "\"vary-v1\""),
                    ],
                ),
                &case.policy,
                &case.backends,
            )
            .await?;
            let LookupOutcome::Revalidate(state) =
                wait_for_cached_outcome(&req, &key, &case.policy, &case.backends).await?
            else {
                panic!("expected revalidation for {}", case.name)
            };
            let not_modified = Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(CACHE_CONTROL, "public, max-age=300")
                .header(VARY, updated_vary)
                .body(Body::empty())?;
            let mut refreshed = revalidate_not_modified(
                &req,
                &case.policy,
                qpx_core::http_message::Response::from_http(not_modified),
                state,
                0,
                Duration::from_secs(1),
                &case.backends,
            )
            .await?;
            assert_eq!(
                collect_body(refreshed.body_mut()).await?.as_ref(),
                b"cached vary body"
            );
            assert_eq!(
                refreshed
                    .headers()
                    .get(&ord(VARY.as_str()))
                    .and_then(|v| v.to_str().ok()),
                Some(updated_vary)
            );

            let mut old_selector = request(&path);
            old_selector
                .headers_mut()
                .insert(ord("accept-language"), HeaderValue::from_static("en"));
            old_selector
                .headers_mut()
                .insert(ord("x-region"), HeaderValue::from_static("ca"));
            let old_key = CacheRequestKey::for_lookup(&old_selector, "http")?.expect("cache key");
            let old_outcome = wait_for_revalidated_outcome(
                &old_selector,
                &old_key,
                &case.policy,
                &case.backends,
                expect_hit,
            )
            .await?;
            if expect_hit {
                let LookupOutcome::Hit(mut hit) = old_outcome else {
                    panic!(
                        "unchanged Vary selector should remain cached for {}",
                        case.name
                    )
                };
                assert_eq!(
                    collect_body(hit.body_mut()).await?.as_ref(),
                    b"cached vary body"
                );
            } else {
                assert!(matches!(old_outcome, LookupOutcome::Miss));
            }

            if updated_vary == "x-region" {
                let mut new_selector = request(&path);
                new_selector
                    .headers_mut()
                    .insert(ord("accept-language"), HeaderValue::from_static("fr"));
                new_selector
                    .headers_mut()
                    .insert(ord("x-region"), HeaderValue::from_static("us"));
                let new_key =
                    CacheRequestKey::for_lookup(&new_selector, "http")?.expect("cache key");
                assert!(matches!(
                    lookup(
                        &new_selector,
                        &new_key,
                        &case.policy,
                        &case.backends,
                        &revalidations(),
                    )
                    .await?,
                    LookupOutcome::Miss
                ));
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn foreground_304_rejects_missing_or_invalid_body() -> Result<()> {
    let backends = backends();
    let policy = policy();
    for corrupt in [false, true] {
        let req = request(if corrupt {
            "/corrupt-304"
        } else {
            "/missing-304"
        });
        let key = CacheRequestKey::for_lookup(&req, "http")?.expect("cache key");
        store_and_drain(
            &req,
            &key,
            response(
                "cached body",
                &[
                    (CACHE_CONTROL.as_str(), "public, no-cache, max-age=60"),
                    (ETAG.as_str(), "\"v1\""),
                ],
            ),
            &policy,
            &backends,
        )
        .await?;
        let LookupOutcome::Revalidate(state) =
            wait_for_cached_outcome(&req, &key, &policy, &backends).await?
        else {
            panic!("expected metadata-backed revalidation")
        };
        let backend = state.backend.clone();
        let namespace = state.namespace.clone();
        let variant_key = state.variant_key.clone();
        let body_key = format!("{variant_key}:body");
        if corrupt {
            backend.put(&namespace, &body_key, b"short", 60).await?;
        } else {
            backend.delete(&namespace, &body_key).await?;
        }
        let not_modified = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(CACHE_CONTROL, "public, max-age=300")
            .body(Body::empty())?;
        assert!(
            revalidate_not_modified(
                &req,
                &policy,
                qpx_core::http_message::Response::from_http(not_modified),
                state,
                0,
                Duration::from_secs(1),
                &backends,
            )
            .await
            .is_err()
        );
        assert!(backend.get(&namespace, &variant_key).await?.is_none());
    }
    Ok(())
}
