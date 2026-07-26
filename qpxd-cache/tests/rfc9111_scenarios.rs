use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http::header::{AGE, CACHE_CONTROL, ETAG, HOST, HeaderMap, HeaderValue, IF_NONE_MATCH, VARY};
use hyper::{Method, Request, Response, StatusCode};
use qpx_core::config::{CacheBackendConfig, CachePolicyConfig};
use qpx_http::body::Body;
use qpxd_cache::{
    CacheBackend, CacheRequestKey, CacheStoreContext, CacheStoreTiming, CacheWritebackAdmission,
    CachedBody, CachedBodyStream, InFlightRevalidations, LookupOutcome,
    attach_revalidation_headers, build_backends, lookup, maybe_store,
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

fn request(path: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(HOST, "cache.example")
        .body(Body::empty())
        .expect("request")
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
    req: &Request<Body>,
    key: &CacheRequestKey,
    response: Response<Body>,
    policy: &CachePolicyConfig,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<()> {
    let writeback_admission = CacheWritebackAdmission::with_default_capacity();
    let mut stored = maybe_store(
        req.method(),
        req.headers(),
        key,
        policy,
        response,
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
    req: &Request<Body>,
    key: &CacheRequestKey,
    policy: &CachePolicyConfig,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<LookupOutcome> {
    for _ in 0..50 {
        let outcome = lookup(
            req.method(),
            req.headers(),
            key,
            policy,
            backends,
            &revalidations(),
        )
        .await?;
        if !matches!(
            outcome,
            LookupOutcome::Miss | LookupOutcome::OnlyIfCachedMiss
        ) {
            return Ok(outcome);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    lookup(
        req.method(),
        req.headers(),
        key,
        policy,
        backends,
        &revalidations(),
    )
    .await
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
            .insert("accept-language", HeaderValue::from_static("en"));
        let mut ja = request("/vary");
        ja.headers_mut()
            .insert("accept-language", HeaderValue::from_static("ja"));
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
            .insert(IF_NONE_MATCH, HeaderValue::from_static("\"v1\""));
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
        let mut headers = HeaderMap::new();
        assert!(attach_revalidation_headers(&mut headers, &state));
        assert_eq!(
            headers.get(IF_NONE_MATCH),
            Some(&HeaderValue::from_static("\"stale-v1\""))
        );
    }
    Ok(())
}
