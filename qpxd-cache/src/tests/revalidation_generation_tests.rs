use super::*;
use crate::types::{BodyStreamWriteOptions, MetadataEncoder};
use tokio::sync::mpsc;

// Observe completed backend operations, not elapsed time or scheduler yields.
// Delegating put_response and decoded reads preserves disk's co-located format;
// MockBackend exercises the split body/metadata publication used by HTTP/Redis.
type StagingGate = (mpsc::UnboundedSender<String>, Arc<tokio::sync::Notify>);

struct ObservedBackend {
    inner: Arc<dyn CacheBackend>,
    mutations: mpsc::UnboundedSender<String>,
    fail_retirement: std::sync::atomic::AtomicBool,
    staged_gate: Mutex<Option<StagingGate>>,
    index_gate: Mutex<Option<StagingGate>>,
}

#[async_trait]
impl CacheBackend for ObservedBackend {
    async fn get(&self, ns: &str, key: &str) -> Result<Option<Bytes>> {
        self.inner.get(ns, key).await
    }
    async fn get_many(&self, ns: &str, keys: &[String]) -> Result<Vec<Option<Bytes>>> {
        self.inner.get_many(ns, keys).await
    }
    fn get_response_candidate(
        &self,
        ns: &str,
        index: &str,
        default: &str,
        now: u64,
    ) -> Result<Option<crate::types::CachedResponseCandidate>> {
        self.inner.get_response_candidate(ns, index, default, now)
    }
    async fn get_decoded_response_metadata_many(
        &self,
        ns: &str,
        keys: &[String],
    ) -> Result<Vec<Option<Arc<CachedResponseEnvelope>>>> {
        let values = self
            .inner
            .get_decoded_response_metadata_many(ns, keys)
            .await?;
        for key in keys {
            self.mutations.send(format!("read-meta:{key}")).unwrap();
        }
        Ok(values)
    }
    async fn put(&self, ns: &str, key: &str, value: &[u8], ttl: u64) -> Result<()> {
        // Pause index publication while the per-primary commit lock is held,
        // after the final check/retirement and before the index is visible.
        // This models the invalidation interleaving window deterministically.
        if key.starts_with("idx:") {
            let gate = self.index_gate.lock().unwrap().take();
            if let Some((entered, release)) = gate {
                entered.send(key.to_owned()).unwrap();
                release.notified().await;
            }
        }
        self.inner.put(ns, key, value, ttl).await?;
        self.mutations.send(key.to_owned()).unwrap();
        Ok(())
    }
    async fn retire_response_metadata(&self, ns: &str, key: &str) -> Result<()> {
        if self
            .fail_retirement
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            anyhow::bail!("injected retirement failure");
        }
        self.inner.retire_response_metadata(ns, key).await?;
        self.mutations.send(format!("retire:{key}")).unwrap();
        Ok(())
    }
    async fn put_response(
        &self,
        ns: &str,
        key: &str,
        body: Body,
        options: BodyStreamWriteOptions,
        encode: MetadataEncoder,
    ) -> Result<u64> {
        let len = self
            .inner
            .put_response(ns, key, body, options, encode)
            .await?;
        let gate = self.staged_gate.lock().unwrap().take();
        if let Some((staged, release)) = gate {
            staged.send(key.to_owned()).unwrap();
            release.notified().await;
        }
        Ok(len)
    }
    async fn get_object_stream(
        &self,
        ns: &str,
        key: &str,
        expected: u64,
        range: Option<(u64, u64)>,
    ) -> Result<Option<CachedBodyStream>> {
        self.inner.get_object_stream(ns, key, expected, range).await
    }
    async fn delete(&self, ns: &str, key: &str) -> Result<()> {
        self.inner.delete(ns, key).await?;
        self.mutations.send(key.to_owned()).unwrap();
        Ok(())
    }
}

fn legacy_test_backend(disk: bool, root: &std::path::Path) -> Arc<dyn CacheBackend> {
    if disk {
        Arc::new(
            crate::backend_disk::DiskCacheBackend::new(qpx_core::config::CacheBackendConfig {
                name: "b".into(),
                kind: "disk".into(),
                endpoint: String::new(),
                path: Some(root.display().to_string()),
                max_bytes: Some(8 * 1024 * 1024),
                sweep_interval_secs: 60,
                timeout_ms: 1000,
                max_object_bytes: 4 * 1024 * 1024,
                auth_header_env: None,
            })
            .unwrap(),
        )
    } else {
        Arc::new(MockBackend::new())
    }
}

async fn seed_legacy_canonical(
    backend: &dyn CacheBackend,
    namespace: &str,
    key: &CacheRequestKey,
) -> (String, Bytes) {
    const LEGACY_TTL_SECS: u64 = 2 * 24 * 60 * 60;
    let legacy_key = variant_storage_key(key.primary_hash().as_str(), &[]);
    let body = Bytes::from(vec![b'l'; 2 * 1024 * 1024]);
    let headers = crate::types::CachedHeaders::from_pairs(vec![
        (
            "cache-control".to_owned(),
            format!("public, max-age={LEGACY_TTL_SECS}"),
        ),
        ("content-length".to_owned(), body.len().to_string()),
        (
            "content-security-policy".to_owned(),
            "default-src *".to_owned(),
        ),
    ]);
    let envelope = CachedResponseEnvelope {
        status: StatusCode::OK.as_u16(),
        headers,
        body: CachedBody::default(),
        body_len: 0,
        stored_at_ms: super::util::now_millis(),
        initial_age_secs: 0,
        response_delay_secs: 0,
        freshness_lifetime_secs: LEGACY_TTL_SECS,
        vary_headers: Vec::new(),
        vary_values: Vec::new(),
        response_directives: Default::default(),
        response_header_values: Default::default(),
    };
    backend
        .put_response(
            namespace,
            legacy_key.as_str(),
            Body::from(body.clone()),
            BodyStreamWriteOptions {
                max_body_bytes: 4 * 1024 * 1024,
                body_read_timeout: Duration::from_secs(5),
                ttl_secs: LEGACY_TTL_SECS,
            },
            Box::new(move |body_len| {
                let mut envelope = envelope;
                envelope.body_len = body_len;
                crate::types::encode_cached_response_metadata(&envelope)
            }),
        )
        .await
        .expect("seed legacy canonical response");
    (legacy_key, body)
}

async fn publish(
    request: &OwnerRequest<()>,
    key: &CacheRequestKey,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
    control: &str,
    body: &str,
    version: &str,
    vary: bool,
) {
    let collapse = test_request_collapse();
    let RequestCollapseJoin::Leader(leader) = collapse.begin(key) else {
        panic!("leader")
    };
    let RequestCollapseJoin::Follower(waiter) = collapse.begin(key) else {
        panic!("follower")
    };
    let mut response = make_response(StatusCode::OK, control, body);
    response
        .headers_mut()
        .insert("x-version", version.parse().unwrap());
    if vary {
        response
            .headers_mut()
            .insert(VARY, "accept-language".parse().unwrap());
    }
    let admission = test_writeback_admission();
    let store = async {
        let response = maybe_store(
            request,
            key,
            &policy(),
            qpx_core::http_message::Response::from_http(response),
            CacheStoreContext {
                timing: CacheStoreTiming {
                    response_delay_secs: 0,
                    body_read_timeout: Duration::from_secs(1),
                    request_collapse_guard: Some(leader),
                },
                writeback_admission: &admission,
                backends,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            qpx_http::body::to_bytes(response.into_head_and_body().1)
                .await
                .unwrap(),
            body
        );
    };
    let (settled, ()) = tokio::join!(waiter.wait(Duration::from_secs(1)), store);
    assert!(settled, "writeback did not settle");
}

#[tokio::test]
async fn retired_legacy_canonical_does_not_resurface_after_short_generation_index_eviction() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for disk in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "qpx-cache-legacy-retirement-{}",
                uuid::Uuid::new_v4()
            ));
            let inner = legacy_test_backend(disk, &root);
            let (mutations, mut completed) = mpsc::unbounded_channel();
            let backend = Arc::new(ObservedBackend {
                inner: inner.clone(),
                mutations,
                fail_retirement: std::sync::atomic::AtomicBool::new(true),
                staged_gate: Mutex::new(None),
                index_gate: Mutex::new(None),
            });
            let backends =
                HashMap::from([("b".to_owned(), backend.clone() as Arc<dyn CacheBackend>)]);
            let request = make_get_request("/legacy-retirement");
            let key = CacheRequestKey::for_lookup(&request, "http")
                .expect("key")
                .expect("cache key");
            let cache_policy = policy();
            let namespace = super::util::cache_namespace(&cache_policy, "default");
            let (legacy_key, legacy_body) =
                seed_legacy_canonical(inner.as_ref(), namespace, &key).await;

            // Untouched historical entries still use the canonical fallback.
            let held_legacy =
                match lookup(&request, &key, &policy(), &backends, &test_revalidations())
                    .await
                    .expect("legacy lookup")
                {
                    LookupOutcome::Hit(response) => response,
                    _ => panic!("untouched legacy entry should hit"),
                };

            // A retirement error must leave the generation undiscoverable.
            publish(
                &request,
                &key,
                &backends,
                "public, max-age=1",
                "failed",
                "failed",
                true,
            )
            .await;
            assert!(
                backend
                    .get(namespace, &index_storage_key(&key.primary_hash()))
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                backend
                    .get_decoded_response_metadata_many(
                        namespace,
                        std::slice::from_ref(&legacy_key)
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .next()
                    .flatten()
                    .is_some()
            );
            backend
                .fail_retirement
                .store(false, std::sync::atomic::Ordering::Relaxed);

            // The replacement is fresh briefly, while the canonical entry's
            // retained lifetime exceeds the index's 24-hour minimum.
            publish(
                &request,
                &key,
                &backends,
                "public, max-age=1",
                "replacement",
                "new",
                true,
            )
            .await;
            let primary = key.primary_hash();
            let mutations = std::iter::from_fn(|| completed.try_recv().ok()).collect::<Vec<_>>();
            let retirement_write = mutations
                .iter()
                .position(|written| written == &format!("retire:{legacy_key}"))
                .expect("canonical metadata retirement");
            let index_key = index_storage_key(primary.as_str());
            let index_write = mutations
                .iter()
                .position(|written| written == &index_key)
                .expect("generation index write");
            assert!(
                retirement_write < index_write,
                "index published before legacy retirement"
            );

            // Removing the index models expiry/eviction before the legacy object
            // expires. There is no independently evictable retirement marker.
            // The old object remains available to an already-held body,
            // but a fresh lookup cannot rediscover it through the fallback.
            backend
                .delete(namespace, index_storage_key(primary.as_str()).as_str())
                .await
                .expect("evict replacement index");
            assert!(
                backend
                    .get_decoded_response_metadata_many(
                        namespace,
                        std::slice::from_ref(&legacy_key)
                    )
                    .await
                    .expect("legacy metadata")
                    .into_iter()
                    .next()
                    .flatten()
                    .is_none()
            );
            assert!(matches!(
                lookup(&request, &key, &policy(), &backends, &test_revalidations(),)
                    .await
                    .expect("lookup after index eviction"),
                LookupOutcome::Miss
            ));

            let body = qpx_http::body::to_bytes(held_legacy.into_head_and_body().1)
                .await
                .expect("held legacy body stream");
            assert_eq!(body.as_ref(), legacy_body.as_ref());
            if disk {
                tokio::fs::remove_dir_all(root)
                    .await
                    .expect("remove disk cache");
            }
        }
    })
    .await
    .expect("bounded legacy retirement regression");
}

// A successful legacy refresh must persist policy and freshness, not merely
// return the merged headers to the one request that received the 304.
#[tokio::test]
async fn legacy_304_persists_merged_policy_in_a_generation() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for disk in [false, true] {
            for (method, range) in [
                (Method::GET, None),
                (Method::HEAD, None),
                (Method::GET, Some("bytes=1-3")),
                (Method::GET, Some("bytes=9999999-")),
            ] {
                let root = std::env::temp_dir()
                    .join(format!("qpx-legacy-refresh-{}", uuid::Uuid::new_v4()));
                let inner = legacy_test_backend(disk, &root);
                let (mutations, mut completed) = mpsc::unbounded_channel();
                let backend = Arc::new(ObservedBackend {
                    inner: inner.clone(),
                    mutations,
                    fail_retirement: std::sync::atomic::AtomicBool::new(false),
                    staged_gate: Mutex::new(None),
                    index_gate: Mutex::new(None),
                });
                let backends =
                    HashMap::from([("b".into(), backend.clone() as Arc<dyn CacheBackend>)]);
                let request = make_get_request("/legacy-policy");
                let key = CacheRequestKey::for_lookup(&request, "http")
                    .unwrap()
                    .unwrap();
                let policy = CachePolicyConfig {
                    max_object_bytes: 4 * 1024 * 1024,
                    ..policy()
                };
                let namespace = super::util::cache_namespace(&policy, "default");
                let (canonical, bytes) =
                    seed_legacy_canonical(inner.as_ref(), namespace, &key).await;
                let mut refresh_request = http::Request::builder()
                    .method(method.clone())
                    .uri("http://example.com/legacy-policy")
                    .header(HOST, "example.com")
                    .header(CACHE_CONTROL, "no-cache");
                if let Some(range) = range {
                    refresh_request = refresh_request.header("range", range);
                }
                let refresh_request = OwnerRequest::from_http(refresh_request.body(()).unwrap());
                let LookupOutcome::Revalidate(state) = lookup(
                    &refresh_request,
                    &key,
                    &policy,
                    &backends,
                    &test_revalidations(),
                )
                .await
                .unwrap() else {
                    panic!("forced legacy revalidation")
                };
                let response = revalidate_not_modified(
                    &refresh_request,
                    &policy,
                    qpx_core::http_message::Response::from_http(
                        Response::builder()
                            .status(304)
                            .header(CACHE_CONTROL, "public, max-age=300")
                            .header("content-security-policy", "default-src 'none'")
                            .header("x-new-policy", "added")
                            .header(CONTENT_LENGTH, "99")
                            .body(Body::empty())
                            .unwrap(),
                    ),
                    state,
                    0,
                    Duration::from_secs(1),
                    &backends,
                )
                .await
                .unwrap();
                let body = qpx_http::body::to_bytes(response.into_head_and_body().1)
                    .await
                    .unwrap();
                if method == Method::HEAD || range == Some("bytes=9999999-") {
                    assert!(body.is_empty());
                } else if range.is_some() {
                    assert_eq!(body, bytes.slice(1..4));
                } else {
                    assert_eq!(body, bytes);
                }
                let index_key = index_storage_key(&key.primary_hash());
                while completed.recv().await.as_deref() != Some(&index_key) {}
                let index = load_variant_index(backend.as_ref(), namespace, &key.primary_hash())
                    .await
                    .unwrap();
                assert_eq!(index.variants.len(), 1);
                assert_ne!(index.variants[0], canonical);
                let metadata = backend
                    .get_decoded_response_metadata_many(namespace, &index.variants)
                    .await
                    .unwrap()
                    .pop()
                    .unwrap()
                    .unwrap();
                assert_eq!(metadata.freshness_lifetime_secs, 300);
                assert_eq!(metadata.body_len, bytes.len() as u64);
                assert!(
                    backend
                        .get_decoded_response_metadata_many(namespace, &[canonical])
                        .await
                        .unwrap()
                        .pop()
                        .unwrap()
                        .is_none()
                );
                let LookupOutcome::Hit(hit) =
                    lookup(&request, &key, &policy, &backends, &test_revalidations())
                        .await
                        .unwrap()
                else {
                    panic!("refreshed legacy response must be a fresh hit")
                };
                let headers = wire_headers(hit.headers());
                assert_eq!(headers["content-security-policy"], "default-src 'none'");
                assert_eq!(headers["x-new-policy"], "added");
                assert_eq!(headers[CACHE_CONTROL], "public, max-age=300");
                assert_eq!(headers[CONTENT_LENGTH], bytes.len().to_string());
                assert_eq!(
                    qpx_http::body::to_bytes(hit.into_head_and_body().1)
                        .await
                        .unwrap(),
                    bytes
                );
                if disk {
                    tokio::fs::remove_dir_all(root).await.unwrap();
                }
            }
        }
    })
    .await
    .expect("bounded legacy metadata refresh");
}

#[tokio::test]
async fn staged_legacy_refresh_loses_to_replacement_even_after_index_eviction() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for disk in [false, true] {
            let root =
                std::env::temp_dir().join(format!("qpx-legacy-stage-{}", uuid::Uuid::new_v4()));
            let inner = legacy_test_backend(disk, &root);
            let (mutations, mut completed) = mpsc::unbounded_channel();
            let backend = Arc::new(ObservedBackend {
                inner: inner.clone(),
                mutations,
                fail_retirement: std::sync::atomic::AtomicBool::new(false),
                staged_gate: Mutex::new(None),
                index_gate: Mutex::new(None),
            });
            let backends = HashMap::from([("b".into(), backend.clone() as Arc<dyn CacheBackend>)]);
            let request = make_get_request("/legacy-stage");
            let key = CacheRequestKey::for_lookup(&request, "http")
                .unwrap()
                .unwrap();
            let policy = CachePolicyConfig {
                max_object_bytes: 4 * 1024 * 1024,
                ..policy()
            };
            let namespace = super::util::cache_namespace(&policy, "default");
            seed_legacy_canonical(inner.as_ref(), namespace, &key).await;
            let mut refresh_request = make_get_request("/legacy-stage");
            refresh_request.headers_mut().insert(
                OrdinaryHeaderName::try_from(CACHE_CONTROL).unwrap(),
                "no-cache".parse().unwrap(),
            );
            let LookupOutcome::Revalidate(state) = lookup(
                &refresh_request,
                &key,
                &policy,
                &backends,
                &test_revalidations(),
            )
            .await
            .unwrap() else {
                panic!("legacy revalidation")
            };
            let release = Arc::new(tokio::sync::Notify::new());
            let (staged, mut stages) = mpsc::unbounded_channel();
            *backend.staged_gate.lock().unwrap() = Some((staged, release.clone()));
            let response = revalidate_not_modified(
                &refresh_request,
                &policy,
                qpx_core::http_message::Response::from_http(
                    Response::builder()
                        .status(304)
                        .header(CACHE_CONTROL, "public, max-age=300")
                        .body(Body::empty())
                        .unwrap(),
                ),
                state,
                0,
                Duration::from_secs(1),
                &backends,
            )
            .await
            .unwrap();
            qpx_http::body::to_bytes(response.into_head_and_body().1)
                .await
                .unwrap();
            // Spooling and generation staging have completed, but no commit
            // lock is held: an ordinary replacement can publish meanwhile.
            let staged_key = stages.recv().await.unwrap();
            publish(
                &request,
                &key,
                &backends,
                "public, max-age=60",
                "replacement",
                "new",
                true,
            )
            .await;
            backend
                .delete(namespace, &index_storage_key(&key.primary_hash()))
                .await
                .unwrap();
            release.notify_one();
            // Losing migration must clean both its split or co-located objects.
            let body_key = cache_body_storage_key(&staged_key);
            while completed.recv().await.as_deref() != Some(&body_key) {}
            assert!(
                backend
                    .get_decoded_response_metadata_many(namespace, &[staged_key])
                    .await
                    .unwrap()
                    .pop()
                    .unwrap()
                    .is_none()
            );
            assert!(
                backend
                    .get_object_stream(namespace, &body_key, 2 * 1024 * 1024, None)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(matches!(
                lookup(&request, &key, &policy, &backends, &test_revalidations())
                    .await
                    .unwrap(),
                LookupOutcome::Miss
            ));
            if disk {
                tokio::fs::remove_dir_all(root).await.unwrap();
            }
        }
    })
    .await
    .expect("bounded staged legacy supersession");
}

#[tokio::test]
async fn delayed_legacy_revalidation_cannot_restore_retired_canonical_after_index_eviction() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for (disk, evict_before) in [(false, false), (false, true), (true, false), (true, true)] {
            let root =
                std::env::temp_dir().join(format!("qpx-legacy-delayed-{}", uuid::Uuid::new_v4()));
            let inner = legacy_test_backend(disk, &root);
            let (mutations, mut completed) = mpsc::unbounded_channel();
            let backend = Arc::new(ObservedBackend {
                inner: inner.clone(),
                mutations,
                fail_retirement: std::sync::atomic::AtomicBool::new(false),
                staged_gate: Mutex::new(None),
                index_gate: Mutex::new(None),
            });
            let backends =
                HashMap::from([("b".to_owned(), backend.clone() as Arc<dyn CacheBackend>)]);
            let stale_request = OwnerRequest::from_http(
                http::Request::builder()
                    .uri("http://example.com/legacy-revalidation-retirement")
                    .header(HOST, "example.com")
                    .body(())
                    .expect("request"),
            );
            let key = CacheRequestKey::for_lookup(&stale_request, "http")
                .expect("key")
                .expect("cache key");
            let legacy_key = variant_storage_key(key.primary_hash().as_str(), &[]);
            let cache_policy = policy();
            let namespace = super::util::cache_namespace(&cache_policy, "default");
            let body = Bytes::from_static(b"legacy body");
            let headers = crate::types::CachedHeaders::from_pairs(vec![
                (
                    "cache-control".to_owned(),
                    "public, no-cache, max-age=172800".to_owned(),
                ),
                ("content-length".to_owned(), body.len().to_string()),
                (
                    "content-security-policy".to_owned(),
                    "default-src *".to_owned(),
                ),
            ]);
            let envelope = CachedResponseEnvelope {
                status: StatusCode::OK.as_u16(),
                headers,
                body: CachedBody::default(),
                body_len: 0,
                stored_at_ms: super::util::now_millis(),
                initial_age_secs: 0,
                response_delay_secs: 0,
                freshness_lifetime_secs: 172800,
                vary_headers: Vec::new(),
                vary_values: Vec::new(),
                response_directives: Default::default(),
                response_header_values: Default::default(),
            };
            inner
                .put_response(
                    namespace,
                    legacy_key.as_str(),
                    Body::from(body.clone()),
                    BodyStreamWriteOptions {
                        max_body_bytes: 1024,
                        body_read_timeout: Duration::from_secs(1),
                        ttl_secs: 172800,
                    },
                    Box::new(move |body_len| {
                        let mut envelope = envelope;
                        envelope.body_len = body_len;
                        crate::types::encode_cached_response_metadata(&envelope)
                    }),
                )
                .await
                .expect("seed legacy canonical response");
            let LookupOutcome::Revalidate(state) = lookup(
                &stale_request,
                &key,
                &cache_policy,
                &backends,
                &test_revalidations(),
            )
            .await
            .expect("lookup") else {
                panic!("max-age=0 must require revalidation")
            };
            assert_eq!(state.variant_key, legacy_key);
            let held_response = revalidate_not_modified(
                &stale_request,
                &cache_policy,
                qpx_core::http_message::Response::from_http(
                    Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .header("cache-control", "public, max-age=172800")
                        .body(Body::empty())
                        .expect("304"),
                ),
                state,
                0,
                Duration::from_secs(1),
                &backends,
            )
            .await
            .expect("revalidated response");

            publish(
                &stale_request,
                &key,
                &backends,
                "public, max-age=60",
                "new varied body",
                "new",
                true,
            )
            .await;
            assert!(
                backend
                    .get_decoded_response_metadata_many(
                        namespace,
                        std::slice::from_ref(&legacy_key)
                    )
                    .await
                    .expect("retired legacy metadata")
                    .into_iter()
                    .next()
                    .flatten()
                    .is_none()
            );

            if evict_before {
                backend
                    .delete(namespace, &index_storage_key(&key.primary_hash()))
                    .await
                    .unwrap();
            }
            // Completing the old body invokes its deferred 304 metadata check.
            while completed.try_recv().is_ok() {}
            assert_eq!(
                qpx_http::body::to_bytes(held_response.into_head_and_body().1)
                    .await
                    .expect("revalidated body"),
                body
            );
            let metadata_read = format!("read-meta:{legacy_key}");
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if completed.recv().await.as_deref() == Some(metadata_read.as_str()) {
                        break;
                    }
                }
            })
            .await
            .expect("deferred legacy metadata check");
            backend
                .delete(namespace, &index_storage_key(key.primary_hash().as_str()))
                .await
                .expect("evict replacement index");
            let normal_request = make_get_request("/legacy-revalidation-retirement");
            assert!(matches!(
                lookup(
                    &normal_request,
                    &key,
                    &cache_policy,
                    &backends,
                    &test_revalidations(),
                )
                .await
                .expect("lookup after index eviction"),
                LookupOutcome::Miss
            ));
            if disk {
                tokio::fs::remove_dir_all(root).await.unwrap();
            }
        }
    })
    .await
    .expect("bounded legacy finalizer reproduction");
}

#[tokio::test]
async fn delayed_304_finalizers_cannot_mutate_a_published_replacement() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for disk in [false, true] {
            let root =
                std::env::temp_dir().join(format!("qpx-cache-generation-{}", uuid::Uuid::new_v4()));
            let inner = legacy_test_backend(disk, &root);
            let (mutations, mut completed) = mpsc::unbounded_channel();
            let backend = Arc::new(ObservedBackend {
                inner,
                mutations,
                fail_retirement: std::sync::atomic::AtomicBool::new(false),
                staged_gate: Mutex::new(None),
                index_gate: Mutex::new(None),
            });
            let backends = HashMap::from([("b".into(), backend.clone() as Arc<dyn CacheBackend>)]);
            for controls in [
                vec!["public, max-age=300"],
                vec!["no-store"],
                vec!["public, max-age=300", "no-store", "public, max-age=300"],
            ] {
                let request = make_get_request("/generation");
                let key = CacheRequestKey::for_lookup(&request, "http")
                    .unwrap()
                    .unwrap();
                publish(
                    &request,
                    &key,
                    &backends,
                    "public, no-cache, max-age=300",
                    "old",
                    "old",
                    false,
                )
                .await;
                let LookupOutcome::Revalidate(state) =
                    lookup(&request, &key, &policy(), &backends, &test_revalidations())
                        .await
                        .unwrap()
                else {
                    panic!("old representation must require revalidation")
                };
                let old_key = state.variant_key.clone();
                let mut held = vec![];
                for control in &controls {
                    held.push(
                        revalidate_not_modified(
                            &request,
                            &policy(),
                            qpx_core::http_message::Response::from_http(
                                Response::builder()
                                    .status(304)
                                    .header(CACHE_CONTROL, *control)
                                    .header("x-version", "old-refreshed")
                                    .body(Body::empty())
                                    .unwrap(),
                            ),
                            state.clone(),
                            0,
                            Duration::from_secs(1),
                            &backends,
                        )
                        .await
                        .unwrap(),
                    );
                }
                // No old response has been polled/dropped: all its completion
                // callbacks are still held, while the same selector is replaced.
                const NEW_BODY: &str = "a distinct longer representation";
                publish(
                    &request,
                    &key,
                    &backends,
                    "public, max-age=300",
                    NEW_BODY,
                    "new",
                    false,
                )
                .await;
                let index_before = backend
                    .get("ns", &index_storage_key(&key.primary_hash()))
                    .await
                    .unwrap()
                    .unwrap();
                let index: VariantIndex = serde_json::from_slice(&index_before).unwrap();
                assert_eq!(index.variants.len(), 1);
                assert_ne!(index.variants[0], old_key);
                assert_eq!(
                    crate::vary::variant_identity(&index.variants[0]),
                    crate::vary::variant_identity(&old_key)
                );
                while completed.try_recv().is_ok() {}
                let mut drains = tokio::task::JoinSet::new();
                for response in held {
                    drains.spawn(async move {
                        assert_eq!(
                            qpx_http::body::to_bytes(response.into_head_and_body().1)
                                .await
                                .unwrap(),
                            "old"
                        );
                    });
                }
                while let Some(result) = drains.join_next().await {
                    result.unwrap();
                }
                let operations = controls
                    .iter()
                    .map(|control| if *control == "no-store" { 2 } else { 1 })
                    .sum();
                for _ in 0..operations {
                    let mutated = completed.recv().await.unwrap();
                    assert!(
                        mutated == old_key || mutated == cache_body_storage_key(&old_key),
                        "stale finalizer mutated {mutated}"
                    );
                }
                assert_eq!(
                    backend
                        .get("ns", &index_storage_key(&key.primary_hash()))
                        .await
                        .unwrap()
                        .unwrap(),
                    index_before
                );
                for request in [request, make_head_request("/generation")] {
                    let LookupOutcome::Hit(response) =
                        lookup(&request, &key, &policy(), &backends, &test_revalidations())
                            .await
                            .unwrap()
                    else {
                        panic!("new generation must remain a hit")
                    };
                    assert_eq!(response.headers().get(&ord("x-version")).unwrap(), "new");
                    assert_eq!(
                        response.headers().declared_content_length().unwrap(),
                        Some(NEW_BODY.len() as u64)
                    );
                    let bytes = qpx_http::body::to_bytes(response.into_head_and_body().1)
                        .await
                        .unwrap();
                    assert_eq!(
                        bytes,
                        if request.method() == Method::HEAD {
                            ""
                        } else {
                            NEW_BODY
                        }
                    );
                }
            }
            drop(backends);
            drop(backend);
            if disk {
                std::fs::remove_dir_all(root).unwrap();
            }
        }
    })
    .await
    .expect("bounded generation regression");
}

// A stalled backend stream must not retain the migration task: the configured
// body-read timeout bounds both the spool and the producer handoff, and a
// timeout never reaches the commit lock or publishes/retires metadata.
struct StalledLegacyBackend {
    inner: Arc<dyn CacheBackend>,
    stalled_body_key: String,
    retire_calls: std::sync::atomic::AtomicUsize,
    staged_calls: std::sync::atomic::AtomicUsize,
    producer_released: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl CacheBackend for StalledLegacyBackend {
    async fn get(&self, ns: &str, key: &str) -> Result<Option<Bytes>> {
        self.inner.get(ns, key).await
    }
    async fn get_many(&self, ns: &str, keys: &[String]) -> Result<Vec<Option<Bytes>>> {
        self.inner.get_many(ns, keys).await
    }
    fn get_response_candidate(
        &self,
        ns: &str,
        index: &str,
        default: &str,
        now: u64,
    ) -> Result<Option<crate::types::CachedResponseCandidate>> {
        self.inner.get_response_candidate(ns, index, default, now)
    }
    async fn get_decoded_response_metadata_many(
        &self,
        ns: &str,
        keys: &[String],
    ) -> Result<Vec<Option<Arc<CachedResponseEnvelope>>>> {
        self.inner
            .get_decoded_response_metadata_many(ns, keys)
            .await
    }
    async fn get_object_stream(
        &self,
        namespace: &str,
        key: &str,
        expected_len: u64,
        range: Option<(u64, u64)>,
    ) -> Result<Option<CachedBodyStream>> {
        if key == self.stalled_body_key && range.is_none() {
            let (sender, body) = Body::channel_with_capacity(16);
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let released = self.producer_released.clone();
            // Hold the sender until the consumer drops the body: dropping the
            // spooled body wakes this backpressured producer, mirroring how
            // HTTP/Redis producers release their operation permits on close.
            // The generous fallback keeps the test bounded if close is missed.
            tokio::spawn(async move {
                let _sender = sender;
                let _ = tokio::time::timeout(Duration::from_secs(5), _sender.closed()).await;
                released.notify_one();
                let _ = done_tx.send(());
            });
            return Ok(Some(CachedBodyStream::from_producer_for_backend(
                expected_len,
                body,
                done_rx,
            )));
        }
        self.inner
            .get_object_stream(namespace, key, expected_len, range)
            .await
    }
    async fn put(&self, ns: &str, key: &str, value: &[u8], ttl: u64) -> Result<()> {
        self.inner.put(ns, key, value, ttl).await
    }
    async fn retire_response_metadata(&self, ns: &str, key: &str) -> Result<()> {
        self.retire_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.retire_response_metadata(ns, key).await
    }
    async fn put_response(
        &self,
        ns: &str,
        key: &str,
        body: Body,
        options: BodyStreamWriteOptions,
        encode: MetadataEncoder,
    ) -> Result<u64> {
        self.staged_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner
            .put_response(ns, key, body, options, encode)
            .await
    }
    async fn delete(&self, ns: &str, key: &str) -> Result<()> {
        self.inner.delete(ns, key).await
    }
}

#[tokio::test]
async fn stalled_legacy_body_timeout_releases_producer_without_publishing() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for disk in [false, true] {
            let root =
                std::env::temp_dir().join(format!("qpx-legacy-stall-{}", uuid::Uuid::new_v4()));
            let inner = legacy_test_backend(disk, &root);
            let request = make_get_request("/legacy-stall");
            let head_request = OwnerRequest::from_http(
                http::Request::builder()
                    .method(Method::HEAD)
                    .uri("http://example.com/legacy-stall")
                    .header(HOST, "example.com")
                    .header(CACHE_CONTROL, "no-cache")
                    .body(())
                    .unwrap(),
            );
            let key = CacheRequestKey::for_lookup(&request, "http")
                .unwrap()
                .unwrap();
            let policy = CachePolicyConfig {
                max_object_bytes: 4 * 1024 * 1024,
                ..policy()
            };
            let namespace = super::util::cache_namespace(&policy, "default");
            let (legacy_key, _) = seed_legacy_canonical(inner.as_ref(), namespace, &key).await;
            let stalled_body_key = cache_body_storage_key(&legacy_key);
            let stalled = Arc::new(StalledLegacyBackend {
                inner: inner.clone(),
                stalled_body_key: stalled_body_key.clone(),
                retire_calls: std::sync::atomic::AtomicUsize::new(0),
                staged_calls: std::sync::atomic::AtomicUsize::new(0),
                producer_released: Arc::new(tokio::sync::Notify::new()),
            });
            let backends = HashMap::from([("b".into(), stalled.clone() as Arc<dyn CacheBackend>)]);
            // Force a legacy revalidation with a HEAD request: the refresh is
            // synchronous, so assertions after return observe the migration.
            let LookupOutcome::Revalidate(state) = lookup(
                &head_request,
                &key,
                &policy,
                &backends,
                &test_revalidations(),
            )
            .await
            .unwrap() else {
                panic!("forced legacy revalidation");
            };
            assert_eq!(state.variant_key, legacy_key);
            let short_timeout = Duration::from_millis(50);
            let response = revalidate_not_modified(
                &head_request,
                &policy,
                qpx_core::http_message::Response::from_http(
                    Response::builder()
                        .status(304)
                        .header(CACHE_CONTROL, "public, max-age=300")
                        .body(Body::empty())
                        .unwrap(),
                ),
                state,
                0,
                short_timeout,
                &backends,
            )
            .await
            .expect("stalled migration must still serve the 304");
            assert_eq!(response.status(), StatusCode::OK);
            // A timeout must not publish the replacement index or retire the
            // canonical metadata; the staged generation must be absent.
            assert_eq!(
                stalled
                    .retire_calls
                    .load(std::sync::atomic::Ordering::Relaxed),
                0,
                "timeout must not retire legacy metadata"
            );
            assert_eq!(
                stalled
                    .staged_calls
                    .load(std::sync::atomic::Ordering::Relaxed),
                0,
                "spool timeout must not reach generation staging"
            );
            assert!(
                stalled
                    .inner
                    .get(namespace, &index_storage_key(key.primary_hash().as_str()))
                    .await
                    .unwrap()
                    .is_none(),
                "timeout must not publish a replacement index"
            );
            assert!(
                stalled
                    .inner
                    .get_decoded_response_metadata_many(
                        namespace,
                        std::slice::from_ref(&legacy_key)
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .next()
                    .flatten()
                    .is_some(),
                "timeout must leave legacy metadata without deletion"
            );
            let generation = crate::vary::representation_storage_key(&legacy_key);
            assert!(
                stalled
                    .inner
                    .get(namespace, &generation)
                    .await
                    .unwrap()
                    .is_none(),
                "failed staged generation must not remain"
            );
            // Dropping the spooled body wakes the stalled producer: the source
            // permit is eventually released even though the spool timed out.
            tokio::time::timeout(Duration::from_secs(5), stalled.producer_released.notified())
                .await
                .expect("stalled producer must eventually release");
            if disk {
                tokio::fs::remove_dir_all(root).await.unwrap();
            }
        }
    })
    .await
    .expect("bounded stalled legacy timeout regression");
}

#[tokio::test]
async fn legacy_migration_invalidation_race_cannot_republish_after_final_check() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for disk in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "qpx-legacy-invalidate-race-{}",
                uuid::Uuid::new_v4()
            ));
            let inner = legacy_test_backend(disk, &root);
            let (mutations, mut completed) = mpsc::unbounded_channel();
            let backend = Arc::new(ObservedBackend {
                inner: inner.clone(),
                mutations,
                fail_retirement: std::sync::atomic::AtomicBool::new(false),
                staged_gate: Mutex::new(None),
                index_gate: Mutex::new(None),
            });
            let backends = HashMap::from([("b".into(), backend.clone() as Arc<dyn CacheBackend>)]);
            let request = make_get_request("/legacy-invalidate-race");
            let key = CacheRequestKey::for_lookup(&request, "http")
                .unwrap()
                .unwrap();
            let cache_policy = CachePolicyConfig {
                max_object_bytes: 4 * 1024 * 1024,
                ..policy()
            };
            let namespace = super::util::cache_namespace(&cache_policy, "default");
            // Long-lived canonical entry replaced by a short-lived 304 refresh.
            // A small body keeps the interleaving deterministic without the
            // 2MiB spool used by the retirement tests.
            const LEGACY_TTL_SECS: u64 = 2 * 24 * 60 * 60;
            let legacy_key = variant_storage_key(key.primary_hash().as_str(), &[]);
            let legacy_body = Bytes::from_static(b"legacy-body-for-invalidation-race");
            let seed_headers = crate::types::CachedHeaders::from_pairs(vec![
                (
                    "cache-control".to_owned(),
                    format!("public, max-age={LEGACY_TTL_SECS}"),
                ),
                ("content-length".to_owned(), legacy_body.len().to_string()),
            ]);
            let seed_envelope = CachedResponseEnvelope {
                status: StatusCode::OK.as_u16(),
                headers: seed_headers,
                body: CachedBody::default(),
                body_len: 0,
                stored_at_ms: super::util::now_millis(),
                initial_age_secs: 0,
                response_delay_secs: 0,
                freshness_lifetime_secs: LEGACY_TTL_SECS,
                vary_headers: Vec::new(),
                vary_values: Vec::new(),
                response_directives: Default::default(),
                response_header_values: Default::default(),
            };
            inner
                .put_response(
                    namespace,
                    legacy_key.as_str(),
                    Body::from(legacy_body.clone()),
                    BodyStreamWriteOptions {
                        max_body_bytes: 4 * 1024 * 1024,
                        body_read_timeout: Duration::from_secs(5),
                        ttl_secs: LEGACY_TTL_SECS,
                    },
                    Box::new(move |body_len| {
                        let mut envelope = seed_envelope;
                        envelope.body_len = body_len;
                        crate::types::encode_cached_response_metadata(&envelope)
                    }),
                )
                .await
                .expect("seed long-lived legacy canonical");
            let mut refresh_request = make_get_request("/legacy-invalidate-race");
            refresh_request.headers_mut().insert(
                OrdinaryHeaderName::try_from(CACHE_CONTROL).unwrap(),
                "no-cache".parse().unwrap(),
            );
            let LookupOutcome::Revalidate(state) = lookup(
                &refresh_request,
                &key,
                &cache_policy,
                &backends,
                &test_revalidations(),
            )
            .await
            .unwrap() else {
                panic!("legacy entry must require revalidation");
            };
            assert_eq!(state.variant_key, legacy_key);
            // Capture the staged generation key, then pause index publication
            // after the final check/retirement while the commit lock is held.
            let (staged_tx, mut staged_rx) = mpsc::unbounded_channel();
            let staged_release = Arc::new(tokio::sync::Notify::new());
            *backend.staged_gate.lock().unwrap() = Some((staged_tx, staged_release.clone()));
            let (index_tx, mut index_rx) = mpsc::unbounded_channel();
            let index_release = Arc::new(tokio::sync::Notify::new());
            *backend.index_gate.lock().unwrap() = Some((index_tx, index_release.clone()));
            while completed.try_recv().is_ok() {}
            let migration_backends = backends.clone();
            let migration_state = state.clone();
            let migration_policy = CachePolicyConfig {
                max_object_bytes: 4 * 1024 * 1024,
                ..cache_policy.clone()
            };
            let migration_request = refresh_request;
            let migration = tokio::spawn(async move {
                let response = revalidate_not_modified(
                    &migration_request,
                    &migration_policy,
                    qpx_core::http_message::Response::from_http(
                        Response::builder()
                            .status(304)
                            .header(CACHE_CONTROL, "public, max-age=300")
                            .body(Body::empty())
                            .unwrap(),
                    ),
                    migration_state,
                    0,
                    Duration::from_secs(5),
                    &migration_backends,
                )
                .await
                .expect("304 must serve even with gated publication");
                qpx_http::body::to_bytes(response.into_head_and_body().1)
                    .await
                    .expect("legacy body must stream while migration is gated")
            });
            // Staging completes before commit coordination; record the
            // generation so the final assertions can prove it was purged.
            let staged_key = tokio::time::timeout(Duration::from_secs(5), staged_rx.recv())
                .await
                .expect("staged generation")
                .expect("staged key");
            staged_release.notify_one();
            // The final check and retirement run under the per-primary lock;
            // this gate fires inside index `put`, before it is visible.
            let gated_index = tokio::time::timeout(Duration::from_secs(5), index_rx.recv())
                .await
                .expect("gated index publication")
                .expect("index key");
            assert_eq!(gated_index, index_storage_key(key.primary_hash().as_str()));
            // Retirement precedes index publication under the same lock.
            let mut saw_retire = false;
            while let Ok(mutation) = completed.try_recv() {
                if mutation == format!("retire:{legacy_key}") {
                    saw_retire = true;
                }
            }
            assert!(
                saw_retire,
                "retirement must precede gated index publication"
            );
            // `maybe_invalidate` (unsafe-method) and `purge_cache_key` both
            // delegate to `invalidate_primary`, so exercising the shared
            // primitive covers both. It must use the same per-primary lock
            // and therefore wait while the migration holds it.
            let primary = key.primary_hash();
            let namespace_owned = namespace.to_string();
            let backend_for_invalidation = backend.clone();
            let mut invalidation = tokio::spawn(async move {
                crate::invalidate::invalidate_primary(
                    backend_for_invalidation.as_ref(),
                    &namespace_owned,
                    primary.as_str(),
                )
                .await
                .expect("invalidation under migration lock")
            });
            // While the migration holds the commit lock, invalidation cannot
            // complete: it must wait rather than miss the staged generation.
            assert!(
                tokio::time::timeout(Duration::from_millis(200), &mut invalidation)
                    .await
                    .is_err(),
                "invalidation must wait for the migration commit lock"
            );
            index_release.notify_one();
            tokio::time::timeout(Duration::from_secs(5), &mut invalidation)
                .await
                .expect("invalidation must complete after release")
                .expect("join");
            let client_body = tokio::time::timeout(Duration::from_secs(5), migration)
                .await
                .expect("migration must complete")
                .expect("join");
            // Response streaming is preserved: the 304 serves the retired
            // body's bytes even though invalidation ran before publication.
            assert_eq!(client_body, legacy_body);
            // The losing publication must not resurface: the index is purged,
            // both the retired canonical and the staged generation are gone,
            // and a fresh lookup cannot hit the invalidated representation.
            // Drain the post-release index write before asserting absence.
            let mut saw_index_write = false;
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if completed.recv().await.as_deref() == Some(gated_index.as_str()) {
                        saw_index_write = true;
                        break;
                    }
                }
            })
            .await
            .expect("published index write");
            assert!(saw_index_write);
            assert!(
                backend
                    .get(namespace, &index_storage_key(key.primary_hash().as_str()))
                    .await
                    .unwrap()
                    .is_none(),
                "invalidated index must not resurface"
            );
            assert!(
                backend
                    .get_decoded_response_metadata_many(
                        namespace,
                        std::slice::from_ref(&legacy_key)
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .next()
                    .flatten()
                    .is_none(),
                "invalidated legacy metadata must stay retired"
            );
            assert!(
                backend
                    .get_decoded_response_metadata_many(
                        namespace,
                        std::slice::from_ref(&staged_key)
                    )
                    .await
                    .unwrap()
                    .into_iter()
                    .next()
                    .flatten()
                    .is_none(),
                "invalidated staged generation must not remain"
            );
            assert!(matches!(
                lookup(
                    &request,
                    &key,
                    &cache_policy,
                    &backends,
                    &test_revalidations()
                )
                .await
                .unwrap(),
                LookupOutcome::Miss
            ));
            drop(backends);
            drop(backend);
            if disk {
                tokio::fs::remove_dir_all(root).await.unwrap();
            }
        }
    })
    .await
    .expect("bounded invalidation race regression");
}
