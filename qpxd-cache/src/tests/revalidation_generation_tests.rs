use super::*;
use crate::types::{BodyStreamWriteOptions, MetadataEncoder};
use tokio::sync::mpsc;

// Observe completed backend operations, not elapsed time or scheduler yields.
// Delegating put_response and decoded reads preserves disk's co-located format;
// MockBackend exercises the split body/metadata publication used by HTTP/Redis.
struct ObservedBackend {
    inner: Arc<dyn CacheBackend>,
    mutations: mpsc::UnboundedSender<String>,
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
        self.inner
            .get_decoded_response_metadata_many(ns, keys)
            .await
    }
    async fn put(&self, ns: &str, key: &str, value: &[u8], ttl: u64) -> Result<()> {
        self.inner.put(ns, key, value, ttl).await?;
        self.mutations.send(key.to_owned()).unwrap();
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
        self.inner
            .put_response(ns, key, body, options, encode)
            .await
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
            let inner: Arc<dyn CacheBackend> = if disk {
                Arc::new(
                    crate::backend_disk::DiskCacheBackend::new(
                        qpx_core::config::CacheBackendConfig {
                            name: "b".into(),
                            kind: "disk".into(),
                            endpoint: String::new(),
                            path: Some(root.display().to_string()),
                            max_bytes: Some(8 * 1024 * 1024),
                            sweep_interval_secs: 60,
                            timeout_ms: 1000,
                            max_object_bytes: 4 * 1024 * 1024,
                            auth_header_env: None,
                        },
                    )
                    .expect("disk backend"),
                )
            } else {
                Arc::new(MockBackend::new())
            };
            let (mutations, mut completed) = mpsc::unbounded_channel();
            let backend = Arc::new(ObservedBackend {
                inner: inner.clone(),
                mutations,
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

            // The replacement is fresh briefly, while the canonical entry's
            // retained lifetime exceeds the index's 24-hour minimum.
            publish(
                &request,
                &key,
                &backends,
                "public, max-age=1",
                "replacement",
                "new",
            )
            .await;
            let primary = key.primary_hash();
            let retirement_key =
                crate::vary::legacy_variant_retirement_storage_key(primary.as_str());
            assert!(
                backend
                    .get(namespace, retirement_key.as_str())
                    .await
                    .unwrap()
                    .is_some()
            );
            let mutations = std::iter::from_fn(|| completed.try_recv().ok()).collect::<Vec<_>>();
            let retirement_write = mutations
                .iter()
                .position(|written| written == &retirement_key)
                .expect("retirement marker write");
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
            // expires. The old object remains available to an already-held body,
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
                    .is_some()
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

#[tokio::test]
async fn delayed_304_finalizers_cannot_mutate_a_published_replacement() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for disk in [false, true] {
            let root =
                std::env::temp_dir().join(format!("qpx-cache-generation-{}", uuid::Uuid::new_v4()));
            let inner: Arc<dyn CacheBackend> = if disk {
                Arc::new(
                    crate::backend_disk::DiskCacheBackend::new(
                        qpx_core::config::CacheBackendConfig {
                            name: "b".into(),
                            kind: "disk".into(),
                            endpoint: String::new(),
                            path: Some(root.display().to_string()),
                            max_bytes: Some(1024 * 1024),
                            sweep_interval_secs: 60,
                            timeout_ms: 1000,
                            max_object_bytes: 1024 * 1024,
                            auth_header_env: None,
                        },
                    )
                    .unwrap(),
                )
            } else {
                Arc::new(MockBackend::new())
            };
            let (mutations, mut completed) = mpsc::unbounded_channel();
            let backend = Arc::new(ObservedBackend { inner, mutations });
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
