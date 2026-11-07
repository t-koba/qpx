use super::*;
use hyper::body::Body as _;
use std::collections::HashSet;
use std::pin::Pin;
use tokio::sync::{Notify, Semaphore, mpsc, oneshot};

const CHUNK: &[u8] = &[b'x'; 64 * 1024];
const CHUNKS: u64 = 32;
const LENGTH: u64 = CHUNK.len() as u64 * CHUNKS;

#[derive(Clone, Copy)]
enum Ending {
    Eof,
    Trailers,
    Error,
    WrongLength,
    Short,
    Long,
}

// HTTP and Redis both hold their active-operation permit while sending large
// objects into a bounded Body channel. All operations share that same limiter.
struct StreamingBackend {
    inner: MockBackend,
    active: Arc<Semaphore>,
    sources: Arc<Mutex<HashSet<String>>>,
    changed: Notify,
    ending: Ending,
}

impl StreamingBackend {
    fn new(ending: Ending) -> Self {
        Self {
            inner: MockBackend::new(),
            active: Arc::new(Semaphore::new(2)),
            sources: Arc::default(),
            changed: Notify::new(),
            ending,
        }
    }

    fn assert_source_stopped(&self, key: &str) {
        let primary = key.split(':').nth(1).expect("storage key");
        assert!(
            !self
                .sources
                .lock()
                .expect("sources")
                .iter()
                .any(|source| source.split(':').nth(1) == Some(primary)),
            "metadata operation {key} raced its producer"
        );
    }
}

#[async_trait]
impl CacheBackend for StreamingBackend {
    async fn get_many(&self, ns: &str, keys: &[String]) -> Result<Vec<Option<Bytes>>> {
        let mut values = Vec::new();
        for key in keys {
            values.push(self.get(ns, key).await?);
        }
        Ok(values)
    }
    async fn get(&self, ns: &str, key: &str) -> Result<Option<Bytes>> {
        self.assert_source_stopped(key);
        let _permit = self.active.acquire().await?;
        self.inner.get(ns, key).await
    }

    async fn put(&self, ns: &str, key: &str, bytes: &[u8], ttl: u64) -> Result<()> {
        self.assert_source_stopped(key);
        let _permit = self.active.acquire().await?;
        self.inner.put(ns, key, bytes, ttl).await?;
        self.changed.notify_one();
        Ok(())
    }

    async fn delete(&self, ns: &str, key: &str) -> Result<()> {
        self.assert_source_stopped(key);
        let _permit = self.active.acquire().await?;
        self.inner.delete(ns, key).await?;
        self.changed.notify_one();
        Ok(())
    }

    async fn get_object_stream(
        &self,
        _ns: &str,
        key: &str,
        expected: u64,
        range: Option<(u64, u64)>,
    ) -> Result<Option<CachedBodyStream>> {
        assert_eq!(expected, LENGTH);
        assert!(range.is_none());
        let permit = self.active.clone().acquire_owned().await?;
        self.sources.lock().expect("sources").insert(key.to_owned());
        let sources = self.sources.clone();
        let key = key.to_owned();
        let ending = self.ending;
        let (mut sender, body) = Body::channel_with_capacity(1);
        let (done, producer_done) = oneshot::channel();
        tokio::spawn(async move {
            let chunks = match ending {
                Ending::Short => CHUNKS - 1,
                Ending::Long => CHUNKS + 1,
                _ => CHUNKS,
            };
            for _ in 0..chunks {
                if sender.send_data(Bytes::from_static(CHUNK)).await.is_err() {
                    break;
                }
            }
            match ending {
                Ending::Trailers => {
                    let mut trailers = http::HeaderMap::new();
                    trailers.append("x-proof", http::HeaderValue::from_static("one"));
                    trailers.append("x-proof", http::HeaderValue::from_static("two"));
                    let _ = sender.send_trailers(trailers).await;
                }
                Ending::Error => sender.abort(),
                _ => {}
            }
            drop(sender);
            // Deliberately leave a scheduling gap after terminal delivery, just
            // like asynchronous connection recycling in the remote backends.
            tokio::task::yield_now().await;
            sources.lock().expect("sources").remove(&key);
            drop(permit);
            let _ = done.send(());
        });
        Ok(Some(CachedBodyStream::from_producer_for_backend(
            if matches!(ending, Ending::WrongLength) {
                LENGTH - 1
            } else {
                LENGTH
            },
            body,
            producer_done,
        )))
    }
}

async fn state(backend: &Arc<StreamingBackend>, index: usize) -> (RevalidationState, Vec<u8>) {
    let variant_key = variant_storage_key(&format!("delivery{index}"), &[]);
    let envelope = CachedResponseEnvelope {
        status: 200,
        headers: crate::types::CachedHeaders::from_pairs(vec![
            (
                "cache-control".into(),
                "public, no-cache, max-age=10".into(),
            ),
            ("content-length".into(), LENGTH.to_string()),
        ]),
        body: CachedBody::default(),
        body_len: LENGTH,
        stored_at_ms: 1,
        initial_age_secs: 0,
        response_delay_secs: 0,
        freshness_lifetime_secs: 10,
        vary_headers: vec![],
        vary_values: vec![],
        response_directives: Default::default(),
        response_header_values: Default::default(),
    };
    let original = encode_cached_response_metadata(&envelope).expect("metadata");
    backend
        .inner
        .put("ns", &variant_key, &original, 60)
        .await
        .unwrap();
    backend
        .inner
        .put("ns", &cache_body_storage_key(&variant_key), b"source", 60)
        .await
        .unwrap();
    (
        RevalidationState {
            backend: backend.clone(),
            namespace: "ns".into(),
            variant_key,
            request_method: Method::GET,
            request_directives: RequestDirectives::default(),
            stale_if_error_secs: None,
            envelope,
            revalidations: test_revalidations(),
        },
        original,
    )
}

async fn wait_for_mutations(
    backend: &StreamingBackend,
    originals: &[(String, Vec<u8>)],
    refresh: bool,
) {
    loop {
        let changed = backend.changed.notified();
        let settled = {
            let map = backend.inner.map.lock().expect("map");
            originals.iter().all(|(key, original)| {
                let metadata = map.get(&MockBackend::key("ns", key));
                if refresh {
                    metadata.is_some_and(|value| value != original)
                } else {
                    metadata.is_none()
                        && !map.contains_key(&MockBackend::key("ns", &cache_body_storage_key(key)))
                }
            })
        };
        if settled {
            break;
        }
        changed.await;
    }
}

#[tokio::test]
async fn foreground_304_returns_backpressured_bodies_before_cache_mutations() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for ending in [Ending::Eof, Ending::Trailers] {
            for (control, vary) in [
                ("public, max-age=300", None),
                ("no-store", None),
                ("private", None),
                ("public, max-age=300", Some("x-new")),
                ("public, max-age=300", Some("*")),
                ("public, max-age=300", Some("bad name")),
            ] {
                let backend = Arc::new(StreamingBackend::new(ending));
                let readers = Arc::new(Semaphore::new(0));
                let (ready, mut responses) = mpsc::unbounded_channel();
                let mut tasks = tokio::task::JoinSet::new();
                let mut originals = vec![];
                for index in 0..3 {
                    let (state, original) = state(&backend, index).await;
                    originals.push((state.variant_key.clone(), original));
                    let backends =
                        HashMap::from([("b".into(), backend.clone() as Arc<dyn CacheBackend>)]);
                    let ready = ready.clone();
                    let readers = readers.clone();
                    tasks.spawn(async move {
                        let mut response = Response::builder()
                            .status(304)
                            .header(CACHE_CONTROL, control);
                        if let Some(vary) = vary {
                            response = response.header(VARY, vary);
                        }
                        let mut response = revalidate_not_modified(
                            &make_get_request("/delivery"),
                            &policy(),
                            qpx_core::http_message::Response::from_http(
                                response.body(Body::empty()).unwrap(),
                            ),
                            state,
                            0,
                            &backends,
                        )
                        .await
                        .expect("response must be consumable before mutation");
                        ready.send(()).unwrap();
                        let _reader = readers.acquire().await.unwrap();
                        let mut observed = 0;
                        let mut trailers = false;
                        while let Some(frame) =
                            std::future::poll_fn(|cx| Pin::new(response.body_mut()).poll_frame(cx))
                                .await
                        {
                            let frame = frame.expect("unchanged frames");
                            if let Some(bytes) = frame.data_ref() {
                                assert!(bytes.iter().all(|byte| *byte == b'x'));
                                observed += bytes.len() as u64;
                            }
                            if let Some(values) = frame.trailers_ref() {
                                assert_eq!(
                                    values
                                        .get_all("x-proof")
                                        .iter()
                                        .map(|v| v.to_str().unwrap())
                                        .collect::<Vec<_>>(),
                                    ["one", "two"]
                                );
                                trailers = true;
                            }
                        }
                        assert_eq!(observed, LENGTH);
                        assert_eq!(trailers, matches!(ending, Ending::Trailers));
                    });
                }
                // Two unread responses saturate both permits. A third cannot
                // open yet; an implementation awaiting put/delete never gets here.
                responses.recv().await.unwrap();
                responses.recv().await.unwrap();
                assert_eq!(backend.active.available_permits(), 0);
                for (key, original) in &originals {
                    assert_eq!(
                        backend
                            .inner
                            .map
                            .lock()
                            .unwrap()
                            .get(&MockBackend::key("ns", key)),
                        Some(original)
                    );
                }
                readers.add_permits(3);
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
                wait_for_mutations(
                    &backend,
                    &originals,
                    control == "public, max-age=300" && vary.is_none(),
                )
                .await;
                assert!(backend.sources.lock().unwrap().is_empty());
                assert_eq!(backend.active.available_permits(), 2);
            }
        }
    })
    .await
    .expect("foreground revalidation deadlocked");
}

#[tokio::test]
async fn foreground_304_cancellation_and_invalid_streams_do_not_refresh() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for ending in [
            Ending::Eof,
            Ending::Error,
            Ending::WrongLength,
            Ending::Short,
            Ending::Long,
        ] {
            for control in ["public, max-age=300", "no-store"] {
                let backend = Arc::new(StreamingBackend::new(ending));
                let (state, original) = state(&backend, 0).await;
                let key = state.variant_key.clone();
                let backends =
                    HashMap::from([("b".into(), backend.clone() as Arc<dyn CacheBackend>)]);
                let response = revalidate_not_modified(
                    &make_get_request("/delivery"),
                    &policy(),
                    qpx_core::http_message::Response::from_http(
                        Response::builder()
                            .status(304)
                            .header(CACHE_CONTROL, control)
                            .body(Body::empty())
                            .unwrap(),
                    ),
                    state,
                    0,
                    &backends,
                )
                .await;
                match ending {
                    Ending::WrongLength => assert!(response.is_err()),
                    Ending::Error | Ending::Short | Ending::Long => {
                        let mut response = response.unwrap();
                        let mut saw_error = false;
                        while let Some(frame) =
                            std::future::poll_fn(|cx| Pin::new(response.body_mut()).poll_frame(cx))
                                .await
                        {
                            if let Err(error) = frame {
                                let message = error.to_string();
                                assert!(message.contains(match ending {
                                    Ending::Short => "shorter than declared",
                                    Ending::Long => "exceeds declared",
                                    _ => "abort",
                                }));
                                saw_error = true;
                                break;
                            }
                        }
                        assert!(saw_error, "source error must reach the consumer");
                    }
                    _ => drop(response.unwrap()), // wakes a blocked producer
                }
                if matches!(ending, Ending::Eof) && control != "no-store" {
                    // Wait for producer shutdown, then ensure the abandoned
                    // response has not published newer metadata.
                    let _all = backend.active.acquire_many(2).await.unwrap();
                    assert_eq!(
                        backend
                            .inner
                            .map
                            .lock()
                            .unwrap()
                            .get(&MockBackend::key("ns", &key)),
                        Some(&original)
                    );
                } else {
                    wait_for_mutations(&backend, &[(key, original)], false).await;
                }
            }
        }
    })
    .await
    .expect("cancelled/invalid producer did not settle");
}
