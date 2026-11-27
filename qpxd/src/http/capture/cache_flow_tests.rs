use super::*;
use bytes::Bytes;
use cache::{CacheWritebackAdmission, CachedBodyStream, InFlightLookups, RequestCollapseJoin};
use qpx_http::body::to_bytes;
use std::sync::Mutex;
use tokio::sync::mpsc;

// Use the default split-object put_response to observe its body write as well
// as each metadata/index write. One namespace is enough for this fixture.
struct RecordingBackend {
    objects: Mutex<HashMap<String, Bytes>>,
    writes: mpsc::UnboundedSender<String>,
}

#[async_trait::async_trait]
impl CacheBackend for RecordingBackend {
    async fn get(&self, _ns: &str, key: &str) -> Result<Option<Bytes>> {
        Ok(self.objects.lock().unwrap().get(key).cloned())
    }

    async fn get_many(&self, _ns: &str, keys: &[String]) -> Result<Vec<Option<Bytes>>> {
        let objects = self.objects.lock().unwrap();
        Ok(keys.iter().map(|key| objects.get(key).cloned()).collect())
    }

    async fn get_object_stream(
        &self,
        ns: &str,
        key: &str,
        expected_len: u64,
        range: Option<(u64, u64)>,
    ) -> Result<Option<CachedBodyStream>> {
        assert!(range.is_none());
        Ok(self.get(ns, key).await?.map(|bytes| {
            assert_eq!(bytes.len() as u64, expected_len);
            CachedBodyStream::from_body_for_backend(expected_len, Body::from(bytes))
        }))
    }

    async fn put(&self, _ns: &str, key: &str, bytes: &[u8], _ttl: u64) -> Result<()> {
        self.objects
            .lock()
            .unwrap()
            .insert(key.into(), Bytes::copy_from_slice(bytes));
        self.writes.send(key.into()).unwrap();
        Ok(())
    }

    async fn put_object_stream(
        &self,
        ns: &str,
        key: &str,
        body: Body,
        max_body_bytes: usize,
        timeout: Duration,
        ttl: u64,
    ) -> Result<u64> {
        let body = tokio::time::timeout(timeout, to_bytes(body)).await??;
        assert!(body.len() <= max_body_bytes);
        self.put(ns, key, &body, ttl).await?;
        Ok(body.len() as u64)
    }

    async fn delete(&self, _ns: &str, key: &str) -> Result<()> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }
}

#[tokio::test]
async fn cache_owned_304_refreshes_metadata_without_storing_again() {
    let timeout = Duration::from_secs(5);
    tokio::time::timeout(timeout, async {
        let (writes, mut written) = mpsc::unbounded_channel();
        let backend: Arc<dyn CacheBackend> = Arc::new(RecordingBackend {
            objects: Mutex::default(),
            writes,
        });
        let backends = HashMap::from([("test".into(), backend)]);
        let policy: CachePolicyConfig =
            serde_json::from_value(serde_json::json!({"enabled": true, "backend": "test"}))
                .unwrap();
        let mut request = OwnerRequest::from_http(
            http::Request::get("http://example.test/revalidated")
                .body(Body::empty())
                .unwrap(),
        );
        let snapshot = clone_request_head_for_revalidation(&request);
        let key = CacheRequestKey::for_lookup(&snapshot, "http")
            .unwrap()
            .unwrap();
        let collapse = Arc::new(InFlightLookups::with_default_shards());
        let writeback_admission = CacheWritebackAdmission::with_default_capacity();
        let process = async |upstream, state| {
            let RequestCollapseJoin::Leader(leader) = collapse.begin(&key) else {
                panic!("expected collapse leader");
            };
            let RequestCollapseJoin::Follower(mut waiter) = collapse.begin(&key) else {
                panic!("expected collapse follower");
            };
            let (settled, ()) = tokio::join!(waiter.wait(timeout), async {
                let response = process_upstream_response_for_cache(
                    Response::from_http(upstream),
                    CacheWritebackContext {
                        request_snapshot: &snapshot,
                        response_delay_secs: 0,
                        cache_target_key: Some(&key),
                        cache_lookup_key: Some(&key),
                        cache_policy: Some(&policy),
                        revalidation_state: state,
                        request_collapse_guard: Some(leader),
                        body_read_timeout: timeout,
                        writeback_admission: &writeback_admission,
                        backends: &backends,
                    },
                )
                .await
                .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    to_bytes(response.into_head_and_body().1).await.unwrap(),
                    "cached body"
                );
            });
            // For a normal store the guard only drops once the writeback task
            // settles. No sleeps or yields are needed to detect a second store.
            assert!(settled, "writeback did not settle");
        };

        let initial = http::Response::builder()
            .header("cache-control", "public, no-cache, max-age=300")
            .header("etag", "\"cached\"")
            .body(Body::from("cached body"))
            .unwrap();
        process(initial, None).await;
        let _body_key = written.try_recv().expect("initial body write");
        let metadata_key = written.try_recv().expect("initial metadata write");
        let index_key = written.try_recv().expect("initial index publication");
        assert_eq!(index_key, format!("idx:{}", key.primary_hash()));

        let (CacheLookupDecision::Miss, Some(state)) = lookup_with_revalidation(
            &mut request,
            &snapshot,
            Some(&key),
            Some(&policy),
            &backends,
            &Arc::new(cache::InFlightRevalidations::with_default_shards()),
            "cache miss",
        )
        .await
        .unwrap() else {
            panic!("expected cache-owned revalidation");
        };
        let not_modified = http::Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("cache-control", "public, max-age=300")
            .body(Body::empty())
            .unwrap();
        process(not_modified, Some(state)).await;
        let mut writes_after_304 = vec![written.recv().await.unwrap()];
        while let Ok(write) = written.try_recv() {
            writes_after_304.push(write);
        }
        assert_eq!(
            writes_after_304,
            [metadata_key],
            "a cache-owned 304 must not write a new body or publish a second index"
        );
    })
    .await
    .expect("bounded cache-owned 304 test");
}

fn ordinary(name: &str) -> OrdinaryHeaderName {
    OrdinaryHeaderName::try_from(name).unwrap()
}

/// Store a stale entry with validators, then take the state a background
/// revalidation would receive. The receiver is kept alive for write events.
async fn stale_revalidation_state() -> (RevalidationState, mpsc::UnboundedReceiver<String>) {
    let (writes, written) = mpsc::unbounded_channel();
    let backend: Arc<dyn CacheBackend> = Arc::new(RecordingBackend {
        objects: Mutex::default(),
        writes,
    });
    let backends = HashMap::from([("test".into(), backend)]);
    let policy: CachePolicyConfig =
        serde_json::from_value(serde_json::json!({"enabled": true, "backend": "test"})).unwrap();
    let seed = clone_request_head_for_revalidation(&OwnerRequest::from_http(
        http::Request::get("http://example.test/asset")
            .body(())
            .unwrap(),
    ));
    let key = CacheRequestKey::for_lookup(&seed, "http").unwrap().unwrap();
    let admission = CacheWritebackAdmission::with_default_capacity();
    let response = cache::maybe_store(
        &seed,
        &key,
        &policy,
        Response::from_http(
            http::Response::builder()
                .header("cache-control", "public, no-cache, max-age=300")
                .header("etag", "\"cached\"")
                .header("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")
                .body(Body::from("cached body"))
                .unwrap(),
        ),
        cache::CacheStoreContext {
            timing: cache::CacheStoreTiming {
                response_delay_secs: 0,
                body_read_timeout: Duration::from_secs(5),
                request_collapse_guard: None,
            },
            writeback_admission: &admission,
            backends: &backends,
        },
    )
    .await
    .unwrap();
    to_bytes(response.into_head_and_body().1).await.unwrap();

    let revalidations = Arc::new(cache::InFlightRevalidations::with_default_shards());
    let state = match cache::lookup(&seed, &key, &policy, &backends, &revalidations)
        .await
        .unwrap()
    {
        cache::LookupOutcome::Revalidate(state) => state,
        _ => panic!("expected a stale entry to require revalidation"),
    };
    (state, written)
}

#[tokio::test]
async fn prepared_revalidation_head_drops_stale_content_length() {
    let (state, _written) = stale_revalidation_state().await;
    let mut req = OwnerRequest::from_http(
        http::Request::get("http://example.test/asset")
            .header("content-length", "42")
            .body(())
            .unwrap(),
    );
    assert_eq!(req.headers().declared_content_length().unwrap(), Some(42));

    prepare_background_revalidation_request(&mut req, &state);

    assert_eq!(req.headers().declared_content_length().unwrap(), None);
}

#[tokio::test]
async fn prepared_revalidation_head_replaces_client_conditions_with_cached_validators() {
    let (state, _written) = stale_revalidation_state().await;
    let mut req = OwnerRequest::from_http(
        http::Request::get("http://example.test/asset")
            .header("content-length", "42")
            .header("if-match", "\"client-match\"")
            .header("if-none-match", "\"client-none-match\"")
            .header("if-modified-since", "Tue, 20 Oct 2015 07:28:00 GMT")
            .header("if-unmodified-since", "Tue, 20 Oct 2015 07:28:00 GMT")
            .header("if-range", "\"client-none-match\"")
            .header("range", "bytes=0-3")
            .header("x-client", "keep")
            .body(())
            .unwrap(),
    );

    prepare_background_revalidation_request(&mut req, &state);

    for name in ["if-match", "if-unmodified-since", "if-range", "range"] {
        assert!(
            !req.headers().contains_key(&ordinary(name)),
            "{name} must be gone"
        );
    }
    assert_eq!(
        req.headers().get(&ordinary("if-none-match")).unwrap(),
        "\"cached\"",
        "the cache's validator replaces the stripped client condition"
    );
    assert_eq!(
        req.headers().get(&ordinary("if-modified-since")).unwrap(),
        "Wed, 21 Oct 2015 07:28:00 GMT",
        "the cache's validator replaces the client's date"
    );
    assert_eq!(
        req.headers().get(&ordinary("x-client")).unwrap(),
        "keep",
        "unrelated client fields survive"
    );
    assert_eq!(req.headers().declared_content_length().unwrap(), None);
}

#[tokio::test]
async fn writeback_snapshot_keeps_original_head_when_preparing_revalidation() {
    let (state, _written) = stale_revalidation_state().await;
    let original = OwnerRequest::from_http(
        http::Request::get("http://example.test/asset")
            .header("content-length", "42")
            .header("if-none-match", "\"client-none-match\"")
            .header("range", "bytes=0-3")
            .header("x-client", "keep")
            .body(())
            .unwrap(),
    );

    let (outgoing, snapshot) = clone_revalidation_head_with_writeback_snapshot(&original, &state);

    assert_eq!(outgoing.headers().declared_content_length().unwrap(), None);
    assert_eq!(
        outgoing.headers().get(&ordinary("if-none-match")).unwrap(),
        "\"cached\""
    );
    assert_eq!(
        snapshot.headers().declared_content_length().unwrap(),
        Some(42)
    );
    assert_eq!(
        snapshot.headers().get(&ordinary("if-none-match")).unwrap(),
        "\"client-none-match\""
    );
    assert!(snapshot.headers().contains_key(&ordinary("range")));
    assert!(
        snapshot
            .headers()
            .get(&ordinary("if-modified-since"))
            .is_none()
    );
    assert_eq!(
        snapshot.headers().get(&ordinary("x-client")).unwrap(),
        "keep"
    );
    assert_eq!(
        original.headers().declared_content_length().unwrap(),
        Some(42),
        "preparing must not mutate the caller's request"
    );
}

/// End-to-end guard for the desync: encode the prepared bodyless head with
/// hyper's H1 client codec and inspect the bytes actually written to the wire.
/// A header-only assertion would miss a stale declaration the encoder could
/// reintroduce; this checks the property that matters to an upstream peer.
#[tokio::test]
async fn prepared_revalidation_head_sends_no_stale_cl_on_wire() {
    use hyper_util::rt::TokioIo;
    use tokio::io::AsyncReadExt;

    let (state, _written) = stale_revalidation_state().await;
    let mut req = OwnerRequest::from_http(
        http::Request::get("http://example.test/asset")
            .header("content-length", "42")
            .body(())
            .unwrap(),
    );
    prepare_background_revalidation_request(&mut req, &state);
    let hyper_req = req
        .map_body(|()| Body::empty())
        .into_http_for_codec()
        .unwrap();

    let (client_io, mut server_io) = tokio::io::duplex(16384);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    tokio::spawn(async move {
        let _ = sender.send_request(hyper_req).await;
    });

    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(Duration::from_secs(5), server_io.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read error");
    let wire = String::from_utf8_lossy(&buf[..n]);
    assert!(
        wire.contains("\r\n\r\n"),
        "expected a complete request head on the wire: {wire:?}"
    );
    assert!(
        !wire.to_ascii_lowercase().contains("content-length: 42"),
        "stale Content-Length reached the wire: {wire:?}"
    );
}
