use super::directives::{parse_request_directives, parse_response_directives};
use super::lookup_ops::classify_for_request;
use super::types::{
    CACHE_HEADER, CacheEntryDisposition, CachedBody, CachedBodyStream, CachedResponseEnvelope,
    MAX_VARIANTS_PER_PRIMARY, RequestDirectives, VariantIndex, VarySpec, cache_body_storage_key,
    decode_cached_response_metadata, encode_cached_response_metadata,
};
use super::util::{cacheable_content_length, load_variant_index, upsert_variant_with_cap};
use super::vary::{index_storage_key, matches_vary, parse_vary, variant_storage_key};
use super::*;
use crate::cache::purge_cache_key;
use crate::http::body::Body;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_LOCATION, DATE, VARY};
use http::header::{
    CONTENT_LENGTH, ETAG, HOST, IF_MATCH, IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE,
    LAST_MODIFIED, SET_COOKIE, TRANSFER_ENCODING,
};
use http::header::{CONTENT_RANGE, RANGE};
use hyper::{Method, Request, Response, StatusCode};
use qpx_core::config::CachePolicyConfig;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

struct MockBackend {
    map: Mutex<HashMap<String, Vec<u8>>>,
    gets: Mutex<Vec<String>>,
}

struct DefaultPutObjectBackend;

impl MockBackend {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            gets: Mutex::new(Vec::new()),
        }
    }

    fn key(namespace: &str, key: &str) -> String {
        format!("{}::{}", namespace, key)
    }

    fn get_log(&self) -> Vec<String> {
        self.gets.lock().expect("lock").clone()
    }

    fn clear_get_log(&self) {
        self.gets.lock().expect("lock").clear();
    }
}

#[async_trait]
impl CacheBackend for MockBackend {
    async fn get(&self, namespace: &str, key: &str) -> Result<Option<bytes::Bytes>> {
        self.gets
            .lock()
            .expect("lock")
            .push(Self::key(namespace, key));
        Ok(self
            .map
            .lock()
            .expect("lock")
            .get(Self::key(namespace, key).as_str())
            .cloned()
            .map(bytes::Bytes::from))
    }

    async fn get_many(
        &self,
        namespace: &str,
        keys: &[String],
    ) -> Result<Vec<Option<bytes::Bytes>>> {
        let mut values = Vec::with_capacity(keys.len());
        for key in keys {
            values.push(self.get(namespace, key).await?);
        }
        Ok(values)
    }

    async fn put(&self, namespace: &str, key: &str, value: &[u8], _ttl_secs: u64) -> Result<()> {
        self.map
            .lock()
            .expect("lock")
            .insert(Self::key(namespace, key), value.to_vec());
        Ok(())
    }

    async fn put_object(
        &self,
        namespace: &str,
        key: &str,
        body: &CachedBody,
        _ttl_secs: u64,
    ) -> Result<()> {
        let mut out = Vec::new();
        let mut stream = body.to_body();
        while let Some(chunk) = stream.data().await {
            out.extend_from_slice(chunk?.as_ref());
        }
        self.map
            .lock()
            .expect("lock")
            .insert(Self::key(namespace, key), out);
        Ok(())
    }

    async fn put_object_stream(
        &self,
        namespace: &str,
        key: &str,
        mut body: Body,
        max_body_bytes: usize,
        body_read_timeout: Duration,
        _ttl_secs: u64,
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
        self.map
            .lock()
            .expect("lock")
            .insert(Self::key(namespace, key), out);
        Ok(len)
    }

    async fn get_object_stream(
        &self,
        namespace: &str,
        key: &str,
        expected_len: u64,
        range: Option<(u64, u64)>,
    ) -> Result<Option<CachedBodyStream>> {
        self.gets
            .lock()
            .expect("lock")
            .push(Self::key(namespace, key));
        let Some(bytes) = self
            .map
            .lock()
            .expect("lock")
            .get(Self::key(namespace, key).as_str())
            .cloned()
            .map(Bytes::from)
        else {
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
        Ok(Some(CachedBodyStream { len, body }))
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        self.map
            .lock()
            .expect("lock")
            .remove(Self::key(namespace, key).as_str());
        Ok(())
    }
}

#[async_trait]
impl CacheBackend for DefaultPutObjectBackend {
    async fn get(&self, _namespace: &str, _key: &str) -> Result<Option<bytes::Bytes>> {
        Ok(None)
    }

    async fn get_many(
        &self,
        _namespace: &str,
        keys: &[String],
    ) -> Result<Vec<Option<bytes::Bytes>>> {
        Ok(vec![None; keys.len()])
    }

    async fn put(&self, _namespace: &str, _key: &str, _value: &[u8], _ttl_secs: u64) -> Result<()> {
        Ok(())
    }

    async fn delete(&self, _namespace: &str, _key: &str) -> Result<()> {
        Ok(())
    }
}

fn policy() -> CachePolicyConfig {
    CachePolicyConfig {
        enabled: true,
        backend: "b".to_string(),
        namespace: Some("ns".to_string()),
        default_ttl_secs: Some(30),
        max_object_bytes: 1024 * 1024,
        allow_set_cookie_store: false,
    }
}

fn backend_map() -> HashMap<String, Arc<dyn CacheBackend>> {
    let mut map = HashMap::new();
    map.insert(
        "b".to_string(),
        Arc::new(MockBackend::new()) as Arc<dyn CacheBackend>,
    );
    map
}

fn make_get_request(path: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(format!("http://example.com{}", path))
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("request")
}

fn make_head_request(path: &str) -> Request<Body> {
    Request::builder()
        .method(Method::HEAD)
        .uri(format!("http://example.com{}", path))
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("request")
}

fn make_response(status: StatusCode, cache_control: &str, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CACHE_CONTROL, cache_control)
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body.to_string()))
        .expect("response")
}

async fn store_and_drain(
    request_method: &Method,
    request_headers: &http::HeaderMap,
    key: &CacheRequestKey,
    policy: &CachePolicyConfig,
    response: Response<Body>,
    timing: CacheStoreTiming,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<Response<Body>> {
    let response = super::maybe_store(
        request_method,
        request_headers,
        key,
        policy,
        response,
        timing,
        backends,
    )
    .await?;
    let (parts, body) = response.into_parts();
    let body = crate::http::body::to_bytes(body).await?;
    // Cache writeback runs behind the response body tee; let that task commit metadata/index.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    Ok(Response::from_parts(parts, Body::from(body)))
}

mod backend_tests;
mod directive_tests;
mod freshness_tests;
mod index_metadata_tests;
mod lookup_head_post_tests;
mod lookup_policy_tests;
mod lookup_range_tests;
mod store_flow_tests;
