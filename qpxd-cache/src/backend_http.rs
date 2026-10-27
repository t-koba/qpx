use super::types::bounded_cache_body_stream;
use super::{CacheBackend, CachedBody};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hyper::{Method, StatusCode, Uri};
use qpx_core::config::CacheBackendConfig;
use qpx_core::http_message::{OrdinaryHeaderName, Request as OwnerRequest};
use qpx_http::body::Body;
use qpx_http::protocol::common::Http1SendRequest;
use qpx_http::tls::builder::connect_client_http1;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::time::timeout;

const HTTP_CACHE_MAX_IDLE_CONNECTIONS: usize = 8;
const HTTP_CACHE_MAX_ACTIVE_OPERATIONS: usize = 32;

fn ord(name: &str) -> OrdinaryHeaderName {
    OrdinaryHeaderName::try_from(name).expect("ordinary header name")
}

fn owner_request(method: Method, uri: Uri, body: Body) -> OwnerRequest<Body> {
    let mut req = OwnerRequest::new(body);
    *req.method_mut() = method;
    *req.uri_mut() = uri;
    req
}

#[derive(Clone)]
pub struct HttpCacheBackend {
    endpoint: String,
    timeout: Duration,
    max_object_bytes: usize,
    auth_header: Option<(http::HeaderName, http::HeaderValue)>,
    user_agent: Option<http::HeaderValue>,
    idle: Arc<AsyncMutex<Vec<Http1SendRequest>>>,
    active: Arc<Semaphore>,
}

impl HttpCacheBackend {
    pub fn new(cfg: CacheBackendConfig, generated_user_agent: Option<&str>) -> Result<Self> {
        let endpoint = cfg.endpoint.trim().trim_end_matches('/').to_string();
        if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
            return Err(anyhow!(
                "cache backend {} endpoint must be http(s)",
                cfg.name
            ));
        }

        let auth_header = if let Some(env) = cfg.auth_header_env.as_deref() {
            match std::env::var(env) {
                Ok(value) if !value.trim().is_empty() => Some((
                    http::HeaderName::from_static("authorization"),
                    http::HeaderValue::from_str(value.trim())?,
                )),
                _ => None,
            }
        } else {
            None
        };

        let user_agent = generated_user_agent
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(http::HeaderValue::from_str)
            .transpose()?;

        Ok(Self {
            endpoint,
            timeout: Duration::from_millis(cfg.timeout_ms),
            max_object_bytes: cfg.max_object_bytes,
            auth_header,
            user_agent,
            idle: Arc::new(AsyncMutex::new(Vec::new())),
            active: Arc::new(Semaphore::new(HTTP_CACHE_MAX_ACTIVE_OPERATIONS)),
        })
    }

    fn object_uri(&self, namespace: &str, key: &str) -> Result<Uri> {
        let uri = format!("{}/v1/cache/{}/{}", self.endpoint, namespace, key);
        Ok(uri.parse()?)
    }

    fn batch_get_uri(&self, namespace: &str) -> Result<Uri> {
        let uri = format!("{}/v1/cache/{}/_batch_get", self.endpoint, namespace);
        Ok(uri.parse()?)
    }

    async fn open_sender(&self, scheme: &str, host: &str, port: u16) -> Result<Http1SendRequest> {
        let tcp = timeout(self.timeout, tokio::net::TcpStream::connect((host, port))).await??;
        match scheme {
            "http" => {
                let (sender, conn) = timeout(
                    self.timeout,
                    qpx_http::protocol::common::handshake_http1(tcp),
                )
                .await??;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                Ok(sender)
            }
            "https" => {
                let (tls, _cert) =
                    timeout(self.timeout, connect_client_http1(host, tcp, true, None)).await??;
                let (sender, conn) = timeout(
                    self.timeout,
                    qpx_http::protocol::common::handshake_http1(tls),
                )
                .await??;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                Ok(sender)
            }
            _ => Err(anyhow!("unsupported cache backend scheme: {}", scheme)),
        }
    }

    async fn checkout_sender(
        &self,
        scheme: &str,
        host: &str,
        port: u16,
    ) -> Result<Http1SendRequest> {
        // Idle pooled senders may have been closed by the peer while parked;
        // hyper reports those as "connection was not ready" at send time, so
        // validate before handing one out and fall through to a fresh dial.
        while let Some(mut sender) = self.idle.lock().await.pop() {
            if sender.is_closed() {
                continue;
            }
            match timeout(self.timeout, sender.ready()).await {
                Ok(Ok(())) => return Ok(sender),
                _ => continue,
            }
        }
        self.open_sender(scheme, host, port).await
    }

    /// Sends `req` on a pooled `sender`, retrying once with a fresh connection
    /// when the pooled sender rejects the request before dispatch.
    /// `try_send_request` recovers the request only in that pre-dispatch case,
    /// so a retry never replays a request that already reached the peer; this
    /// covers the race where the peer closes the connection between checkout
    /// and send, which `checkout_sender` validation cannot observe.
    async fn send_with_fresh_retry(
        &self,
        mut sender: Http1SendRequest,
        req: OwnerRequest<Body>,
        scheme: &str,
        host: &str,
        port: u16,
    ) -> Result<(hyper::Response<hyper::body::Incoming>, Http1SendRequest)> {
        let req = req
            .into_http_for_codec()
            .map_err(|err| anyhow!("cache backend request framing invalid: {err}"))?;
        match timeout(self.timeout, sender.try_send_request(req)).await? {
            Ok(resp) => Ok((resp, sender)),
            Err(mut err) => {
                let Some(req) = err.take_message() else {
                    return Err(err.into_error().into());
                };
                let mut fresh = self.open_sender(scheme, host, port).await?;
                let resp = timeout(self.timeout, fresh.send_request(req)).await??;
                Ok((resp, fresh))
            }
        }
    }

    async fn recycle_sender(&self, sender: Http1SendRequest) {
        recycle_sender(self.idle.clone(), sender).await;
    }

    async fn send_collect(
        &self,
        mut req: OwnerRequest<Body>,
    ) -> Result<(StatusCode, bytes::Bytes)> {
        let _permit = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("http cache backend operation limiter closed"))?;
        let uri = req.uri().clone();
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| anyhow!("cache backend request missing scheme"))?;
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow!("cache backend request missing authority"))?
            .to_string();
        let authority_parsed: http::uri::Authority = authority.parse()?;
        let host = authority_parsed.host();
        let port = authority_parsed.port_u16().unwrap_or(match scheme {
            "https" => 443,
            _ => 80,
        });

        let origin = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        *req.uri_mut() = Uri::builder().path_and_query(origin).build()?;
        *req.version_mut() = http::Version::HTTP_11;
        if !req.headers().contains_key(&ord("host")) {
            req.headers_mut().insert(
                ord("host"),
                http::HeaderValue::from_str(authority.as_str())?,
            );
        }

        let sender = self.checkout_sender(scheme, host, port).await?;
        let (resp, sender) = self
            .send_with_fresh_retry(sender, req, scheme, host, port)
            .await?;
        let status = resp.status();
        let max_body_bytes = if status == StatusCode::OK {
            self.max_object_bytes
        } else {
            self.max_object_bytes.min(64 * 1024)
        };
        if let Some(length) = declared_response_length(resp.headers())
            && length > max_body_bytes as u64
        {
            return Err(anyhow!(
                "http cache backend response payload too large: {} > {}",
                length,
                max_body_bytes
            ));
        }
        let body = timeout(
            self.timeout,
            collect_body_limited(resp.map(Body::from).into_body(), max_body_bytes),
        )
        .await??;
        self.recycle_sender(sender).await;
        Ok((status, body))
    }

    async fn send_collect_object(
        &self,
        mut req: OwnerRequest<Body>,
    ) -> Result<(StatusCode, CachedBody)> {
        let _permit = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("http cache backend operation limiter closed"))?;
        let uri = req.uri().clone();
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| anyhow!("cache backend request missing scheme"))?;
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow!("cache backend request missing authority"))?
            .to_string();
        let authority_parsed: http::uri::Authority = authority.parse()?;
        let host = authority_parsed.host();
        let port = authority_parsed.port_u16().unwrap_or(match scheme {
            "https" => 443,
            _ => 80,
        });

        let origin = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        *req.uri_mut() = Uri::builder().path_and_query(origin).build()?;
        *req.version_mut() = http::Version::HTTP_11;
        if !req.headers().contains_key(&ord("host")) {
            req.headers_mut().insert(
                ord("host"),
                http::HeaderValue::from_str(authority.as_str())?,
            );
        }

        let sender = self.checkout_sender(scheme, host, port).await?;
        let (resp, sender) = self
            .send_with_fresh_retry(sender, req, scheme, host, port)
            .await?;
        let status = resp.status();
        let max_body_bytes = if status == StatusCode::OK {
            self.max_object_bytes
        } else {
            self.max_object_bytes.min(64 * 1024)
        };
        if let Some(length) = declared_response_length(resp.headers())
            && length > max_body_bytes as u64
        {
            return Err(anyhow!(
                "http cache backend response payload too large: {} > {}",
                length,
                max_body_bytes
            ));
        }
        let body = CachedBody::from_body_limited(
            resp.map(Body::from).into_body(),
            max_body_bytes,
            self.timeout,
        )
        .await?;
        self.recycle_sender(sender).await;
        Ok((status, body))
    }

    async fn send_status(&self, req: OwnerRequest<Body>) -> Result<StatusCode> {
        let (status, _) = self.send_collect(req).await?;
        Ok(status)
    }

    fn apply_common_headers(&self, req: &mut OwnerRequest<Body>) {
        if let Some((name, value)) = &self.auth_header
            && let Ok(ordinary) = OrdinaryHeaderName::try_from(name.clone())
        {
            req.headers_mut().insert(ordinary, value.clone());
        }
        if let Some(value) = &self.user_agent {
            req.headers_mut().insert(ord("user-agent"), value.clone());
        }
    }
}

#[derive(Serialize)]
struct BatchGetRequest<'a> {
    keys: &'a [String],
}

#[derive(Deserialize)]
struct BatchGetResponse {
    values: Vec<Option<String>>,
}

/// The length the cached response declares, read through the owner.
///
/// The declaration is read the way every other site reads it: a comma list
/// of equal members is one length, and a declaration the owner refuses - a
/// value that is not text, a member that is not a `1*DIGIT` sequence, or two
/// members that disagree - declares no length. A response that declares no
/// length is not measured against the cache's limits; the body is bounded by
/// the streaming limit instead, so the size check here is a fast path and not
/// the limit itself.
fn declared_response_length(headers: &http::HeaderMap) -> Option<u64> {
    qpx_core::http_content_length::declared_content_length(headers)
        .ok()
        .flatten()
}

async fn recycle_sender(idle: Arc<AsyncMutex<Vec<Http1SendRequest>>>, sender: Http1SendRequest) {
    if sender.is_closed() {
        return;
    }
    let mut idle = idle.lock().await;
    if idle.len() < HTTP_CACHE_MAX_IDLE_CONNECTIONS {
        idle.push(sender);
    }
}

#[async_trait]
impl CacheBackend for HttpCacheBackend {
    async fn get(&self, namespace: &str, key: &str) -> Result<Option<bytes::Bytes>> {
        let uri = self.object_uri(namespace, key)?;
        let mut req = owner_request(Method::GET, uri, Body::empty());
        self.apply_common_headers(&mut req);

        let (status, body) = self.send_collect(req).await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if status != StatusCode::OK {
            return Err(anyhow!("http cache get failed with status {}", status));
        }
        Ok(Some(body))
    }

    async fn get_many(
        &self,
        namespace: &str,
        keys: &[String],
    ) -> Result<Vec<Option<bytes::Bytes>>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let uri = self.batch_get_uri(namespace)?;
        let payload = serde_json::to_vec(&BatchGetRequest { keys })?;
        let payload_len = payload.len() as u64;
        let mut req = owner_request(Method::POST, uri, Body::from(payload));
        req.headers_mut().insert(
            ord("content-type"),
            http::HeaderValue::from_static("application/json"),
        );
        req.headers_mut().set_content_length(payload_len);
        self.apply_common_headers(&mut req);
        let (status, body) = self.send_collect(req).await?;
        if status != StatusCode::OK {
            return Err(anyhow!(
                "http cache batch get failed with status {}; backend must implement POST /v1/cache/{{namespace}}/_batch_get",
                status
            ));
        }
        let response: BatchGetResponse = serde_json::from_slice(body.as_ref())?;
        if response.values.len() != keys.len() {
            return Err(anyhow!(
                "http cache batch get returned {} values for {} keys",
                response.values.len(),
                keys.len()
            ));
        }
        response
            .values
            .into_iter()
            .map(|value| {
                value
                    .map(|encoded| BASE64.decode(encoded.as_bytes()).map(bytes::Bytes::from))
                    .transpose()
                    .map_err(Into::into)
            })
            .collect()
    }

    async fn get_object(&self, namespace: &str, key: &str) -> Result<Option<CachedBody>> {
        let uri = self.object_uri(namespace, key)?;
        let mut req = owner_request(Method::GET, uri, Body::empty());
        self.apply_common_headers(&mut req);

        let (status, body) = self.send_collect_object(req).await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if status != StatusCode::OK {
            return Err(anyhow!("http cache get failed with status {}", status));
        }
        Ok(Some(body))
    }

    async fn get_object_stream(
        &self,
        namespace: &str,
        key: &str,
        expected_len: u64,
        range: Option<(u64, u64)>,
    ) -> Result<Option<super::types::CachedBodyStream>> {
        let _permit = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("http cache backend operation limiter closed"))?;
        let uri = self.object_uri(namespace, key)?;
        let mut req = owner_request(Method::GET, uri, Body::empty());
        if let Some((start, end)) = range {
            req.headers_mut().insert(
                ord("range"),
                http::HeaderValue::from_str(format!("bytes={start}-{end}").as_str())?,
            );
        }
        self.apply_common_headers(&mut req);

        let uri = req.uri().clone();
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| anyhow!("cache backend request missing scheme"))?;
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow!("cache backend request missing authority"))?
            .to_string();
        let authority_parsed: http::uri::Authority = authority.parse()?;
        let host = authority_parsed.host();
        let port = authority_parsed.port_u16().unwrap_or(match scheme {
            "https" => 443,
            _ => 80,
        });
        let origin = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        *req.uri_mut() = Uri::builder().path_and_query(origin).build()?;
        *req.version_mut() = http::Version::HTTP_11;
        if !req.headers().contains_key(&ord("host")) {
            req.headers_mut().insert(
                ord("host"),
                http::HeaderValue::from_str(authority.as_str())?,
            );
        }

        let sender = self.checkout_sender(scheme, host, port).await?;
        let (resp, sender) = self
            .send_with_fresh_retry(sender, req, scheme, host, port)
            .await?;
        let expected_status = if range.is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        };
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if resp.status() != expected_status {
            return Err(anyhow!(
                "http cache get failed with status {}",
                resp.status()
            ));
        }
        let expected_body_len = range
            .map(|(start, end)| end.saturating_sub(start).saturating_add(1))
            .unwrap_or(expected_len);
        if let Some(length) = declared_response_length(resp.headers())
            && length != expected_body_len
        {
            return Ok(None);
        }
        let (mut tx, body) = Body::channel_with_capacity(16);
        let timeout_dur = self.timeout;
        let idle = self.idle.clone();
        tokio::spawn(async move {
            let mut body = resp.map(Body::from).into_body();
            let mut seen = 0u64;
            let result = async {
                while let Some(chunk) = timeout(timeout_dur, body.data()).await? {
                    let chunk = chunk?;
                    seen = seen
                        .checked_add(chunk.len() as u64)
                        .ok_or_else(|| anyhow!("http cache object length overflow"))?;
                    if seen > expected_body_len {
                        return Err(anyhow!("http cache object exceeded expected length"));
                    }
                    if tx.send_data(chunk).await.is_err() {
                        return Err(anyhow!("http cache body consumer closed"));
                    }
                }
                if seen != expected_body_len {
                    return Err(anyhow!("http cache object length mismatch"));
                }
                Ok(sender)
            }
            .await;
            match result {
                Ok(sender) => recycle_sender(idle, sender).await,
                Err(_) => tx.abort(),
            }
            drop(_permit);
        });
        Ok(Some(super::types::CachedBodyStream {
            len: expected_body_len,
            body,
        }))
    }

    async fn put(&self, namespace: &str, key: &str, value: &[u8], ttl_secs: u64) -> Result<()> {
        if value.len() > self.max_object_bytes {
            return Err(anyhow!(
                "http cache put payload too large: {} > {}",
                value.len(),
                self.max_object_bytes
            ));
        }
        let uri = self.object_uri(namespace, key)?;
        let mut req = owner_request(Method::PUT, uri, Body::from(value.to_vec()));
        req.headers_mut().insert(
            ord("content-type"),
            http::HeaderValue::from_static("application/octet-stream"),
        );
        req.headers_mut().insert(
            ord("x-qpx-ttl-secs"),
            http::HeaderValue::from_str(ttl_secs.to_string().as_str())?,
        );
        self.apply_common_headers(&mut req);

        let status = self.send_status(req).await?;
        if status != StatusCode::OK && status != StatusCode::CREATED {
            return Err(anyhow!("http cache put failed with status {}", status));
        }
        Ok(())
    }

    async fn put_object(
        &self,
        namespace: &str,
        key: &str,
        body: &CachedBody,
        ttl_secs: u64,
    ) -> Result<()> {
        if body.len() > self.max_object_bytes as u64 {
            return Err(anyhow!(
                "http cache put payload too large: {} > {}",
                body.len(),
                self.max_object_bytes
            ));
        }
        let uri = self.object_uri(namespace, key)?;
        let mut req = owner_request(Method::PUT, uri, body.to_body());
        req.headers_mut().insert(
            ord("content-type"),
            http::HeaderValue::from_static("application/octet-stream"),
        );
        req.headers_mut().set_content_length(body.len());
        req.headers_mut().insert(
            ord("x-qpx-ttl-secs"),
            http::HeaderValue::from_str(ttl_secs.to_string().as_str())?,
        );
        self.apply_common_headers(&mut req);

        let status = self.send_status(req).await?;
        if status != StatusCode::OK && status != StatusCode::CREATED {
            return Err(anyhow!("http cache put failed with status {}", status));
        }
        Ok(())
    }

    async fn put_object_stream(
        &self,
        namespace: &str,
        key: &str,
        body: Body,
        max_body_bytes: usize,
        body_read_timeout: Duration,
        ttl_secs: u64,
    ) -> Result<u64> {
        let (body, byte_count) = bounded_cache_body_stream(
            body,
            max_body_bytes.min(self.max_object_bytes),
            body_read_timeout,
        );
        let uri = self.object_uri(namespace, key)?;
        let mut req = owner_request(Method::PUT, uri, body);
        req.headers_mut().insert(
            ord("content-type"),
            http::HeaderValue::from_static("application/octet-stream"),
        );
        req.headers_mut().insert(
            ord("x-qpx-ttl-secs"),
            http::HeaderValue::from_str(ttl_secs.to_string().as_str())?,
        );
        self.apply_common_headers(&mut req);

        let status = self.send_status(req).await?;
        let len = byte_count
            .await
            .map_err(|_| anyhow!("cache body byte counter dropped"))??;
        if status != StatusCode::OK && status != StatusCode::CREATED {
            return Err(anyhow!("http cache put failed with status {}", status));
        }
        Ok(len)
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        let uri = self.object_uri(namespace, key)?;
        let mut req = owner_request(Method::DELETE, uri, Body::empty());
        self.apply_common_headers(&mut req);
        let status = self.send_status(req).await?;
        if status != StatusCode::OK
            && status != StatusCode::NO_CONTENT
            && status != StatusCode::NOT_FOUND
        {
            return Err(anyhow!("http cache delete failed with status {}", status));
        }
        Ok(())
    }
}

mod body;

use self::body::collect_body_limited;

#[cfg(test)]
mod tests;
