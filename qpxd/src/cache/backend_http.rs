use super::CacheBackend;
use crate::tls::client::connect_tls_http1;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use hyper::body::HttpBody as _;
use hyper::header::HOST;
use hyper::{Body, Method, Request, StatusCode, Uri};
use qpx_core::config::CacheBackendConfig;
use std::time::Duration;
use tokio::time::timeout;

pub(super) struct HttpCacheBackend {
    endpoint: String,
    timeout: Duration,
    max_object_bytes: usize,
    auth_header: Option<(http::HeaderName, http::HeaderValue)>,
    user_agent: Option<http::HeaderValue>,
}

impl HttpCacheBackend {
    pub(super) fn new(cfg: CacheBackendConfig, generated_user_agent: Option<&str>) -> Result<Self> {
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
        })
    }

    fn object_uri(&self, namespace: &str, key: &str) -> Result<Uri> {
        let uri = format!("{}/v1/cache/{}/{}", self.endpoint, namespace, key);
        Ok(uri.parse()?)
    }

    async fn send(&self, mut req: Request<Body>) -> Result<hyper::Response<Body>> {
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
        if !req.headers().contains_key(HOST) {
            req.headers_mut()
                .insert(HOST, http::HeaderValue::from_str(authority.as_str())?);
        }

        let tcp = timeout(self.timeout, tokio::net::TcpStream::connect((host, port))).await??;
        match scheme {
            "http" => {
                let (mut sender, conn) = timeout(
                    self.timeout,
                    hyper::client::conn::Builder::new().handshake(tcp),
                )
                .await??;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                Ok(timeout(self.timeout, sender.send_request(req)).await??)
            }
            "https" => {
                let tls = timeout(self.timeout, connect_tls_http1(host, tcp)).await??;
                let (mut sender, conn) = timeout(
                    self.timeout,
                    hyper::client::conn::Builder::new().handshake(tls),
                )
                .await??;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                Ok(timeout(self.timeout, sender.send_request(req)).await??)
            }
            _ => Err(anyhow!("unsupported cache backend scheme: {}", scheme)),
        }
    }
}

#[async_trait]
impl CacheBackend for HttpCacheBackend {
    async fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let uri = self.object_uri(namespace, key)?;
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())?;
        if let Some((name, value)) = &self.auth_header {
            req.headers_mut().insert(name, value.clone());
        }
        if let Some(value) = &self.user_agent {
            req.headers_mut()
                .insert(http::header::USER_AGENT, value.clone());
        }

        let resp = self.send(req).await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if resp.status() != StatusCode::OK {
            return Err(anyhow!(
                "http cache get failed with status {}",
                resp.status()
            ));
        }
        if let Some(length) = resp
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<usize>().ok())
        {
            if length > self.max_object_bytes {
                return Err(anyhow!(
                    "http cache get payload too large: {} > {}",
                    length,
                    self.max_object_bytes
                ));
            }
        }
        let body = timeout(
            self.timeout,
            collect_body_limited(resp.into_body(), self.max_object_bytes),
        )
        .await??;
        Ok(Some(body.to_vec()))
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
        let mut req = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header("content-type", "application/octet-stream")
            .header("x-qpx-ttl-secs", ttl_secs.to_string())
            .body(Body::from(value.to_vec()))?;
        if let Some((name, value)) = &self.auth_header {
            req.headers_mut().insert(name, value.clone());
        }
        if let Some(value) = &self.user_agent {
            req.headers_mut()
                .insert(http::header::USER_AGENT, value.clone());
        }

        let resp = self.send(req).await?;
        if resp.status() != StatusCode::OK && resp.status() != StatusCode::CREATED {
            return Err(anyhow!(
                "http cache put failed with status {}",
                resp.status()
            ));
        }
        Ok(())
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        let uri = self.object_uri(namespace, key)?;
        let mut req = Request::builder()
            .method(Method::DELETE)
            .uri(uri)
            .body(Body::empty())?;
        if let Some((name, value)) = &self.auth_header {
            req.headers_mut().insert(name, value.clone());
        }
        if let Some(value) = &self.user_agent {
            req.headers_mut()
                .insert(http::header::USER_AGENT, value.clone());
        }
        let resp = self.send(req).await?;
        if resp.status() != StatusCode::OK
            && resp.status() != StatusCode::NO_CONTENT
            && resp.status() != StatusCode::NOT_FOUND
        {
            return Err(anyhow!(
                "http cache delete failed with status {}",
                resp.status()
            ));
        }
        Ok(())
    }
}

async fn collect_body_limited(mut body: Body, max_bytes: usize) -> Result<bytes::Bytes> {
    let mut out = BytesMut::new();
    while let Some(frame) = body.data().await {
        let chunk = frame?;
        let next = out
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("http cache get body length overflow"))?;
        if next > max_bytes {
            return Err(anyhow!(
                "http cache get payload too large: {} > {}",
                next,
                max_bytes
            ));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn collect_body_limited_rejects_large_payload() {
        let err = collect_body_limited(Body::from(vec![0_u8; 5]), 4)
            .await
            .expect_err("must fail");
        assert!(err.to_string().contains("payload too large"));
    }
}
