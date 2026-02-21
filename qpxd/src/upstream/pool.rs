use crate::upstream::http1::{
    open_upstream_proxy_sender as open_proxy_sender_once, parse_upstream_proxy_endpoint,
    UpstreamProxyEndpoint,
};
use anyhow::{anyhow, Result};
use http::header::PROXY_AUTHORIZATION;
use hyper::{Body, Request, Response};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

type UpstreamProxySender = hyper::client::conn::SendRequest<Body>;
type UpstreamProxySlot = Arc<Mutex<Option<UpstreamProxySender>>>;
type UpstreamProxyMap = HashMap<String, UpstreamProxySlot>;
type UpstreamProxyPool = Arc<Mutex<UpstreamProxyMap>>;

fn upstream_proxy_pool() -> &'static UpstreamProxyPool {
    static POOL: OnceLock<UpstreamProxyPool> = OnceLock::new();
    POOL.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

pub async fn send_via_upstream_proxy(
    mut req: Request<Body>,
    upstream: &str,
    timeout_dur: Duration,
) -> Result<Response<Body>> {
    let endpoint = parse_upstream_proxy_endpoint(upstream)?;
    req.headers_mut().remove(PROXY_AUTHORIZATION);
    if let Some(value) = endpoint.proxy_authorization.as_ref() {
        req.headers_mut().insert(PROXY_AUTHORIZATION, value.clone());
    }
    let pool_key = endpoint.cache_key();

    let slot = {
        let pool = upstream_proxy_pool();
        let mut guard = pool.lock().await;
        guard
            .entry(pool_key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone()
    };

    let mut sender_guard = slot.lock().await;
    if sender_guard.is_none() {
        *sender_guard = Some(open_upstream_proxy_sender(&endpoint, timeout_dur).await?);
    }

    let sender = sender_guard
        .as_mut()
        .ok_or_else(|| anyhow!("upstream proxy sender unavailable"))?;
    match timeout(timeout_dur, sender.send_request(req)).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(err)) => {
            *sender_guard = None;
            Err(err.into())
        }
        Err(_) => {
            *sender_guard = None;
            Err(anyhow!("upstream proxy request timed out"))
        }
    }
}

async fn open_upstream_proxy_sender(
    endpoint: &UpstreamProxyEndpoint,
    timeout_dur: Duration,
) -> Result<UpstreamProxySender> {
    open_proxy_sender_once(endpoint, Some(timeout_dur), "upstream proxy pooled").await
}
