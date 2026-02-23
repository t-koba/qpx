use crate::upstream::http1::{
    open_upstream_proxy_sender as open_proxy_sender_once, parse_upstream_proxy_endpoint,
    UpstreamProxyEndpoint,
};
use anyhow::{anyhow, Result};
use http::header::PROXY_AUTHORIZATION;
use hyper::{Body, Request, Response};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{timeout, Duration};

type UpstreamProxySender = hyper::client::conn::SendRequest<Body>;

static UPSTREAM_PROXY_MAX_CONCURRENT_PER_ENDPOINT: AtomicUsize = AtomicUsize::new(8);

pub(crate) fn set_upstream_proxy_max_concurrent_per_endpoint(value: usize) {
    UPSTREAM_PROXY_MAX_CONCURRENT_PER_ENDPOINT.store(value.max(1), Ordering::Relaxed);
}

fn upstream_proxy_max_concurrent_per_endpoint() -> usize {
    UPSTREAM_PROXY_MAX_CONCURRENT_PER_ENDPOINT
        .load(Ordering::Relaxed)
        .max(1)
}

struct UpstreamProxySlot {
    senders: Mutex<Vec<UpstreamProxySender>>,
    semaphore: Arc<Semaphore>,
}

type UpstreamProxySlotHandle = Arc<UpstreamProxySlot>;
type UpstreamProxyMap = HashMap<String, UpstreamProxySlotHandle>;
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
            .or_insert_with(|| {
                Arc::new(UpstreamProxySlot {
                    senders: Mutex::new(Vec::new()),
                    semaphore: Arc::new(Semaphore::new(
                        upstream_proxy_max_concurrent_per_endpoint(),
                    )),
                })
            })
            .clone()
    };

    let _permit = slot
        .semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| anyhow!("upstream proxy concurrency limiter closed"))?;

    let sender = { slot.senders.lock().await.pop() };
    let mut sender = match sender {
        Some(sender) => sender,
        None => open_upstream_proxy_sender(&endpoint, timeout_dur).await?,
    };

    match timeout(timeout_dur, sender.send_request(req)).await {
        Ok(Ok(response)) => {
            slot.senders.lock().await.push(sender);
            Ok(response)
        }
        Ok(Err(err)) => Err(err.into()),
        Err(_) => Err(anyhow!("upstream proxy request timed out")),
    }
}

async fn open_upstream_proxy_sender(
    endpoint: &UpstreamProxyEndpoint,
    timeout_dur: Duration,
) -> Result<UpstreamProxySender> {
    open_proxy_sender_once(endpoint, Some(timeout_dur), "upstream proxy pooled").await
}
