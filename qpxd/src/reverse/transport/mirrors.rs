use super::ReverseConnInfo;
use super::request_template::{ReverseRequestHeadTemplate, ReverseRequestTemplate};
use crate::reverse::health::{
    EndpointLifecycleRuntime, HealthCheckRuntime, PassiveFailureKind, UpstreamEndpoint,
};
use crate::reverse::router::{RoutePolicy, SelectedMirrorTarget};
use crate::upstream::origin::proxy_http;
use anyhow::Error;
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use hyper::{Request, StatusCode};
use qpx_core::tls::CompiledUpstreamTlsTrust;
use qpx_http::body::Body;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Duration, timeout};
use tracing::warn;

const MIRROR_MAX_INFLIGHT_PER_ENDPOINT: usize = 256;
static MIRROR_PERMITS: LazyLock<Mutex<HashMap<String, Arc<Semaphore>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(in crate::reverse) fn prune_mirror_permits(active_targets: &[String]) {
    let active = active_targets.iter().collect::<HashSet<_>>();
    let mut permits = MIRROR_PERMITS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    permits.retain(|target, _| active.contains(target));
}

pub(super) fn request_seed(conn: &ReverseConnInfo, host: &str, req: &Request<Body>) -> u64 {
    // Deterministic hashing for stable canary/mirror sampling.
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;

    fn feed(mut hash: u64, bytes: &[u8]) -> u64 {
        for b in bytes {
            hash ^= *b as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }

    let mut hash = FNV_OFFSET;
    match conn.remote_addr.ip() {
        std::net::IpAddr::V4(ip) => {
            hash = feed(hash, &ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            hash = feed(hash, &ip.octets());
        }
    }
    hash = feed(hash, host.as_bytes());
    hash = feed(hash, req.method().as_str().as_bytes());
    if let Some(pq) = req.uri().path_and_query() {
        hash = feed(hash, pq.as_str().as_bytes());
    } else {
        hash = feed(hash, b"/");
    }
    hash
}

pub(super) fn record_reverse_upstream_status(
    upstream: &UpstreamEndpoint,
    policy: &RoutePolicy,
    status: StatusCode,
    elapsed: Duration,
) {
    let Some(passive) = policy.passive_health.as_ref() else {
        if status.is_server_error() {
            upstream.mark_failure(&policy.health);
        } else {
            policy.retry_budget.record_success();
            upstream.mark_success(&policy.lifecycle);
        }
        return;
    };
    if status.is_server_error() {
        upstream.mark_passive_failure(Some(passive), PassiveFailureKind::Http5xx);
        return;
    }
    policy.retry_budget.record_success();
    upstream.mark_passive_success(&policy.lifecycle);
    upstream.mark_passive_latency(Some(passive), elapsed);
}

pub(super) fn record_reverse_upstream_error(
    upstream: &UpstreamEndpoint,
    policy: &RoutePolicy,
    err: &Error,
) {
    let Some(passive) = policy.passive_health.as_ref() else {
        upstream.mark_failure(&policy.health);
        return;
    };
    let err_text = err.to_string().to_ascii_lowercase();
    let kind = if err_text.contains("reset") {
        PassiveFailureKind::Reset
    } else {
        PassiveFailureKind::ConnectError
    };
    upstream.mark_passive_failure(Some(passive), kind);
}

pub(super) fn record_reverse_upstream_timeout(upstream: &UpstreamEndpoint, policy: &RoutePolicy) {
    if policy.passive_health.is_some() {
        upstream.mark_passive_failure(policy.passive_health.as_ref(), PassiveFailureKind::Timeout);
    } else {
        upstream.mark_failure(&policy.health);
    }
}

pub(super) fn request_is_templateable(req: &Request<Body>, max_body_bytes: usize) -> bool {
    // We only attempt to clone/mirror requests that can be safely buffered.
    if req.headers().contains_key(TRANSFER_ENCODING) {
        return false;
    }
    let values = req.headers().get_all(CONTENT_LENGTH);
    let mut parsed = Vec::new();
    for value in values {
        let Ok(raw) = value.to_str() else {
            return false;
        };
        let Ok(len) = raw.trim().parse::<u64>() else {
            return false;
        };
        parsed.push(len);
    }
    if parsed.is_empty() {
        // HTTP/1.1 without Content-Length/Transfer-Encoding cannot have a body.
        return req.version() == http::Version::HTTP_11;
    }
    if parsed.iter().any(|l| *l != parsed[0]) {
        return false;
    }
    (parsed[0] as usize) <= max_body_bytes
}

#[expect(
    clippy::too_many_arguments,
    reason = "mirror dispatch threads each routing/health dimension plus the pool registry"
)]
pub(super) fn dispatch_mirrors(
    pools: Arc<crate::pool::PoolRegistry>,
    template: &ReverseRequestTemplate,
    mirror_upstreams: Vec<SelectedMirrorTarget>,
    timeout_dur: Duration,
    health_policy: HealthCheckRuntime,
    lifecycle: EndpointLifecycleRuntime,
    upstream_trust: Option<Arc<CompiledUpstreamTlsTrust>>,
    proxy_name: &str,
) {
    if mirror_upstreams.is_empty() {
        return;
    }
    let proxy_name = proxy_name.to_string();
    for mirror in mirror_upstreams {
        let upstream = mirror.upstream;
        let req = match template.build() {
            Ok(req) => req,
            Err(err) => {
                warn!(error = ?err, "reverse mirror build failed");
                continue;
            }
        };
        upstream.inflight.fetch_add(1, Ordering::Relaxed);
        let Some(_mirror_permit) = try_acquire_mirror_permit(upstream.as_ref()) else {
            upstream.inflight.fetch_sub(1, Ordering::Relaxed);
            continue;
        };
        let upstream_for_task = upstream.clone();
        let target = upstream.origin.clone();
        let proxy_name = proxy_name.clone();
        let health_policy = health_policy.clone();
        let lifecycle = lifecycle.clone();
        let upstream_trust = upstream_trust.clone();
        let pools = pools.clone();
        tokio::spawn(async move {
            let _mirror_permit = _mirror_permit;
            let response = timeout(
                timeout_dur,
                proxy_http(
                    &pools,
                    req,
                    &target,
                    proxy_name.as_str(),
                    upstream_trust.as_deref(),
                ),
            )
            .await;
            upstream_for_task.inflight.fetch_sub(1, Ordering::Relaxed);
            match response {
                Ok(Ok(_)) => upstream_for_task.mark_success(&lifecycle),
                Ok(Err(_)) | Err(_) => upstream_for_task.mark_failure(&health_policy),
            }
        });
    }
}

pub(super) fn dispatch_streaming_mirrors(input: StreamingMirrorDispatch<'_>) {
    let StreamingMirrorDispatch {
        pools,
        template,
        mirror_upstreams,
        mirror_bodies,
        timeout_dur,
        health_policy,
        lifecycle,
        upstream_trust,
        proxy_name,
    } = input;
    if mirror_upstreams.is_empty() {
        return;
    }
    let proxy_name = proxy_name.to_string();
    for (mirror, body) in mirror_upstreams.into_iter().zip(mirror_bodies) {
        let req = match template.build_with_body(body) {
            Ok(req) => req,
            Err(err) => {
                warn!(error = ?err, "reverse streaming mirror build failed");
                continue;
            }
        };
        let upstream = mirror.upstream;
        upstream.inflight.fetch_add(1, Ordering::Relaxed);
        let Some(_mirror_permit) = try_acquire_mirror_permit(upstream.as_ref()) else {
            upstream.inflight.fetch_sub(1, Ordering::Relaxed);
            continue;
        };
        let upstream_for_task = upstream.clone();
        let target = upstream.origin.clone();
        let proxy_name = proxy_name.clone();
        let health_policy = health_policy.clone();
        let lifecycle = lifecycle.clone();
        let upstream_trust = upstream_trust.clone();
        let pools = pools.clone();
        tokio::spawn(async move {
            let _mirror_permit = _mirror_permit;
            let response = timeout(
                timeout_dur,
                proxy_http(
                    &pools,
                    req,
                    &target,
                    proxy_name.as_str(),
                    upstream_trust.as_deref(),
                ),
            )
            .await;
            upstream_for_task.inflight.fetch_sub(1, Ordering::Relaxed);
            match response {
                Ok(Ok(_)) => upstream_for_task.mark_success(&lifecycle),
                Ok(Err(_)) | Err(_) => upstream_for_task.mark_failure(&health_policy),
            }
        });
    }
}

fn try_acquire_mirror_permit(upstream: &UpstreamEndpoint) -> Option<OwnedSemaphorePermit> {
    let semaphore = {
        let mut permits = MIRROR_PERMITS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        permits
            .entry(upstream.target.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(MIRROR_MAX_INFLIGHT_PER_ENDPOINT)))
            .clone()
    };
    match semaphore.try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(err) => {
            super::metrics::mirror_dropped(upstream.target.as_str(), "inflight_limit");
            warn!(
                error = ?err,
                target = upstream.target.as_str(),
                "reverse mirror dropped because endpoint mirror concurrency is full"
            );
            None
        }
    }
}

pub(super) struct StreamingMirrorDispatch<'a> {
    pub(super) pools: Arc<crate::pool::PoolRegistry>,
    pub(super) template: ReverseRequestHeadTemplate,
    pub(super) mirror_upstreams: Vec<SelectedMirrorTarget>,
    pub(super) mirror_bodies: Vec<Body>,
    pub(super) timeout_dur: Duration,
    pub(super) health_policy: HealthCheckRuntime,
    pub(super) lifecycle: EndpointLifecycleRuntime,
    pub(super) upstream_trust: Option<Arc<CompiledUpstreamTlsTrust>>,
    pub(super) proxy_name: &'a str,
}
