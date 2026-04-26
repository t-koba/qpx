use super::{LoadBalanceStrategy, RoutePolicy};
use crate::http::body::Body;
use hyper::Request;
use ring::rand::{SecureRandom, SystemRandom};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::reverse::health::{now_millis, EndpointLifecycleRuntime, UpstreamEndpoint};

pub(super) fn select_upstream_inner(
    upstreams: &[Arc<UpstreamEndpoint>],
    policy: &RoutePolicy,
    rr_counter: &AtomicUsize,
    request_seed: u64,
    sticky_seed: u64,
) -> Option<Arc<UpstreamEndpoint>> {
    if upstreams.is_empty() {
        return None;
    }
    let now_ms = now_millis();
    let gate_seed = request_seed ^ sticky_seed;
    let counts = count_candidates(upstreams, policy, now_ms, gate_seed);
    if counts.eligible == 0 {
        return None;
    }
    let scope = selection_scope(counts);
    let effective_len = scope_len(counts, scope);

    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;
    let rendezvous = |seed: u64| -> Arc<UpstreamEndpoint> {
        let mut best = None;
        for u in upstreams {
            if !endpoint_selected(u, policy, now_ms, gate_seed, scope) {
                continue;
            }
            let mut hash = seed ^ FNV_OFFSET;
            for b in u.target.as_bytes() {
                hash ^= *b as u64;
                hash = hash.wrapping_mul(FNV_PRIME);
            }
            match best {
                Some((_, score)) if score >= hash => {}
                _ => {
                    best = Some((u.clone(), hash));
                }
            }
        }
        best.map(|(u, _)| u).unwrap_or_else(|| upstreams[0].clone())
    };

    let selected = match policy.lb {
        LoadBalanceStrategy::RoundRobin => {
            let idx = rr_counter.fetch_add(1, Ordering::Relaxed) % effective_len;
            nth_endpoint(upstreams, policy, now_ms, gate_seed, scope, counts, idx)
                .unwrap_or_else(|| upstreams[0].clone())
        }
        LoadBalanceStrategy::Random => {
            let idx = secure_random_index(effective_len);
            nth_endpoint(upstreams, policy, now_ms, gate_seed, scope, counts, idx)
                .unwrap_or_else(|| upstreams[0].clone())
        }
        LoadBalanceStrategy::LeastConnections => upstreams
            .iter()
            .filter(|endpoint| endpoint_selected(endpoint, policy, now_ms, gate_seed, scope))
            .min_by_key(|u| u.inflight.load(Ordering::Relaxed))
            .cloned()
            .unwrap_or_else(|| upstreams[0].clone()),
        LoadBalanceStrategy::ConsistentHash => rendezvous(request_seed),
        LoadBalanceStrategy::Sticky => rendezvous(sticky_seed),
    };
    Some(selected)
}

fn secure_random_index(len: usize) -> usize {
    debug_assert!(len > 0);
    let mut bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("secure random upstream selection");
    (u64::from_ne_bytes(bytes) as usize) % len
}

#[derive(Clone, Copy, Debug)]
struct EndpointSelectionCounts {
    eligible: usize,
    ready: usize,
    admitted_ramping: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointCandidateClass {
    Ready,
    AdmittedRamping,
    EligibleOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointSelectionScope {
    Eligible,
    AdmittedOnly,
    ReadyThenAdmitted,
}

fn count_candidates(
    upstreams: &[Arc<UpstreamEndpoint>],
    policy: &RoutePolicy,
    now_ms: u64,
    gate_seed: u64,
) -> EndpointSelectionCounts {
    let mut counts = EndpointSelectionCounts {
        eligible: 0,
        ready: 0,
        admitted_ramping: 0,
    };
    for endpoint in upstreams {
        let Some(class) = classify_endpoint(endpoint, policy, now_ms, gate_seed) else {
            continue;
        };
        counts.eligible += 1;
        match class {
            EndpointCandidateClass::Ready => counts.ready += 1,
            EndpointCandidateClass::AdmittedRamping => counts.admitted_ramping += 1,
            EndpointCandidateClass::EligibleOnly => {}
        }
    }
    counts
}

fn classify_endpoint(
    endpoint: &UpstreamEndpoint,
    policy: &RoutePolicy,
    now_ms: u64,
    gate_seed: u64,
) -> Option<EndpointCandidateClass> {
    if !endpoint.is_healthy(now_ms)
        || (endpoint.is_half_open(now_ms) && endpoint.inflight.load(Ordering::Relaxed) != 0)
        || endpoint.is_draining()
        || policy
            .max_upstream_concurrency
            .is_some_and(|max| endpoint.inflight.load(Ordering::Relaxed) >= max)
    {
        return None;
    }

    Some(
        match endpoint_lifecycle_state(endpoint, &policy.lifecycle, now_ms) {
            EndpointLifecycleState::Ready => EndpointCandidateClass::Ready,
            EndpointLifecycleState::Ramping(progress) => {
                if slow_start_admits(endpoint, gate_seed, progress) {
                    EndpointCandidateClass::AdmittedRamping
                } else {
                    EndpointCandidateClass::EligibleOnly
                }
            }
            EndpointLifecycleState::Warming => EndpointCandidateClass::EligibleOnly,
        },
    )
}

fn selection_scope(counts: EndpointSelectionCounts) -> EndpointSelectionScope {
    if counts.ready > 0 {
        EndpointSelectionScope::ReadyThenAdmitted
    } else if counts.admitted_ramping > 0 {
        EndpointSelectionScope::AdmittedOnly
    } else {
        EndpointSelectionScope::Eligible
    }
}

fn scope_len(counts: EndpointSelectionCounts, scope: EndpointSelectionScope) -> usize {
    match scope {
        EndpointSelectionScope::Eligible => counts.eligible,
        EndpointSelectionScope::AdmittedOnly => counts.admitted_ramping,
        EndpointSelectionScope::ReadyThenAdmitted => counts.ready + counts.admitted_ramping,
    }
}

fn endpoint_selected(
    endpoint: &UpstreamEndpoint,
    policy: &RoutePolicy,
    now_ms: u64,
    gate_seed: u64,
    scope: EndpointSelectionScope,
) -> bool {
    let Some(class) = classify_endpoint(endpoint, policy, now_ms, gate_seed) else {
        return false;
    };
    match scope {
        EndpointSelectionScope::Eligible => true,
        EndpointSelectionScope::AdmittedOnly => class == EndpointCandidateClass::AdmittedRamping,
        EndpointSelectionScope::ReadyThenAdmitted => {
            matches!(
                class,
                EndpointCandidateClass::Ready | EndpointCandidateClass::AdmittedRamping
            )
        }
    }
}

fn nth_endpoint(
    upstreams: &[Arc<UpstreamEndpoint>],
    policy: &RoutePolicy,
    now_ms: u64,
    gate_seed: u64,
    scope: EndpointSelectionScope,
    counts: EndpointSelectionCounts,
    idx: usize,
) -> Option<Arc<UpstreamEndpoint>> {
    match scope {
        EndpointSelectionScope::Eligible => nth_endpoint_in_class(
            upstreams,
            policy,
            now_ms,
            gate_seed,
            EndpointSelectionScope::Eligible,
            idx,
        ),
        EndpointSelectionScope::AdmittedOnly => nth_endpoint_in_class(
            upstreams,
            policy,
            now_ms,
            gate_seed,
            EndpointSelectionScope::AdmittedOnly,
            idx,
        ),
        EndpointSelectionScope::ReadyThenAdmitted => {
            if idx < counts.ready {
                nth_endpoint_by_class(
                    upstreams,
                    policy,
                    now_ms,
                    gate_seed,
                    EndpointCandidateClass::Ready,
                    idx,
                )
            } else {
                nth_endpoint_by_class(
                    upstreams,
                    policy,
                    now_ms,
                    gate_seed,
                    EndpointCandidateClass::AdmittedRamping,
                    idx - counts.ready,
                )
            }
        }
    }
}

fn nth_endpoint_in_class(
    upstreams: &[Arc<UpstreamEndpoint>],
    policy: &RoutePolicy,
    now_ms: u64,
    gate_seed: u64,
    scope: EndpointSelectionScope,
    idx: usize,
) -> Option<Arc<UpstreamEndpoint>> {
    let mut seen = 0usize;
    for endpoint in upstreams {
        if endpoint_selected(endpoint, policy, now_ms, gate_seed, scope) {
            if seen == idx {
                return Some(endpoint.clone());
            }
            seen += 1;
        }
    }
    None
}

fn nth_endpoint_by_class(
    upstreams: &[Arc<UpstreamEndpoint>],
    policy: &RoutePolicy,
    now_ms: u64,
    gate_seed: u64,
    class: EndpointCandidateClass,
    idx: usize,
) -> Option<Arc<UpstreamEndpoint>> {
    let mut seen = 0usize;
    for endpoint in upstreams {
        if classify_endpoint(endpoint, policy, now_ms, gate_seed) == Some(class) {
            if seen == idx {
                return Some(endpoint.clone());
            }
            seen += 1;
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum EndpointLifecycleState {
    Ready,
    Ramping(f64),
    Warming,
}

pub(super) fn endpoint_lifecycle_state(
    endpoint: &UpstreamEndpoint,
    lifecycle: &EndpointLifecycleRuntime,
    now_ms: u64,
) -> EndpointLifecycleState {
    if !lifecycle.is_enabled() {
        return EndpointLifecycleState::Ready;
    }
    let warmup_until = endpoint.warmup_until_ms();
    if warmup_until > now_ms {
        return EndpointLifecycleState::Warming;
    }
    let Some(slow_start) = lifecycle.slow_start else {
        return EndpointLifecycleState::Ready;
    };
    let recovery_start = endpoint.recovery_start_ms();
    if recovery_start == 0 || recovery_start >= now_ms {
        return EndpointLifecycleState::Ready;
    }
    let elapsed_ms = now_ms.saturating_sub(recovery_start);
    let slow_start_ms = slow_start.as_millis() as u64;
    if elapsed_ms >= slow_start_ms {
        EndpointLifecycleState::Ready
    } else {
        EndpointLifecycleState::Ramping(elapsed_ms as f64 / slow_start_ms as f64)
    }
}

pub(super) fn slow_start_admits(endpoint: &UpstreamEndpoint, seed: u64, progress: f64) -> bool {
    let ratio = progress.clamp(0.0, 1.0);
    if ratio >= 1.0 {
        return true;
    }
    let bucket = feed(seed ^ fnv_offset(), endpoint.target.as_bytes()) % 10_000;
    bucket < (ratio * 10_000.0) as u64
}

pub(super) fn fnv_offset() -> u64 {
    14695981039346656037
}

pub(super) fn feed(mut hash: u64, bytes: &[u8]) -> u64 {
    const FNV_PRIME: u64 = 1099511628211;
    for b in bytes {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

pub(super) fn feed_ip(hash: u64, ip: IpAddr) -> u64 {
    match ip {
        IpAddr::V4(ip) => feed(hash, &ip.octets()),
        IpAddr::V6(ip) => feed(hash, &ip.octets()),
    }
}

pub(super) fn header_affinity_seed(
    hash: u64,
    req: &Request<Body>,
    name: &str,
    fallback: &str,
) -> u64 {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| feed(hash, value.as_bytes()))
        .unwrap_or_else(|| feed(hash, fallback.as_bytes()))
}

pub(super) fn cookie_affinity_seed(
    hash: u64,
    req: &Request<Body>,
    name: &str,
    fallback: &str,
) -> u64 {
    let cookie = req
        .headers()
        .get(http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(';').find_map(|part| {
                let (cookie_name, cookie_value) = part.trim().split_once('=')?;
                (cookie_name.trim() == name)
                    .then_some(cookie_value.trim())
                    .filter(|value| !value.is_empty())
            })
        });
    cookie
        .map(|value| feed(hash, value.as_bytes()))
        .unwrap_or_else(|| feed(hash, fallback.as_bytes()))
}

pub(super) fn query_affinity_seed(
    hash: u64,
    req: &Request<Body>,
    name: &str,
    fallback: &str,
) -> u64 {
    let query = req.uri().query().and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes()).find_map(|(key, value)| {
            (key == name && !value.is_empty()).then_some(value.into_owned())
        })
    });
    query
        .as_deref()
        .map(|value| feed(hash, value.as_bytes()))
        .unwrap_or_else(|| feed(hash, fallback.as_bytes()))
}
