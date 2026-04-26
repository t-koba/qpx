use super::health::{
    now_millis, probe_upstream, EndpointLifecycleRuntime, HealthCheckRuntime, PassiveHealthRuntime,
    UpstreamEndpoint,
};
use crate::http::body::Body;
use crate::http::modules::{CompiledHttpModuleChain, HttpModuleRegistry};
use crate::http::response_policy::HttpResponseRuleEngine;
use crate::rate_limit::RateLimitSet;
use anyhow::Result;
use arc_swap::ArcSwap;
use hyper::Request;
use metrics::gauge;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use qpx_core::config::ReverseTlsPassthroughRouteConfig;
use qpx_core::config::{
    CachePolicyConfig, PathRewriteConfig, PolicyContextConfig, ReverseConfig, ReverseRouteConfig,
    UpstreamConfig, UpstreamDiscoveryConfig,
};
use qpx_core::matchers::CompiledMatch;
use qpx_core::prefilter::{MatchPrefilterContext, MatchPrefilterIndex, StringInterner};
use qpx_core::rules::{CompiledHeaderControl, RuleMatchContext};
use regex::Regex;
use std::collections::{HashMap, HashSet};
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::{timeout, Duration};
use tracing::warn;

use crate::ipc_client::IpcUpstream;
use crate::tls::CompiledUpstreamTlsTrust;
use crate::upstream::origin::OriginEndpoint;

#[path = "router_compile.rs"]
mod router_compile;
#[path = "router_impls.rs"]
mod router_impls;
#[path = "router_selection.rs"]
mod router_selection;

use self::router_compile::{
    compile_backends, compile_mirrors, compile_response_rules, refresh_dynamic_upstreams,
    select_weighted_backend_idx,
};
pub(in crate::reverse) use self::router_impls::normalize_host_for_match;
use self::router_selection::{
    cookie_affinity_seed, feed, feed_ip, fnv_offset, header_affinity_seed, query_affinity_seed,
    select_upstream_inner,
};

pub(crate) struct ReverseRouter {
    http_routes: Vec<HttpRoute>,
    http_prefilter: MatchPrefilterIndex,
    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    tls_routes: Vec<TlsPassthroughRoute>,
    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    tls_prefilter: MatchPrefilterIndex,
    health_shutdown: watch::Sender<()>,
}

#[derive(Debug, Clone, Copy)]
enum LoadBalanceStrategy {
    RoundRobin,
    Random,
    LeastConnections,
    ConsistentHash,
    Sticky,
}

#[derive(Debug, Clone)]
pub(super) struct RoutePolicy {
    pub(super) retry_attempts: usize,
    pub(super) retry_backoff: Duration,
    pub(super) retry_budget: Arc<RetryBudgetRuntime>,
    pub(super) timeout: Duration,
    pub(super) health: HealthCheckRuntime,
    pub(super) passive_health: Option<PassiveHealthRuntime>,
    pub(super) lifecycle: EndpointLifecycleRuntime,
    pub(super) max_upstream_concurrency: Option<usize>,
    lb: LoadBalanceStrategy,
}

#[derive(Debug)]
struct WeightedBackend {
    weight: u32,
    upstreams: Arc<UpstreamPool>,
    rr_counter: AtomicUsize,
}

#[derive(Debug)]
struct MirrorTarget {
    percent: u32,
    upstreams: Arc<UpstreamPool>,
    rr_counter: AtomicUsize,
}

#[derive(Debug)]
pub(super) struct RetryBudgetRuntime {
    balance: AtomicIsize,
    max_balance: isize,
}

#[derive(Debug)]
struct UpstreamPool {
    static_endpoints: Arc<Vec<Arc<UpstreamEndpoint>>>,
    endpoints: ArcSwap<Vec<Arc<UpstreamEndpoint>>>,
    discovery: Vec<DynamicDiscovery>,
    lifecycle: EndpointLifecycleRuntime,
    discovery_started: AtomicBool,
}

#[derive(Debug, Clone)]
struct DynamicDiscovery {
    base_upstream: Arc<str>,
    config: UpstreamDiscoveryConfig,
}

#[derive(Debug, Clone)]
enum ReverseAffinityKey {
    SrcIp,
    Host,
    Header(Arc<str>),
    Cookie(Arc<str>),
    User,
    Tenant,
    Query(Arc<str>),
}

#[derive(Debug, Clone)]
pub(super) struct ReverseAffinityRuntime {
    key: ReverseAffinityKey,
}

#[derive(Debug, Clone)]
pub(super) struct CompiledPathRewrite {
    pub(super) strip_prefix: Option<String>,
    pub(super) add_prefix: Option<String>,
    pub(super) regex: Option<CompiledRegexPathRewrite>,
}

#[derive(Debug, Clone)]
pub(super) struct CompiledRegexPathRewrite {
    pub(super) pattern: Regex,
    pub(super) replace: String,
}

pub(super) struct HttpRoute {
    matcher: CompiledMatch,
    pub(super) name: Option<Arc<str>>,
    pub(super) policy_context: Option<PolicyContextConfig>,
    pub(super) local_response: Option<qpx_core::config::LocalResponseConfig>,
    pub(super) cache_policy: Option<CachePolicyConfig>,
    pub(super) rate_limit: RateLimitSet,
    pub(super) headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) ipc: Option<IpcUpstream>,
    pub(super) http_modules: Arc<CompiledHttpModuleChain>,
    backends: Vec<WeightedBackend>,
    mirrors: Vec<MirrorTarget>,
    pub(super) response_rules: Option<Arc<HttpResponseRuleEngine>>,
    pub(super) path_rewrite: Option<CompiledPathRewrite>,
    pub(super) upstream_trust: Option<Arc<CompiledUpstreamTlsTrust>>,
    pub(super) affinity: ReverseAffinityRuntime,
    pub(super) policy: RoutePolicy,
}

#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
pub(super) struct TlsPassthroughRoute {
    matcher: CompiledMatch,
    upstreams: Arc<UpstreamPool>,
    affinity: ReverseAffinityRuntime,
    pub(super) policy: RoutePolicy,
    rr_counter: AtomicUsize,
}

impl ReverseRouter {
    pub(super) fn new(
        config: ReverseConfig,
        upstream_configs: &[UpstreamConfig],
        http_module_registry: &HttpModuleRegistry,
    ) -> Result<Self> {
        let upstreams = upstream_configs
            .iter()
            .map(|cfg| (cfg.name.as_str(), cfg))
            .collect::<HashMap<_, _>>();
        let mut interner = StringInterner::default();
        let mut http_routes = Vec::with_capacity(config.routes.len());
        let mut http_hints = Vec::with_capacity(config.routes.len());

        for route in config.routes {
            let (route, hint) =
                HttpRoute::from_config(route, &upstreams, &mut interner, http_module_registry)?;
            http_routes.push(route);
            http_hints.push(hint);
        }

        let mut http_prefilter = MatchPrefilterIndex::new(http_routes.len());
        for (idx, hint) in http_hints.iter().enumerate() {
            http_prefilter.insert_hint(idx, hint, &mut interner);
        }

        #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
        let (tls_routes, tls_prefilter) = {
            let mut tls_routes = Vec::with_capacity(config.tls_passthrough_routes.len());
            let mut tls_hints = Vec::with_capacity(config.tls_passthrough_routes.len());
            for route in config.tls_passthrough_routes {
                let (route, hint) =
                    TlsPassthroughRoute::from_config(route, &upstreams, &mut interner)?;
                tls_routes.push(route);
                tls_hints.push(hint);
            }
            let mut tls_prefilter = MatchPrefilterIndex::new(tls_routes.len());
            for (idx, hint) in tls_hints.iter().enumerate() {
                tls_prefilter.insert_hint(idx, hint, &mut interner);
            }
            (tls_routes, tls_prefilter)
        };

        let (health_shutdown, _) = watch::channel(());
        Ok(Self {
            http_routes,
            http_prefilter,
            #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
            tls_routes,
            #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
            tls_prefilter,
            health_shutdown,
        })
    }

    pub(super) fn spawn_health_tasks(
        self: &Arc<Self>,
        reverse_name: Arc<str>,
        unhealthy_metric: Arc<str>,
    ) {
        self.spawn_discovery_tasks();
        let spawn_one = |route_kind: &'static str,
                         route_idx: usize,
                         pools: Vec<Arc<UpstreamPool>>,
                         trust: Option<Arc<CompiledUpstreamTlsTrust>>,
                         policy: HealthCheckRuntime,
                         lifecycle: EndpointLifecycleRuntime,
                         reverse_name: Arc<str>,
                         unhealthy_metric: Arc<str>,
                         mut shutdown: watch::Receiver<()>| {
            tokio::spawn(async move {
                let route_idx_label = route_idx.to_string();
                let unhealthy_gauge = gauge!(
                    unhealthy_metric.to_string(),
                    "reverse" => reverse_name.to_string(),
                    "route_kind" => route_kind,
                    "route_idx" => route_idx_label.clone()
                );
                let draining_gauge = gauge!(
                    crate::runtime::metric_names()
                        .reverse_upstreams_draining
                        .clone(),
                    "reverse" => reverse_name.to_string(),
                    "route_kind" => route_kind,
                    "route_idx" => route_idx_label
                );
                let mut ticker = tokio::time::interval(policy.interval);
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {}
                        res = shutdown.changed() => {
                            if res.is_err() {
                                break;
                            }
                            continue;
                        }
                    }
                    let mut upstreams = Vec::new();
                    for pool in &pools {
                        let endpoints = pool.endpoints();
                        upstreams.extend(endpoints.iter().cloned());
                    }
                    for upstream in &upstreams {
                        let healthy = matches!(
                            timeout(
                                policy.timeout,
                                probe_upstream(
                                    &upstream.origin,
                                    policy.http.as_deref(),
                                    trust.as_deref(),
                                )
                            )
                            .await,
                            Ok(Ok(_))
                        );
                        if healthy {
                            upstream.mark_success(&lifecycle);
                        } else {
                            upstream.mark_failure(&policy);
                        }
                    }
                    let unhealthy = upstreams
                        .iter()
                        .filter(|u| !u.is_healthy(now_millis()))
                        .count();
                    let draining = upstreams.iter().filter(|u| u.is_draining()).count();
                    unhealthy_gauge.set(unhealthy as f64);
                    draining_gauge.set(draining as f64);
                }
            });
        };

        for (idx, route) in self.http_routes.iter().enumerate() {
            let pools = route.health_upstream_pools();
            if pools.is_empty() {
                continue;
            }
            spawn_one(
                "http",
                idx,
                pools,
                route.upstream_trust.clone(),
                route.policy.health.clone(),
                route.policy.lifecycle.clone(),
                reverse_name.clone(),
                unhealthy_metric.clone(),
                self.health_shutdown.subscribe(),
            );
        }
        #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
        {
            for (idx, route) in self.tls_routes.iter().enumerate() {
                let pools = route.health_upstream_pools();
                if pools.is_empty() {
                    continue;
                }
                spawn_one(
                    "tls_passthrough",
                    idx,
                    pools,
                    None,
                    route.policy.health.clone(),
                    route.policy.lifecycle.clone(),
                    reverse_name.clone(),
                    unhealthy_metric.clone(),
                    self.health_shutdown.subscribe(),
                );
            }
        }
    }

    fn spawn_discovery_tasks(self: &Arc<Self>) {
        let pools = self
            .all_upstream_pools()
            .into_iter()
            .filter(|pool| !pool.discovery.is_empty())
            .collect::<Vec<_>>();
        for pool in pools {
            pool.spawn_discovery(self.health_shutdown.subscribe());
        }
    }

    pub(super) fn try_for_each_candidate_route<E>(
        &self,
        ctx: MatchPrefilterContext<'_>,
        mut visitor: impl FnMut(usize, &HttpRoute) -> std::result::Result<bool, E>,
    ) -> std::result::Result<(), E> {
        let mut result = Ok(());
        self.http_prefilter.for_each_candidate(&ctx, |idx| {
            let Some(route) = self.http_routes.get(idx) else {
                return false;
            };
            match visitor(idx, route) {
                Ok(stop) => stop,
                Err(err) => {
                    result = Err(err);
                    true
                }
            }
        });
        result
    }

    pub(super) fn route_at(&self, idx: usize) -> Option<&HttpRoute> {
        self.http_routes.get(idx)
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub(super) fn select_tls_passthrough_upstream(
        &self,
        remote_ip: IpAddr,
        dst_port: u16,
        sni: Option<&str>,
    ) -> Option<Arc<UpstreamEndpoint>> {
        // Deterministic hashing for stable selection across connections.
        const FNV_OFFSET: u64 = 14695981039346656037;
        const FNV_PRIME: u64 = 1099511628211;
        fn feed(mut hash: u64, bytes: &[u8]) -> u64 {
            for b in bytes {
                hash ^= *b as u64;
                hash = hash.wrapping_mul(FNV_PRIME);
            }
            hash
        }
        let mut tls_seed = FNV_OFFSET;
        match remote_ip {
            IpAddr::V4(ip) => {
                tls_seed = feed(tls_seed, &ip.octets());
            }
            IpAddr::V6(ip) => {
                tls_seed = feed(tls_seed, &ip.octets());
            }
        }
        tls_seed = feed(tls_seed, &dst_port.to_be_bytes());
        if let Some(sni) = sni {
            tls_seed = feed(tls_seed, sni.as_bytes());
        }

        let ctx = RuleMatchContext {
            src_ip: Some(remote_ip),
            dst_port: Some(dst_port),
            host: None,
            sni,
            method: None,
            path: None,
            headers: None,
            user: None,
            user_groups: &[],
            device_id: None,
            posture: &[],
            tenant: None,
            auth_strength: None,
            idp: None,
            ..Default::default()
        };
        let prefilter_ctx = MatchPrefilterContext {
            method: None,
            dst_port: Some(dst_port),
            src_ip: Some(remote_ip),
            host: None,
            sni,
            path: None,
        };
        self.tls_prefilter.find_first(&prefilter_ctx, |idx| {
            let route = &self.tls_routes[idx];
            if route.matches(&ctx) {
                let sticky_seed = route.affinity.seed_tls_passthrough(remote_ip, sni);
                return route.select_upstream(tls_seed, sticky_seed);
            }
            None
        })
    }

    fn all_upstream_pools(&self) -> Vec<Arc<UpstreamPool>> {
        let mut pools = Vec::new();
        for route in &self.http_routes {
            pools.extend(route.health_upstream_pools());
        }
        #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
        for route in &self.tls_routes {
            pools.extend(route.health_upstream_pools());
        }
        pools
    }
}

#[cfg(test)]
#[path = "router_tests.rs"]
mod tests;
