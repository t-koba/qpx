use super::health::{now_millis, probe_upstream, HealthCheckRuntime, UpstreamEndpoint};
use anyhow::Result;
use metrics::gauge;
use qpx_core::config::ReverseRouteBackendConfig;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use qpx_core::config::ReverseTlsPassthroughRouteConfig;
use qpx_core::config::{
    CachePolicyConfig, PathRewriteConfig, RetryConfig, ReverseConfig, ReverseRouteConfig,
};
use qpx_core::matchers::CompiledMatch;
use qpx_core::prefilter::{MatchPrefilterContext, MatchPrefilterIndex, StringInterner};
use qpx_core::rules::{CompiledHeaderControl, RuleMatchContext};
use rand::Rng;
use regex::Regex;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::{timeout, Duration};

use crate::fastcgi_client::FastCgiUpstream;

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
    pub(super) timeout: Duration,
    pub(super) health: HealthCheckRuntime,
    lb: LoadBalanceStrategy,
}

#[derive(Debug)]
struct WeightedBackend {
    weight: u32,
    upstreams: Vec<Arc<UpstreamEndpoint>>,
    rr_counter: AtomicUsize,
}

#[derive(Debug)]
struct MirrorTarget {
    percent: u32,
    upstreams: Vec<Arc<UpstreamEndpoint>>,
    rr_counter: AtomicUsize,
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
    pub(super) local_response: Option<qpx_core::config::LocalResponseConfig>,
    pub(super) cache_policy: Option<CachePolicyConfig>,
    pub(super) headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) fastcgi: Option<FastCgiUpstream>,
    backends: Vec<WeightedBackend>,
    mirrors: Vec<MirrorTarget>,
    pub(super) path_rewrite: Option<CompiledPathRewrite>,
    pub(super) policy: RoutePolicy,
}

#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
pub(super) struct TlsPassthroughRoute {
    matcher: CompiledMatch,
    upstreams: Vec<Arc<UpstreamEndpoint>>,
    pub(super) policy: RoutePolicy,
    rr_counter: AtomicUsize,
}

impl ReverseRouter {
    pub(super) fn new(config: ReverseConfig) -> Result<Self> {
        let mut interner = StringInterner::default();
        let mut http_routes = Vec::with_capacity(config.routes.len());
        let mut http_hints = Vec::with_capacity(config.routes.len());

        for route in config.routes {
            let (route, hint) = HttpRoute::from_config(route, &mut interner)?;
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
                let (route, hint) = TlsPassthroughRoute::from_config(route, &mut interner)?;
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
        let spawn_one = |route_kind: &'static str,
                         route_idx: usize,
                         upstreams: Vec<Arc<UpstreamEndpoint>>,
                         policy: HealthCheckRuntime,
                         reverse_name: Arc<str>,
                         unhealthy_metric: Arc<str>,
                         mut shutdown: watch::Receiver<()>| {
            tokio::spawn(async move {
                let route_idx_label = route_idx.to_string();
                let unhealthy_gauge = gauge!(
                    unhealthy_metric.to_string(),
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
                    for upstream in &upstreams {
                        let healthy = matches!(
                            timeout(
                                policy.timeout,
                                probe_upstream(&upstream.target, policy.http.as_deref())
                            )
                            .await,
                            Ok(Ok(_))
                        );
                        if healthy {
                            upstream.mark_success();
                        } else {
                            upstream.mark_failure(&policy);
                        }
                    }
                    let unhealthy = upstreams
                        .iter()
                        .filter(|u| !u.is_healthy(now_millis()))
                        .count();
                    unhealthy_gauge.set(unhealthy as f64);
                }
            });
        };

        for (idx, route) in self.http_routes.iter().enumerate() {
            let upstreams = route.health_upstreams();
            if upstreams.is_empty() {
                continue;
            }
            spawn_one(
                "http",
                idx,
                upstreams,
                route.policy.health.clone(),
                reverse_name.clone(),
                unhealthy_metric.clone(),
                self.health_shutdown.subscribe(),
            );
        }
        #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
        {
            for (idx, route) in self.tls_routes.iter().enumerate() {
                if route.upstreams.is_empty() {
                    continue;
                }
                spawn_one(
                    "tls_passthrough",
                    idx,
                    route.upstreams.clone(),
                    route.policy.health.clone(),
                    reverse_name.clone(),
                    unhealthy_metric.clone(),
                    self.health_shutdown.subscribe(),
                );
            }
        }
    }

    pub(super) fn select_route(&self, ctx: &RuleMatchContext<'_>) -> Option<&HttpRoute> {
        let prefilter_ctx = MatchPrefilterContext {
            method: ctx.method,
            dst_port: ctx.dst_port,
            src_ip: ctx.src_ip,
            host: ctx.host,
            sni: ctx.sni,
            path: ctx.path,
        };

        self.http_prefilter.find_first(&prefilter_ctx, |idx| {
            let route = &self.http_routes[idx];
            if route.matches(ctx) {
                return Some(route);
            }
            None
        })
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub(super) fn select_tls_passthrough_upstream(
        &self,
        remote_ip: IpAddr,
        dst_port: u16,
        sni: Option<&str>,
    ) -> Option<String> {
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
            user_groups: &[],
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
                return route
                    .select_upstream(tls_seed, tls_seed)
                    .map(|u| u.target.clone());
            }
            None
        })
    }
}

fn select_upstream_inner(
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
    let candidates: Vec<Arc<UpstreamEndpoint>> = upstreams
        .iter()
        .filter(|u| u.is_healthy(now_ms))
        .cloned()
        .collect();
    if candidates.is_empty() {
        return None;
    }

    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;
    let rendezvous = |seed: u64| -> Arc<UpstreamEndpoint> {
        let mut best = None;
        for u in &candidates {
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
        best.map(|(u, _)| u).unwrap_or_else(|| candidates[0].clone())
    };

    let selected = match policy.lb {
        LoadBalanceStrategy::RoundRobin => {
            let idx = rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
            candidates[idx].clone()
        }
        LoadBalanceStrategy::Random => {
            let idx = rand::thread_rng().gen_range(0..candidates.len());
            candidates[idx].clone()
        }
        LoadBalanceStrategy::LeastConnections => candidates
            .into_iter()
            .min_by_key(|u| u.inflight.load(Ordering::Relaxed))
            .unwrap_or_else(|| upstreams[0].clone()),
        LoadBalanceStrategy::ConsistentHash => rendezvous(request_seed),
        LoadBalanceStrategy::Sticky => rendezvous(sticky_seed),
    };
    Some(selected)
}

impl HttpRoute {
    fn from_config(
        config: ReverseRouteConfig,
        interner: &mut StringInterner,
    ) -> Result<(Self, qpx_core::prefilter::MatchPrefilterHint)> {
        let (matcher, hint) = CompiledMatch::compile(&config.r#match, interner)?;
        let policy = RoutePolicy::from_http_config(&config)?;
        let cache_policy = config.cache.clone();
        let path_rewrite = config
            .path_rewrite
            .as_ref()
            .map(CompiledPathRewrite::compile)
            .transpose()?;
        let headers = config
            .headers
            .as_ref()
            .map(CompiledHeaderControl::compile)
            .transpose()?
            .map(Arc::new);

        let fastcgi = config
            .fastcgi
            .as_ref()
            .map(FastCgiUpstream::from_config)
            .transpose()?;
        if fastcgi.is_some() && (!config.upstreams.is_empty() || !config.backends.is_empty()) {
            return Err(anyhow::anyhow!(
                "reverse route fastcgi cannot be combined with upstreams/backends"
            ));
        }
        let backends = if fastcgi.is_some() {
            Vec::new()
        } else {
            compile_backends(config.upstreams, config.backends)
        };
        let mirrors = compile_mirrors(config.mirrors);
        Ok((
            Self {
                matcher,
                local_response: config.local_response.clone(),
                cache_policy,
                headers,
                fastcgi,
                backends,
                mirrors,
                path_rewrite,
                policy,
            },
            hint,
        ))
    }

    fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        self.matcher.matches(ctx)
    }

    pub(super) fn select_upstream(
        &self,
        request_seed: u64,
        sticky_seed: u64,
    ) -> Option<Arc<UpstreamEndpoint>> {
        let idx = select_weighted_backend_idx(&self.backends, request_seed)?;
        let backend = &self.backends[idx];
        select_upstream_inner(
            &backend.upstreams,
            &self.policy,
            &backend.rr_counter,
            request_seed,
            sticky_seed,
        )
    }

    pub(super) fn select_mirror_upstreams(
        &self,
        request_seed: u64,
        sticky_seed: u64,
    ) -> Vec<Arc<UpstreamEndpoint>> {
        let mut out = Vec::new();
        for (idx, mirror) in self.mirrors.iter().enumerate() {
            // 0..9999 range; percent has 0.01% resolution.
            let sample = (request_seed
                .wrapping_add((idx as u64 + 1) * 0x9e3779b97f4a7c15)
                % 10_000) as u32;
            if sample >= mirror.percent.saturating_mul(100) {
                continue;
            }
            let mirror_seed = request_seed.wrapping_add((idx as u64 + 1) * 0x517cc1b727220a95);
            if let Some(upstream) =
                select_upstream_inner(
                    &mirror.upstreams,
                    &self.policy,
                    &mirror.rr_counter,
                    mirror_seed,
                    sticky_seed,
                )
            {
                out.push(upstream);
            }
        }
        out
    }

    fn health_upstreams(&self) -> Vec<Arc<UpstreamEndpoint>> {
        let mut out = Vec::new();
        for backend in &self.backends {
            out.extend(backend.upstreams.iter().cloned());
        }
        for mirror in &self.mirrors {
            out.extend(mirror.upstreams.iter().cloned());
        }
        out
    }
}

impl CompiledPathRewrite {
    fn compile(raw: &PathRewriteConfig) -> Result<Self> {
        let regex = raw
            .regex
            .as_ref()
            .map(|r| -> Result<CompiledRegexPathRewrite> {
                Ok(CompiledRegexPathRewrite {
                    pattern: Regex::new(r.pattern.as_str())?,
                    replace: r.replace.clone(),
                })
            })
            .transpose()?;
        Ok(Self {
            strip_prefix: raw.strip_prefix.clone(),
            add_prefix: raw.add_prefix.clone(),
            regex,
        })
    }
}

fn compile_backends(
    upstreams: Vec<String>,
    backends: Vec<ReverseRouteBackendConfig>,
) -> Vec<WeightedBackend> {
    if !backends.is_empty() {
        return backends
            .into_iter()
            .map(|b| WeightedBackend {
                weight: b.weight,
                upstreams: b
                    .upstreams
                    .into_iter()
                    .map(UpstreamEndpoint::new)
                    .map(Arc::new)
                    .collect(),
                rr_counter: AtomicUsize::new(0),
            })
            .collect();
    }
    if upstreams.is_empty() {
        return Vec::new();
    }
    vec![WeightedBackend {
        weight: 1,
        upstreams: upstreams
            .into_iter()
            .map(UpstreamEndpoint::new)
            .map(Arc::new)
            .collect(),
        rr_counter: AtomicUsize::new(0),
    }]
}

fn compile_mirrors(mirrors: Vec<qpx_core::config::ReverseRouteMirrorConfig>) -> Vec<MirrorTarget> {
    mirrors
        .into_iter()
        .map(|m| MirrorTarget {
            percent: m.percent,
            upstreams: m
                .upstreams
                .into_iter()
                .map(UpstreamEndpoint::new)
                .map(Arc::new)
                .collect(),
            rr_counter: AtomicUsize::new(0),
        })
        .collect()
}

fn select_weighted_backend_idx(backends: &[WeightedBackend], seed: u64) -> Option<usize> {
    if backends.is_empty() {
        return None;
    }
    let total = backends.iter().map(|b| b.weight as u64).sum::<u64>();
    if total == 0 {
        return None;
    }
    let pick = seed % total;
    let mut acc = 0u64;
    for (idx, backend) in backends.iter().enumerate() {
        acc = acc.saturating_add(backend.weight as u64);
        if pick < acc {
            return Some(idx);
        }
    }
    Some(backends.len().saturating_sub(1))
}

#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
impl TlsPassthroughRoute {
    fn from_config(
        config: ReverseTlsPassthroughRouteConfig,
        interner: &mut StringInterner,
    ) -> Result<(Self, qpx_core::prefilter::MatchPrefilterHint)> {
        let (matcher, hint) = CompiledMatch::compile_tls_passthrough(&config.r#match, interner)?;
        let policy = RoutePolicy::from_tls_config(&config)?;
        let upstreams = config
            .upstreams
            .into_iter()
            .map(UpstreamEndpoint::new)
            .map(Arc::new)
            .collect();
        Ok((
            Self {
                matcher,
                upstreams,
                policy,
                rr_counter: AtomicUsize::new(0),
            },
            hint,
        ))
    }

    fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        self.matcher.matches(ctx)
    }

    pub(super) fn select_upstream(
        &self,
        request_seed: u64,
        sticky_seed: u64,
    ) -> Option<Arc<UpstreamEndpoint>> {
        select_upstream_inner(
            &self.upstreams,
            &self.policy,
            &self.rr_counter,
            request_seed,
            sticky_seed,
        )
    }
}

impl RoutePolicy {
    fn from_http_config(config: &ReverseRouteConfig) -> Result<Self> {
        Self::from_parts(
            config.lb.as_str(),
            config.retry.as_ref(),
            config.timeout_ms,
            config.health_check.as_ref(),
        )
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    fn from_tls_config(config: &ReverseTlsPassthroughRouteConfig) -> Result<Self> {
        Self::from_parts(
            config.lb.as_str(),
            config.retry.as_ref(),
            config.timeout_ms,
            config.health_check.as_ref(),
        )
    }

    fn from_parts(
        lb: &str,
        retry: Option<&RetryConfig>,
        timeout_ms: Option<u64>,
        health_check: Option<&qpx_core::config::HealthCheckConfig>,
    ) -> Result<Self> {
        let lb_lower = lb.trim().to_ascii_lowercase();
        let lb = match lb_lower.as_str() {
            "round_robin" | "roundrobin" => LoadBalanceStrategy::RoundRobin,
            "random" => LoadBalanceStrategy::Random,
            "least_conn" | "least_connections" => LoadBalanceStrategy::LeastConnections,
            "consistent_hash" | "consistent-hash" => LoadBalanceStrategy::ConsistentHash,
            "sticky" | "sticky_ip" | "sticky-src-ip" => LoadBalanceStrategy::Sticky,
            other => return Err(anyhow::anyhow!("unknown lb strategy: {}", other)),
        };
        let retry = retry.cloned().unwrap_or(RetryConfig {
            attempts: 1,
            backoff_ms: 0,
        });
        if retry.attempts == 0 {
            return Err(anyhow::anyhow!("retry.attempts must be >= 1"));
        }
        Ok(Self {
            lb,
            retry_attempts: retry.attempts,
            retry_backoff: Duration::from_millis(retry.backoff_ms),
            timeout: Duration::from_millis(timeout_ms.unwrap_or(30_000)),
            health: HealthCheckRuntime::from_config(health_check),
        })
    }
}

pub(super) fn normalize_host_for_match(raw: &str) -> String {
    if let Ok(authority) = raw.parse::<http::uri::Authority>() {
        return authority.host().to_ascii_lowercase();
    }
    raw.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use qpx_core::config::{HealthCheckConfig, MatchConfig};

    #[test]
    fn weighted_backend_selection_is_stable() {
        let backends = vec![
            WeightedBackend {
                weight: 9,
                upstreams: Vec::new(),
                rr_counter: AtomicUsize::new(0),
            },
            WeightedBackend {
                weight: 1,
                upstreams: Vec::new(),
                rr_counter: AtomicUsize::new(0),
            },
        ];
        for seed in 0..9 {
            assert_eq!(select_weighted_backend_idx(&backends, seed), Some(0));
        }
        assert_eq!(select_weighted_backend_idx(&backends, 9), Some(1));
        assert_eq!(select_weighted_backend_idx(&backends, 19), Some(1));
        assert_eq!(select_weighted_backend_idx(&backends, 20), Some(0));
    }

    #[test]
    fn route_policy_uses_configured_values() {
        let cfg = ReverseRouteConfig {
            r#match: MatchConfig::default(),
            upstreams: vec!["http://127.0.0.1:8080".to_string()],
            backends: Vec::new(),
            mirrors: Vec::new(),
            local_response: None,
            headers: None,
            lb: "least_conn".to_string(),
            retry: Some(RetryConfig {
                attempts: 4,
                backoff_ms: 250,
            }),
            timeout_ms: Some(12_000),
            health_check: Some(HealthCheckConfig {
                interval_ms: 1500,
                timeout_ms: 700,
                fail_threshold: 5,
                cooldown_ms: 9_000,
                http: None,
            }),
            cache: None,
            path_rewrite: None,
            fastcgi: None,
        };
        let policy = RoutePolicy::from_http_config(&cfg).expect("policy");
        assert!(matches!(policy.lb, LoadBalanceStrategy::LeastConnections));
        assert_eq!(policy.retry_attempts, 4);
        assert_eq!(policy.retry_backoff, Duration::from_millis(250));
        assert_eq!(policy.timeout, Duration::from_millis(12_000));
        assert_eq!(policy.health.interval, Duration::from_millis(1500));
        assert_eq!(policy.health.timeout, Duration::from_millis(700));
        assert_eq!(policy.health.fail_threshold, 5);
        assert_eq!(policy.health.cooldown, Duration::from_millis(9_000));
    }

    #[test]
    fn route_policy_default_health_and_lb() {
        let cfg = ReverseRouteConfig {
            r#match: MatchConfig::default(),
            upstreams: vec!["http://127.0.0.1:8080".to_string()],
            backends: Vec::new(),
            mirrors: Vec::new(),
            local_response: None,
            headers: None,
            lb: "round_robin".to_string(),
            retry: None,
            timeout_ms: None,
            health_check: None,
            cache: None,
            path_rewrite: None,
            fastcgi: None,
        };
        let policy = RoutePolicy::from_http_config(&cfg).expect("policy");
        assert!(matches!(policy.lb, LoadBalanceStrategy::RoundRobin));
        assert_eq!(policy.retry_attempts, 1);
        assert_eq!(policy.retry_backoff, Duration::from_millis(0));
        assert_eq!(policy.timeout, Duration::from_millis(30_000));
        assert_eq!(policy.health.interval, Duration::from_secs(5));
        assert_eq!(policy.health.timeout, Duration::from_secs(1));
        assert_eq!(policy.health.fail_threshold, 3);
        assert_eq!(policy.health.cooldown, Duration::from_secs(30));
    }

    #[test]
    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    fn tls_passthrough_prefilter_does_not_require_host_or_path() {
        let cfg = ReverseConfig {
            name: "rev".to_string(),
            listen: "127.0.0.1:0".to_string(),
            tls: Some(qpx_core::config::ReverseTlsConfig {
                certificates: Vec::new(),
                client_ca: None,
            }),
            http3: None,
            xdp: None,
            enforce_sni_host_match: false,
            sni_host_exceptions: Vec::new(),
            routes: Vec::new(),
            tls_passthrough_routes: vec![ReverseTlsPassthroughRouteConfig {
                r#match: qpx_core::config::TlsPassthroughMatchConfig {
                    src_ip: Vec::new(),
                    dst_port: vec![443],
                    sni: vec!["example.com".to_string()],
                },
                upstreams: vec!["127.0.0.1:8443".to_string()],
                lb: "round_robin".to_string(),
                retry: None,
                timeout_ms: None,
                health_check: None,
            }],
        };

        let router = ReverseRouter::new(cfg).expect("router");
        let selected = router.select_tls_passthrough_upstream(
            "203.0.113.10".parse().expect("ip"),
            443,
            Some("example.com"),
        );
        assert_eq!(selected.as_deref(), Some("127.0.0.1:8443"));
    }
}
