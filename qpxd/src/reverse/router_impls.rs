#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use super::router_compile::compile_upstream_pool;
use super::*;
use crate::http::modules::compile_http_modules;
use crate::rate_limit::RateLimitSet;

impl HttpRoute {
    pub(in crate::reverse) fn from_config(
        config: ReverseRouteConfig,
        upstreams: &HashMap<&str, &UpstreamConfig>,
        interner: &mut StringInterner,
        http_module_registry: &crate::http::modules::HttpModuleRegistry,
    ) -> Result<(Self, qpx_core::prefilter::MatchPrefilterHint)> {
        let (matcher, hint) = CompiledMatch::compile(&config.r#match, interner)?;
        let policy = RoutePolicy::from_http_config(&config)?;
        let affinity = ReverseAffinityRuntime::from_config(config.affinity.as_ref())?;
        let cache_policy = config.cache.clone();
        let rate_limit = RateLimitSet::from_config(config.rate_limit.as_ref());
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

        let ipc = config
            .ipc
            .as_ref()
            .map(IpcUpstream::from_config)
            .transpose()?;
        if ipc.is_some() && (!config.upstreams.is_empty() || !config.backends.is_empty()) {
            return Err(anyhow::anyhow!(
                "reverse route ipc cannot be combined with upstreams/backends"
            ));
        }
        let backends = if ipc.is_some() {
            Vec::new()
        } else {
            compile_backends(
                config.upstreams,
                config.backends,
                upstreams,
                &policy.lifecycle,
            )?
        };
        let mirrors = compile_mirrors(config.mirrors, upstreams, &policy.lifecycle)?;
        let response_rules = compile_response_rules(
            config
                .http
                .as_ref()
                .map(|http| http.response_rules.as_slice())
                .unwrap_or(&[]),
        )?;
        let upstream_trust = CompiledUpstreamTlsTrust::from_config(config.upstream_trust.as_ref())?;
        let http_modules =
            compile_http_modules(config.http_modules.as_slice(), http_module_registry)?;
        Ok((
            Self {
                matcher,
                name: config.name.as_deref().map(Arc::<str>::from),
                policy_context: config.policy_context.clone(),
                local_response: config.local_response.clone(),
                cache_policy,
                rate_limit,
                headers,
                ipc,
                http_modules,
                backends,
                mirrors,
                response_rules,
                path_rewrite,
                upstream_trust,
                affinity,
                policy,
            },
            hint,
        ))
    }

    pub(in crate::reverse) fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        self.matcher.matches(ctx)
    }

    pub(in crate::reverse) fn requires_request_size(&self) -> bool {
        self.matcher.requires_request_size()
    }

    pub(in crate::reverse) fn requires_request_body_observation(&self) -> bool {
        self.matcher.requires_request_body_observation()
    }

    pub(in crate::reverse) fn requires_request_rpc_context(&self) -> bool {
        self.matcher.requires_request_rpc_context()
    }

    pub(in crate::reverse) fn response_rules_require_request_rpc_context(&self) -> bool {
        self.response_rules
            .as_ref()
            .map(|engine| engine.any_rule_requires_response_request_rpc_context())
            .unwrap_or(false)
    }

    pub(in crate::reverse) fn response_rules_require_request_body_observation(&self) -> bool {
        self.response_rules
            .as_ref()
            .map(|engine| engine.any_rule_requires_response_request_body_observation())
            .unwrap_or(false)
    }

    pub(in crate::reverse) fn affinity_seed(
        &self,
        conn: &crate::reverse::transport::ReverseConnInfo,
        host: &str,
        req: &Request<Body>,
        identity: &crate::policy_context::ResolvedIdentity,
    ) -> u64 {
        self.affinity.seed_http(conn, host, req, identity)
    }

    pub(in crate::reverse) fn select_upstream(
        &self,
        request_seed: u64,
        sticky_seed: u64,
    ) -> Option<Arc<UpstreamEndpoint>> {
        let idx = select_weighted_backend_idx(&self.backends, request_seed)?;
        let backend = &self.backends[idx];
        let endpoints = backend.upstreams.endpoints();
        select_upstream_inner(
            endpoints.as_slice(),
            &self.policy,
            &backend.rr_counter,
            request_seed,
            sticky_seed,
        )
    }

    pub(in crate::reverse) fn select_mirror_upstreams(
        &self,
        request_seed: u64,
        sticky_seed: u64,
    ) -> Vec<Arc<UpstreamEndpoint>> {
        let mut out = Vec::new();
        for (idx, mirror) in self.mirrors.iter().enumerate() {
            let sample =
                (request_seed.wrapping_add((idx as u64 + 1) * 0x9e3779b97f4a7c15) % 10_000) as u32;
            if sample >= mirror.percent.saturating_mul(100) {
                continue;
            }
            let mirror_seed = request_seed.wrapping_add((idx as u64 + 1) * 0x517cc1b727220a95);
            let endpoints = mirror.upstreams.endpoints();
            if let Some(upstream) = select_upstream_inner(
                endpoints.as_slice(),
                &self.policy,
                &mirror.rr_counter,
                mirror_seed,
                sticky_seed,
            ) {
                out.push(upstream);
            }
        }
        out
    }

    pub(super) fn health_upstream_pools(&self) -> Vec<Arc<UpstreamPool>> {
        let mut out = Vec::new();
        for backend in &self.backends {
            out.push(backend.upstreams.clone());
        }
        for mirror in &self.mirrors {
            out.push(mirror.upstreams.clone());
        }
        out
    }
}

impl RetryBudgetRuntime {
    pub(in crate::reverse) fn new(retry_attempts: usize) -> Arc<Self> {
        let burst = retry_attempts.saturating_sub(1).max(1) as isize;
        Arc::new(Self {
            balance: AtomicIsize::new(burst),
            max_balance: burst.saturating_mul(8),
        })
    }

    pub(in crate::reverse) fn try_consume_retry(&self) -> bool {
        self.balance
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (current > 0).then_some(current - 1)
            })
            .is_ok()
    }

    pub(in crate::reverse) fn record_success(&self) {
        let _ = self
            .balance
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some((current + 1).min(self.max_balance))
            });
    }
}

impl CompiledPathRewrite {
    pub(in crate::reverse) fn compile(raw: &PathRewriteConfig) -> Result<Self> {
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

impl ReverseAffinityRuntime {
    pub(in crate::reverse) fn from_config(
        config: Option<&qpx_core::config::ReverseAffinityConfig>,
    ) -> Result<Self> {
        let key = match config.map(|cfg| cfg.key.trim().to_ascii_lowercase()) {
            None => ReverseAffinityKey::SrcIp,
            Some(key) if key == "src_ip" => ReverseAffinityKey::SrcIp,
            Some(key) if key == "host" => ReverseAffinityKey::Host,
            Some(key) if key == "header" => ReverseAffinityKey::Header(Arc::<str>::from(
                config
                    .and_then(|cfg| cfg.header.as_deref())
                    .unwrap_or_default()
                    .trim(),
            )),
            Some(key) if key == "cookie" => ReverseAffinityKey::Cookie(Arc::<str>::from(
                config
                    .and_then(|cfg| cfg.cookie.as_deref())
                    .unwrap_or_default()
                    .trim(),
            )),
            Some(key) if key == "user" => ReverseAffinityKey::User,
            Some(key) if key == "tenant" => ReverseAffinityKey::Tenant,
            Some(key) if key == "query" => ReverseAffinityKey::Query(Arc::<str>::from(
                config
                    .and_then(|cfg| cfg.query.as_deref())
                    .unwrap_or_default()
                    .trim(),
            )),
            Some(other) => {
                return Err(anyhow::anyhow!("unknown reverse affinity key: {}", other));
            }
        };
        Ok(Self { key })
    }

    pub(in crate::reverse) fn seed_http(
        &self,
        conn: &crate::reverse::transport::ReverseConnInfo,
        host: &str,
        req: &Request<Body>,
        identity: &crate::policy_context::ResolvedIdentity,
    ) -> u64 {
        let mut hash = fnv_offset();
        match &self.key {
            ReverseAffinityKey::SrcIp => {
                hash = feed_ip(hash, conn.remote_addr.ip());
                feed(hash, host.as_bytes())
            }
            ReverseAffinityKey::Host => feed(hash, host.as_bytes()),
            ReverseAffinityKey::Header(name) => {
                header_affinity_seed(hash, req, name.as_ref(), host)
            }
            ReverseAffinityKey::Cookie(name) => {
                cookie_affinity_seed(hash, req, name.as_ref(), host)
            }
            ReverseAffinityKey::User => {
                feed(hash, identity.user.as_deref().unwrap_or(host).as_bytes())
            }
            ReverseAffinityKey::Tenant => {
                feed(hash, identity.tenant.as_deref().unwrap_or(host).as_bytes())
            }
            ReverseAffinityKey::Query(name) => query_affinity_seed(hash, req, name.as_ref(), host),
        }
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub(in crate::reverse) fn seed_tls_passthrough(
        &self,
        remote_ip: IpAddr,
        sni: Option<&str>,
    ) -> u64 {
        let host = sni.unwrap_or("");
        let mut hash = fnv_offset();
        match &self.key {
            ReverseAffinityKey::Host => feed(hash, host.as_bytes()),
            _ => {
                hash = feed_ip(hash, remote_ip);
                feed(hash, host.as_bytes())
            }
        }
    }
}

impl UpstreamPool {
    pub(in crate::reverse) fn new(
        static_endpoints: Vec<Arc<UpstreamEndpoint>>,
        seed_endpoints: Vec<Arc<UpstreamEndpoint>>,
        discovery: Vec<DynamicDiscovery>,
        lifecycle: EndpointLifecycleRuntime,
    ) -> Arc<Self> {
        Arc::new(Self {
            static_endpoints: Arc::new(static_endpoints),
            endpoints: ArcSwap::from_pointee(seed_endpoints),
            discovery,
            lifecycle,
            discovery_started: AtomicBool::new(false),
        })
    }

    pub(in crate::reverse) fn endpoints(&self) -> Arc<Vec<Arc<UpstreamEndpoint>>> {
        self.endpoints.load_full()
    }

    pub(in crate::reverse) fn spawn_discovery(self: &Arc<Self>, mut shutdown: watch::Receiver<()>) {
        if self.discovery.is_empty() || self.discovery_started.swap(true, Ordering::Relaxed) {
            return;
        }
        let pool = self.clone();
        tokio::spawn(async move {
            let mut delay = Duration::ZERO;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    res = shutdown.changed() => {
                        if res.is_err() {
                            break;
                        }
                        continue;
                    }
                }
                match refresh_dynamic_upstreams(&pool.discovery).await {
                    Ok((resolved, next_delay)) => {
                        let combined = pool.reconcile_dynamic_endpoints(resolved);
                        pool.endpoints.store(Arc::new(combined));
                        delay = next_delay;
                    }
                    Err(err) => {
                        warn!(error = ?err, "reverse dynamic upstream discovery failed");
                        delay = pool
                            .discovery
                            .iter()
                            .map(|entry| Duration::from_millis(entry.config.interval_ms))
                            .min()
                            .unwrap_or_else(|| Duration::from_secs(30));
                    }
                }
            }
        });
    }

    pub(in crate::reverse) fn reconcile_dynamic_endpoints(
        &self,
        resolved: Vec<OriginEndpoint>,
    ) -> Vec<Arc<UpstreamEndpoint>> {
        let now_ms = now_millis();
        let static_labels = self
            .static_endpoints
            .iter()
            .map(|endpoint| endpoint.target.clone())
            .collect::<HashSet<_>>();
        let mut reusable = self
            .endpoints()
            .iter()
            .filter(|endpoint| !static_labels.contains(endpoint.target.as_str()))
            .map(|endpoint| (endpoint.target.clone(), endpoint.clone()))
            .collect::<HashMap<_, _>>();
        let mut combined = self.static_endpoints.as_ref().clone();
        for origin in resolved {
            let label = origin.label();
            if let Some(endpoint) = reusable.remove(label.as_str()) {
                endpoint.reactivate(&self.lifecycle);
                combined.push(endpoint);
            } else {
                let endpoint = Arc::new(UpstreamEndpoint::from_origin(origin));
                endpoint.begin_recovery_window(&self.lifecycle);
                combined.push(endpoint);
            }
        }
        for endpoint in reusable.into_values() {
            if endpoint.mark_draining(&self.lifecycle) && endpoint.should_retain_draining(now_ms) {
                combined.push(endpoint);
            }
        }
        combined
    }
}

#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
impl TlsPassthroughRoute {
    pub(in crate::reverse) fn from_config(
        config: ReverseTlsPassthroughRouteConfig,
        upstreams: &HashMap<&str, &UpstreamConfig>,
        interner: &mut StringInterner,
    ) -> Result<(Self, qpx_core::prefilter::MatchPrefilterHint)> {
        let (matcher, hint) = CompiledMatch::compile_tls_passthrough(&config.r#match, interner)?;
        let policy = RoutePolicy::from_tls_config(&config)?;
        let affinity = ReverseAffinityRuntime::from_config(config.affinity.as_ref())?;
        let upstreams =
            compile_upstream_pool(config.upstreams, upstreams, true, &policy.lifecycle)?;
        Ok((
            Self {
                matcher,
                upstreams,
                affinity,
                policy,
                rr_counter: AtomicUsize::new(0),
            },
            hint,
        ))
    }

    pub(in crate::reverse) fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        self.matcher.matches(ctx)
    }

    pub(in crate::reverse) fn select_upstream(
        &self,
        request_seed: u64,
        sticky_seed: u64,
    ) -> Option<Arc<UpstreamEndpoint>> {
        let endpoints = self.upstreams.endpoints();
        select_upstream_inner(
            endpoints.as_slice(),
            &self.policy,
            &self.rr_counter,
            request_seed,
            sticky_seed,
        )
    }

    pub(super) fn health_upstream_pools(&self) -> Vec<Arc<UpstreamPool>> {
        vec![self.upstreams.clone()]
    }
}

impl RoutePolicy {
    pub(in crate::reverse) fn from_http_config(config: &ReverseRouteConfig) -> Result<Self> {
        let (retry_attempts, retry_backoff_ms) = config
            .resilience
            .as_ref()
            .map(resilience_retry_runtime)
            .unwrap_or((1, 0));
        let passive_health = config.resilience.as_ref().map(resilience_to_passive_health);
        let max_upstream_concurrency = config
            .resilience
            .as_ref()
            .and_then(|resilience| resilience.max_upstream_concurrency);
        Self::from_parts(RoutePolicyParts {
            lb: config.lb.as_str(),
            retry_attempts,
            retry_backoff_ms,
            timeout_ms: config.timeout_ms,
            health_check: config.health_check.as_ref(),
            passive_health,
            lifecycle: config.lifecycle.as_ref(),
            max_upstream_concurrency,
        })
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub(in crate::reverse) fn from_tls_config(
        config: &ReverseTlsPassthroughRouteConfig,
    ) -> Result<Self> {
        let (retry_attempts, retry_backoff_ms) = config
            .resilience
            .as_ref()
            .map(resilience_retry_runtime)
            .unwrap_or((1, 0));
        let passive_health = config.resilience.as_ref().map(resilience_to_passive_health);
        let max_upstream_concurrency = config
            .resilience
            .as_ref()
            .and_then(|resilience| resilience.max_upstream_concurrency);
        Self::from_parts(RoutePolicyParts {
            lb: config.lb.as_str(),
            retry_attempts,
            retry_backoff_ms,
            timeout_ms: config.timeout_ms,
            health_check: config.health_check.as_ref(),
            passive_health,
            lifecycle: config.lifecycle.as_ref(),
            max_upstream_concurrency,
        })
    }

    fn from_parts(parts: RoutePolicyParts<'_>) -> Result<Self> {
        let lb_lower = parts.lb.trim().to_ascii_lowercase();
        let lb = match lb_lower.as_str() {
            "round_robin" | "roundrobin" => LoadBalanceStrategy::RoundRobin,
            "random" => LoadBalanceStrategy::Random,
            "least_conn" | "least_connections" => LoadBalanceStrategy::LeastConnections,
            "consistent_hash" | "consistent-hash" => LoadBalanceStrategy::ConsistentHash,
            "sticky" | "sticky_ip" | "sticky-src-ip" => LoadBalanceStrategy::Sticky,
            other => return Err(anyhow::anyhow!("unknown lb strategy: {}", other)),
        };
        if parts.retry_attempts == 0 {
            return Err(anyhow::anyhow!("retry.attempts must be >= 1"));
        }
        let health = HealthCheckRuntime::from_config(parts.health_check);
        Ok(Self {
            lb,
            retry_attempts: parts.retry_attempts,
            retry_backoff: Duration::from_millis(parts.retry_backoff_ms),
            retry_budget: RetryBudgetRuntime::new(parts.retry_attempts),
            timeout: Duration::from_millis(parts.timeout_ms.unwrap_or(30_000)),
            passive_health: parts.passive_health,
            lifecycle: EndpointLifecycleRuntime::from_config(parts.lifecycle),
            max_upstream_concurrency: parts.max_upstream_concurrency,
            health,
        })
    }
}

struct RoutePolicyParts<'a> {
    lb: &'a str,
    retry_attempts: usize,
    retry_backoff_ms: u64,
    timeout_ms: Option<u64>,
    health_check: Option<&'a qpx_core::config::HealthCheckConfig>,
    passive_health: Option<PassiveHealthRuntime>,
    lifecycle: Option<&'a qpx_core::config::EndpointLifecycleConfig>,
    max_upstream_concurrency: Option<usize>,
}

fn resilience_to_passive_health(
    resilience: &qpx_core::config::ResilienceConfig,
) -> PassiveHealthRuntime {
    let consecutive = resilience
        .outlier_detection
        .as_ref()
        .and_then(|cfg| cfg.consecutive_failures.as_ref());
    let latency = resilience
        .outlier_detection
        .as_ref()
        .and_then(|cfg| cfg.latency.as_ref());
    let ejection = resilience.ejection.as_ref();
    PassiveHealthRuntime {
        consecutive_5xx: consecutive.and_then(|cfg| cfg.http_5xx).unwrap_or_default(),
        consecutive_timeouts: consecutive.and_then(|cfg| cfg.timeouts).unwrap_or_default(),
        consecutive_connect_errors: consecutive
            .and_then(|cfg| cfg.connect_errors)
            .unwrap_or_default(),
        consecutive_resets: consecutive.and_then(|cfg| cfg.resets).unwrap_or_default(),
        max_ejection: Duration::from_millis(
            ejection
                .and_then(|cfg| cfg.max_ms.or(cfg.base_ms))
                .unwrap_or(30_000)
                .max(1),
        ),
        latency_threshold: latency
            .and_then(|cfg| cfg.p95_ms)
            .map(|threshold| Duration::from_millis(threshold.max(1))),
    }
}

fn resilience_retry_runtime(resilience: &qpx_core::config::ResilienceConfig) -> (usize, u64) {
    resilience
        .retry
        .as_ref()
        .map(|retry| (retry.attempts, retry.backoff_ms))
        .unwrap_or((1, 0))
}

pub(in crate::reverse) fn normalize_host_for_match(raw: &str) -> String {
    if let Ok(authority) = raw.parse::<http::uri::Authority>() {
        return authority.host().to_ascii_lowercase();
    }
    raw.to_ascii_lowercase()
}
