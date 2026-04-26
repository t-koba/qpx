use super::{DynamicDiscovery, MirrorTarget, UpstreamPool, WeightedBackend};
use crate::http::response_policy::HttpResponseRuleEngine;
use anyhow::Result;
use qpx_core::config::{
    HttpResponseRuleConfig, ReverseRouteBackendConfig, UpstreamConfig, UpstreamDiscoveryConfig,
};
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::time::Duration;

use crate::reverse::health::{EndpointLifecycleRuntime, UpstreamEndpoint};
use crate::upstream::origin::{discover_origin_endpoints, OriginEndpoint};

#[derive(Debug)]
struct ResolvedRouteUpstream {
    target: String,
    discovery: Option<UpstreamDiscoveryConfig>,
}

pub(super) fn compile_backends(
    upstreams: Vec<String>,
    backends: Vec<ReverseRouteBackendConfig>,
    upstream_configs: &HashMap<&str, &UpstreamConfig>,
    lifecycle: &EndpointLifecycleRuntime,
) -> Result<Vec<WeightedBackend>> {
    if !backends.is_empty() {
        return backends
            .into_iter()
            .map(|b| {
                Ok(WeightedBackend {
                    weight: b.weight,
                    upstreams: compile_upstream_pool(
                        b.upstreams,
                        upstream_configs,
                        false,
                        lifecycle,
                    )?,
                    rr_counter: AtomicUsize::new(0),
                })
            })
            .collect();
    }
    if upstreams.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![WeightedBackend {
        weight: 1,
        upstreams: compile_upstream_pool(upstreams, upstream_configs, false, lifecycle)?,
        rr_counter: AtomicUsize::new(0),
    }])
}

pub(super) fn compile_mirrors(
    mirrors: Vec<qpx_core::config::ReverseRouteMirrorConfig>,
    upstream_configs: &HashMap<&str, &UpstreamConfig>,
    lifecycle: &EndpointLifecycleRuntime,
) -> Result<Vec<MirrorTarget>> {
    mirrors
        .into_iter()
        .map(|m| {
            Ok(MirrorTarget {
                percent: m.percent,
                upstreams: compile_upstream_pool(m.upstreams, upstream_configs, false, lifecycle)?,
                rr_counter: AtomicUsize::new(0),
            })
        })
        .collect()
}

pub(super) fn compile_response_rules(
    rules: &[HttpResponseRuleConfig],
) -> Result<Option<Arc<HttpResponseRuleEngine>>> {
    Ok(HttpResponseRuleEngine::new(rules)?.map(Arc::new))
}

pub(super) fn compile_upstream_pool(
    upstream_refs: Vec<String>,
    upstream_configs: &HashMap<&str, &UpstreamConfig>,
    allow_authority: bool,
    lifecycle: &EndpointLifecycleRuntime,
) -> Result<Arc<UpstreamPool>> {
    let mut static_endpoints = Vec::new();
    let mut seed_endpoints = Vec::new();
    let mut discovery = Vec::new();

    for upstream_ref in upstream_refs {
        let resolved =
            resolve_route_upstream(upstream_ref.as_str(), upstream_configs, allow_authority)?;
        if let Some(config) = resolved.discovery {
            discovery.push(DynamicDiscovery {
                base_upstream: Arc::<str>::from(resolved.target.as_str()),
                config,
            });
            seed_endpoints.push(Arc::new(UpstreamEndpoint::new(resolved.target)));
        } else {
            let endpoint = Arc::new(UpstreamEndpoint::new(resolved.target));
            static_endpoints.push(endpoint.clone());
            seed_endpoints.push(endpoint);
        }
    }

    Ok(UpstreamPool::new(
        static_endpoints,
        seed_endpoints,
        discovery,
        lifecycle.clone(),
    ))
}

fn resolve_route_upstream(
    upstream_ref: &str,
    upstream_configs: &HashMap<&str, &UpstreamConfig>,
    allow_authority: bool,
) -> Result<ResolvedRouteUpstream> {
    if upstream_ref.contains("://") {
        return Ok(ResolvedRouteUpstream {
            target: upstream_ref.to_string(),
            discovery: None,
        });
    }
    if allow_authority
        && (upstream_ref.contains(':') || upstream_ref.starts_with('['))
        && crate::http::address::parse_authority_host_port(upstream_ref, 443).is_some()
    {
        return Ok(ResolvedRouteUpstream {
            target: upstream_ref.to_string(),
            discovery: None,
        });
    }
    let upstream = upstream_configs
        .get(upstream_ref)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("unknown upstream reference: {}", upstream_ref))?;
    Ok(ResolvedRouteUpstream {
        target: upstream.url.clone(),
        discovery: upstream.discovery.clone(),
    })
}

pub(super) async fn refresh_dynamic_upstreams(
    discovery: &[DynamicDiscovery],
) -> Result<(Vec<OriginEndpoint>, Duration)> {
    let mut endpoints = Vec::new();
    let mut next_delay: Option<Duration> = None;
    for entry in discovery {
        let (resolved, delay) =
            discover_origin_endpoints(entry.base_upstream.as_ref(), &entry.config).await?;
        next_delay = Some(match next_delay {
            Some(current) => current.min(delay),
            None => delay,
        });
        endpoints.extend(resolved);
    }
    Ok((
        endpoints,
        next_delay.unwrap_or_else(|| Duration::from_secs(30)),
    ))
}

pub(super) fn select_weighted_backend_idx(
    backends: &[WeightedBackend],
    seed: u64,
) -> Option<usize> {
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
