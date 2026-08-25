use super::super::compile::{
    compile_backends, compile_mirrors, compile_response_rules, select_weighted_backend_idx,
};
use super::super::selection::select_upstream_inner;
use super::super::{
    CompiledPathRewrite, HttpRoute, ReverseAffinityRuntime, RoutePolicy, SelectedMirrorTarget,
    UpstreamEndpointSet,
};
use crate::ipc_client::IpcUpstream;
use crate::reverse::health::UpstreamEndpoint;
use anyhow::Result;
use hyper::Request;
use qpx_core::config::WebDavOriginConfig;
use qpx_core::config::{ReverseRouteConfig, ReverseRouteTargetConfig, UpstreamConfig};
use qpx_core::prefilter::{MatchPrefilterContext, MatchPrefilterHint, StringInterner};
use qpx_core::rules::{CompiledHeaderControl, RuleMatchContext};
use qpx_core::tls::CompiledUpstreamTlsTrust;
use qpx_http::body::Body;
use std::collections::HashMap;
use std::sync::Arc;

impl HttpRoute {
    pub(in crate::reverse) fn from_config(
        config: ReverseRouteConfig,
        upstreams: &HashMap<&str, &UpstreamConfig>,
        webdav_origins: &HashMap<&str, &WebDavOriginConfig>,
        interner: &mut StringInterner,
        _http_module_registry: &crate::http::modules::HttpModuleRegistry,
        compiled_route: &crate::runtime::CompiledReverseRoute,
    ) -> Result<(Self, MatchPrefilterHint)> {
        let _ = interner;
        let matcher = compiled_route.matcher.clone();
        let hint = compiled_route.hint.clone();
        let policy = RoutePolicy::from_http_config(&config)?;
        let affinity = ReverseAffinityRuntime::from_config(config.affinity.as_ref())?;
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

        let (local_response, ipc, webdav, backends) = match config.target {
            ReverseRouteTargetConfig::Upstream {
                upstreams: refs, ..
            } => (
                None,
                None,
                None,
                compile_backends(refs, Vec::new(), upstreams, &policy.lifecycle)?,
            ),
            ReverseRouteTargetConfig::Weighted { backends, .. } => (
                None,
                None,
                None,
                compile_backends(Vec::new(), backends, upstreams, &policy.lifecycle)?,
            ),
            ReverseRouteTargetConfig::Ipc { config } => (
                None,
                Some(IpcUpstream::from_config(&config)?),
                None,
                Vec::new(),
            ),
            ReverseRouteTargetConfig::LocalResponse { response } => (
                Some(crate::http::local_response::CompiledLocalResponse::compile(
                    *response,
                )?),
                None,
                None,
                Vec::new(),
            ),
            ReverseRouteTargetConfig::Webdav { origin } => {
                let origin = webdav_origins.get(origin.as_str()).ok_or_else(|| {
                    anyhow::anyhow!("unknown WebDAV origin during route compilation: {origin}")
                })?;
                let data = qpx_webdav::FileSystemDataStore::open(&origin.root)?;
                let metadata = qpx_webdav::RedbMetadataStore::open(&origin.metadata)?;
                let store = qpx_webdav::PersistentWebDavStore::new(data, metadata);
                let service = qpx_webdav::WebDavService::new(Arc::new(store)).with_limits(
                    origin.max_depth,
                    origin.max_multistatus_entries,
                    origin.max_lock_timeout_seconds,
                )?;
                (None, None, Some(Arc::new(service)), Vec::new())
            }
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
        Ok((
            Self {
                matcher,
                name: config.name.as_deref().map(Arc::<str>::from),
                target: compiled_route.target.clone(),
                plan: compiled_route.plan.clone(),
                local_response,
                headers,
                ipc,
                webdav,
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

    pub(in crate::reverse) fn matches_every_request(&self) -> bool {
        self.matcher.is_unconditional()
    }

    pub(in crate::reverse) fn matches_without_request_body_observation(
        &self,
        ctx: &RuleMatchContext<'_>,
    ) -> bool {
        self.matcher.matches_without_request_body_observation(ctx)
    }

    pub(in crate::reverse) fn requires_request_size(&self) -> bool {
        self.matcher.requires_request_size()
    }

    pub(in crate::reverse) fn requires_destination_context(&self) -> bool {
        self.matcher.requires_destination_context()
    }

    pub(in crate::reverse) fn requires_destination_after_selection(&self) -> bool {
        self.response_rules
            .as_deref()
            .is_some_and(|rules| rules.any_rule_requires_destination_context())
    }

    pub(in crate::reverse) fn requires_request_body_observation(&self) -> bool {
        self.matcher.requires_request_body_observation()
    }

    pub(in crate::reverse) fn requires_request_rpc_context(&self) -> bool {
        self.matcher.requires_request_rpc_context()
    }

    pub(in crate::reverse) fn response_rule_candidate_profile(
        &self,
        ctx: MatchPrefilterContext<'_>,
    ) -> crate::http::policy::response_policy::ResponseRuleCandidates {
        self.response_rules
            .as_ref()
            .map(|engine| engine.candidate_profile(ctx))
            .unwrap_or_default()
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

    pub(in crate::reverse) fn selection_is_seed_independent(&self) -> bool {
        self.mirrors.is_empty()
            && self.backends.len() == 1
            && self.backends[0].upstreams.is_single_static_endpoint()
    }

    pub(in crate::reverse) fn single_plain_http_upstream(&self) -> Option<&UpstreamEndpoint> {
        let [backend] = self.backends.as_slice() else {
            return None;
        };
        let endpoint = backend.upstreams.single_static_endpoint()?;
        endpoint
            .origin
            .direct_plain_http1_authorities()
            .map(|_| endpoint.as_ref())
    }

    pub(in crate::reverse) fn single_plain_http_upstream_arc(
        &self,
    ) -> Option<Arc<UpstreamEndpoint>> {
        let [backend] = self.backends.as_slice() else {
            return None;
        };
        let endpoint = backend.upstreams.single_static_endpoint()?;
        endpoint
            .origin
            .direct_plain_http1_authorities()
            .map(|_| Arc::clone(endpoint))
    }

    pub(in crate::reverse) fn available_plain_http_upstream(&self) -> Option<&UpstreamEndpoint> {
        let endpoint = self.single_plain_http_upstream()?;
        (!endpoint.has_time_dependent_admission_state()).then_some(endpoint)
    }

    pub(in crate::reverse) fn supports_plain_http_dispatch(&self) -> bool {
        self.plan.flags.bits() == 0
            && self.plan.api_metadata.is_none()
            && self.plan.hsts.is_none()
            && self.plan.forwarded.is_none()
            && self
                .plan
                .rate_limits
                .is_empty_for_scope(crate::rate_limit::TransportScope::Request)
            && self.headers.is_none()
            && self.local_response.is_none()
            && self.ipc.is_none()
            && self.webdav.is_none()
            && self.response_rules.is_none()
            && self.path_rewrite.is_none()
            && self.policy.retry_attempts == 1
            && self.policy.max_upstream_concurrency.is_none()
            && self.selection_is_seed_independent()
            && self.single_plain_http_upstream().is_some()
            && !self.requires_destination_context()
            && !self.requires_request_size()
            && !self.requires_request_body_observation()
            && !self.requires_request_rpc_context()
            && matches!(
                self.target,
                crate::runtime::CompiledReverseRouteTarget::Upstream { .. }
                    | crate::runtime::CompiledReverseRouteTarget::Weighted { .. }
            )
    }

    pub(in crate::reverse) fn supports_raw_http1_dispatch(&self) -> bool {
        self.supports_plain_http_dispatch()
            && !self.matcher.requires_request_headers()
            && !self.plan.require_precondition
    }

    pub(in crate::reverse) fn supports_raw_cache_hit_dispatch(&self) -> bool {
        // Same eligibility as the plain raw HTTP/1 dispatch except the route
        // may carry exactly a lookup+store cache policy: only unconditional
        // GETs served from the hot response cache can take that path, and any
        // other request shape falls back to the generic dispatch chain. The
        // strict flag equality keeps every non-cache feature (guard, auth,
        // forwarded, rate limits, header controls, modules, capture, ...)
        // structurally out of scope for the fast path.
        self.plan.flags
            == crate::runtime::PlanFlags::CACHE_LOOKUP.union(crate::runtime::PlanFlags::CACHE_STORE)
            && !self.matcher.requires_request_headers()
            && !self.plan.require_precondition
            && self.plan.api_metadata.is_none()
            && self.plan.hsts.is_none()
            && self.plan.forwarded.is_none()
            && self
                .plan
                .rate_limits
                .is_empty_for_scope(crate::rate_limit::TransportScope::Request)
            && self.headers.is_none()
            && self.local_response.is_none()
            && self.ipc.is_none()
            && self.webdav.is_none()
            && self.response_rules.is_none()
            && self.path_rewrite.is_none()
            && self.mirrors.is_empty()
            && self.policy.retry_attempts == 1
            && self.policy.max_upstream_concurrency.is_none()
            && self.selection_is_seed_independent()
            && self.single_plain_http_upstream().is_some()
            && !self.requires_destination_context()
            && !self.requires_request_size()
            && !self.requires_request_body_observation()
            && !self.requires_request_rpc_context()
            && matches!(
                self.target,
                crate::runtime::CompiledReverseRouteTarget::Upstream { .. }
                    | crate::runtime::CompiledReverseRouteTarget::Weighted { .. }
            )
    }

    pub(in crate::reverse) fn supports_direct_local_response_dispatch(&self) -> bool {
        self.plan.flags.bits() == 0
            && self.plan.forwarded.is_none()
            && self
                .plan
                .rate_limits
                .is_empty_for_scope(crate::rate_limit::TransportScope::Request)
            && !self.plan.require_precondition
            && self.headers.is_none()
            && self.local_response.is_some()
            && self.ipc.is_none()
            && self.webdav.is_none()
            && self.response_rules.is_none()
            && self.mirrors.is_empty()
            && self.policy.max_upstream_concurrency.is_none()
            && !self.requires_destination_context()
            && !self.requires_request_size()
            && !self.requires_request_body_observation()
            && !self.requires_request_rpc_context()
            && matches!(
                self.target,
                crate::runtime::CompiledReverseRouteTarget::LocalResponse { .. }
            )
    }

    pub(in crate::reverse) fn supports_raw_local_response_dispatch(&self) -> bool {
        self.supports_direct_local_response_dispatch() && !self.matcher.requires_request_headers()
    }

    pub(in crate::reverse) fn supports_direct_webdav_dispatch(&self) -> bool {
        self.plan.flags.bits() == 0
            && self.plan.forwarded.is_none()
            && self
                .plan
                .rate_limits
                .is_empty_for_scope(crate::rate_limit::TransportScope::Request)
            && self.headers.is_none()
            && self.local_response.is_none()
            && self.ipc.is_none()
            && self.webdav.is_some()
            && self.response_rules.is_none()
            && self.mirrors.is_empty()
            && self.policy.max_upstream_concurrency.is_none()
            && !self.requires_destination_context()
            && !self.requires_request_size()
            && !self.requires_request_body_observation()
            && !self.requires_request_rpc_context()
            && matches!(
                self.target,
                crate::runtime::CompiledReverseRouteTarget::Webdav { .. }
            )
    }

    pub(in crate::reverse) fn select_upstream(
        &self,
        request_seed: u64,
        sticky_seed: u64,
    ) -> Option<Arc<UpstreamEndpoint>> {
        let idx = select_weighted_backend_idx(&self.backends, request_seed)?;
        let backend = &self.backends[idx];
        if let Some(endpoints) = backend.upstreams.fixed_endpoints() {
            return select_upstream_inner(
                endpoints,
                &self.policy,
                &backend.rr_counter,
                request_seed,
                sticky_seed,
            );
        }
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
    ) -> Vec<SelectedMirrorTarget> {
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
                out.push(SelectedMirrorTarget {
                    upstream,
                    max_mirror_body_bytes: mirror.max_mirror_body_bytes,
                });
            }
        }
        out
    }

    pub(in crate::reverse::router) fn health_upstream_pools(
        &self,
    ) -> Vec<Arc<UpstreamEndpointSet>> {
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
