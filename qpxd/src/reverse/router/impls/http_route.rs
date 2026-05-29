use super::super::compile::{
    compile_backends, compile_mirrors, compile_response_rules, select_weighted_backend_idx,
};
use super::super::selection::select_upstream_inner;
use super::super::{
    CompiledPathRewrite, HttpRoute, ReverseAffinityRuntime, RoutePolicy, SelectedMirrorTarget,
    UpstreamPool,
};
use crate::http::body::Body;
use crate::ipc_client::IpcUpstream;
use crate::reverse::health::UpstreamEndpoint;
use crate::tls::CompiledUpstreamTlsTrust;
use anyhow::Result;
use hyper::Request;
use qpx_core::config::{ReverseRouteConfig, ReverseRouteTargetConfig, UpstreamConfig};
use qpx_core::prefilter::{MatchPrefilterContext, MatchPrefilterHint, StringInterner};
use qpx_core::rules::{CompiledHeaderControl, RuleMatchContext};
use std::collections::HashMap;
use std::sync::Arc;

impl HttpRoute {
    pub(in crate::reverse) fn from_config(
        config: ReverseRouteConfig,
        upstreams: &HashMap<&str, &UpstreamConfig>,
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

        let (local_response, ipc, backends) = match config.target {
            ReverseRouteTargetConfig::Upstream {
                upstreams: refs, ..
            } => (
                None,
                None,
                compile_backends(refs, Vec::new(), upstreams, &policy.lifecycle)?,
            ),
            ReverseRouteTargetConfig::Weighted { backends, .. } => (
                None,
                None,
                compile_backends(Vec::new(), backends, upstreams, &policy.lifecycle)?,
            ),
            ReverseRouteTargetConfig::Ipc { config } => {
                (None, Some(IpcUpstream::from_config(&config)?), Vec::new())
            }
            ReverseRouteTargetConfig::LocalResponse { response } => {
                (Some(*response), None, Vec::new())
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

    pub(in crate::reverse) fn matches_without_request_body_observation(
        &self,
        ctx: &RuleMatchContext<'_>,
    ) -> bool {
        self.matcher.matches_without_request_body_observation(ctx)
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

    pub(in crate::reverse::router) fn health_upstream_pools(&self) -> Vec<Arc<UpstreamPool>> {
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
