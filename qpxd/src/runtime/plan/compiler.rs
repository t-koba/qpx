// Extracted from runtime/plan.rs; public surface is re-exported by mod.rs.
use super::types::*;
use crate::policy_context::EffectivePolicyContext;
use crate::rate_limit::{CompiledRateLimitPlan, RateLimitSet};
use crate::runtime::RuntimeResources;
use anyhow::Result;
use qpx_core::config::{IngressEdgeMode, ReverseRouteTargetConfig};
use qpx_core::matchers::CompiledMatch;
use qpx_core::prefilter::StringInterner;
use std::sync::Arc;

mod common;
mod streaming;

use self::common::{
    ExecutionPlanInputs, compile_ingress_edge_settings, execution_plan_for_forward_action,
    execution_plan_for_reverse_route,
};
#[cfg(test)]
pub(super) use self::streaming::validate_streaming_requirement;
pub(super) use self::streaming::{resolve_streaming_limits, validate_streaming_required_route};
use self::streaming::{
    validate_streaming_required_plan, validate_unknown_length_exact_size_policy,
};

fn compile_reverse_route_target(target: &ReverseRouteTargetConfig) -> CompiledReverseRouteTarget {
    match target {
        ReverseRouteTargetConfig::Upstream { upstreams, lb } => {
            CompiledReverseRouteTarget::Upstream {
                upstreams: upstreams
                    .iter()
                    .map(|upstream| Arc::<str>::from(upstream.as_str()))
                    .collect::<Vec<_>>()
                    .into(),
                lb: Arc::from(lb.as_str()),
            }
        }
        ReverseRouteTargetConfig::Weighted { backends, lb } => {
            CompiledReverseRouteTarget::Weighted {
                backends: backends
                    .iter()
                    .map(|backend| CompiledRouteBackend {
                        name: backend.name.as_deref().map(Arc::<str>::from),
                        weight: backend.weight,
                        upstreams: backend
                            .upstreams
                            .iter()
                            .map(|upstream| Arc::<str>::from(upstream.as_str()))
                            .collect::<Vec<_>>()
                            .into(),
                    })
                    .collect::<Vec<_>>()
                    .into(),
                lb: Arc::from(lb.as_str()),
            }
        }
        ReverseRouteTargetConfig::Ipc { config } => CompiledReverseRouteTarget::Ipc {
            mode: Arc::from(match config.mode {
                qpx_core::config::IpcMode::Shm => "shm",
                qpx_core::config::IpcMode::Tcp => "tcp",
            }),
            address: Arc::from(config.address.as_str()),
        },
        ReverseRouteTargetConfig::LocalResponse { response } => {
            CompiledReverseRouteTarget::LocalResponse {
                status: response.status,
            }
        }
    }
}

pub struct PlanCompiler<'a> {
    pub config: &'a RuntimeResources,
}

impl<'a> PlanCompiler<'a> {
    pub fn compile(&self) -> Result<RuntimePlan> {
        let mut edges = Vec::new();
        let mut interner = StringInterner::default();
        for listener in self.config.operational.ingress_edge_configs() {
            let ingress_edge_settings = compile_ingress_edge_settings(listener)?;
            let default_action_kind = listener.default_action.kind.clone();
            let default_plan = execution_plan_for_forward_action(
                self.config,
                ExecutionPlanInputs {
                    listener_streaming: listener.streaming.as_ref(),
                    route_streaming: None,
                    listener_grpc: listener.grpc.as_ref(),
                    route_grpc: None,
                    listener_sse: listener.sse.as_ref(),
                    route_sse: None,
                    policy_context: EffectivePolicyContext::from_single(
                        listener.policy_context.as_ref(),
                    ),
                    destination_resolution: listener.destination_resolution.as_ref(),
                    http_guard_profile: listener.http_guard_profile.as_deref(),
                    cache: listener.cache.as_ref(),
                    capture: listener.capture.as_ref(),
                    rate_limit: listener.rate_limit.as_ref(),
                    http: listener.http.as_ref(),
                    http_modules: listener.http_modules.as_slice(),
                    streaming_requirement: listener.streaming_requirement.as_ref(),
                },
                Some(&listener.default_action),
            )?;
            let listener_rate_limits = RateLimitSet::from_config(listener.rate_limit.as_ref());
            let mut default_plan = default_plan;
            default_plan.rate_limits = CompiledRateLimitPlan::from_sets(
                listener_rate_limits.clone(),
                RateLimitSet::default(),
            );
            validate_streaming_required_plan(
                listener.streaming_requirement.as_ref(),
                &default_plan,
            )?;
            validate_unknown_length_exact_size_policy(
                listener.streaming_requirement.as_ref(),
                &default_plan,
                self.config.operational.runtime.unknown_length_exact_size,
            )?;
            let rules = listener
                .rules
                .iter()
                .map(|rule| {
                    let match_cfg = rule.r#match.clone().unwrap_or_default();
                    let (matcher, _) = CompiledMatch::compile(&match_cfg, &mut interner)?;
                    let action = rule.action.as_ref().unwrap_or(&listener.default_action);
                    let action_kind = action.kind.clone();
                    let mut plan = execution_plan_for_forward_action(
                        self.config,
                        ExecutionPlanInputs {
                            listener_streaming: listener.streaming.as_ref(),
                            route_streaming: None,
                            listener_grpc: listener.grpc.as_ref(),
                            route_grpc: None,
                            listener_sse: listener.sse.as_ref(),
                            route_sse: None,
                            policy_context: EffectivePolicyContext::from_single(
                                listener.policy_context.as_ref(),
                            ),
                            destination_resolution: listener.destination_resolution.as_ref(),
                            http_guard_profile: listener.http_guard_profile.as_deref(),
                            cache: listener.cache.as_ref(),
                            capture: listener.capture.as_ref(),
                            rate_limit: rule.rate_limit.as_ref().or(listener.rate_limit.as_ref()),
                            http: listener.http.as_ref(),
                            http_modules: listener.http_modules.as_slice(),
                            streaming_requirement: listener.streaming_requirement.as_ref(),
                        },
                        Some(action),
                    )?;
                    plan.rate_limits = CompiledRateLimitPlan::from_sets(
                        listener_rate_limits.clone(),
                        RateLimitSet::from_config(rule.rate_limit.as_ref()),
                    );
                    if rule
                        .auth
                        .as_ref()
                        .map(|auth| !auth.require.is_empty())
                        .unwrap_or(false)
                    {
                        plan.flags.insert(PlanFlags::AUTH);
                    }
                    apply_matcher_flags(&matcher, &mut plan);
                    validate_streaming_required_route(
                        listener.streaming_requirement.as_ref(),
                        &matcher,
                        &plan,
                    )?;
                    validate_unknown_length_exact_size_policy(
                        listener.streaming_requirement.as_ref(),
                        &plan,
                        self.config.operational.runtime.unknown_length_exact_size,
                    )?;
                    Ok(CompiledForwardRule {
                        name: Arc::from(rule.name.as_str()),
                        matcher,
                        action_kind,
                        plan,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let flags = rules.iter().fold(default_plan.flags, |flags, rule| {
                flags.union(rule.plan.flags)
            });
            match listener.mode {
                IngressEdgeMode::Forward => {
                    edges.push(CompiledEdge::Forward(CompiledForwardEdge {
                        name: Arc::from(listener.name.as_str()),
                        listener: ingress_edge_settings,
                        flags,
                        default_action_kind,
                        default_plan,
                        rules: rules.into_iter().collect::<Vec<_>>().into(),
                    }))
                }
                IngressEdgeMode::Transparent => {
                    edges.push(CompiledEdge::Transparent(CompiledTransparentEdge {
                        name: Arc::from(listener.name.as_str()),
                        listener: ingress_edge_settings,
                        flags,
                        default_action_kind,
                        default_plan,
                        rules: rules
                            .into_iter()
                            .map(|rule| CompiledTransparentRule {
                                name: rule.name,
                                matcher: rule.matcher,
                                action_kind: rule.action_kind,
                                plan: rule.plan,
                            })
                            .collect::<Vec<_>>()
                            .into(),
                    }))
                }
            }
        }

        for reverse_edges in self.config.operational.reverse_edge_configs() {
            let routes = reverse_edges
                .routes
                .iter()
                .enumerate()
                .map(|(idx, route)| {
                    let (matcher, hint) = CompiledMatch::compile(&route.r#match, &mut interner)?;
                    let mut plan =
                        execution_plan_for_reverse_route(self.config, reverse_edges, route)?;
                    apply_matcher_flags(&matcher, &mut plan);
                    validate_streaming_required_route(
                        route.streaming_requirement.as_ref(),
                        &matcher,
                        &plan,
                    )?;
                    validate_unknown_length_exact_size_policy(
                        route.streaming_requirement.as_ref(),
                        &plan,
                        self.config.operational.runtime.unknown_length_exact_size,
                    )?;
                    let id = Arc::<str>::from(route_id(idx, route.name.as_deref()));
                    Ok(CompiledReverseRoute {
                        id: id.clone(),
                        name: id,
                        matcher,
                        hint,
                        target: compile_reverse_route_target(&route.target),
                        plan,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let tls_passthrough_routes = reverse_edges
                .tls_passthrough_routes
                .iter()
                .enumerate()
                .map(|(idx, route)| {
                    let (matcher, tls_passthrough_hint) =
                        CompiledMatch::compile_tls_passthrough(&route.r#match, &mut interner)?;
                    #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
                    let _ = tls_passthrough_hint;
                    Ok(CompiledTlsPassthroughRoute {
                        id: Arc::from(format!("tls_passthrough[{idx}]")),
                        name: Arc::from(format!("tls_passthrough[{idx}]")),
                        matcher,
                        #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
                        hint: tls_passthrough_hint,
                        target: CompiledReverseRouteTarget::TlsPassthrough {
                            upstreams: route
                                .upstreams
                                .iter()
                                .map(|upstream| Arc::from(upstream.as_str()))
                                .collect::<Vec<_>>()
                                .into(),
                            lb: Arc::from(route.lb.as_str()),
                        },
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let flags = tls_passthrough_routes.iter().fold(
                routes.iter().fold(PlanFlags::empty(), |flags, route| {
                    flags.union(route.plan.flags)
                }),
                |mut flags, route| {
                    if route.matcher.requires_tls_fingerprint() {
                        flags.insert(PlanFlags::TLS_FINGERPRINT);
                    }
                    flags
                },
            );
            let streaming = resolve_streaming_limits(
                &self.config.operational.runtime,
                reverse_edges.streaming.as_ref(),
                None,
                reverse_edges.grpc.as_ref(),
                None,
                reverse_edges.sse.as_ref(),
                None,
            );
            edges.push(CompiledEdge::Reverse(CompiledReverseEdge {
                name: Arc::from(reverse_edges.name.as_str()),
                flags,
                streaming,
                routes: routes.into(),
                tls_passthrough_routes: tls_passthrough_routes.into(),
            }));
        }

        Ok(RuntimePlan {
            edges: edges.into(),
            identity: CompiledRuntimeIdentity {
                proxy_name: Arc::from(self.config.operational.identity.proxy_name.as_str()),
            },
            limits: CompiledRuntimeLimits {
                general: GeneralLimits {
                    reuse_port: self.config.operational.runtime.reuse_port,
                    trace_enabled: self.config.operational.runtime.trace_enabled,
                    trace_reflect_all_headers: self
                        .config
                        .operational
                        .runtime
                        .trace_reflect_all_headers,
                    max_concurrent_connections: self
                        .config
                        .operational
                        .runtime
                        .max_concurrent_connections,
                },
                timeouts: TimeoutLimits {
                    upstream_http_timeout_ms: self
                        .config
                        .operational
                        .runtime
                        .upstream_http_timeout_ms,
                    tls_peek_timeout_ms: self.config.operational.runtime.tls_peek_timeout_ms,
                    http_header_read_timeout_ms: self
                        .config
                        .operational
                        .runtime
                        .http_header_read_timeout_ms,
                    upgrade_wait_timeout_ms: self
                        .config
                        .operational
                        .runtime
                        .upgrade_wait_timeout_ms,
                    tunnel_idle_timeout_ms: self.config.operational.runtime.tunnel_idle_timeout_ms,
                    h3_read_timeout_ms: self.config.operational.runtime.h3_read_timeout_ms,
                },
                body: BodyLimits {
                    max_observed_request_body_bytes: self
                        .config
                        .operational
                        .runtime
                        .max_observed_request_body_bytes,
                    max_observed_response_body_bytes: self
                        .config
                        .operational
                        .runtime
                        .max_observed_response_body_bytes,
                    max_h3_request_body_bytes: self
                        .config
                        .operational
                        .runtime
                        .max_h3_request_body_bytes,
                    max_h3_response_body_bytes: self
                        .config
                        .operational
                        .runtime
                        .max_h3_response_body_bytes,
                    body_channel_capacity: self.config.operational.runtime.body_channel_capacity,
                },
                grpc: GrpcLimits {
                    max_grpc_message_bytes: self.config.operational.runtime.max_grpc_message_bytes,
                    max_grpc_web_trailer_bytes: self
                        .config
                        .operational
                        .runtime
                        .max_grpc_web_trailer_bytes,
                    max_grpc_stream_duration_ms: self
                        .config
                        .operational
                        .runtime
                        .max_grpc_stream_duration_ms,
                },
                h3: H3ChannelLimits {
                    max_h3_streams_per_connection: self
                        .config
                        .operational
                        .runtime
                        .max_h3_streams_per_connection,
                    datagram_channel_capacity: self
                        .config
                        .operational
                        .runtime
                        .datagram_channel_capacity,
                    webtransport_datagram_channel_capacity: self
                        .config
                        .operational
                        .runtime
                        .webtransport_datagram_channel_capacity,
                    webtransport_stream_channel_capacity: self
                        .config
                        .operational
                        .runtime
                        .webtransport_stream_channel_capacity,
                },
                upstream: UpstreamLimits {
                    upstream_proxy_max_concurrent_per_endpoint: self
                        .config
                        .operational
                        .runtime
                        .upstream_proxy_max_concurrent_per_endpoint,
                    max_reverse_retry_template_body_bytes: self
                        .config
                        .operational
                        .runtime
                        .max_reverse_retry_template_body_bytes,
                },
                sse: self.config.operational.runtime.sse,
            },
        })
    }
}

fn route_id(idx: usize, name: Option<&str>) -> String {
    name.map(str::to_string)
        .unwrap_or_else(|| format!("route[{idx}]"))
}

pub(super) fn apply_matcher_flags(matcher: &CompiledMatch, plan: &mut ExecutionPlan) {
    if matcher.requires_tls_fingerprint() {
        plan.flags.insert(PlanFlags::TLS_FINGERPRINT);
    }
    if matcher.requires_request_body_observation() {
        plan.flags.insert(PlanFlags::REQUEST_BODY_OBSERVE);
        plan.add_buffering_reason("rpc.body");
    }
    if matcher.requires_response_body_observation() || matcher.requires_response_rpc_observation() {
        plan.flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
        plan.add_buffering_reason("rpc.response_body");
    }
    if matcher.requires_request_size_matcher() {
        plan.add_buffering_reason("request.size_exact_unknown");
    }
    if matcher.requires_response_size_matcher() {
        plan.add_buffering_reason("response.size_exact_unknown");
    }
}
