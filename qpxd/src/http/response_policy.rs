use crate::http::body::Body;
use crate::http::body_size::observed_response_size;
use crate::http::local_response::build_local_response;
use crate::http::observation::ResponseObservationPlan;
use crate::http::rpc::RpcMatchContext;
use crate::policy_context::merge_header_controls;
use anyhow::Result;
use hyper::Response;
use qpx_core::config::HttpResponseRuleConfig;
use qpx_core::prefilter::{MatchPrefilterContext, MatchPrefilterIndex, StringInterner};
use qpx_core::rules::{CompiledHeaderControl, RuleMatchContext};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy)]
pub(crate) struct ResponseBodyObservationLimits {
    pub(crate) max_body_bytes: usize,
    pub(crate) read_timeout: Duration,
}

pub(crate) enum ListenerResponsePolicyDecision {
    Continue {
        response: Response<Body>,
        headers: Option<Arc<CompiledHeaderControl>>,
        cache_bypass: bool,
        suppress_retry: bool,
        mirror: Option<bool>,
        policy_tags: Vec<String>,
    },
    LocalResponse {
        response: Response<Body>,
        headers: Option<Arc<CompiledHeaderControl>>,
        policy_tags: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct HttpResponseRuleEngine {
    rules: Vec<CompiledHttpResponseRule>,
    prefilter: MatchPrefilterIndex,
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledHttpResponseRule {
    pub(crate) matcher: qpx_core::matchers::CompiledMatch,
    pub(crate) local_response: Option<qpx_core::config::LocalResponseConfig>,
    pub(crate) headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) cache_bypass: bool,
    pub(crate) suppress_retry: bool,
    pub(crate) mirror: Option<bool>,
    pub(crate) policy_tags: Arc<[String]>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ResponseRuleCandidates {
    pub(crate) indices: Vec<usize>,
    pub(crate) requires_response_size: bool,
    pub(crate) requires_response_body_observation: bool,
    pub(crate) requires_response_rpc_context: bool,
    pub(crate) requires_request_rpc_context: bool,
    pub(crate) requires_request_body_observation: bool,
    pub(crate) requires_response_rpc_observation: bool,
}

impl HttpResponseRuleEngine {
    pub(crate) fn new(rules: &[HttpResponseRuleConfig]) -> Result<Option<Self>> {
        if rules.is_empty() {
            return Ok(None);
        }

        let mut interner = StringInterner::default();
        let mut compiled = Vec::with_capacity(rules.len());
        let mut hints = Vec::with_capacity(rules.len());
        for rule in rules {
            let (matcher, hint) = qpx_core::matchers::CompiledMatch::compile(
                rule.r#match.as_ref().unwrap_or(&Default::default()),
                &mut interner,
            )?;
            compiled.push(CompiledHttpResponseRule {
                matcher,
                local_response: rule.effects.local_response.clone(),
                headers: rule
                    .effects
                    .headers
                    .as_ref()
                    .map(CompiledHeaderControl::compile)
                    .transpose()?
                    .map(Arc::new),
                cache_bypass: rule
                    .effects
                    .cache
                    .as_ref()
                    .map(|cache| cache.bypass)
                    .unwrap_or(false),
                suppress_retry: rule
                    .effects
                    .retry
                    .as_ref()
                    .map(|retry| retry.suppress)
                    .unwrap_or(false),
                mirror: rule
                    .effects
                    .mirror
                    .as_ref()
                    .and_then(|mirror| mirror.enabled),
                policy_tags: Arc::<[String]>::from(rule.effects.tags.clone()),
            });
            hints.push(hint);
        }

        let mut prefilter = MatchPrefilterIndex::new(compiled.len());
        for (idx, hint) in hints.iter().enumerate() {
            prefilter.insert_hint(idx, hint, &mut interner);
        }

        Ok(Some(Self {
            rules: compiled,
            prefilter,
        }))
    }

    pub(crate) fn candidate_profile(
        &self,
        ctx: MatchPrefilterContext<'_>,
    ) -> ResponseRuleCandidates {
        let mut out = ResponseRuleCandidates::default();
        self.prefilter.for_each_candidate(&ctx, |idx| {
            out.indices.push(idx);
            if let Some(rule) = self.rules.get(idx) {
                out.requires_response_size |= rule.matcher.requires_response_size();
                out.requires_response_body_observation |=
                    rule.matcher.requires_response_body_observation();
                out.requires_response_rpc_context |= rule.matcher.requires_response_rpc_context();
                out.requires_request_rpc_context |=
                    rule.matcher.requires_response_request_rpc_context();
                out.requires_request_body_observation |=
                    rule.matcher.requires_response_request_body_observation();
                out.requires_response_rpc_observation |=
                    rule.matcher.requires_response_rpc_observation();
            }
            false
        });
        out
    }

    pub(crate) fn rule_at(&self, idx: usize) -> Option<&CompiledHttpResponseRule> {
        self.rules.get(idx)
    }

    pub(crate) fn any_rule_requires_response_request_rpc_context(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.matcher.requires_response_request_rpc_context())
    }

    pub(crate) fn any_rule_requires_response_request_body_observation(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.matcher.requires_response_request_body_observation())
    }
}

pub(crate) async fn apply_listener_response_policy(
    engine: Option<&HttpResponseRuleEngine>,
    candidates: ResponseRuleCandidates,
    mut ctx: RuleMatchContext<'_>,
    mut response: Response<Body>,
    headers: Option<Arc<CompiledHeaderControl>>,
    request_rpc: Option<&RpcMatchContext>,
    body_observation: ResponseBodyObservationLimits,
) -> Result<ListenerResponsePolicyDecision> {
    let Some(engine) = engine else {
        return Ok(ListenerResponsePolicyDecision::Continue {
            response,
            headers,
            cache_bypass: false,
            suppress_retry: false,
            mirror: None,
            policy_tags: Vec::new(),
        });
    };

    let observation_plan = ResponseObservationPlan::from_policy_candidates(&candidates);
    response = observation_plan
        .observe_response(
            response,
            body_observation.max_body_bytes,
            body_observation.read_timeout,
        )
        .await?;
    let response_rpc = if observation_plan.needs_rpc_observation {
        let default_request_rpc;
        let request_rpc = match request_rpc {
            Some(request_rpc) => request_rpc,
            None => {
                default_request_rpc = RpcMatchContext::default();
                &default_request_rpc
            }
        };
        Some(crate::http::rpc::inspect_response(request_rpc, &response))
    } else {
        None
    };
    if observation_plan.needs_rpc_context {
        if let Some(response_rpc) = response_rpc.as_ref() {
            ctx.rpc_protocol = response_rpc.protocol.as_deref();
            ctx.rpc_service = response_rpc.service.as_deref();
            ctx.rpc_method = response_rpc.method.as_deref();
            ctx.rpc_streaming = response_rpc.streaming.as_deref();
            ctx.rpc_status = response_rpc.status.as_deref();
            ctx.rpc_message_size = response_rpc.message_size;
            ctx.rpc_message = response_rpc.message.as_deref();
            ctx.rpc_trailers = response_rpc.trailers.as_ref();
        } else if let Some(request_rpc) = request_rpc {
            ctx.rpc_protocol = request_rpc.protocol.as_deref();
            ctx.rpc_service = request_rpc.service.as_deref();
            ctx.rpc_method = request_rpc.method.as_deref();
            ctx.rpc_streaming = request_rpc.streaming.as_deref();
        }
    }
    ctx.response_status = Some(response.status().as_u16());
    ctx.response_size = observed_response_size(&response);
    ctx.headers = Some(response.headers());

    for idx in candidates.indices {
        let Some(rule) = engine.rule_at(idx) else {
            continue;
        };
        if !rule.matcher.matches(&ctx) {
            continue;
        }
        return apply_compiled_response_rule(rule, response, headers);
    }

    Ok(ListenerResponsePolicyDecision::Continue {
        response,
        headers,
        cache_bypass: false,
        suppress_retry: false,
        mirror: None,
        policy_tags: Vec::new(),
    })
}

pub(crate) fn apply_compiled_response_rule(
    rule: &CompiledHttpResponseRule,
    response: Response<Body>,
    headers: Option<Arc<CompiledHeaderControl>>,
) -> Result<ListenerResponsePolicyDecision> {
    let merged_headers = merge_header_controls(headers, rule.headers.clone());
    let cache_bypass = rule.cache_bypass
        || rule.matcher.requires_response_context()
        || rule
            .headers
            .as_deref()
            .map(CompiledHeaderControl::has_response_mutations)
            .unwrap_or(false);
    let policy_tags = rule.policy_tags.as_ref().to_vec();
    if let Some(local) = rule.local_response.as_ref() {
        return Ok(ListenerResponsePolicyDecision::LocalResponse {
            response: build_local_response(local)?,
            headers: merged_headers,
            policy_tags,
        });
    }
    Ok(ListenerResponsePolicyDecision::Continue {
        response,
        headers: merged_headers,
        cache_bypass,
        suppress_retry: rule.suppress_retry,
        mirror: rule.mirror,
        policy_tags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qpx_core::config::{
        HeaderControl, HttpResponseCacheEffectsConfig, HttpResponseEffectsConfig,
        HttpResponseRetryEffectsConfig, MatchConfig, RpcMatchConfig,
    };

    #[tokio::test]
    async fn response_policy_surfaces_tags_and_retry_controls() {
        let rules = vec![HttpResponseRuleConfig {
            name: "response-policy".to_string(),
            r#match: Some(MatchConfig {
                response_status: vec!["200".to_string()],
                ..Default::default()
            }),
            effects: HttpResponseEffectsConfig {
                headers: Some(HeaderControl {
                    response_set: std::collections::HashMap::from([(
                        "x-response-policy".to_string(),
                        "applied".to_string(),
                    )]),
                    ..Default::default()
                }),
                cache: Some(HttpResponseCacheEffectsConfig { bypass: true }),
                retry: Some(HttpResponseRetryEffectsConfig { suppress: true }),
                mirror: Some(qpx_core::config::HttpResponseMirrorEffectsConfig {
                    enabled: Some(false),
                    upstreams: Vec::new(),
                }),
                tags: vec!["resp-tag".to_string()],
                ..Default::default()
            },
        }];
        let engine = HttpResponseRuleEngine::new(rules.as_slice())
            .expect("engine")
            .expect("some");
        let response = Response::builder()
            .status(200)
            .body(Body::from("ok"))
            .expect("response");
        let candidates = engine.candidate_profile(MatchPrefilterContext {
            method: Some("GET"),
            dst_port: Some(443),
            src_ip: None,
            host: Some("example.com"),
            sni: None,
            path: Some("/"),
        });
        let decision = apply_listener_response_policy(
            Some(&engine),
            candidates,
            RuleMatchContext {
                method: Some("GET"),
                host: Some("example.com"),
                path: Some("/"),
                ..Default::default()
            },
            response,
            None,
            None,
            ResponseBodyObservationLimits {
                max_body_bytes: usize::MAX,
                read_timeout: Duration::from_secs(1),
            },
        )
        .await
        .expect("decision");

        match decision {
            ListenerResponsePolicyDecision::Continue {
                cache_bypass,
                suppress_retry,
                mirror,
                policy_tags,
                headers,
                ..
            } => {
                assert!(cache_bypass);
                assert!(suppress_retry);
                assert_eq!(mirror, Some(false));
                assert_eq!(policy_tags, vec!["resp-tag".to_string()]);
                let headers = headers.expect("headers");
                assert!(headers.has_response_mutations());
            }
            ListenerResponsePolicyDecision::LocalResponse { .. } => {
                panic!("expected continued response")
            }
        }
    }

    #[tokio::test]
    async fn grpc_status_rule_matches_trailers() {
        let rules = vec![HttpResponseRuleConfig {
            name: "grpc-status".to_string(),
            r#match: Some(MatchConfig {
                rpc: Some(RpcMatchConfig {
                    protocol: vec!["grpc".to_string()],
                    status: vec!["14".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            effects: HttpResponseEffectsConfig {
                local_response: Some(qpx_core::config::LocalResponseConfig {
                    status: 204,
                    body: String::new(),
                    content_type: None,
                    headers: Default::default(),
                    rpc: None,
                }),
                tags: vec!["grpc".to_string()],
                ..Default::default()
            },
        }];
        let engine = HttpResponseRuleEngine::new(rules.as_slice())
            .expect("engine")
            .expect("some");
        let (mut sender, body) = Body::channel();
        tokio::spawn(async move {
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", http::HeaderValue::from_static("14"));
            let _ = sender.send_trailers(trailers).await;
        });
        let response = Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(body)
            .expect("response");
        let response = crate::http::body_size::buffer_response_body(
            response,
            usize::MAX,
            Duration::from_secs(1),
        )
        .await
        .expect("buffer");
        let request_rpc = crate::http::rpc::RpcMatchContext {
            protocol: Some("grpc".to_string()),
            service: Some("demo.Echo".to_string()),
            method: Some("Say".to_string()),
            ..Default::default()
        };
        let candidates = engine.candidate_profile(MatchPrefilterContext {
            method: Some("POST"),
            dst_port: Some(443),
            src_ip: None,
            host: Some("rpc.example.com"),
            sni: None,
            path: Some("/demo.Echo/Say"),
        });
        let decision = apply_listener_response_policy(
            Some(&engine),
            candidates,
            RuleMatchContext {
                method: Some("POST"),
                host: Some("rpc.example.com"),
                path: Some("/demo.Echo/Say"),
                ..Default::default()
            },
            response,
            None,
            Some(&request_rpc),
            ResponseBodyObservationLimits {
                max_body_bytes: usize::MAX,
                read_timeout: Duration::from_secs(1),
            },
        )
        .await
        .expect("decision");

        match decision {
            ListenerResponsePolicyDecision::LocalResponse { policy_tags, .. } => {
                assert_eq!(policy_tags, vec!["grpc".to_string()]);
            }
            ListenerResponsePolicyDecision::Continue { .. } => {
                panic!("expected grpc local response")
            }
        }
    }

    #[tokio::test]
    async fn rpc_protocol_service_method_rule_uses_request_rpc_without_response_inspection() {
        let rules = vec![HttpResponseRuleConfig {
            name: "grpc-method".to_string(),
            r#match: Some(MatchConfig {
                rpc: Some(RpcMatchConfig {
                    protocol: vec!["grpc".to_string()],
                    service: vec!["demo.Echo".to_string()],
                    method: vec!["Say".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            effects: HttpResponseEffectsConfig {
                local_response: Some(qpx_core::config::LocalResponseConfig {
                    status: 204,
                    body: String::new(),
                    content_type: None,
                    headers: Default::default(),
                    rpc: None,
                }),
                tags: vec!["grpc-method".to_string()],
                ..Default::default()
            },
        }];
        let engine = HttpResponseRuleEngine::new(rules.as_slice())
            .expect("engine")
            .expect("some");
        let candidates = engine.candidate_profile(MatchPrefilterContext {
            method: Some("POST"),
            dst_port: Some(443),
            src_ip: None,
            host: Some("rpc.example.com"),
            sni: None,
            path: Some("/demo.Echo/Say"),
        });
        assert!(candidates.requires_request_rpc_context);
        assert!(!candidates.requires_request_body_observation);
        assert!(candidates.requires_response_rpc_context);
        assert!(!candidates.requires_response_rpc_observation);
        let response = Response::builder()
            .status(200)
            .body(Body::from("ok"))
            .expect("response");
        let request_rpc = crate::http::rpc::RpcMatchContext {
            protocol: Some("grpc".to_string()),
            service: Some("demo.Echo".to_string()),
            method: Some("Say".to_string()),
            ..Default::default()
        };
        let decision = apply_listener_response_policy(
            Some(&engine),
            candidates,
            RuleMatchContext {
                method: Some("POST"),
                host: Some("rpc.example.com"),
                path: Some("/demo.Echo/Say"),
                ..Default::default()
            },
            response,
            None,
            Some(&request_rpc),
            ResponseBodyObservationLimits {
                max_body_bytes: usize::MAX,
                read_timeout: Duration::from_secs(1),
            },
        )
        .await
        .expect("decision");

        match decision {
            ListenerResponsePolicyDecision::LocalResponse { policy_tags, .. } => {
                assert_eq!(policy_tags, vec!["grpc-method".to_string()]);
            }
            ListenerResponsePolicyDecision::Continue { .. } => {
                panic!("expected grpc method local response")
            }
        }
    }

    #[test]
    fn response_rpc_streaming_requires_request_body_observation() {
        let rules = vec![HttpResponseRuleConfig {
            name: "grpc-client-streaming".to_string(),
            r#match: Some(qpx_core::config::MatchConfig {
                rpc: Some(qpx_core::config::RpcMatchConfig {
                    streaming: vec!["client".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            effects: HttpResponseEffectsConfig::default(),
        }];
        let engine = HttpResponseRuleEngine::new(rules.as_slice())
            .expect("engine")
            .expect("some");
        let candidates = engine.candidate_profile(MatchPrefilterContext {
            method: Some("POST"),
            dst_port: Some(443),
            src_ip: None,
            host: Some("rpc.example.com"),
            sni: None,
            path: Some("/demo.Echo/Say"),
        });
        assert!(candidates.requires_request_rpc_context);
        assert!(candidates.requires_request_body_observation);
        assert!(candidates.requires_response_rpc_context);
        assert!(candidates.requires_response_rpc_observation);
    }
}
