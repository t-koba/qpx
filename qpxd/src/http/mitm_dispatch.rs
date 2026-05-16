use super::*;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchGuardInput, DispatchRequestPrepareInput,
    DispatchResponsePolicyInput, DispatchResponsePolicyOutcome, ExtAuthzDenyResponseInput,
    PreparedDispatchRequest, annotate_dispatch_response, apply_dispatch_response_policy,
    evaluate_http_guard, ext_authz_deny_response, prepare_dispatch_request,
    record_upstream_request_duration,
};
use crate::http::rule_context::{
    RequestRuleContextInput, ResponseRuleContextInput, attach_destination_trace,
    build_request_rule_match_context, build_response_rule_match_context,
};

#[tracing::instrument(skip_all, fields(kind = "mitm", host = %route.host, method = %base.method))]
pub(super) async fn dispatch_mitm_request(
    mut req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    sender: Arc<Mutex<SendRequest<Body>>>,
    route: MitmRouteContext<'_>,
) -> Result<Response<Body>> {
    let state = runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let mitm_plan = state
        .plan
        .mitm_plan(route.listener_name, None)
        .ok_or_else(|| anyhow!("compiled MITM listener execution plan not found"))?;
    let base_plan = mitm_plan.http;
    let effective_policy = base_plan.policy_context.clone();
    let http_guard = base_plan.guard.as_deref();
    let websocket = is_websocket_upgrade(req.headers());
    let client_upgrade = websocket.then(|| crate::http::upgrade::on(&mut req));
    let path_owned = base.path.clone().unwrap_or_else(|| "/".to_string());
    let engine = state
        .policy
        .rules_by_listener
        .get(route.listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: Some(route.dst_port),
        src_ip: Some(route.src_addr.ip()),
        host: Some(route.host),
        sni: Some(route.sni),
        path: Some(path_owned.as_str()),
    };
    let response_engine = base_plan.response_rules.as_deref();
    let response_candidates_for_request = response_engine
        .map(|engine| engine.candidate_profile(prefilter_ctx.clone()))
        .unwrap_or_default();
    let max_observed_request_body_bytes = http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(state.plan.limits.max_observed_request_body_bytes))
        .unwrap_or(state.plan.limits.max_observed_request_body_bytes);
    let max_observed_request_body_bytes =
        base_plan.body_observation_limit(max_observed_request_body_bytes);
    let request_version_for_observation = req.version();
    let PreparedDispatchRequest {
        req: prepared_req,
        observation_plan: _observation_plan,
        sanitized_headers,
        identity,
        request_rpc,
    } = match prepare_dispatch_request(DispatchRequestPrepareInput {
        req,
        rule_engine: engine,
        response_candidates: &response_candidates_for_request,
        prefilter_ctx,
        http_guard,
        capture_body: base_plan
            .flags
            .contains(crate::runtime::PlanFlags::CAPTURE_BODY),
        max_observed_request_body_bytes,
        read_timeout: std::time::Duration::from_millis(
            state.plan.limits.http_header_read_timeout_ms.max(1),
        ),
        request_method: &base.method,
        request_version: request_version_for_observation,
        proxy_name,
        state: &state,
        effective_policy: &effective_policy,
        remote_ip: route.src_addr.ip(),
    })
    .await?
    {
        Ok(prepared) => prepared,
        Err(response) => return Ok(response),
    };
    req = prepared_req;
    let path = path_owned.as_str();
    let request_uri = base.request_uri.as_str();
    let req_method = req.method().clone();
    let req_version = req.version();
    let mut identity = identity;
    let upstream_cert = route.upstream_cert.as_deref();
    let destination = state.classify_destination(
        &DestinationInputs {
            host: Some(route.host),
            ip: route.host.parse().ok(),
            sni: Some(route.sni),
            scheme: Some("https"),
            port: Some(route.dst_port),
            cert_subject: upstream_cert.and_then(|cert| cert.subject.as_deref()),
            cert_issuer: upstream_cert.and_then(|cert| cert.issuer.as_deref()),
            cert_san_dns: upstream_cert
                .map(|cert| cert.san_dns.as_slice())
                .unwrap_or(&[]),
            cert_san_uri: upstream_cert
                .map(|cert| cert.san_uri.as_slice())
                .unwrap_or(&[]),
            cert_fingerprint_sha256: upstream_cert
                .and_then(|cert| cert.fingerprint_sha256.as_deref()),
            ..Default::default()
        },
        state
            .plan
            .ingress_edge_execution_plan(route.listener_name, None)
            .and_then(|plan| plan.destination_resolution.as_ref()),
    );
    if let Some(response) = evaluate_http_guard(DispatchGuardInput {
        profile: http_guard,
        req: &req,
        destination: &destination,
        proxy_name,
        audit: DispatchAuditContext::new(
            state.clone(),
            crate::http::dispatch::ProxyKind::Mitm,
            route.listener_name,
            route.src_addr,
            req.method().clone(),
            Some(path_owned.clone()),
            identity.to_log_context(None, None, None),
        )
        .with_host(Some(route.host.to_string()))
        .with_sni(Some(route.sni.to_string())),
    })? {
        return Ok(response);
    }
    let ctx = build_request_rule_match_context(RequestRuleContextInput {
        base: &base,
        headers: &sanitized_headers,
        destination: &destination,
        identity: &identity,
        request_size: observed_request_size(&req),
        rpc: request_rpc.as_ref(),
        client_cert: None,
        upstream_cert,
    });
    let decision = evaluate_forward_policy(
        &runtime,
        route.listener_name,
        ctx,
        &sanitized_headers,
        req.method().as_str(),
        request_uri,
    )
    .await?;
    let (mut headers, matched_rule, early_response) = match decision {
        ForwardPolicyDecision::Allow(allowed) => {
            identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
            if matches!(allowed.action.kind, ActionKind::Block) {
                (
                    None,
                    allowed.matched_rule.map(|s| s.to_string()),
                    Some(finalize_response_for_request(
                        req.method(),
                        req.version(),
                        proxy_name,
                        blocked(state.messages.blocked.as_str()),
                        false,
                    )),
                )
            } else if matches!(allowed.action.kind, ActionKind::Respond) {
                let local = allowed
                    .action
                    .local_response
                    .as_ref()
                    .ok_or_else(|| anyhow!("respond action requires local_response"))?;
                (
                    None,
                    allowed.matched_rule.map(|s| s.to_string()),
                    Some(finalize_response_for_request(
                        req.method(),
                        req.version(),
                        proxy_name,
                        build_local_response(local)?,
                        false,
                    )),
                )
            } else {
                (
                    allowed.headers,
                    allowed.matched_rule.map(|s| s.to_string()),
                    None,
                )
            }
        }
        #[cfg(feature = "auth-basic")]
        ForwardPolicyDecision::Challenge(chal) => {
            let response = proxy_auth_required(chal, state.messages.proxy_auth_required.as_str());
            (
                None,
                None,
                Some(finalize_response_for_request(
                    req.method(),
                    req.version(),
                    proxy_name,
                    response,
                    false,
                )),
            )
        }
        #[cfg(feature = "auth-basic")]
        ForwardPolicyDecision::Forbidden => (
            None,
            None,
            Some(finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                forbidden(state.messages.forbidden.as_str()),
                false,
            )),
        ),
    };
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(route.listener_name, matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled MITM listener execution plan not found"))?;
    let request_limit_ctx = RateLimitContext::from_identity(
        route.src_addr.ip(),
        &identity,
        matched_rule.as_deref(),
        None,
    );
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &selected_plan.rate_limits,
        None,
        crate::rate_limit::TransportScope::Request,
        &request_limit_ctx,
        1,
    )?;
    let ext_authz = if early_response.is_none() {
        Some(
            enforce_ext_authz(
                &state,
                &effective_policy,
                ExtAuthzInput {
                    proxy_kind: crate::http::dispatch::ProxyKind::Forward,
                    proxy_name,
                    scope_name: route.listener_name,
                    remote_ip: route.src_addr.ip(),
                    dst_port: Some(route.dst_port),
                    host: Some(route.host),
                    sni: Some(route.sni),
                    method: Some(req.method().as_str()),
                    path: Some(path_owned.as_str()),
                    uri: Some(request_uri),
                    matched_rule: matched_rule.as_deref(),
                    matched_route: None,
                    action: None,
                    headers: Some(&sanitized_headers),
                    identity: &identity,
                },
            )
            .await?,
        )
    } else {
        None
    };
    let ext_authz_policy_id = ext_authz.as_ref().and_then(|decision| match decision {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_id.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_id.clone(),
    });
    let ext_authz_policy_tags = ext_authz
        .as_ref()
        .map(|decision| match decision {
            ExtAuthzEnforcement::Continue(allow) => allow.policy_tags.clone(),
            ExtAuthzEnforcement::Deny(deny) => deny.policy_tags.clone(),
        })
        .unwrap_or_default();
    let mut log_context = identity.to_log_context(
        matched_rule.as_deref(),
        None,
        ext_authz_policy_id.as_deref(),
    );
    attach_destination_trace(&mut log_context, &destination);
    log_context.policy_tags = ext_authz_policy_tags;
    let audit = DispatchAuditContext::new(
        state.clone(),
        crate::http::dispatch::ProxyKind::Mitm,
        route.listener_name,
        route.src_addr,
        req_method.clone(),
        Some(path_owned.clone()),
        log_context,
    )
    .with_host(Some(route.host.to_string()))
    .with_sni(Some(route.sni.to_string()))
    .with_matched_rule(matched_rule.clone())
    .with_ext_authz_policy_id(ext_authz_policy_id.clone());
    let annotate_with_tags = |response: &mut Response<Body>,
                              outcome: crate::http::dispatch::DispatchOutcome,
                              extra_policy_tags: &[String]| {
        annotate_dispatch_response(response, &audit, outcome, extra_policy_tags);
    };
    let annotate = |response: &mut Response<Body>,
                    outcome: crate::http::dispatch::DispatchOutcome| {
        annotate_with_tags(response, outcome, &[]);
    };
    let mut timeout_override = None;
    if let Some(ext_authz) = ext_authz {
        match ext_authz {
            ExtAuthzEnforcement::Continue(allow) => {
                validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ForwardMitmHttp)?;
                headers = merge_header_controls(headers, allow.headers);
                timeout_override = allow.timeout_override;
                if let Some(retry_after) = request_limits.merge_profile_and_check(
                    &state.policy.rate_limiters,
                    allow.rate_limit_profile.as_deref(),
                    crate::rate_limit::TransportScope::Request,
                    &request_limit_ctx,
                    1,
                )? {
                    let mut response = finalize_response_for_request(
                        req.method(),
                        req.version(),
                        proxy_name,
                        too_many_requests(Some(retry_after)),
                        false,
                    );
                    annotate(
                        &mut response,
                        crate::http::dispatch::DispatchOutcome::RateLimited,
                    );
                    return Ok(response);
                }
            }
            ExtAuthzEnforcement::Deny(deny) => {
                return ext_authz_deny_response(ExtAuthzDenyResponseInput {
                    ext_authz: ExtAuthzEnforcement::Deny(deny),
                    base_headers: headers.clone(),
                    request_method: req.method(),
                    request_version: req.version(),
                    proxy_name,
                    default_response: forbidden(state.messages.forbidden.as_str()),
                    audit: &audit,
                });
            }
        }
    }
    if let Some(retry_after) = retry_after {
        let mut response = finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            too_many_requests(Some(retry_after)),
            false,
        );
        annotate(
            &mut response,
            crate::http::dispatch::DispatchOutcome::RateLimited,
        );
        return Ok(response);
    }
    if let Some(response) = early_response {
        let mut response = response;
        annotate(
            &mut response,
            crate::http::dispatch::DispatchOutcome::EarlyResponse,
        );
        return Ok(response);
    }

    let export_server = format_authority_host_port(route.host, route.dst_port);
    let _concurrency_permits =
        match request_limits.acquire_concurrency(&RateLimitContext::from_identity(
            route.src_addr.ip(),
            &identity,
            matched_rule.as_deref(),
            Some(export_server.as_str()),
        )) {
            Some(permits) => permits,
            None => {
                let mut response = finalize_response_for_request(
                    req.method(),
                    req.version(),
                    proxy_name,
                    too_many_requests(None),
                    false,
                );
                annotate(
                    &mut response,
                    crate::http::dispatch::DispatchOutcome::ConcurrencyLimited,
                );
                return Ok(response);
            }
        };
    let export_session =
        state.export_session_for_plan(selected_plan, route.src_addr, export_server);
    if let Some(response) = handle_max_forwards_in_place(
        &mut req,
        proxy_name,
        state.plan.limits.trace_reflect_all_headers,
        state.plan.limits.max_observed_request_body_bytes,
        std::time::Duration::from_millis(state.plan.limits.http_header_read_timeout_ms.max(1)),
    )
    .await
    {
        let mut response = response;
        annotate(
            &mut response,
            crate::http::dispatch::DispatchOutcome::MaxForwards,
        );
        return Ok(response);
    }
    strip_untrusted_identity_headers(
        &state,
        &effective_policy,
        route.src_addr.ip(),
        req.headers_mut(),
    )?;
    prepare_request_with_headers_in_place(&mut req, proxy_name, headers.as_deref(), websocket);
    *req.version_mut() = http::Version::HTTP_11;
    if !req.headers().contains_key(http::header::HOST) {
        let authority = format_authority_host_port(route.host, route.dst_port);
        req.headers_mut()
            .insert(http::header::HOST, http::HeaderValue::from_str(&authority)?);
    }
    let mut http_modules = selected_plan.modules.start(
        state.clone(),
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: crate::http::dispatch::ProxyKind::Mitm,
            proxy_name,
            scope_name: route.listener_name,
            route_name: None,
            remote_ip: route.src_addr.ip(),
            sni: Some(route.host),
            identity_user: identity.user.as_deref(),
            cache_policy: None,
            cache_default_scheme: None,
        },
    );
    match http_modules.on_request_headers(&mut req).await? {
        crate::http::modules::RequestHeadersOutcome::Continue => {}
        crate::http::modules::RequestHeadersOutcome::Respond(response) => {
            let mut response = http_modules.prepare_downstream_response(*response).await?;
            let response_version = response.version();
            finalize_response_with_headers_in_place(
                &req_method,
                response_version,
                proxy_name,
                &mut response,
                headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(response.status()), None).await;
            annotate(
                &mut response,
                crate::http::dispatch::DispatchOutcome::HttpModuleLocalResponse,
            );
            return Ok(response);
        }
    }
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.plan.limits.upstream_http_timeout_ms));
    let upstream_started = std::time::Instant::now();
    http_modules.on_upstream_request(&mut req).await?;
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let mut guard = sender.lock().await;
    let upstream_result = timeout(upstream_timeout, guard.send_request(req)).await;
    record_upstream_request_duration(audit.kind, upstream_started.elapsed());
    let mut response = match upstream_result {
        Ok(Ok(response)) => response.map(Body::from),
        Ok(Err(err)) => {
            let err = err.into();
            http_modules.on_error(&err).await;
            return Err(err);
        }
        Err(err) => {
            let err = err.into();
            http_modules.on_error(&err).await;
            return Err(err);
        }
    };
    response = http_modules.on_upstream_response(response).await?;
    let response_candidates = response_engine
        .map(|engine| {
            engine.candidate_profile(MatchPrefilterContext {
                method: Some(req_method.as_str()),
                dst_port: Some(route.dst_port),
                src_ip: Some(route.src_addr.ip()),
                host: Some(route.host),
                sni: Some(route.sni),
                path: Some(path),
            })
        })
        .unwrap_or_default();
    let response_status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let response_policy_tags = match apply_dispatch_response_policy(DispatchResponsePolicyInput {
        response,
        engine: response_engine,
        candidates: response_candidates,
        rule_context: build_response_rule_match_context(ResponseRuleContextInput {
            base: &base,
            headers: &response_headers,
            destination: &destination,
            identity: &identity,
            response_status,
            response_size: None,
            rpc: None,
            client_cert: None,
            upstream_cert,
        }),
        headers: headers.clone(),
        request_rpc: request_rpc.as_ref(),
        body_observation: ResponseBodyObservationLimits {
            max_body_bytes: selected_plan
                .body_observation_limit(state.plan.limits.max_observed_response_body_bytes),
            read_timeout: std::time::Duration::from_millis(
                state.plan.limits.upstream_http_timeout_ms.max(1),
            ),
            force_body: selected_plan
                .flags
                .contains(crate::runtime::PlanFlags::CAPTURE_BODY),
        },
        http_modules: &mut http_modules,
        audit: &audit,
        request_method: &req_method,
        request_version: req_version,
        proxy_name,
        pre_finalize_local_response: true,
    })
    .await?
    {
        DispatchResponsePolicyOutcome::Continue {
            response: updated,
            headers: updated_headers,
            cache_bypass: _cache_bypass,
            suppress_retry: _suppress_retry,
            mirror: _mirror,
            policy_tags,
        } => {
            response = updated;
            headers = updated_headers;
            policy_tags
        }
        DispatchResponsePolicyOutcome::Response(response) => return Ok(response),
    };
    response = http_modules.prepare_downstream_response(response).await?;
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_response_preview(&response);
        session.emit_plaintext(false, &preview);
    }
    let keep_upgrade = websocket && response.status() == http::StatusCode::SWITCHING_PROTOCOLS;
    if keep_upgrade {
        let upgrade_wait_timeout = Duration::from_millis(state.plan.limits.upgrade_wait_timeout_ms);
        let tunnel_idle_timeout = Duration::from_millis(state.plan.limits.tunnel_idle_timeout_ms);
        if let Some(client_upgrade) = client_upgrade {
            spawn_upgrade_tunnel(
                &mut response,
                client_upgrade,
                "mitm",
                upgrade_wait_timeout,
                tunnel_idle_timeout,
            );
        }
    }
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        &req_method,
        response_version,
        proxy_name,
        &mut response,
        headers.as_deref(),
        keep_upgrade,
    );
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_with_tags(
        &mut response,
        crate::http::dispatch::DispatchOutcome::Allow,
        &response_policy_tags,
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::body::to_bytes;
    use crate::http::mitm::proxy_mitm_request;
    use crate::test_util::{decode_gzip, spawn_http1_send_request};
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config,
        IdentityConfig, IngressEdgeConfig, IngressEdgeMode, MessagesConfig, RuntimeConfig,
        SystemLogConfig,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn mitm_http_modules_can_compress_responses() {
        let runtime = Runtime::new(Config {
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig::default(),
            telemetry: qpx_core::config::TelemetryConfig {
                system_log: SystemLogConfig::default(),
                access_log: AccessLogConfig::default(),
                audit_log: AuditLogConfig::default(),
                metrics: None,
                otel: None,
                exporter: None,
            },
            security: qpx_core::config::SecurityConfig {
                auth: AuthConfig::default(),
                identity_sources: Vec::new(),
                decisions: qpx_core::config::DecisionConfig {
                    ext_authz: Vec::new(),
                },
                destination: Default::default(),
                named_sets: Vec::new(),
                upstream_trust_profiles: Vec::new(),
            },
            http: qpx_core::config::HttpGlobalConfig::default(),
            traffic: qpx_core::config::TrafficConfig::default(),
            acme: None,
            edges: vec![qpx_core::config::EdgeConfig::Forward(IngressEdgeConfig {
                name: "forward".to_string(),
                mode: IngressEdgeMode::Forward,
                listen: "127.0.0.1:0".to_string(),
                default_action: ActionConfig {
                    kind: ActionKind::Direct,
                    upstream: None,
                    local_response: None,
                },
                original_dst: None,
                tls_inspection: None,
                rules: Vec::new(),
                connection_filter: Vec::new(),
                upstream_proxy: None,
                http3: None,
                ftp: Default::default(),
                xdp: None,
                cache: None,
                capture: None,
                rate_limit: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                http_modules: vec![
                    serde_yaml::from_str(
                        r#"type: response_compression
settings:
  min_body_bytes: 1
  max_body_bytes: 65536
  content_types:
    - text/plain
  gzip: true
  brotli: false
  zstd: false
  gzip_level: 6
  brotli_level: 5
  zstd_level: 3"#,
                    )
                    .expect("http module config"),
                ],
            })],
            upstreams: Vec::new(),
            caches: Vec::new(),
        })
        .expect("runtime");
        let sender = spawn_http1_send_request("mitm compression").await;
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/asset")
            .header("host", "secure.example")
            .header("accept-encoding", "gzip")
            .version(http::Version::HTTP_11)
            .body(Body::empty())
            .expect("request");

        let response = proxy_mitm_request(
            request,
            runtime,
            sender,
            crate::http::mitm::MitmRouteContext {
                listener_name: "forward",
                src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
                dst_port: 443,
                host: "secure.example",
                sni: "secure.example",
                upstream_cert: None,
            },
        )
        .await
        .expect("response");

        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok()),
            Some("gzip")
        );
        let body = to_bytes(response.into_body()).await.expect("body");
        assert_eq!(decode_gzip(body.as_ref()), "mitm compression");
    }
}
