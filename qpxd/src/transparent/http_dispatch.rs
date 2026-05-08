use super::*;
use crate::http::observation::RequestObservationPlan;
use crate::http::rule_context::{
    attach_destination_trace, build_request_rule_match_context, build_response_rule_match_context,
    RequestRuleContextInput, ResponseRuleContextInput,
};

pub(super) async fn dispatch_transparent_request(
    mut req: Request<Body>,
    runtime: Runtime,
    remote_addr: SocketAddr,
    original_target: Option<ConnectTarget>,
    listener_name: &str,
) -> Result<hyper::Response<Body>> {
    let state = runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    if let PreflightOutcome::Reject(response) = preflight_validate(
        &req,
        proxy_name,
        PreflightOptions::reject_connect(
            state.plan.limits.trace_enabled,
            state.messages.trace_disabled.as_str(),
            StatusCode::METHOD_NOT_ALLOWED,
            "transparent HTTP forward_edges do not support CONNECT",
        ),
    ) {
        return Ok(*response);
    }
    let engine = state
        .policy
        .rules_by_listener
        .get(listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;
    let listener_cfg = state
        .ingress_edge_settings(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    let compiled_edge = state
        .plan
        .transparent_edge(listener_name)
        .ok_or_else(|| anyhow!("compiled transparent edge not found"))?;
    let effective_policy = compiled_edge.default_plan.policy_context.clone();
    let http_guard = compiled_edge.default_plan.guard.as_deref();

    let (connect_target, host_for_match) = resolve_http_target(&req, original_target.as_ref())?;
    let base = extract_base_request_fields(
        &req,
        BaseRequestContext {
            peer_ip: Some(remote_addr.ip()),
            dst_port: Some(connect_target.port()),
            host: host_for_match.as_deref(),
            scheme: Some("http"),
            ..Default::default()
        },
    );
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: Some(connect_target.port()),
        src_ip: Some(remote_addr.ip()),
        host: host_for_match.as_deref(),
        sni: None,
        path: base.path.as_deref(),
    };
    let response_engine = compiled_edge.default_plan.response_rules.as_deref();
    let response_candidates_for_request = response_engine
        .map(|engine| engine.candidate_profile(prefilter_ctx.clone()))
        .unwrap_or_default();
    let mut observation_plan = RequestObservationPlan::from_policy_candidates(
        engine,
        &response_candidates_for_request,
        prefilter_ctx.clone(),
    );
    observation_plan.include_body(
        compiled_edge
            .flags
            .contains(crate::runtime::PlanFlags::CAPTURE_BODY),
    );
    let guard_requires_buffering =
        http_guard.is_some_and(|profile| profile.requires_request_body_buffering(&req));
    observation_plan.include_body(guard_requires_buffering);
    let max_observed_request_body_bytes = http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(state.plan.limits.max_observed_request_body_bytes))
        .unwrap_or(state.plan.limits.max_observed_request_body_bytes);
    let max_observed_request_body_bytes =
        compiled_edge.body_observation_limit(max_observed_request_body_bytes);
    let request_version_for_observation = req.version();
    req = match observation_plan
        .observe_request(
            req,
            max_observed_request_body_bytes,
            std::time::Duration::from_millis(state.plan.limits.http_header_read_timeout_ms.max(1)),
        )
        .await
    {
        Ok(req) => req,
        Err(err) if crate::http::body_size::is_observed_body_limit_exceeded(&err) => {
            return Ok(finalize_response_for_request(
                &base.method,
                request_version_for_observation,
                proxy_name,
                hyper::Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Body::from("request body too large"))?,
                false,
            ));
        }
        Err(err) => return Err(err),
    };
    let path = base.path.as_deref();
    let request_uri = base.request_uri.as_str();
    let request_version = req.version();
    let sanitized_headers =
        sanitize_headers_for_policy(&state, &effective_policy, remote_addr.ip(), req.headers())?;
    let identity = resolve_identity(
        &state,
        &effective_policy,
        remote_addr.ip(),
        Some(&sanitized_headers),
        None,
    )?;
    let destination = state.classify_destination(
        &DestinationInputs {
            host: host_for_match.as_deref(),
            ip: host_for_match
                .as_deref()
                .and_then(|value| value.parse().ok()),
            scheme: base.scheme.as_deref(),
            port: Some(connect_target.port()),
            ..Default::default()
        },
        compiled_edge.default_plan.destination_resolution.as_ref(),
    );
    if let Some(profile) = http_guard {
        if let Some(reject) = profile.evaluate_request(&req)? {
            let mut log_context = identity.to_log_context(None, None, None);
            attach_destination_trace(&mut log_context, &destination);
            let mut response = finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                hyper::Response::builder()
                    .status(reject.status)
                    .body(Body::from(reject.body))?,
                false,
            );
            attach_log_context(&mut response, &log_context);
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "transparent",
                    name: listener_name,
                    remote_ip: remote_addr.ip(),
                    host: host_for_match.as_deref(),
                    sni: None,
                    method: Some(req.method().as_str()),
                    path,
                    outcome: "http_guard_reject",
                    status: Some(response.status().as_u16()),
                    matched_rule: None,
                    matched_route: None,
                    ext_authz_policy_id: None,
                },
                &log_context,
            );
            return Ok(response);
        }
    }
    let request_rpc = observation_plan
        .needs_rpc
        .then(|| crate::http::rpc::inspect_request(&req));
    let ctx = build_request_rule_match_context(RequestRuleContextInput {
        base: &base,
        headers: &sanitized_headers,
        destination: &destination,
        identity: &identity,
        request_size: observed_request_size(&req),
        rpc: request_rpc.as_ref(),
        client_cert: None,
        upstream_cert: None,
    });
    let decision = evaluate_listener_policy(
        engine,
        &ctx,
        req.method(),
        req.version(),
        proxy_name,
        forbidden,
        state.messages.forbidden.as_str(),
    )?;
    let (policy, early_response, matched_rule) = match decision {
        ListenerPolicyDecision::Proceed(mut policy) => {
            let matched_rule = policy.matched_rule.take();
            (Some(policy), None, matched_rule)
        }
        ListenerPolicyDecision::Early(response, matched_rule) => {
            (None, Some(response), matched_rule)
        }
    };
    let selected_plan = compiled_edge.execution_plan_for_rule(matched_rule.as_deref());
    let request_limit_ctx =
        RateLimitContext::from_identity(remote_addr.ip(), &identity, matched_rule.as_deref(), None);
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
    if let Some(retry_after) = retry_after {
        let mut log_context = identity.to_log_context(matched_rule.as_deref(), None, None);
        attach_destination_trace(&mut log_context, &destination);
        let mut response = finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            too_many_requests(Some(retry_after)),
            false,
        );
        attach_log_context(&mut response, &log_context);
        emit_audit_log(
            &state,
            AuditRecord {
                kind: "transparent",
                name: listener_name,
                remote_ip: remote_addr.ip(),
                host: host_for_match.as_deref(),
                sni: None,
                method: Some(req.method().as_str()),
                path,
                outcome: "rate_limited",
                status: Some(response.status().as_u16()),
                matched_rule: matched_rule.as_deref(),
                matched_route: None,
                ext_authz_policy_id: None,
            },
            &log_context,
        );
        return Ok(response);
    }
    let request_method = req.method().clone();
    let ext_authz = if let Some(policy) = policy.as_ref() {
        Some(
            enforce_ext_authz(
                &state,
                &effective_policy,
                ExtAuthzInput {
                    proxy_kind: "transparent",
                    proxy_name,
                    scope_name: listener_name,
                    remote_ip: remote_addr.ip(),
                    dst_port: Some(connect_target.port()),
                    host: host_for_match.as_deref(),
                    sni: None,
                    method: Some(req.method().as_str()),
                    path: base.path.as_deref(),
                    uri: Some(request_uri),
                    matched_rule: matched_rule.as_deref(),
                    matched_route: None,
                    action: Some(&policy.action),
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
    let annotate_with_tags = |response: &mut hyper::Response<Body>,
                              outcome: &'static str,
                              extra_policy_tags: &[String]| {
        let mut annotated_context = log_context.clone();
        merge_policy_tags(&mut annotated_context.policy_tags, extra_policy_tags);
        attach_log_context(response, &annotated_context);
        emit_audit_log(
            &state,
            AuditRecord {
                kind: "transparent",
                name: listener_name,
                remote_ip: remote_addr.ip(),
                host: host_for_match.as_deref(),
                sni: None,
                method: Some(request_method.as_str()),
                path: base.path.as_deref(),
                outcome,
                status: Some(response.status().as_u16()),
                matched_rule: matched_rule.as_deref(),
                matched_route: None,
                ext_authz_policy_id: ext_authz_policy_id.as_deref(),
            },
            &annotated_context,
        );
    };
    let annotate = |response: &mut hyper::Response<Body>, outcome: &'static str| {
        annotate_with_tags(response, outcome, &[]);
    };
    let mut timeout_override = None;
    if let Some(mut response) = early_response {
        annotate(&mut response, "early_response");
        return Ok(*response);
    }
    let mut policy = policy.expect("policy");
    if let Some(ext_authz) = ext_authz {
        match ext_authz {
            ExtAuthzEnforcement::Continue(allow) => {
                validate_ext_authz_allow_mode(&allow, ExtAuthzMode::TransparentHttp)?;
                policy.headers = merge_header_controls(policy.headers, allow.headers.clone());
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
                    annotate(&mut response, "rate_limited");
                    return Ok(response);
                }
                apply_ext_authz_action_overrides(&mut policy.action, &allow);
            }
            ExtAuthzEnforcement::Deny(deny) => {
                let merged_headers = merge_header_controls(policy.headers.clone(), deny.headers);
                let mut response = if let Some(local) = deny.local_response.as_ref() {
                    crate::http::l7::finalize_response_with_headers(
                        req.method(),
                        req.version(),
                        proxy_name,
                        crate::http::local_response::build_local_response(local)?,
                        merged_headers.as_deref(),
                        false,
                    )
                } else {
                    crate::http::l7::finalize_response_with_headers(
                        req.method(),
                        req.version(),
                        proxy_name,
                        forbidden(state.messages.forbidden.as_str()),
                        merged_headers.as_deref(),
                        false,
                    )
                };
                annotate(
                    &mut response,
                    if deny.local_response.is_some() {
                        "ext_authz_local_response"
                    } else {
                        "ext_authz_deny"
                    },
                );
                return Ok(response);
            }
        }
    }

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
        annotate(&mut response, "max_forwards");
        return Ok(response);
    }
    strip_untrusted_identity_headers(
        &state,
        &effective_policy,
        remote_addr.ip(),
        req.headers_mut(),
    )?;
    let websocket = is_websocket_upgrade(req.headers());
    prepare_request_with_headers_in_place(
        &mut req,
        proxy_name,
        policy.headers.as_deref(),
        websocket,
    );
    let mut http_modules = selected_plan.modules.start(
        state.clone(),
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: "transparent",
            proxy_name: proxy_name.to_string(),
            scope_name: listener_name.to_string(),
            route_name: None,
            remote_ip: remote_addr.ip(),
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
                &request_method,
                response_version,
                proxy_name,
                &mut response,
                policy.headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(response.status()), None).await;
            annotate(&mut response, "http_module_local_response");
            return Ok(response);
        }
    }

    let upstream = resolve_upstream(&policy.action, &state, listener_cfg)?;
    let rate_limit_ctx = RateLimitContext::from_identity(
        remote_addr.ip(),
        &identity,
        matched_rule.as_deref(),
        upstream.as_ref().map(|upstream| upstream.key()),
    );
    let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_ctx) {
        Some(permits) => permits,
        None => {
            let mut response = finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                too_many_requests(None),
                false,
            );
            annotate(&mut response, "concurrency_limited");
            return Ok(response);
        }
    };
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.plan.limits.upstream_http_timeout_ms));
    let upgrade_wait_timeout = Duration::from_millis(state.plan.limits.upgrade_wait_timeout_ms);
    let tunnel_idle_timeout = Duration::from_millis(state.plan.limits.tunnel_idle_timeout_ms);
    let authority = connect_target.authority();
    let export_session =
        state.export_session_for_plan(selected_plan, remote_addr, authority.as_str());
    if websocket {
        if let Some(session) = export_session.as_ref() {
            let preview = crate::exporter::serialize_request_preview(&req);
            session.emit_plaintext(true, &preview);
        }
        let mut response = proxy_websocket_http1(
            req,
            WebsocketProxyConfig {
                upstream_proxy: upstream.as_ref(),
                direct_connect_authority: authority.as_str(),
                direct_host_header: authority.as_str(),
                timeout_dur: upstream_timeout,
                upgrade_wait_timeout,
                tunnel_idle_timeout,
                tunnel_label: "transparent",
                upstream_context: "transparent websocket upstream proxy",
                direct_context: "transparent websocket direct",
            },
        )
        .await?;
        response = http_modules.on_upstream_response(response).await?;
        response = http_modules.prepare_downstream_response(response).await?;
        if let Some(session) = export_session.as_ref() {
            let preview = crate::exporter::serialize_response_preview(&response);
            session.emit_plaintext(false, &preview);
        }
        let keep_upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS;
        let response_version = response.version();
        finalize_response_with_headers_in_place(
            &request_method,
            response_version,
            proxy_name,
            &mut response,
            policy.headers.as_deref(),
            keep_upgrade,
        );
        http_modules.on_logging(Some(response.status()), None).await;
        annotate(&mut response, "allow");
        return Ok(response);
    }

    http_modules.on_upstream_request(&mut req).await?;
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let proxied = match proxy_http1_request_with_interim(
        req,
        upstream.as_ref(),
        authority.as_str(),
        upstream_timeout,
    )
    .await
    {
        Ok(proxied) => proxied,
        Err(err) => {
            http_modules.on_error(&err).await;
            return Err(err);
        }
    };
    let mut response = proxied.response;
    if !proxied.interim.is_empty() {
        response.extensions_mut().insert(proxied.interim);
    }
    response = http_modules.on_upstream_response(response).await?;
    let response_candidates = response_engine
        .map(|engine| {
            engine.candidate_profile(MatchPrefilterContext {
                method: Some(request_method.as_str()),
                dst_port: Some(connect_target.port()),
                src_ip: Some(remote_addr.ip()),
                host: host_for_match.as_deref(),
                sni: None,
                path: base.path.as_deref(),
            })
        })
        .unwrap_or_default();
    let response_status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let response_policy_tags = match apply_listener_response_policy(
        response_engine,
        response_candidates,
        build_response_rule_match_context(ResponseRuleContextInput {
            base: &base,
            headers: &response_headers,
            destination: &destination,
            identity: &identity,
            response_status,
            response_size: None,
            rpc: None,
            client_cert: None,
            upstream_cert: None,
        }),
        response,
        policy.headers.clone(),
        request_rpc.as_ref(),
        ResponseBodyObservationLimits {
            max_body_bytes: selected_plan
                .body_observation_limit(state.plan.limits.max_observed_response_body_bytes),
            read_timeout: std::time::Duration::from_millis(
                state.plan.limits.upstream_http_timeout_ms.max(1),
            ),
            force_body: selected_plan
                .flags
                .contains(crate::runtime::PlanFlags::CAPTURE_BODY),
        },
    )
    .await?
    {
        ListenerResponsePolicyDecision::Continue {
            response: updated,
            headers: updated_headers,
            cache_bypass: _cache_bypass,
            suppress_retry: _suppress_retry,
            mirror: _mirror,
            policy_tags,
        } => {
            response = updated;
            policy.headers = updated_headers;
            policy_tags
        }
        ListenerResponsePolicyDecision::LocalResponse {
            response: local,
            headers: updated_headers,
            policy_tags,
        } => {
            let response = http_modules.prepare_downstream_response(local).await?;
            let mut response = finalize_response_for_request(
                &request_method,
                request_version,
                proxy_name,
                response,
                false,
            );
            finalize_response_with_headers_in_place(
                &request_method,
                request_version,
                proxy_name,
                &mut response,
                updated_headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(response.status()), None).await;
            annotate_with_tags(&mut response, "response_local_response", &policy_tags);
            return Ok(response);
        }
    };
    response = http_modules.prepare_downstream_response(response).await?;
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_response_preview(&response);
        session.emit_plaintext(false, &preview);
    }
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        &request_method,
        response_version,
        proxy_name,
        &mut response,
        policy.headers.as_deref(),
        false,
    );
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_with_tags(&mut response, "allow", &response_policy_tags);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::body::to_bytes;
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config,
        IdentityConfig, IngressEdgeConfig, IngressEdgeMode, MessagesConfig, RuntimeConfig,
        SystemLogConfig,
    };
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_static_http_server(body: &str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let body = body.to_string();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.expect("write");
        });
        addr
    }

    fn decode_gzip(bytes: &[u8]) -> String {
        let mut decoder = flate2::read::GzDecoder::new(bytes);
        let mut out = String::new();
        decoder.read_to_string(&mut out).expect("decode");
        out
    }

    #[tokio::test]
    async fn transparent_http_modules_can_compress_responses() {
        let upstream_addr = spawn_static_http_server("transparent compression").await;
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
                name: "transparent".to_string(),
                mode: IngressEdgeMode::Transparent,
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
                http_modules: vec![serde_yaml::from_str(
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
                .expect("http module config")],
            })],
            upstreams: Vec::new(),
            caches: Vec::new(),
        })
        .expect("runtime");
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("http://{upstream_addr}/asset"))
            .header("host", upstream_addr.to_string())
            .header("accept-encoding", "gzip")
            .version(http::Version::HTTP_11)
            .body(Body::empty())
            .expect("request");

        let response = dispatch_transparent_request(
            request,
            runtime,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            None,
            "transparent",
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
        assert_eq!(decode_gzip(body.as_ref()), "transparent compression");
    }
}
