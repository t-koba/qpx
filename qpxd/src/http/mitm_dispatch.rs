use super::*;
use crate::http::observation::RequestObservationPlan;
use crate::http::rule_context::{
    attach_destination_trace, build_request_rule_match_context, build_response_rule_match_context,
    RequestRuleContextInput, ResponseRuleContextInput,
};

pub(super) async fn dispatch_mitm_request(
    mut req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    sender: Arc<Mutex<SendRequest<Body>>>,
    route: MitmRouteContext<'_>,
) -> Result<Response<Body>> {
    let state = runtime.state();
    let proxy_name = state.config.identity.proxy_name.as_str();
    let listener_cfg = state
        .listener_config(route.listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    let effective_policy =
        EffectivePolicyContext::from_single(listener_cfg.policy_context.as_ref());
    let http_guard = listener_cfg
        .http_guard_profile
        .as_deref()
        .and_then(|name| state.http_guard_profile(name));
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
    let response_engine = state
        .policy
        .response_rules_by_listener
        .get(route.listener_name)
        .map(Arc::as_ref);
    let response_candidates_for_request = response_engine
        .map(|engine| engine.candidate_profile(prefilter_ctx.clone()))
        .unwrap_or_default();
    let mut observation_plan = RequestObservationPlan::from_policy_candidates(
        engine,
        &response_candidates_for_request,
        prefilter_ctx.clone(),
    );
    let guard_requires_buffering =
        http_guard.is_some_and(|profile| profile.requires_request_body_buffering(&req));
    observation_plan.include_body(guard_requires_buffering);
    let max_observed_request_body_bytes = http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(state.config.runtime.max_observed_request_body_bytes))
        .unwrap_or(state.config.runtime.max_observed_request_body_bytes);
    let request_version_for_observation = req.version();
    req = match observation_plan
        .observe_request(
            req,
            max_observed_request_body_bytes,
            std::time::Duration::from_millis(
                state.config.runtime.http_header_read_timeout_ms.max(1),
            ),
        )
        .await
    {
        Ok(req) => req,
        Err(err) if crate::http::body_size::is_observed_body_limit_exceeded(&err) => {
            return Ok(finalize_response_for_request(
                &base.method,
                request_version_for_observation,
                proxy_name,
                Response::builder()
                    .status(hyper::StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Body::from("request body too large"))?,
                false,
            ));
        }
        Err(err) => return Err(err),
    };
    let path = path_owned.as_str();
    let request_uri = base.request_uri.as_str();
    let req_method = req.method().clone();
    let req_version = req.version();
    let sanitized_headers = sanitize_headers_for_policy(
        &state,
        &effective_policy,
        route.src_addr.ip(),
        req.headers(),
    )?;
    let mut identity = resolve_identity(
        &state,
        &effective_policy,
        route.src_addr.ip(),
        Some(&sanitized_headers),
        None,
    )?;
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
        listener_cfg.destination_resolution.as_ref(),
    );
    if let Some(profile) = http_guard {
        if let Some(reject) = profile.evaluate_request(&req)? {
            let mut log_context = identity.to_log_context(None, None, None);
            attach_destination_trace(&mut log_context, &destination);
            let mut response = finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                Response::builder()
                    .status(reject.status)
                    .body(Body::from(reject.body))?,
                false,
            );
            attach_log_context(&mut response, &log_context);
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "forward",
                    name: route.listener_name,
                    remote_ip: route.src_addr.ip(),
                    host: Some(route.host),
                    sni: Some(route.sni),
                    method: Some(req.method().as_str()),
                    path: Some(path_owned.as_str()),
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
    let (mut headers, matched_rule, mut early_response) = match decision {
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
    let request_limit_ctx = RateLimitContext::from_identity(
        route.src_addr.ip(),
        &identity,
        matched_rule.as_deref(),
        None,
    );
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_request(
        crate::rate_limit::RequestLimitCollectInput {
            listener: Some(route.listener_name),
            rule: matched_rule.as_deref(),
            profile: None,
            scope: crate::rate_limit::TransportScope::Request,
            extra: None,
            ctx: &request_limit_ctx,
            cost: 1,
        },
    )?;
    let ext_authz = if early_response.is_none() {
        Some(
            enforce_ext_authz(
                &state,
                &effective_policy,
                ExtAuthzInput {
                    proxy_kind: "forward",
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
    let annotate_with_tags =
        |response: &mut Response<Body>, outcome: &'static str, extra_policy_tags: &[String]| {
            let mut annotated_context = log_context.clone();
            merge_policy_tags(&mut annotated_context.policy_tags, extra_policy_tags);
            attach_log_context(response, &annotated_context);
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "forward",
                    name: route.listener_name,
                    remote_ip: route.src_addr.ip(),
                    host: Some(route.host),
                    sni: Some(route.sni),
                    method: Some(req_method.as_str()),
                    path: Some(path_owned.as_str()),
                    outcome,
                    status: Some(response.status().as_u16()),
                    matched_rule: matched_rule.as_deref(),
                    matched_route: None,
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                },
                &annotated_context,
            );
        };
    let annotate = |response: &mut Response<Body>, outcome: &'static str| {
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
                    annotate(&mut response, "rate_limited");
                    return Ok(response);
                }
            }
            ExtAuthzEnforcement::Deny(deny) => {
                early_response = Some(if let Some(local) = deny.local_response.as_ref() {
                    finalize_response_for_request(
                        req.method(),
                        req.version(),
                        proxy_name,
                        build_local_response(local)?,
                        false,
                    )
                } else {
                    finalize_response_for_request(
                        req.method(),
                        req.version(),
                        proxy_name,
                        forbidden(state.messages.forbidden.as_str()),
                        false,
                    )
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
        annotate(&mut response, "rate_limited");
        return Ok(response);
    }
    if let Some(response) = early_response {
        let mut response = response;
        annotate(&mut response, "early_response");
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
                annotate(&mut response, "concurrency_limited");
                return Ok(response);
            }
        };
    let export_session = state.export_session(route.src_addr, export_server);
    if let Some(response) = handle_max_forwards_in_place(
        &mut req,
        proxy_name,
        state.config.runtime.trace_reflect_all_headers,
        state.config.runtime.max_observed_request_body_bytes,
        std::time::Duration::from_millis(state.config.runtime.http_header_read_timeout_ms.max(1)),
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
    let http_modules_chain = state
        .listener_http_modules(route.listener_name)
        .cloned()
        .unwrap_or_else(|| {
            std::sync::Arc::new(crate::http::modules::CompiledHttpModuleChain::default())
        });
    let mut http_modules = http_modules_chain.start(
        state.clone(),
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: "mitm",
            proxy_name: proxy_name.to_string(),
            scope_name: route.listener_name.to_string(),
            route_name: None,
            remote_ip: route.src_addr.ip(),
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
            http_modules.on_logging(Some(&response), None);
            annotate(&mut response, "http_module_local_response");
            return Ok(response);
        }
    }
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.config.runtime.upstream_http_timeout_ms));
    http_modules.on_upstream_request(&mut req).await?;
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let mut guard = sender.lock().await;
    let mut response = match timeout(upstream_timeout, guard.send_request(req)).await {
        Ok(Ok(response)) => response.map(Body::from),
        Ok(Err(err)) => {
            let err = err.into();
            http_modules.on_error(&err);
            return Err(err);
        }
        Err(err) => {
            let err = err.into();
            http_modules.on_error(&err);
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
            upstream_cert,
        }),
        response,
        headers.clone(),
        request_rpc.as_ref(),
        ResponseBodyObservationLimits {
            max_body_bytes: state.config.runtime.max_observed_response_body_bytes,
            read_timeout: std::time::Duration::from_millis(
                state.config.runtime.upstream_http_timeout_ms.max(1),
            ),
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
            headers = updated_headers;
            policy_tags
        }
        ListenerResponsePolicyDecision::LocalResponse {
            response: local,
            headers: updated_headers,
            policy_tags,
        } => {
            let response = http_modules.prepare_downstream_response(local).await?;
            let mut response = finalize_response_for_request(
                &req_method,
                req_version,
                proxy_name,
                response,
                false,
            );
            finalize_response_with_headers_in_place(
                &req_method,
                req_version,
                proxy_name,
                &mut response,
                updated_headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(&response), None);
            annotate_with_tags(&mut response, "response_local_response", &policy_tags);
            return Ok(response);
        }
    };
    response = http_modules.prepare_downstream_response(response).await?;
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_response_preview(&response);
        session.emit_plaintext(false, &preview);
    }
    let keep_upgrade = websocket && response.status() == http::StatusCode::SWITCHING_PROTOCOLS;
    if keep_upgrade {
        let upgrade_wait_timeout =
            Duration::from_millis(state.config.runtime.upgrade_wait_timeout_ms);
        let tunnel_idle_timeout =
            Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms);
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
    http_modules.on_logging(Some(&response), None);
    annotate_with_tags(&mut response, "allow", &response_policy_tags);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::body::to_bytes;
    use crate::http::mitm::proxy_mitm_request;
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CacheConfig, Config,
        IdentityConfig, ListenerConfig, ListenerMode, MessagesConfig, RuntimeConfig,
        SystemLogConfig,
    };
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn spawn_send_request(body: &str) -> Arc<Mutex<SendRequest<Body>>> {
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
        let stream = TcpStream::connect(addr).await.expect("connect");
        let (sender, connection) = crate::http::common::handshake_http1(stream)
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Arc::new(Mutex::new(sender))
    }

    fn decode_gzip(bytes: &[u8]) -> String {
        let mut decoder = flate2::read::GzDecoder::new(bytes);
        let mut out = String::new();
        decoder.read_to_string(&mut out).expect("decode");
        out
    }

    #[tokio::test]
    async fn mitm_http_modules_can_compress_responses() {
        let runtime = Runtime::new(Config {
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig::default(),
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            acme: None,
            exporter: None,
            auth: AuthConfig::default(),
            identity_sources: Vec::new(),
            ext_authz: Vec::new(),
            destination_resolution: Default::default(),
            listeners: vec![ListenerConfig {
                name: "forward".to_string(),
                mode: ListenerMode::Forward,
                listen: "127.0.0.1:0".to_string(),
                default_action: ActionConfig {
                    kind: ActionKind::Direct,
                    upstream: None,
                    local_response: None,
                },
                tls_inspection: None,
                rules: Vec::new(),
                connection_filter: Vec::new(),
                upstream_proxy: None,
                http3: None,
                ftp: Default::default(),
                xdp: None,
                cache: None,
                rate_limit: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                http_modules: vec![serde_yaml::from_str(
                    r#"type: response_compression
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
            }],
            named_sets: Vec::new(),
            http_guard_profiles: Vec::new(),
            rate_limit_profiles: Vec::new(),
            upstream_trust_profiles: Vec::new(),
            reverse: Vec::new(),
            upstreams: Vec::new(),
            cache: CacheConfig::default(),
        })
        .expect("runtime");
        let sender = spawn_send_request("mitm compression").await;
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
