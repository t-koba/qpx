use super::*;
use crate::http::observation::RequestObservationPlan;
use crate::reverse::health::UpstreamEndpoint;
use crate::reverse::ReloadableReverse;

pub(super) async fn dispatch_reverse_request(
    mut req: Request<Body>,
    base: BaseRequestFields,
    reverse: ReloadableReverse,
    runtime: Runtime,
    conn: ReverseConnInfo,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    let compiled = reverse.compiled().await;
    let router: Arc<ReverseRouter> = compiled.router.clone();
    let security_policy = compiled.security_policy.as_ref();
    let state = runtime.state();
    let proxy_name = state.config.identity.proxy_name.clone();
    if let Err(err) =
        security_policy.validate_request(&req, conn.tls_sni.as_deref(), conn.tls_terminated)
    {
        warn!(error = ?err, "reverse TLS host policy rejected request");
        let request_method = req.method().clone();
        return Ok(empty_interim_response(finalize_response_for_request(
            &request_method,
            req.version(),
            state.config.identity.proxy_name.as_str(),
            Response::builder()
                .status(StatusCode::MISDIRECTED_REQUEST)
                .body(Body::from("misdirected request"))?,
            false,
        )));
    }
    let host = base.host.clone().unwrap_or_default();
    let request_method = req.method().clone();
    let request_version = req.version();
    let method = request_method.as_str();
    let path_owned = base.path.clone();
    let request_uri = base.request_uri.clone();
    let reverse_cfg = state
        .reverse_config(reverse.name.as_ref())
        .ok_or_else(|| anyhow!("reverse config missing"))?;
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(method),
        dst_port: Some(conn.dst_port),
        src_ip: Some(conn.remote_addr.ip()),
        host: (!host.is_empty()).then_some(host.as_str()),
        sni: conn.tls_sni.as_deref(),
        path: path_owned.as_deref(),
    };
    let mut observation_plan = RequestObservationPlan::default();
    let mut max_observed_request_body_bytes = state.config.runtime.max_observed_request_body_bytes;
    router.try_for_each_candidate_route(prefilter_ctx.clone(), |idx, route| {
        let route_cfg = reverse_cfg
            .routes
            .get(idx)
            .ok_or_else(|| anyhow!("reverse route config missing"))?;
        let route_http_guard = route_cfg
            .http_guard_profile
            .as_deref()
            .and_then(|name| state.http_guard_profile(name));
        if let Some(cap) =
            route_http_guard.and_then(|profile| profile.request_body_observation_cap())
        {
            max_observed_request_body_bytes = max_observed_request_body_bytes.min(cap);
        }
        let guard_requires_buffering =
            route_http_guard.is_some_and(|profile| profile.requires_request_body_buffering(&req));
        Ok::<bool, anyhow::Error>(observation_plan.include(
            route.requires_request_size(),
            route.requires_request_body_observation()
                || route.response_rules_require_request_body_observation()
                || guard_requires_buffering,
            route.requires_request_rpc_context()
                || route.response_rules_require_request_rpc_context(),
        ))
    })?;
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
            return Ok(empty_interim_response(finalize_response_for_request(
                &request_method,
                request_version,
                proxy_name.as_ref(),
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Body::from("request body too large"))?,
                false,
            )));
        }
        Err(err) => return Err(err),
    };
    let request_rpc = observation_plan
        .needs_rpc
        .then(|| crate::http::rpc::inspect_request(&req));
    let mut selected_route_idx = None;
    let mut selected_policy = EffectivePolicyContext::default();
    let mut selected_identity = None;
    let mut selected_headers = None;
    let mut request_destination_cache =
        std::collections::HashMap::<String, crate::destination::DestinationMetadata>::new();
    router.try_for_each_candidate_route(prefilter_ctx, |idx, candidate| {
        let route_cfg = reverse_cfg
            .routes
            .get(idx)
            .ok_or_else(|| anyhow!("reverse route config missing"))?;
        let resolution_override = merge_destination_resolution_override(
            reverse_cfg.destination_resolution.as_ref(),
            route_cfg.destination_resolution.as_ref(),
        );
        let effective_policy = EffectivePolicyContext::merged(
            reverse_cfg.policy_context.as_ref(),
            candidate.policy_context.as_ref(),
        );
        let sanitized_headers = sanitize_headers_for_policy(
            &state,
            &effective_policy,
            conn.remote_addr.ip(),
            req.headers(),
        )?;
        let identity = resolve_identity(
            &state,
            &effective_policy,
            conn.remote_addr.ip(),
            Some(&sanitized_headers),
            conn.peer_certificates
                .as_deref()
                .map(|certs| certs.as_slice()),
        )?;
        let cache_key = format!("{:?}", resolution_override);
        let request_destination = request_destination_cache
            .entry(cache_key)
            .or_insert_with(|| {
                classify_reverse_destination(
                    &state,
                    &conn,
                    host.as_str(),
                    None,
                    resolution_override.as_ref(),
                )
            })
            .clone();
        let ctx = crate::http::rule_context::build_request_rule_match_context(
            crate::http::rule_context::RequestRuleContextInput {
                base: &base,
                headers: &sanitized_headers,
                destination: &request_destination,
                identity: &identity,
                request_size: observed_request_size(&req),
                rpc: request_rpc.as_ref(),
                client_cert: conn.peer_certificate_info.as_deref(),
                upstream_cert: None,
            },
        );
        if candidate.matches(&ctx) {
            selected_route_idx = Some(idx);
            selected_policy = effective_policy;
            selected_identity = Some(identity);
            selected_headers = Some(sanitized_headers);
            Ok::<bool, anyhow::Error>(true)
        } else {
            Ok::<bool, anyhow::Error>(false)
        }
    })?;
    let route = selected_route_idx
        .and_then(|idx| router.route_at(idx))
        .ok_or_else(|| anyhow!("no route matched"))?;
    let route_cfg = reverse_cfg
        .routes
        .get(selected_route_idx.expect("selected route index"))
        .ok_or_else(|| anyhow!("reverse route config missing"))?;
    let resolution_override = merge_destination_resolution_override(
        reverse_cfg.destination_resolution.as_ref(),
        route_cfg.destination_resolution.as_ref(),
    );
    let route_http_guard = route_cfg
        .http_guard_profile
        .as_deref()
        .and_then(|name| state.http_guard_profile(name));
    let route_max_observed_request_body_bytes = route_http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(max_observed_request_body_bytes))
        .unwrap_or(max_observed_request_body_bytes);
    let identity = selected_identity.expect("identity for selected reverse route");
    let sanitized_headers = selected_headers.expect("sanitized headers for selected reverse route");
    let request_destination = request_destination_cache
        .get(&format!("{:?}", resolution_override))
        .cloned()
        .unwrap_or_else(|| {
            classify_reverse_destination(
                &state,
                &conn,
                host.as_str(),
                None,
                resolution_override.as_ref(),
            )
        });
    if route_http_guard.is_some_and(|profile| profile.requires_request_body_buffering(&req))
        && crate::http::body_size::observed_request_bytes(&req).is_none()
    {
        req = match buffer_request_body(
            req,
            route_max_observed_request_body_bytes,
            std::time::Duration::from_millis(
                state.config.runtime.http_header_read_timeout_ms.max(1),
            ),
        )
        .await
        {
            Ok(req) => req,
            Err(err) if crate::http::body_size::is_observed_body_limit_exceeded(&err) => {
                return Ok(empty_interim_response(finalize_response_for_request(
                    &request_method,
                    request_version,
                    proxy_name.as_ref(),
                    Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Body::from("request body too large"))?,
                    false,
                )));
            }
            Err(err) => return Err(err),
        };
    }
    let seed = request_seed(&conn, host.as_str(), &req);
    let sticky_seed = route.affinity_seed(&conn, host.as_str(), &req, &identity);
    let ext_authz = enforce_ext_authz(
        &state,
        &selected_policy,
        ExtAuthzInput {
            proxy_kind: "reverse",
            proxy_name: proxy_name.as_ref(),
            scope_name: reverse.name.as_ref(),
            remote_ip: conn.remote_addr.ip(),
            dst_port: Some(conn.dst_port),
            host: (!host.is_empty()).then_some(host.as_str()),
            sni: conn.tls_sni.as_deref(),
            method: Some(method),
            path: path_owned.as_deref(),
            uri: Some(request_uri.as_str()),
            matched_rule: None,
            matched_route: route.name.as_deref(),
            action: None,
            headers: Some(&sanitized_headers),
            identity: &identity,
        },
    )
    .await?;
    let ext_authz_policy_id = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_id.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_id.clone(),
    };
    let ext_authz_policy_tags = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_tags.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_tags.clone(),
    };
    let mut log_context =
        identity.to_log_context(None, route.name.as_deref(), ext_authz_policy_id.as_deref());
    crate::http::rule_context::attach_destination_trace(&mut log_context, &request_destination);
    log_context.policy_tags = ext_authz_policy_tags;
    let annotate_with_tags =
        |response: &mut Response<Body>, outcome: &'static str, extra_policy_tags: &[String]| {
            let mut annotated_context = log_context.clone();
            merge_policy_tags(&mut annotated_context.policy_tags, extra_policy_tags);
            attach_log_context(response, &annotated_context);
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "reverse",
                    name: reverse.name.as_ref(),
                    remote_ip: conn.remote_addr.ip(),
                    host: (!host.is_empty()).then_some(host.as_str()),
                    sni: conn.tls_sni.as_deref(),
                    method: Some(request_method.as_str()),
                    path: path_owned.as_deref(),
                    outcome,
                    status: Some(response.status().as_u16()),
                    matched_rule: None,
                    matched_route: route.name.as_deref(),
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                },
                &annotated_context,
            );
        };
    let annotate = |response: &mut Response<Body>, outcome: &'static str| {
        annotate_with_tags(response, outcome, &[]);
    };
    if let Some(profile) = route_http_guard {
        if let Some(reject) = profile.evaluate_request(&req)? {
            let mut response = finalize_response_for_request(
                &request_method,
                req.version(),
                proxy_name.as_str(),
                Response::builder()
                    .status(reject.status)
                    .body(Body::from(reject.body))?,
                false,
            );
            annotate(&mut response, "http_guard_reject");
            return Ok(empty_interim_response(response));
        }
    }
    let mut route_headers = route.headers.clone();
    let (
        override_upstream,
        timeout_override,
        cache_bypass,
        ext_authz_mirror_upstreams,
        rate_limit_profile,
    ) = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ReverseHttp)?;
            route_headers = merge_header_controls(route_headers, allow.headers);
            (
                allow.override_upstream,
                allow.timeout_override,
                allow.cache_bypass,
                allow.mirror_upstreams,
                allow.rate_limit_profile,
            )
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let merged_headers = merge_header_controls(route_headers.clone(), deny.headers);
            let mut response = if let Some(local) = deny.local_response.as_ref() {
                finalize_response_with_headers(
                    &request_method,
                    req.version(),
                    proxy_name.as_str(),
                    build_local_response(local)?,
                    merged_headers.as_deref(),
                    false,
                )
            } else {
                finalize_response_with_headers(
                    &request_method,
                    req.version(),
                    proxy_name.as_str(),
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from(state.messages.reverse_error.clone()))?,
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
            return Ok(empty_interim_response(response));
        }
    };
    let route_timeout = timeout_override.unwrap_or(route.policy.timeout);
    let request_limit_ctx = RateLimitContext::from_identity(
        conn.remote_addr.ip(),
        &identity,
        route.name.as_deref(),
        override_upstream.as_deref(),
    );
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_request(
        crate::rate_limit::RequestLimitCollectInput {
            listener: None,
            rule: None,
            profile: None,
            scope: crate::rate_limit::TransportScope::Request,
            extra: Some(&route.rate_limit),
            ctx: &request_limit_ctx,
            cost: 1,
        },
    )?;
    if let Some(retry_after) = retry_after {
        let mut response = finalize_response_for_request(
            &request_method,
            req.version(),
            proxy_name.as_str(),
            too_many_requests(Some(retry_after)),
            false,
        );
        annotate(&mut response, "rate_limited");
        return Ok(empty_interim_response(response));
    }
    if let Some(retry_after) = request_limits.merge_profile_and_check(
        &state.policy.rate_limiters,
        rate_limit_profile.as_deref(),
        crate::rate_limit::TransportScope::Request,
        &request_limit_ctx,
        1,
    )? {
        let mut response = finalize_response_for_request(
            &request_method,
            req.version(),
            proxy_name.as_str(),
            too_many_requests(Some(retry_after)),
            false,
        );
        annotate(&mut response, "rate_limited");
        return Ok(empty_interim_response(response));
    }
    if let Some(local) = route.local_response.as_ref() {
        let mut response = finalize_response_with_headers(
            &request_method,
            req.version(),
            proxy_name.as_str(),
            build_local_response(local)?,
            route_headers.as_deref(),
            false,
        );
        counter!(state
            .observability
            .metric_names
            .reverse_local_response_total
            .clone())
        .increment(1);
        annotate(&mut response, "respond");
        return Ok(empty_interim_response(response));
    }

    if let Some(response) = handle_max_forwards_in_place(
        &mut req,
        proxy_name.as_str(),
        state.config.runtime.trace_reflect_all_headers,
        state.config.runtime.max_observed_request_body_bytes,
        std::time::Duration::from_millis(state.config.runtime.http_header_read_timeout_ms.max(1)),
    )
    .await
    {
        let mut response = response;
        annotate(&mut response, "max_forwards");
        return Ok(empty_interim_response(response));
    }

    strip_untrusted_identity_headers(
        &state,
        &selected_policy,
        conn.remote_addr.ip(),
        req.headers_mut(),
    )?;
    if let Some(rewrite) = route.path_rewrite.as_ref() {
        apply_path_rewrite(&mut req, rewrite);
    }

    apply_request_headers(req.headers_mut(), route_headers.as_deref());
    let request_cache_policy = route
        .cache_policy
        .as_ref()
        .filter(|cache| cache.enabled && !cache_bypass)
        .cloned();
    let mut http_modules = route.http_modules.start(
        state.clone(),
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: "reverse",
            proxy_name: proxy_name.to_string(),
            scope_name: reverse.name.as_ref().to_string(),
            route_name: route.name.as_deref().map(str::to_string),
            remote_ip: conn.remote_addr.ip(),
            cache_policy: request_cache_policy.clone(),
            cache_default_scheme: Some(
                if conn.tls_terminated { "https" } else { "http" }.to_string(),
            ),
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
                proxy_name.as_str(),
                &mut response,
                route_headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(&response), None);
            annotate(&mut response, "http_module_local_response");
            return Ok(empty_interim_response(response));
        }
    }

    if is_websocket_upgrade(req.headers()) {
        let upgrade_wait_timeout =
            Duration::from_millis(state.config.runtime.upgrade_wait_timeout_ms);
        let tunnel_idle_timeout =
            Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms);
        let selected_upstream = if override_upstream.is_none() {
            Some(
                route
                    .select_upstream(seed, sticky_seed)
                    .ok_or_else(|| anyhow!("no healthy upstream"))?,
            )
        } else {
            None
        };
        let override_origin = override_upstream.as_deref().map(OriginEndpoint::direct);
        let upstream_origin = override_origin
            .as_ref()
            .or_else(|| selected_upstream.as_ref().map(|upstream| &upstream.origin))
            .ok_or_else(|| anyhow!("no healthy upstream"))?;
        let mut concurrency_ctx = request_limit_ctx.clone();
        if concurrency_ctx.upstream.is_none() {
            concurrency_ctx.upstream = selected_upstream
                .as_ref()
                .map(|upstream| upstream.target.clone());
        }
        let _concurrency_permits = match request_limits.acquire_concurrency(&concurrency_ctx) {
            Some(permits) => permits,
            None => {
                let mut response = finalize_response_for_request(
                    &request_method,
                    req.version(),
                    proxy_name.as_str(),
                    too_many_requests(None),
                    false,
                );
                annotate(&mut response, "concurrency_limited");
                return Ok(empty_interim_response(response));
            }
        };
        if let Some(upstream) = selected_upstream.as_ref() {
            upstream.inflight.fetch_add(1, Ordering::Relaxed);
        }
        let started = Instant::now();
        let response = timeout(
            route_timeout,
            proxy_websocket(
                req,
                upstream_origin,
                proxy_name.as_str(),
                route_timeout,
                upgrade_wait_timeout,
                tunnel_idle_timeout,
                route.upstream_trust.as_deref(),
            ),
        )
        .await;
        if let Some(upstream) = selected_upstream.as_ref() {
            upstream.inflight.fetch_sub(1, Ordering::Relaxed);
        }
        match response {
            Ok(Ok(mut resp)) => {
                if let Some(upstream) = selected_upstream.as_ref() {
                    record_reverse_upstream_status(
                        upstream,
                        &route.policy,
                        resp.status(),
                        started.elapsed(),
                    );
                }
                histogram!(state
                    .observability
                    .metric_names
                    .reverse_upstream_latency_ms
                    .clone())
                .record(started.elapsed().as_secs_f64() * 1000.0);
                counter!(
                    state.observability.metric_names.reverse_requests_total.clone(),
                    "result" => "ok"
                )
                .increment(1);
                resp = http_modules.on_upstream_response(resp).await?;
                resp = http_modules.prepare_downstream_response(resp).await?;
                let keep_upgrade = resp.status() == StatusCode::SWITCHING_PROTOCOLS;
                let resp_version = resp.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    resp_version,
                    proxy_name.as_str(),
                    &mut resp,
                    route_headers.as_deref(),
                    keep_upgrade,
                );
                http_modules.on_logging(Some(&resp), None);
                annotate(&mut resp, "allow");
                return Ok(empty_interim_response(resp));
            }
            Ok(Err(err)) => {
                http_modules.on_error(&err);
                if let Some(upstream) = selected_upstream.as_ref() {
                    record_reverse_upstream_error(upstream, &route.policy, &err);
                }
                counter!(
                    state.observability.metric_names.reverse_requests_total.clone(),
                    "result" => "error"
                )
                .increment(1);
                return Err(err);
            }
            Err(_) => {
                let err = anyhow!("upstream timeout");
                http_modules.on_error(&err);
                if let Some(upstream) = selected_upstream.as_ref() {
                    record_reverse_upstream_timeout(upstream, &route.policy);
                }
                counter!(
                    state.observability.metric_names.reverse_requests_total.clone(),
                    "result" => "timeout"
                )
                .increment(1);
                return Err(err);
            }
        }
    }

    let cache_policy = request_cache_policy.as_ref();
    let cache_default_scheme = if conn.tls_terminated { "https" } else { "http" };
    let (request_headers_snapshot, cache_lookup_key, cache_target_key) = if cache_policy.is_some() {
        let cache_lookup_key = CacheRequestKey::for_lookup(&req, cache_default_scheme)?;
        let cache_target_key = CacheRequestKey::for_target(&req, cache_default_scheme)?;
        let snapshot = cache_lookup_key.as_ref().map(|_| req.headers().clone());
        (snapshot, cache_lookup_key, cache_target_key)
    } else {
        (None, None, None)
    };
    let mut revalidation_state = None;
    if let (Some(snapshot), Some(_)) = (request_headers_snapshot.as_ref(), cache_policy) {
        let (lookup_decision, lookup_revalidation_state) = lookup_with_revalidation(
            &mut req,
            snapshot,
            cache_lookup_key.as_ref(),
            cache_policy,
            &runtime.state().cache.backends,
            state.messages.cache_miss.as_str(),
        )
        .await?;
        revalidation_state = lookup_revalidation_state;
        let cache_hit = matches!(
            lookup_decision,
            CacheLookupDecision::Hit(_) | CacheLookupDecision::StaleWhileRevalidate(_, _)
        );
        http_modules.on_cache_lookup(cache_hit).await?;
        match lookup_decision {
            CacheLookupDecision::Hit(mut hit) => {
                hit = http_modules.prepare_downstream_response(hit).await?;
                let hit_version = hit.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    hit_version,
                    proxy_name.as_str(),
                    &mut hit,
                    route_headers.as_deref(),
                    false,
                );
                http_modules.on_logging(Some(&hit), None);
                annotate(&mut hit, "cache_hit");
                return Ok(empty_interim_response(hit));
            }
            CacheLookupDecision::StaleWhileRevalidate(mut hit, state) => {
                if request_method == Method::GET && route.ipc.is_none() {
                    if let (Some(policy), Some(snapshot), Some(lookup_key), Some(target_key)) = (
                        cache_policy,
                        request_headers_snapshot.as_ref(),
                        cache_lookup_key.as_ref(),
                        cache_target_key.as_ref(),
                    ) {
                        if let Some(target) = override_upstream
                            .as_deref()
                            .map(OriginEndpoint::direct)
                            .or_else(|| {
                                route
                                    .select_upstream(seed, sticky_seed)
                                    .map(|u| u.origin.clone())
                            })
                        {
                            if !target.upstream.starts_with("ipc://")
                                && !target.upstream.starts_with("ipc+unix://")
                            {
                                if let Some(guard) =
                                    crate::cache::try_begin_background_revalidation(&state)
                                {
                                    let runtime = runtime.clone();
                                    let proxy_name = proxy_name.clone();
                                    let timeout_dur = route_timeout;
                                    let policy = (*policy).clone();
                                    let snapshot = (*snapshot).clone();
                                    let lookup_key = (*lookup_key).clone();
                                    let target_key = (*target_key).clone();
                                    let upstream_trust = route.upstream_trust.clone();
                                    let bg_req = clone_request_head_for_revalidation(&req);
                                    tokio::spawn(async move {
                                        let _guard = guard;
                                        let started = Instant::now();
                                        let resp = timeout(
                                            timeout_dur,
                                            proxy_http(
                                                bg_req,
                                                &target,
                                                proxy_name.as_str(),
                                                upstream_trust.as_deref(),
                                            ),
                                        )
                                        .await;
                                        let Ok(Ok(resp)) = resp else {
                                            return;
                                        };
                                        let response_delay_secs = started.elapsed().as_secs();
                                        let state_ref = runtime.state();
                                        let backends = &state_ref.cache.backends;
                                        let method = Method::GET;
                                        let _ = process_upstream_response_for_cache(
                                            resp,
                                            CacheWritebackContext {
                                                request_method: &method,
                                                response_delay_secs,
                                                cache_target_key: Some(&target_key),
                                                cache_lookup_key: Some(&lookup_key),
                                                cache_policy: Some(&policy),
                                                request_headers_snapshot: &snapshot,
                                                revalidation_state: Some(state),
                                                body_read_timeout: std::time::Duration::from_millis(
                                                    state_ref
                                                        .config
                                                        .runtime
                                                        .upstream_http_timeout_ms
                                                        .max(1),
                                                ),
                                                backends,
                                            },
                                        )
                                        .await;
                                    });
                                }
                            }
                        }
                    }
                }
                hit = http_modules.prepare_downstream_response(hit).await?;
                let hit_version = hit.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    hit_version,
                    proxy_name.as_str(),
                    &mut hit,
                    route_headers.as_deref(),
                    false,
                );
                http_modules.on_logging(Some(&hit), None);
                annotate(&mut hit, "cache_stale");
                return Ok(empty_interim_response(hit));
            }
            CacheLookupDecision::OnlyIfCachedMiss(response) => {
                let response = http_modules.prepare_downstream_response(response).await?;
                let mut response = finalize_response_with_headers(
                    &request_method,
                    req.version(),
                    proxy_name.as_str(),
                    response,
                    route_headers.as_deref(),
                    false,
                );
                http_modules.on_logging(Some(&response), None);
                annotate(&mut response, "cache_only_if_cached_miss");
                return Ok(empty_interim_response(response));
            }
            CacheLookupDecision::Miss => {}
        }
    }

    let mut _cache_collapse_guard = None;
    if request_method == Method::GET {
        if let (Some(snapshot), Some(policy), Some(lookup_key)) = (
            request_headers_snapshot.as_ref(),
            cache_policy,
            cache_lookup_key.as_ref(),
        ) {
            match crate::cache::begin_request_collapse(lookup_key) {
                crate::cache::RequestCollapseJoin::Leader(guard) => {
                    _cache_collapse_guard = Some(guard);
                }
                crate::cache::RequestCollapseJoin::Follower(waiter) => {
                    if waiter.wait(route_timeout).await {
                        let (lookup_decision, lookup_revalidation_state) =
                            lookup_with_revalidation(
                                &mut req,
                                snapshot,
                                cache_lookup_key.as_ref(),
                                Some(policy),
                                &runtime.state().cache.backends,
                                state.messages.cache_miss.as_str(),
                            )
                            .await?;
                        revalidation_state = lookup_revalidation_state;
                        let cache_hit = matches!(
                            lookup_decision,
                            CacheLookupDecision::Hit(_)
                                | CacheLookupDecision::StaleWhileRevalidate(_, _)
                        );
                        http_modules.on_cache_lookup(cache_hit).await?;
                        match lookup_decision {
                            CacheLookupDecision::Hit(mut hit) => {
                                hit = http_modules.prepare_downstream_response(hit).await?;
                                let hit_version = hit.version();
                                finalize_response_with_headers_in_place(
                                    &request_method,
                                    hit_version,
                                    proxy_name.as_str(),
                                    &mut hit,
                                    route_headers.as_deref(),
                                    false,
                                );
                                http_modules.on_logging(Some(&hit), None);
                                annotate(&mut hit, "cache_collapsed_hit");
                                return Ok(empty_interim_response(hit));
                            }
                            CacheLookupDecision::StaleWhileRevalidate(mut hit, _) => {
                                hit = http_modules.prepare_downstream_response(hit).await?;
                                let hit_version = hit.version();
                                finalize_response_with_headers_in_place(
                                    &request_method,
                                    hit_version,
                                    proxy_name.as_str(),
                                    &mut hit,
                                    route_headers.as_deref(),
                                    false,
                                );
                                http_modules.on_logging(Some(&hit), None);
                                annotate(&mut hit, "cache_collapsed_stale");
                                return Ok(empty_interim_response(hit));
                            }
                            CacheLookupDecision::OnlyIfCachedMiss(response) => {
                                let response =
                                    http_modules.prepare_downstream_response(response).await?;
                                let mut response = finalize_response_with_headers(
                                    &request_method,
                                    request_version,
                                    proxy_name.as_str(),
                                    response,
                                    route_headers.as_deref(),
                                    false,
                                );
                                http_modules.on_logging(Some(&response), None);
                                annotate(&mut response, "cache_only_if_cached_miss");
                                return Ok(empty_interim_response(response));
                            }
                            CacheLookupDecision::Miss => {}
                        }
                    }
                }
            }
        }
    }

    let can_retry = request_is_retryable(&req, &request_method);
    let attempts = if can_retry {
        route.policy.retry_attempts
    } else {
        1
    };
    let max_template_body_bytes = runtime
        .state()
        .config
        .runtime
        .max_reverse_retry_template_body_bytes;
    let mut mirror_upstreams = if request_is_templateable(&req, max_template_body_bytes) {
        route.select_mirror_upstreams(seed, sticky_seed)
    } else {
        Vec::new()
    };
    mirror_upstreams.extend(
        ext_authz_mirror_upstreams
            .into_iter()
            .map(UpstreamEndpoint::new)
            .map(Arc::new),
    );
    let need_template = attempts > 1 || !mirror_upstreams.is_empty();
    let (mut first_request, template) = if need_template {
        (
            None,
            Some(
                ReverseRequestTemplate::from_request(
                    req,
                    max_template_body_bytes,
                    std::time::Duration::from_millis(
                        state.config.runtime.http_header_read_timeout_ms.max(1),
                    ),
                )
                .await?,
            ),
        )
    } else {
        (Some(req), None)
    };

    let ipc_conn = ClientConnInfo {
        remote_addr: Some(conn.remote_addr),
    };

    let mut last_err = None;

    if override_upstream.is_none() {
        if let Some(ipc) = route.ipc.as_ref() {
            let _concurrency_permits = match request_limits.acquire_concurrency(&request_limit_ctx)
            {
                Some(permits) => permits,
                None => {
                    let mut response = finalize_response_for_request(
                        &request_method,
                        request_version,
                        proxy_name.as_str(),
                        too_many_requests(None),
                        false,
                    );
                    annotate(&mut response, "concurrency_limited");
                    return Ok(empty_interim_response(response));
                }
            };
            let timeout_dur = std::cmp::min(route_timeout, ipc.timeout());
            for attempt_idx in 0..attempts {
                let started = Instant::now();
                let mut req_for_upstream = if attempt_idx == 0 {
                    match (&template, first_request.take()) {
                        (Some(template), _) => template.build()?,
                        (None, Some(req)) => req,
                        (None, None) => {
                            return Err(anyhow!("missing reverse request for first attempt"))
                        }
                    }
                } else {
                    template
                        .as_ref()
                        .ok_or_else(|| anyhow!("reverse retry template missing"))?
                        .build()?
                };
                http_modules
                    .on_upstream_request(&mut req_for_upstream)
                    .await?;

                let response = timeout(
                    timeout_dur,
                    proxy_ipc_upstream(
                        req_for_upstream,
                        ipc,
                        proxy_name.as_str(),
                        ipc_conn,
                        route_timeout,
                    ),
                )
                .await;

                match response {
                    Ok(Ok(resp)) => {
                        let resp = http_modules.on_upstream_response(resp).await?;
                        let response_rule = apply_response_rules(ResponseRuleInput {
                            route,
                            base: &base,
                            conn: &conn,
                            destination: &request_destination,
                            upstream_cert: None,
                            identity: &identity,
                            request_rpc: request_rpc.as_ref(),
                            route_headers: route_headers.clone(),
                            response: resp,
                            max_observed_response_body_bytes: state
                                .config
                                .runtime
                                .max_observed_response_body_bytes,
                            response_body_read_timeout: std::time::Duration::from_millis(
                                state.config.runtime.upstream_http_timeout_ms.max(1),
                            ),
                        })
                        .await?;
                        let (
                            mut resp,
                            route_headers_for_response,
                            response_cache_bypass,
                            response_policy_tags,
                            response_mirror,
                        ) = match response_rule {
                            ResponseRuleDecision::Continue {
                                response,
                                route_headers,
                                cache_bypass,
                                policy_tags,
                                suppress_retry,
                                mirror,
                            } => {
                                if response.status().is_server_error()
                                    && attempt_idx + 1 < attempts
                                    && !suppress_retry
                                {
                                    let retry_reason =
                                        format!("upstream returned {}", response.status());
                                    last_err = Some(anyhow!(retry_reason.clone()));
                                    if !route.policy.retry_budget.try_consume_retry() {
                                        counter!(state
                                            .observability
                                            .metric_names
                                            .reverse_retry_budget_exhausted_total
                                            .clone())
                                        .increment(1);
                                        break;
                                    }
                                    http_modules
                                        .on_retry(attempt_idx + 2, retry_reason.as_str())
                                        .await?;
                                    if route.policy.retry_backoff > Duration::ZERO {
                                        sleep(route.policy.retry_backoff).await;
                                    }
                                    continue;
                                }
                                (response, route_headers, cache_bypass, policy_tags, mirror)
                            }
                            ResponseRuleDecision::LocalResponse {
                                response,
                                route_headers,
                                policy_tags,
                            } => {
                                let response =
                                    http_modules.prepare_downstream_response(response).await?;
                                let mut response = finalize_response_with_headers(
                                    &request_method,
                                    request_version,
                                    proxy_name.as_str(),
                                    response,
                                    route_headers.as_deref(),
                                    false,
                                );
                                http_modules.on_logging(Some(&response), None);
                                annotate_with_tags(
                                    &mut response,
                                    "response_rule_local_response",
                                    policy_tags.as_ref(),
                                );
                                return Ok(empty_interim_response(response));
                            }
                        };
                        if resp.status().is_server_error() {
                            if let Some(stale) = revalidation_state
                                .as_ref()
                                .and_then(crate::cache::maybe_build_stale_if_error_response)
                            {
                                let stale = http_modules.prepare_downstream_response(stale).await?;
                                let mut stale = stale;
                                let stale_version = stale.version();
                                finalize_response_with_headers_in_place(
                                    &request_method,
                                    stale_version,
                                    proxy_name.as_str(),
                                    &mut stale,
                                    route_headers.as_deref(),
                                    false,
                                );
                                http_modules.on_logging(Some(&stale), None);
                                annotate(&mut stale, "stale_if_error");
                                return Ok(empty_interim_response(stale));
                            }
                        }
                        histogram!(state
                            .observability
                            .metric_names
                            .reverse_upstream_latency_ms
                            .clone())
                        .record(started.elapsed().as_secs_f64() * 1000.0);
                        let response_delay_secs = started.elapsed().as_secs();
                        counter!(
                            state.observability.metric_names.reverse_requests_total.clone(),
                            "result" => "ok"
                        )
                        .increment(1);
                        if let (Some(policy), Some(snapshot)) = (
                            cache_policy.filter(|_| !response_cache_bypass),
                            request_headers_snapshot.as_ref(),
                        ) {
                            resp = process_upstream_response_for_cache(
                                resp,
                                CacheWritebackContext {
                                    request_method: &request_method,
                                    response_delay_secs,
                                    cache_target_key: cache_target_key.as_ref(),
                                    cache_lookup_key: cache_lookup_key.as_ref(),
                                    cache_policy: Some(policy),
                                    request_headers_snapshot: snapshot,
                                    revalidation_state: revalidation_state.take(),
                                    body_read_timeout: std::time::Duration::from_millis(
                                        runtime
                                            .state()
                                            .config
                                            .runtime
                                            .upstream_http_timeout_ms
                                            .max(1),
                                    ),
                                    backends: &runtime.state().cache.backends,
                                },
                            )
                            .await?;
                        } else if let Some(policy) = cache_policy.filter(|_| !response_cache_bypass)
                        {
                            crate::cache::maybe_invalidate(
                                &request_method,
                                resp.status(),
                                resp.headers(),
                                cache_target_key.as_ref(),
                                policy,
                                &runtime.state().cache.backends,
                            )
                            .await?;
                        }
                        resp = http_modules.prepare_downstream_response(resp).await?;
                        let resp_version = resp.version();
                        finalize_response_with_headers_in_place(
                            &request_method,
                            resp_version,
                            proxy_name.as_str(),
                            &mut resp,
                            route_headers_for_response.as_deref(),
                            false,
                        );
                        let should_dispatch_mirrors =
                            response_mirror.unwrap_or(true) && !mirror_upstreams.is_empty();
                        if should_dispatch_mirrors {
                            if let Some(template) = template.as_ref() {
                                dispatch_mirrors(
                                    template,
                                    std::mem::take(&mut mirror_upstreams),
                                    route_timeout,
                                    route.policy.health.clone(),
                                    route.policy.lifecycle.clone(),
                                    route.upstream_trust.clone(),
                                    proxy_name.as_str(),
                                );
                            }
                        }
                        http_modules.on_logging(Some(&resp), None);
                        annotate_with_tags(&mut resp, "allow", response_policy_tags.as_ref());
                        return Ok(empty_interim_response(resp));
                    }
                    Ok(Err(err)) => {
                        http_modules.on_error(&err);
                        counter!(
                            state.observability.metric_names.reverse_requests_total.clone(),
                            "result" => "error"
                        )
                        .increment(1);
                        last_err = Some(err);
                    }
                    Err(_) => {
                        let err = anyhow!("upstream timeout");
                        http_modules.on_error(&err);
                        counter!(
                            state.observability.metric_names.reverse_requests_total.clone(),
                            "result" => "timeout"
                        )
                        .increment(1);
                        last_err = Some(err);
                    }
                }

                if attempt_idx + 1 < attempts {
                    if !route.policy.retry_budget.try_consume_retry() {
                        counter!(state
                            .observability
                            .metric_names
                            .reverse_retry_budget_exhausted_total
                            .clone())
                        .increment(1);
                        break;
                    }
                    if let Some(err) = last_err.as_ref() {
                        let retry_reason = err.to_string();
                        http_modules
                            .on_retry(attempt_idx + 2, retry_reason.as_str())
                            .await?;
                    }
                    if route.policy.retry_backoff > Duration::ZERO {
                        sleep(route.policy.retry_backoff).await;
                    }
                }
            }

            if let Some(stale) = revalidation_state
                .as_ref()
                .and_then(crate::cache::maybe_build_stale_if_error_response)
            {
                let stale = http_modules.prepare_downstream_response(stale).await?;
                let mut stale = stale;
                let stale_version = stale.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    stale_version,
                    proxy_name.as_str(),
                    &mut stale,
                    route_headers.as_deref(),
                    false,
                );
                http_modules.on_logging(Some(&stale), None);
                annotate(&mut stale, "stale_if_error");
                return Ok(empty_interim_response(stale));
            }

            if let Some(err) = last_err.as_ref() {
                http_modules.on_error(err);
            }
            return Err(last_err.unwrap_or_else(|| anyhow!("upstream request failed")));
        }
    }

    for attempt_idx in 0..attempts {
        let selected_upstream = if override_upstream.is_none() {
            Some(
                route
                    .select_upstream(seed, sticky_seed)
                    .ok_or_else(|| anyhow!("no upstream"))?,
            )
        } else {
            None
        };
        let override_origin = override_upstream.as_deref().map(OriginEndpoint::direct);
        let upstream_origin = override_origin
            .as_ref()
            .or_else(|| selected_upstream.as_ref().map(|upstream| &upstream.origin))
            .ok_or_else(|| anyhow!("no upstream"))?;
        let mut concurrency_ctx = request_limit_ctx.clone();
        if concurrency_ctx.upstream.is_none() {
            concurrency_ctx.upstream = selected_upstream
                .as_ref()
                .map(|upstream| upstream.target.clone());
        }
        let _concurrency_permits = match request_limits.acquire_concurrency(&concurrency_ctx) {
            Some(permits) => permits,
            None => {
                let mut response = finalize_response_for_request(
                    &request_method,
                    request_version,
                    proxy_name.as_str(),
                    too_many_requests(None),
                    false,
                );
                annotate(&mut response, "concurrency_limited");
                return Ok(empty_interim_response(response));
            }
        };
        if let Some(upstream) = selected_upstream.as_ref() {
            upstream.inflight.fetch_add(1, Ordering::Relaxed);
        }
        let started = Instant::now();
        let mut req_for_upstream = if attempt_idx == 0 {
            match (&template, first_request.take()) {
                (Some(template), _) => template.build()?,
                (None, Some(req)) => req,
                (None, None) => return Err(anyhow!("missing reverse request for first attempt")),
            }
        } else {
            template
                .as_ref()
                .ok_or_else(|| anyhow!("reverse retry template missing"))?
                .build()?
        };
        http_modules
            .on_upstream_request(&mut req_for_upstream)
            .await?;
        let response = timeout(route_timeout, async {
            if upstream_origin.upstream.starts_with("ipc://")
                || upstream_origin.upstream.starts_with("ipc+unix://")
            {
                let url = Url::parse(upstream_origin.upstream.as_str())
                    .map_err(|err| anyhow!("invalid ipc upstream url: {}", err))?;
                return Ok((
                    Vec::new(),
                    proxy_ipc(req_for_upstream, &url, proxy_name.as_str()).await?,
                    None,
                ));
            }
            if matches!(
                request_version,
                http::Version::HTTP_10
                    | http::Version::HTTP_11
                    | http::Version::HTTP_2
                    | http::Version::HTTP_3
            ) {
                let proxied = proxy_http_with_interim(
                    req_for_upstream,
                    upstream_origin,
                    proxy_name.as_str(),
                    route.upstream_trust.as_deref(),
                )
                .await?;
                return Ok((proxied.interim, proxied.response, proxied.upstream_cert));
            }
            Ok((
                Vec::new(),
                proxy_http(
                    req_for_upstream,
                    upstream_origin,
                    proxy_name.as_str(),
                    route.upstream_trust.as_deref(),
                )
                .await?,
                None,
            ))
        })
        .await;
        if let Some(upstream) = selected_upstream.as_ref() {
            upstream.inflight.fetch_sub(1, Ordering::Relaxed);
        }

        match response {
            Ok(Ok((interim, resp, upstream_cert))) => {
                let resp = http_modules.on_upstream_response(resp).await?;
                let response_destination = classify_reverse_destination(
                    &state,
                    &conn,
                    host.as_str(),
                    upstream_cert.as_ref(),
                    resolution_override.as_ref(),
                );
                let response_rule = apply_response_rules(ResponseRuleInput {
                    route,
                    base: &base,
                    conn: &conn,
                    destination: &response_destination,
                    upstream_cert: upstream_cert.as_ref(),
                    identity: &identity,
                    request_rpc: request_rpc.as_ref(),
                    route_headers: route_headers.clone(),
                    response: resp,
                    max_observed_response_body_bytes: state
                        .config
                        .runtime
                        .max_observed_response_body_bytes,
                    response_body_read_timeout: std::time::Duration::from_millis(
                        state.config.runtime.upstream_http_timeout_ms.max(1),
                    ),
                })
                .await?;
                let (
                    mut resp,
                    route_headers_for_response,
                    response_cache_bypass,
                    response_policy_tags,
                    response_mirror,
                ) = match response_rule {
                    ResponseRuleDecision::Continue {
                        response,
                        route_headers,
                        cache_bypass,
                        policy_tags,
                        suppress_retry,
                        mirror,
                    } => {
                        if response.status().is_server_error()
                            && attempt_idx + 1 < attempts
                            && !suppress_retry
                        {
                            if let Some(upstream) = selected_upstream.as_ref() {
                                record_reverse_upstream_status(
                                    upstream,
                                    &route.policy,
                                    response.status(),
                                    started.elapsed(),
                                );
                            }
                            let retry_reason = format!("upstream returned {}", response.status());
                            last_err = Some(anyhow!(retry_reason.clone()));
                            if !route.policy.retry_budget.try_consume_retry() {
                                counter!(state
                                    .observability
                                    .metric_names
                                    .reverse_retry_budget_exhausted_total
                                    .clone())
                                .increment(1);
                                break;
                            }
                            http_modules
                                .on_retry(attempt_idx + 2, retry_reason.as_str())
                                .await?;
                            if route.policy.retry_backoff > Duration::ZERO {
                                sleep(route.policy.retry_backoff).await;
                            }
                            continue;
                        }
                        (response, route_headers, cache_bypass, policy_tags, mirror)
                    }
                    ResponseRuleDecision::LocalResponse {
                        response,
                        route_headers,
                        policy_tags,
                    } => {
                        let response = http_modules.prepare_downstream_response(response).await?;
                        let mut response = finalize_response_with_headers(
                            &request_method,
                            request_version,
                            proxy_name.as_str(),
                            response,
                            route_headers.as_deref(),
                            false,
                        );
                        http_modules.on_logging(Some(&response), None);
                        annotate_with_tags(
                            &mut response,
                            "response_rule_local_response",
                            policy_tags.as_ref(),
                        );
                        return Ok(empty_interim_response(response));
                    }
                };
                if resp.status().is_server_error() {
                    if let Some(stale) = revalidation_state
                        .as_ref()
                        .and_then(crate::cache::maybe_build_stale_if_error_response)
                    {
                        if let Some(upstream) = selected_upstream.as_ref() {
                            record_reverse_upstream_status(
                                upstream,
                                &route.policy,
                                resp.status(),
                                started.elapsed(),
                            );
                        }
                        let stale = http_modules.prepare_downstream_response(stale).await?;
                        let mut stale = stale;
                        let stale_version = stale.version();
                        finalize_response_with_headers_in_place(
                            &request_method,
                            stale_version,
                            proxy_name.as_str(),
                            &mut stale,
                            route_headers.as_deref(),
                            false,
                        );
                        http_modules.on_logging(Some(&stale), None);
                        annotate(&mut stale, "stale_if_error");
                        return Ok(empty_interim_response(stale));
                    }
                }
                if let Some(upstream) = selected_upstream.as_ref() {
                    record_reverse_upstream_status(
                        upstream,
                        &route.policy,
                        resp.status(),
                        started.elapsed(),
                    );
                }
                histogram!(state
                    .observability
                    .metric_names
                    .reverse_upstream_latency_ms
                    .clone())
                .record(started.elapsed().as_secs_f64() * 1000.0);
                let response_delay_secs = started.elapsed().as_secs();
                counter!(
                    state.observability.metric_names.reverse_requests_total.clone(),
                    "result" => "ok"
                )
                .increment(1);
                if let (Some(policy), Some(snapshot)) = (
                    cache_policy.filter(|_| !response_cache_bypass),
                    request_headers_snapshot.as_ref(),
                ) {
                    resp = process_upstream_response_for_cache(
                        resp,
                        CacheWritebackContext {
                            request_method: &request_method,
                            response_delay_secs,
                            cache_target_key: cache_target_key.as_ref(),
                            cache_lookup_key: cache_lookup_key.as_ref(),
                            cache_policy: Some(policy),
                            request_headers_snapshot: snapshot,
                            revalidation_state: revalidation_state.take(),
                            body_read_timeout: std::time::Duration::from_millis(
                                runtime
                                    .state()
                                    .config
                                    .runtime
                                    .upstream_http_timeout_ms
                                    .max(1),
                            ),
                            backends: &runtime.state().cache.backends,
                        },
                    )
                    .await?;
                } else if let Some(policy) = cache_policy.filter(|_| !response_cache_bypass) {
                    crate::cache::maybe_invalidate(
                        &request_method,
                        resp.status(),
                        resp.headers(),
                        cache_target_key.as_ref(),
                        policy,
                        &runtime.state().cache.backends,
                    )
                    .await?;
                }
                resp = http_modules.prepare_downstream_response(resp).await?;
                let resp_version = resp.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    resp_version,
                    proxy_name.as_str(),
                    &mut resp,
                    route_headers_for_response.as_deref(),
                    false,
                );
                let should_dispatch_mirrors =
                    response_mirror.unwrap_or(true) && !mirror_upstreams.is_empty();
                if should_dispatch_mirrors {
                    if let Some(template) = template.as_ref() {
                        dispatch_mirrors(
                            template,
                            std::mem::take(&mut mirror_upstreams),
                            route_timeout,
                            route.policy.health.clone(),
                            route.policy.lifecycle.clone(),
                            route.upstream_trust.clone(),
                            proxy_name.as_str(),
                        );
                    }
                }
                http_modules.on_logging(Some(&resp), None);
                annotate_with_tags(&mut resp, "allow", response_policy_tags.as_ref());
                return Ok((interim, resp));
            }
            Ok(Err(err)) => {
                http_modules.on_error(&err);
                if let Some(upstream) = selected_upstream.as_ref() {
                    record_reverse_upstream_error(upstream, &route.policy, &err);
                }
                counter!(
                    state.observability.metric_names.reverse_requests_total.clone(),
                    "result" => "error"
                )
                .increment(1);
                last_err = Some(err);
            }
            Err(_) => {
                let err = anyhow!("upstream timeout");
                http_modules.on_error(&err);
                if let Some(upstream) = selected_upstream.as_ref() {
                    record_reverse_upstream_timeout(upstream, &route.policy);
                }
                counter!(
                    state.observability.metric_names.reverse_requests_total.clone(),
                    "result" => "timeout"
                )
                .increment(1);
                last_err = Some(err);
            }
        }

        if attempt_idx + 1 < attempts {
            if !route.policy.retry_budget.try_consume_retry() {
                counter!(state
                    .observability
                    .metric_names
                    .reverse_retry_budget_exhausted_total
                    .clone())
                .increment(1);
                break;
            }
            if let Some(err) = last_err.as_ref() {
                let retry_reason = err.to_string();
                http_modules
                    .on_retry(attempt_idx + 2, retry_reason.as_str())
                    .await?;
            }
            if route.policy.retry_backoff > Duration::ZERO {
                sleep(route.policy.retry_backoff).await;
            }
        }
    }

    if let Some(stale) = revalidation_state
        .as_ref()
        .and_then(crate::cache::maybe_build_stale_if_error_response)
    {
        let stale = http_modules.prepare_downstream_response(stale).await?;
        let mut stale = stale;
        let stale_version = stale.version();
        finalize_response_with_headers_in_place(
            &request_method,
            stale_version,
            proxy_name.as_str(),
            &mut stale,
            route_headers.as_deref(),
            false,
        );
        http_modules.on_logging(Some(&stale), None);
        annotate(&mut stale, "stale_if_error");
        return Ok(empty_interim_response(stale));
    }

    if let Some(err) = last_err.as_ref() {
        http_modules.on_error(err);
    }
    Err(last_err.unwrap_or_else(|| anyhow!("upstream request failed")))
}
