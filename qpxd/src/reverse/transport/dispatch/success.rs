use super::super::empty_interim_response;
use super::super::mirrors::record_reverse_upstream_status;
use super::super::response_rules::{
    DispatchResponseRuleInput, ResponseRuleInput, apply_dispatch_response_rules,
};
use super::finalize::{ReverseFinalizeResponseInput, finalize_reverse_dispatch_response};
use super::{
    ReverseAttemptOutcome, ReverseResponseRuleInput, ReverseSuccessInput,
    capture_reverse_response_outcome, record_reverse_success_metrics,
    reverse_continue_response_rule,
};
use crate::http::dispatch::finalize_dispatch_stale_if_error_response;
use anyhow::Result;

pub(super) async fn handle_reverse_success(
    input: ReverseSuccessInput<'_>,
) -> Result<ReverseAttemptOutcome> {
    let ReverseSuccessInput {
        base,
        state,
        conn,
        route,
        response_destination,
        request_method,
        request_version,
        request_rpc,
        identity,
        route_headers,
        cache_policy,
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        revalidation_state,
        cache_collapse_guard,
        template,
        replay_recorder,
        mirror_upstreams,
        attempts,
        route_timeout,
        proxy_name,
        http_modules,
        audit_ctx,
        attempt_idx,
        selected_upstream,
        upstream_cert,
        interim,
        started,
        response: resp,
        export_session,
    } = input;
    let response_rule = apply_dispatch_response_rules(DispatchResponseRuleInput {
        rule: ResponseRuleInput {
            route,
            base,
            conn,
            destination: response_destination,
            upstream_cert,
            identity,
            request_rpc,
            route_headers: route_headers.clone(),
            response: resp,
            max_observed_response_body_bytes: route.plan.response_body_observation_limit(
                state.plan.limits.body.max_observed_response_body_bytes,
            ),
            response_body_read_timeout: state.plan.limits.timeouts.upstream_body_read_timeout(),
            force_response_body_observation: false,
        },
        http_modules,
        audit: audit_ctx,
        request_method,
        request_version,
        proxy_name,
    })
    .await?;
    let (resp, route_headers_for_response, response_cache_bypass, policy_tags, mirror) =
        match reverse_continue_response_rule(ReverseResponseRuleInput {
            response_rule,
            http_modules,
            state,
            route,
            selected_upstream,
            attempt_idx,
            attempts,
            started,
        })
        .await?
        {
            Ok(values) => values,
            Err(outcome) => {
                return Ok(capture_reverse_response_outcome(outcome, route, export_session).await);
            }
        };
    if resp.status().is_server_error()
        && let Some(stale) = finalize_dispatch_stale_if_error_response(
            revalidation_state.as_ref(),
            &route.plan,
            request_method,
            proxy_name,
            route_headers.as_deref(),
            http_modules,
            audit_ctx,
        )
        .await?
    {
        if let Some(upstream) = selected_upstream {
            record_reverse_upstream_status(upstream, &route.policy, resp.status(), started);
        }
        return Ok(capture_reverse_response_outcome(
            ReverseAttemptOutcome::Response(Box::new(empty_interim_response(stale))),
            route,
            export_session,
        )
        .await);
    }
    if let Some(upstream) = selected_upstream {
        record_reverse_upstream_status(upstream, &route.policy, resp.status(), started);
    }
    record_reverse_success_metrics(state, started);
    let resp = finalize_reverse_dispatch_response(ReverseFinalizeResponseInput {
        response: resp,
        state,
        route,
        request_method,
        cache_policy,
        response_cache_bypass,
        request_headers_snapshot,
        cache_target_key,
        cache_lookup_key,
        revalidation_state,
        cache_collapse_guard,
        started,
        route_headers_for_response,
        export_session,
        template,
        replay_recorder: replay_recorder.as_ref(),
        mirror_upstreams,
        mirror,
        route_timeout,
        proxy_name,
        http_modules,
        audit_ctx,
        policy_tags: policy_tags.as_slice(),
    })
    .await?;
    Ok(ReverseAttemptOutcome::Response(Box::new((interim, resp))))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    mod unix {
        use super::super::*;
        use crate::http::dispatch::{DispatchAuditContext, ProxyKind};
        use crate::http::modules::HttpModuleExecution;
        use crate::http::protocol::base_fields::extract_base_request_fields;
        use crate::reverse::router::ReverseRouter;
        use crate::reverse::transport::{InterimList, ReverseConnInfo};
        use hyper::{Method, Request, Response, StatusCode, Version};
        use qpx_http::body::{Body, to_bytes};
        use std::time::Duration;

        // Exercise the real policy, cache, health, finalizer and capture owners with
        // synthetic responses; no transport or lifecycle callbacks are substituted.
        #[tokio::test]
        async fn success_tail_orders_policy_retry_stale_finalization_and_capture() -> Result<()> {
            use crate::exporter::ExporterSink;
            use qpx_core::exporter::CaptureEvent;
            use qpx_core::shm_ring::ShmRingBuffer;
            use qpxd_cache::{CacheRequestKey, CacheStoreContext, CacheStoreTiming, LookupOutcome};

            for case in ["http", "ipc", "retry", "stop", "stale", "local"] {
                let dir = tempfile::tempdir()?;
                let cache_path = dir.path().canonicalize()?.join("cache");
                let config = qpx_core::config::load_config_value(
                    serde_yaml::from_str(&format!(
                        r#"upstreams:
- name: origin
  url: http://127.0.0.1:1
caches:
- name: disk
  kind: disk
  max_bytes: 1048576
  path: {}
edges:
- kind: reverse
  name: test
  listen: 127.0.0.1:0
  routes:
  - name: route
    match: {{}}
    streaming_requirement: preferred
    health_check: {{fail_threshold: 1, cooldown_ms: 60000}}
    target: {{type: upstream, upstreams: [origin]}}
"#,
                        serde_json::to_string(&cache_path)?
                    ))?,
                    "success tail test",
                )?;
                let mut edge = config.reverse_edges().next().unwrap().clone();
                if case == "local" {
                    edge.routes[0].http = Some(serde_yaml::from_str(
                        "response_rules:\n- name: local\n  effects:\n    local_response: {status: 418, body: policy}",
                    )?);
                }
                let registry = crate::http::modules::default_http_module_registry();
                let router = ReverseRouter::new(edge, &config.upstreams, registry.as_ref())?;
                let route = router.route_at(0).unwrap();
                let state = crate::runtime::Runtime::new(config)?.state();
                let selected = route.select_upstream(0, 0).unwrap();
                if matches!(case, "http" | "ipc") {
                    selected.mark_failure(&route.policy.health);
                }
                if case == "stop" {
                    while route.policy.retry_budget.try_consume_retry() {}
                }
                let request = Request::builder()
                    .uri("http://example.test/asset")
                    .body(Body::empty())?;
                let key = CacheRequestKey::for_lookup(&request, "http")?.unwrap();
                let policy = serde_yaml::from_str("enabled: true\nbackend: disk")?;
                let qpxd_cache::RequestCollapseJoin::Leader(guard) =
                    state.cache.begin_request_collapse(&key)
                else {
                    panic!("cache leader");
                };
                let qpxd_cache::RequestCollapseJoin::Follower(waiter) =
                    state.cache.begin_request_collapse(&key)
                else {
                    panic!("cache follower");
                };
                let wait = waiter.wait(Duration::from_secs(1));
                tokio::pin!(wait);
                assert!(futures_util::poll!(wait.as_mut()).is_pending());
                let cached = qpxd_cache::maybe_store(
                    &Method::GET,
                    request.headers(),
                    &key,
                    &policy,
                    Response::builder()
                        .header("cache-control", "max-age=0, stale-if-error=60")
                        .body(Body::from("cached"))?,
                    CacheStoreContext {
                        timing: CacheStoreTiming {
                            response_delay_secs: 0,
                            body_read_timeout: Duration::from_secs(1),
                            request_collapse_guard: Some(guard),
                        },
                        writeback_admission: &state.cache.writeback_admission,
                        backends: &state.cache.backends,
                    },
                )
                .await?;
                assert_eq!(to_bytes(cached.into_body()).await?, "cached");
                assert!(wait.await, "cache writeback completed");
                let LookupOutcome::Revalidate(stale) = qpxd_cache::lookup(
                    &Method::GET,
                    request.headers(),
                    &key,
                    &policy,
                    &state.cache.backends,
                    &state.cache.background_revalidations,
                )
                .await?
                else {
                    panic!("expected immediately stale cache entry: {case}");
                };
                let mut revalidation = Some(stale);
                let mut collapse = None;
                let mut modules = HttpModuleExecution::Empty;
                let conn = ReverseConnInfo::plain("127.0.0.1:1234".parse()?, 80);
                let base = extract_base_request_fields(&request, Default::default());
                let audit = DispatchAuditContext::new(
                    None,
                    ProxyKind::Reverse,
                    None,
                    conn.remote_addr,
                    Method::GET,
                    None,
                    Default::default(),
                );
                let shm_path = dir.path().join("capture.shm");
                let exporter = serde_yaml::from_str(&format!(
                    "enabled: true\nshm_path: {}\nshm_size_mb: 1\nmax_queue_events: 8\ncapture: {{plaintext: true}}",
                    serde_json::to_string(&shm_path)?
                ))?;
                let sink = ExporterSink::from_config(&exporter)?;
                let session = sink.session("client", "origin");
                let mut ring = ShmRingBuffer::create_or_open(&shm_path, 1024 * 1024)?;
                let mut interim = InterimList::new();
                if case != "ipc" {
                    let mut headers = http::HeaderMap::new();
                    headers.insert("link", "</asset>; rel=preload".parse()?);
                    interim.push(crate::upstream::raw_http1::InterimResponseHead {
                        status: StatusCode::EARLY_HINTS,
                        headers,
                    });
                }
                let is_error = !matches!(case, "http" | "ipc");
                let outcome = handle_reverse_success(ReverseSuccessInput {
                    base: &base,
                    state: &state,
                    conn: &conn,
                    route,
                    response_destination: &Default::default(),
                    request_method: &Method::GET,
                    request_version: Version::HTTP_11,
                    request_rpc: None,
                    identity: &Default::default(),
                    route_headers: None,
                    cache_policy: None,
                    request_headers_snapshot: None,
                    cache_lookup_key: None,
                    cache_target_key: None,
                    revalidation_state: &mut revalidation,
                    cache_collapse_guard: &mut collapse,
                    template: None,
                    replay_recorder: None,
                    mirror_upstreams: &mut Vec::new(),
                    attempts: if matches!(case, "retry" | "stop" | "local") {
                        2
                    } else {
                        1
                    },
                    route_timeout: Duration::from_secs(1),
                    proxy_name: "qpx-test",
                    http_modules: &mut modules,
                    audit_ctx: &audit,
                    attempt_idx: 0,
                    selected_upstream: (case != "ipc").then_some(&selected),
                    upstream_cert: None,
                    interim,
                    started: Some(tokio::time::Instant::now()),
                    response: Response::builder()
                        .status(if is_error { 503 } else { 200 })
                        .header("connection", "keep-alive")
                        .body(Body::from("origin"))?,
                    export_session: Some(&session),
                })
                .await?;
                match outcome {
                    ReverseAttemptOutcome::Retry(_) => assert_eq!(case, "retry"),
                    ReverseAttemptOutcome::Stop(_) => assert_eq!(case, "stop"),
                    ReverseAttemptOutcome::Response(response) => {
                        assert!(!matches!(case, "retry" | "stop"));
                        let (interim, response) = *response;
                        assert_eq!(interim.len(), usize::from(case == "http"), "{case}");
                        if case == "http" {
                            assert_eq!(interim[0].status, StatusCode::EARLY_HINTS);
                            assert_eq!(interim[0].headers["link"], "</asset>; rel=preload");
                        }
                        assert_eq!(
                            response.status().as_u16(),
                            if case == "local" { 418 } else { 200 }
                        );
                        assert!(response.headers().contains_key("via"), "{case}");
                        assert!(!response.headers().contains_key("connection"), "{case}");
                        assert_eq!(
                            to_bytes(response.into_body()).await?,
                            match case {
                                "stale" => "cached",
                                "local" => "policy",
                                _ => "origin",
                            }
                        );
                    }
                }
                assert_eq!(
                    selected.is_healthy(crate::runtime::now_millis()),
                    matches!(case, "http" | "local"),
                    "{case}"
                );
                // FIFO sentinel makes absence/uniqueness assertions deterministic:
                // all response events must precede this event, without sleeps.
                session.emit_plaintext(false, b"end");
                let events = tokio::time::timeout(Duration::from_secs(1), async {
                    let mut events = Vec::new();
                    loop {
                        if let Some(bytes) = ring.try_pop()? {
                            let event = CaptureEvent::decode_wire(bytes.into())?;
                            if event.payload.as_ref() == b"end" {
                                return Ok::<_, anyhow::Error>(events);
                            }
                            events.push(String::from_utf8(event.payload.to_vec())?);
                        } else {
                            ring.wait_for_data().await?;
                        }
                    }
                })
                .await??;
                assert_eq!(
                    events.len(),
                    usize::from(!matches!(case, "retry" | "stop")),
                    "{case}"
                );
                if let Some(event) = events.first() {
                    assert!(
                        event.to_ascii_lowercase().contains("via:"),
                        "{case}: {event}"
                    );
                }
                assert_eq!(
                    revalidation.is_some(),
                    !matches!(case, "http" | "ipc"),
                    "only normal finalization consumes cache state: {case}"
                );
                ring.unlink_doorbells()?;
            }
            Ok(())
        }
    }
}
