use super::*;
use crate::http::dispatch::{
    DispatchCacheDecisionInput, DispatchCachedResponseInput, DispatchCollapsedCacheDecisionInput,
    ProxyKind, finalize_dispatch_cache_decision, finalize_dispatch_cached_response,
    finalize_dispatch_collapsed_cache_decision,
};
use crate::http::modules::{self, HttpModuleEvent, HttpModuleStage, ModuleStages};
use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use qpx_core::http_message::OrdinaryHeaderName;
use qpxd_cache::{CacheStoreContext, CacheStoreTiming, LookupOutcome};
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct Probe(Mutex<Vec<HttpModuleStage>>);
impl modules::HttpModuleFactory for Arc<Probe> {
    fn build(
        &self,
        _: &qpx_core::config::HttpModuleConfig,
    ) -> Result<Arc<dyn modules::HttpModule>> {
        Ok(self.clone())
    }
}
#[async_trait::async_trait]
impl modules::HttpModule for Probe {
    fn capabilities(&self) -> modules::HttpModuleCapabilities {
        let mut caps = modules::HttpModuleCapabilities::headers_only(ModuleStages::all());
        caps.mutates_response_headers = true;
        caps
    }
    async fn call<'a>(
        &self,
        stage: HttpModuleStage,
        _: &mut modules::HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> Result<HttpModuleEvent<'a>> {
        self.0.lock().unwrap().push(stage);
        Ok(match event {
            HttpModuleEvent::UpstreamRequest(_) => HttpModuleEvent::Complete,
            HttpModuleEvent::DownstreamResponse(mut response) => {
                // Common finalization must follow this standard-only hook.
                response.set_header(
                    http::header::CONNECTION,
                    HeaderValue::from_static("x-remove"),
                );
                response.set_header(
                    http::HeaderName::from_static("x-remove"),
                    HeaderValue::from_static("gone"),
                );
                response.set_header(
                    http::HeaderName::from_static("x-module"),
                    HeaderValue::from_static("prepared"),
                );
                HttpModuleEvent::DownstreamResponse(response)
            }
            HttpModuleEvent::Log {
                response_status,
                err,
            } => {
                assert!(response_status.is_some());
                assert!(err.is_none());
                HttpModuleEvent::Complete
            }
            HttpModuleEvent::Error(_) => HttpModuleEvent::Complete,
            event => event,
        })
    }
}

struct Fixture {
    runtime: crate::runtime::Runtime,
    probe: Arc<Probe>,
    _dir: tempfile::TempDir,
}
impl Fixture {
    fn new(active: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let probe = Arc::new(Probe::default());
        let mut registry = modules::HttpModuleRegistryBuilder::new();
        registry.register_factory("probe", probe.clone()).unwrap();
        let mut config: qpx_core::config::Config = serde_yaml::from_str(
            r#"
edges:
  - kind: forward
    name: forward
    listen: 127.0.0.1:0
    default_action: { type: direct }
    cache: { enabled: true, backend: test }
caches:
  - name: test
    kind: disk
    max_bytes: 1048576
"#,
        )
        .unwrap();
        let cache_path = std::fs::canonicalize(dir.path()).unwrap();
        config.caches[0].path = Some(cache_path.to_str().unwrap().to_owned());
        if active {
            let qpx_core::config::EdgeConfig::Forward(edge) = &mut config.edges[0] else {
                unreachable!()
            };
            edge.http_modules = vec![serde_yaml::from_str("type: probe").unwrap()];
        }
        let runtime =
            crate::runtime::Runtime::with_http_module_registry(config, Arc::new(registry.build()))
                .unwrap();
        Self {
            runtime,
            probe,
            _dir: dir,
        }
    }
    fn modules(&self) -> modules::HttpModuleExecution {
        let state = self.runtime.state();
        state
            .plan
            .ingress_edge_execution_plan("forward", None)
            .unwrap()
            .modules
            .start(
                &state,
                modules::HttpModuleSessionInit {
                    proxy_kind: ProxyKind::Forward,
                    proxy_name: "forward",
                    scope_name: "forward",
                    route_name: None,
                    remote_ip: "127.0.0.1".parse().unwrap(),
                    sni: None,
                    identity_user: None,
                    cache_policy: None,
                    cache_default_scheme: Some("http"),
                },
            )
    }
    async fn stale(&self, method: &Method, eligible: bool) -> qpxd_cache::RevalidationState {
        let state = self.runtime.state();
        let policy = state
            .plan
            .ingress_edge_execution_plan("forward", None)
            .unwrap()
            .cache
            .as_ref()
            .unwrap();
        let mut request = Request::new(());
        *request.uri_mut() = "http://example.test/asset".parse().unwrap();
        let key = CacheRequestKey::for_lookup(&request, "http")
            .unwrap()
            .unwrap();
        let response = http::Response::builder()
            .header(
                "cache-control",
                if eligible {
                    "max-age=0, stale-if-error=3600"
                } else {
                    "max-age=0, must-revalidate, stale-if-error=3600"
                },
            )
            .header("etag", "\"cached\"")
            .header("content-length", "6")
            .header("x-duplicate", "first")
            .header("x-duplicate", "second")
            .body(Body::from("cached"))
            .unwrap();
        let response = qpxd_cache::maybe_store(
            &request,
            &key,
            policy,
            OwnerResponse::from_http(response),
            CacheStoreContext {
                timing: CacheStoreTiming {
                    response_delay_secs: 0,
                    body_read_timeout: Duration::from_secs(1),
                    request_collapse_guard: None,
                },
                writeback_admission: &state.cache.writeback_admission,
                backends: &state.cache.backends,
            },
        )
        .await
        .unwrap();
        qpx_http::body::to_bytes(response.into_head_and_body().1)
            .await
            .unwrap();
        *request.method_mut() = method.clone();
        // Poll the public lookup boundary, not a fixed sleep or private cache metadata.
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let LookupOutcome::Revalidate(stale) = qpxd_cache::lookup(
                    &request,
                    &key,
                    policy,
                    &state.cache.backends,
                    &Arc::new(qpxd_cache::InFlightRevalidations::with_default_shards()),
                )
                .await
                .unwrap()
                {
                    break stale;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("cache writeback completed")
    }
    async fn dispatch(
        &self,
        transport_error: bool,
        stale: Option<qpxd_cache::RevalidationState>,
        method: &Method,
    ) -> Result<OwnerResponse<Body>> {
        // A retained loopback listener avoids an unused-port race. EOF is a real
        // bounded transport error; 503 exercises the distinct upstream-status exit.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                if socket.read(&mut byte).await.unwrap() == 0 {
                    return;
                }
                head.push(byte[0]);
                assert!(head.len() < 8192);
            }
            if !transport_error {
                socket.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            }
        });
        let mut request = Request::new(Body::empty());
        *request.method_mut() = method.clone();
        *request.uri_mut() = format!("http://{addr}/asset").parse().unwrap();
        let base = extract_base_request_fields(&request, BaseRequestContext::default());
        let state = self.runtime.state();
        let plan = state
            .plan
            .ingress_edge_execution_plan("forward", None)
            .unwrap();
        let mut modules = self.modules();
        let audit = audit(method);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            execute_forward_upstream(ForwardUpstreamInput {
                req: request,
                upstream: None,
                http_authority: &addr.to_string(),
                upstream_timeout: Duration::from_secs(1),
                http_modules: &mut modules,
                export_session: None,
                request_method: method,
                client_version: http::Version::HTTP_11,
                proxy_name: "forward",
                headers: None,
                cache_policy: None,
                request_headers_snapshot: None,
                cache_lookup_key: None,
                cache_target_key: None,
                revalidation_state: stale,
                cache_collapse_guard: None,
                response_engine: None,
                selected_plan: plan,
                base: &base,
                destination: &Default::default(),
                identity: &Default::default(),
                host: &HostPort {
                    host: "127.0.0.1".to_owned(),
                    port: Some(addr.port()),
                },
                remote_addr: "127.0.0.1:12345".parse().unwrap(),
                state: &state,
                request_rpc: None,
                audit: &audit,
            }),
        )
        .await
        .expect("bounded forward dispatch");
        if server.is_finished() {
            server.await.unwrap();
        } else {
            server.abort();
            panic!("upstream was not reached: {:?}", result.as_ref().err());
        }
        result
    }
}
fn audit(method: &Method) -> DispatchAuditContext {
    DispatchAuditContext::new(
        None,
        ProxyKind::Forward,
        None,
        "127.0.0.1:12345".parse().unwrap(),
        method.clone(),
        Some("/asset".to_owned()),
        Default::default(),
    )
}
fn ord(name: &str) -> OrdinaryHeaderName {
    OrdinaryHeaderName::try_from(name).unwrap()
}

#[tokio::test]
async fn forward_stale_dispatch_transport_and_5xx_preserve_head_and_module_order() {
    for transport_error in [true, false] {
        for active in [false, true] {
            for method in [Method::GET, Method::HEAD] {
                let fixture = Fixture::new(active);
                let stale = fixture.stale(&method, true).await;
                let mut response = fixture
                    .dispatch(transport_error, Some(stale), &method)
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    response.headers().declared_content_length().unwrap(),
                    Some(6)
                );
                assert_eq!(
                    response
                        .headers()
                        .get_all(&ord("x-duplicate"))
                        .map(|v| v.to_str().unwrap())
                        .collect::<Vec<_>>(),
                    ["first", "second"]
                );
                assert!(response.headers().contains_key(&ord("via")));
                assert!(!response.headers().contains_key(&ord("x-remove")));
                assert!(!response.headers().contains_key(&ord("connection")));
                assert_eq!(response.headers().contains_key(&ord("x-module")), active);
                let bytes = qpx_http::body::to_bytes(response.body_mut()).await.unwrap();
                assert_eq!(
                    bytes.as_ref(),
                    if method == Method::HEAD {
                        &b""[..]
                    } else {
                        &b"cached"[..]
                    }
                );
                assert!(response.body_mut().trailers().await.unwrap().is_none());
                let expected = if active {
                    vec![
                        HttpModuleStage::UpstreamRequest,
                        if transport_error {
                            HttpModuleStage::Error
                        } else {
                            HttpModuleStage::UpstreamResponse
                        },
                        HttpModuleStage::DownstreamResponse,
                        HttpModuleStage::Log,
                    ]
                } else {
                    vec![]
                };
                assert_eq!(*fixture.probe.0.lock().unwrap(), expected);
            }
        }
    }
}

#[tokio::test]
async fn forward_stale_dispatch_without_eligible_stale_keeps_error_or_5xx() {
    for transport_error in [true, false] {
        for active in [false, true] {
            for ineligible in [false, true] {
                let fixture = Fixture::new(active);
                let stale = if ineligible {
                    Some(fixture.stale(&Method::GET, false).await)
                } else {
                    None
                };
                let response = fixture.dispatch(transport_error, stale, &Method::GET).await;
                if transport_error {
                    assert!(response.is_err());
                } else {
                    assert_eq!(response.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
                }
                let expected = if !active {
                    vec![]
                } else if transport_error {
                    vec![HttpModuleStage::UpstreamRequest, HttpModuleStage::Error]
                } else {
                    vec![
                        HttpModuleStage::UpstreamRequest,
                        HttpModuleStage::UpstreamResponse,
                        HttpModuleStage::DownstreamResponse,
                        HttpModuleStage::Log,
                    ]
                };
                assert_eq!(*fixture.probe.0.lock().unwrap(), expected);
            }
        }
    }
}

// Stale cache construction cannot persist arbitrary response extensions or
// trailers. Exercise those at the shared terminal seam, comparing both outputs.
#[tokio::test]
async fn cached_terminal_carriers_preserve_extensions_framing_trailers_and_errors() {
    for active in [false, true] {
        for abort in [false, true] {
            let fixture = Fixture::new(active);
            let state = fixture.runtime.state();
            let plan = state
                .plan
                .ingress_edge_execution_plan("forward", None)
                .unwrap();
            let mut observed = Vec::new();
            for owned in [false, true] {
                let (mut sender, body) = Body::channel_with_capacity(1);
                let producer = tokio::spawn(async move {
                    sender
                        .send_data(Bytes::from_static(b"cached"))
                        .await
                        .unwrap();
                    if abort {
                        sender.abort();
                    } else {
                        let mut trailers = HeaderMap::new();
                        trailers.insert("x-trailer", HeaderValue::from_static("kept"));
                        trailers.insert("content-length", HeaderValue::from_static("900"));
                        sender.send_trailers(trailers).await.unwrap();
                    }
                });
                let mut response = http::Response::builder()
                    .status(201)
                    .header("x-duplicate", "one")
                    .header("x-duplicate", "two")
                    .body(body)
                    .unwrap();
                response
                    .headers_mut()
                    .get_mut("x-duplicate")
                    .unwrap()
                    .set_sensitive(true);
                response.extensions_mut().insert(42usize);
                let mut modules = fixture.modules();
                let audit = audit(&Method::GET);
                let input = DispatchCachedResponseInput {
                    response: OwnerResponse::from_http(response),
                    outcome: DispatchOutcome::StaleIfError,
                    plan,
                    request_method: &Method::GET,
                    response_version: None,
                    proxy_name: "forward",
                    headers: None,
                    http_modules: &mut modules,
                    audit: &audit,
                };
                let response = finalize_dispatch_cached_response(input).await.unwrap();
                // Observe the same final head at the library serializer boundary.
                let mut response = if owned {
                    response
                } else {
                    OwnerResponse::from_http(response.into_http_for_library())
                };
                assert_eq!(response.extensions().get::<usize>(), Some(&42));
                assert!(
                    response
                        .headers()
                        .get(&ord("x-duplicate"))
                        .unwrap()
                        .is_sensitive()
                );
                assert_eq!(
                    response
                        .headers()
                        .get_all(&ord("x-duplicate"))
                        .map(|v| v.as_bytes().to_vec())
                        .collect::<Vec<_>>(),
                    [b"one".to_vec(), b"two".to_vec()]
                );
                let mut bytes = Vec::new();
                let mut failed = false;
                while let Some(chunk) = response.body_mut().data().await {
                    match chunk {
                        Ok(chunk) => bytes.extend_from_slice(&chunk),
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    }
                }
                let trailers = if failed {
                    None
                } else {
                    response.body_mut().trailers().await.unwrap()
                };
                assert_eq!(failed, abort);
                if !abort {
                    assert_eq!(bytes, b"cached");
                    let trailers = trailers.as_ref().unwrap();
                    assert_eq!(trailers["x-trailer"], "kept");
                    assert!(!trailers.contains_key("content-length"));
                }
                observed.push((
                    response.status(),
                    response.headers().clone(),
                    bytes,
                    failed,
                    trailers,
                ));
                producer.await.unwrap();
            }
            assert_eq!(observed[0], observed[1]);
        }
    }
}

// The decision wrappers must select the owner before the shared terminal suffix,
// including the local miss response; a real miss must not finalize or log.
#[tokio::test]
async fn forward_cache_decisions_return_owners_for_lookup_and_collapsed_terminals() {
    use crate::http::capture::cache_flow::CacheLookupDecision;

    for active in [false, true] {
        let fixture = Fixture::new(active);
        let stale = fixture.stale(&Method::GET, true).await;
        let state = fixture.runtime.state();
        let plan = state
            .plan
            .ingress_edge_execution_plan("forward", None)
            .unwrap();
        for collapsed in [false, true] {
            for branch in ["hit", "stale", "only-if-cached", "miss"] {
                fixture.probe.0.lock().unwrap().clear();
                let status = if branch == "only-if-cached" {
                    StatusCode::GATEWAY_TIMEOUT
                } else {
                    StatusCode::OK
                };
                let mut response = http::Response::builder()
                    .status(status)
                    .header("content-length", "6")
                    .body(Body::from("cached"))
                    .unwrap();
                response.extensions_mut().insert(42usize);
                let decision = match branch {
                    "hit" => CacheLookupDecision::Hit(OwnerResponse::from_http(response)),
                    "stale" => CacheLookupDecision::StaleWhileRevalidate(
                        Box::new(OwnerResponse::from_http(response)),
                        Box::new(stale.clone()),
                    ),
                    "only-if-cached" => {
                        CacheLookupDecision::OnlyIfCachedMiss(OwnerResponse::from_http(response))
                    }
                    "miss" => CacheLookupDecision::Miss,
                    _ => unreachable!(),
                };
                let mut modules = fixture.modules();
                let audit = audit(&Method::GET);
                let response_version =
                    (branch == "only-if-cached").then_some(http::Version::HTTP_10);
                let response: Option<OwnerResponse<Body>> = if collapsed {
                    finalize_dispatch_collapsed_cache_decision(
                        DispatchCollapsedCacheDecisionInput {
                            decision,
                            plan,
                            request_method: &Method::GET,
                            response_version,
                            proxy_name: "forward",
                            headers: None,
                            http_modules: &mut modules,
                            audit: &audit,
                        },
                    )
                    .await
                    .unwrap()
                } else {
                    finalize_dispatch_cache_decision(DispatchCacheDecisionInput {
                        decision,
                        hit_outcome: DispatchOutcome::CacheHit,
                        stale_outcome: DispatchOutcome::CacheStale,
                        plan,
                        request_method: &Method::GET,
                        response_version,
                        proxy_name: "forward",
                        headers: None,
                        http_modules: &mut modules,
                        audit: &audit,
                    })
                    .await
                    .unwrap()
                };
                if branch == "miss" {
                    assert!(response.is_none());
                } else {
                    let mut response: OwnerResponse<Body> =
                        crate::http::capture::stream::emit_optional_response_for_export(
                            response.unwrap(),
                            plan,
                            None,
                        )
                        .await;
                    assert_eq!(response.status(), status);
                    // The request-version override selects Via, not the
                    // cached response's own protocol version.
                    assert_eq!(response.version(), http::Version::HTTP_11);
                    assert_eq!(
                        response.headers().get(&ord("via")).unwrap(),
                        if branch == "only-if-cached" {
                            "1.0 forward"
                        } else {
                            "1.1 forward"
                        }
                    );
                    assert_eq!(response.extensions().get::<usize>(), Some(&42));
                    assert_eq!(
                        response.headers().declared_content_length().unwrap(),
                        Some(6)
                    );
                    assert!(response.headers().contains_key(&ord("via")));
                    assert!(!response.headers().contains_key(&ord("x-remove")));
                    assert!(!response.headers().contains_key(&ord("connection")));
                    assert_eq!(response.headers().contains_key(&ord("x-module")), active);
                    assert_eq!(
                        qpx_http::body::to_bytes(response.body_mut()).await.unwrap(),
                        "cached"
                    );
                }
                let expected = if active && branch != "miss" {
                    vec![HttpModuleStage::DownstreamResponse, HttpModuleStage::Log]
                } else {
                    vec![]
                };
                assert_eq!(*fixture.probe.0.lock().unwrap(), expected);
            }
        }
    }
}
