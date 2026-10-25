use super::execution::subrequest::SubrequestModule;
use super::execution::template::{
    CompiledTemplate, TemplateModifier, TemplatePart, TemplateVariable, compile_template,
    render_template,
};
use super::*;
use crate::runtime::Runtime;
use bytes::Bytes;
use http::header::{HOST, LOCATION};
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use qpx_core::config::{
    AccessLogConfig, AuditLogConfig, AuthConfig, Config, HttpModuleConfig, IdentityConfig,
    MessagesConfig, RuntimeConfig, SubrequestModuleConfig, SubrequestPhase, SystemLogConfig,
};
use qpx_http::body::Body;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

fn module_test_runtime() -> Runtime {
    Runtime::new(Config {
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
                services: Vec::new(),
            },
            destination: Default::default(),
            named_sets: Vec::new(),
            upstream_trust_profiles: Vec::new(),
        },
        http: qpx_core::config::HttpGlobalConfig::default(),
        traffic: qpx_core::config::TrafficConfig::default(),
        acme: None,
        edges: Vec::new(),
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime")
}

pub(super) fn module_test_context() -> HttpModuleContext {
    HttpModuleContext::new(
        module_test_runtime().state(),
        HttpModuleSessionInit {
            proxy_kind: crate::http::dispatch::ProxyKind::Forward,
            proxy_name: "test-proxy",
            scope_name: "test-scope",
            route_name: Some("test-route"),
            remote_ip: "127.0.0.1".parse::<IpAddr>().expect("ip"),
            sni: Some("example.com"),
            identity_user: Some("alice"),
            cache_policy: None,
            cache_default_scheme: None,
        },
    )
}

#[tokio::test]
async fn empty_module_chain_is_a_context_free_identity_transform() {
    let runtime = module_test_runtime();
    let chain = Arc::new(CompiledHttpModuleChain::default());
    let state = runtime.state();
    let mut execution = chain.start(
        &state,
        HttpModuleSessionInit {
            proxy_kind: crate::http::dispatch::ProxyKind::Reverse,
            proxy_name: "test-proxy",
            scope_name: "test-scope",
            route_name: Some("test-route"),
            remote_ip: "127.0.0.1".parse::<IpAddr>().expect("ip"),
            sni: Some("example.com"),
            identity_user: Some("alice"),
            cache_policy: None,
            cache_default_scheme: Some("https"),
        },
    );
    let mut request = Request::builder()
        .uri("https://example.com/resource")
        .body(Body::empty())
        .expect("request");
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("body"))
        .expect("response");

    assert!(!execution.has_context());
    assert!(matches!(
        execution
            .on_request_headers(&mut request)
            .await
            .expect("request headers"),
        RequestHeadersOutcome::Continue
    ));
    let response = execution
        .on_upstream_response(response)
        .await
        .expect("upstream response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        qpx_http::body::to_bytes(response.into_body())
            .await
            .expect("body"),
        "body"
    );
}

#[test]
fn request_inactive_modules_skip_session_allocation_without_skipping_applicable_requests() {
    let configs: Vec<HttpModuleConfig> = serde_yaml::from_str(
        r#"
- type: cache_purge
  settings:
    methods: [PURGE]
    require_identity: false
- type: response_compression
  settings:
    content_types: [application/octet-stream]
    gzip: false
    brotli: false
    zstd: false
"#,
    )
    .expect("module configs");
    let chain = compile_http_modules(&configs, &default_http_module_registry()).expect("chain");
    let runtime = module_test_runtime();
    let state = runtime.state();
    let init = || HttpModuleSessionInit {
        proxy_kind: crate::http::dispatch::ProxyKind::Reverse,
        proxy_name: "test-proxy",
        scope_name: "test-scope",
        route_name: Some("test-route"),
        remote_ip: "127.0.0.1".parse::<IpAddr>().expect("ip"),
        sni: None,
        identity_user: None,
        cache_policy: None,
        cache_default_scheme: Some("http"),
    };

    let ordinary = Request::builder()
        .method(Method::GET)
        .uri("http://example.com/resource")
        .body(Body::empty())
        .expect("ordinary request");
    assert!(
        !chain
            .start_for_request(&state, &ordinary, init)
            .has_context()
    );

    let compressed = Request::builder()
        .method(Method::GET)
        .uri("http://example.com/resource")
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .expect("compression request");
    assert!(
        !chain
            .start_for_request(&state, &compressed, init)
            .has_context()
    );

    let purge = Request::builder()
        .method("PURGE")
        .uri("http://example.com/resource")
        .body(Body::empty())
        .expect("purge request");
    assert!(chain.start_for_request(&state, &purge, init).has_context());
}

#[tokio::test]
async fn response_compression_marks_absent_identity_before_gzip_variant() {
    let configs: Vec<HttpModuleConfig> = serde_yaml::from_str(
        r#"
- type: response_compression
  settings:
    min_body_bytes: 1
    max_body_bytes: 4096
    content_types: [text/plain]
    gzip: true
    brotli: false
    zstd: false
"#,
    )
    .expect("module configs");
    let chain = compile_http_modules(&configs, &default_http_module_registry()).expect("chain");
    let runtime = module_test_runtime();
    let state = runtime.state();
    let init = || HttpModuleSessionInit {
        proxy_kind: crate::http::dispatch::ProxyKind::Reverse,
        proxy_name: "test-proxy",
        scope_name: "test-scope",
        route_name: Some("test-route"),
        remote_ip: "127.0.0.1".parse::<IpAddr>().expect("ip"),
        sni: None,
        identity_user: None,
        cache_policy: None,
        cache_default_scheme: Some("http"),
    };
    let body = "x".repeat(2048);
    let response = || {
        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .header(http::header::CONTENT_LENGTH, body.len().to_string())
            .header(http::header::CACHE_CONTROL, "public, max-age=60")
            .body(Body::from(body.clone()))
            .expect("origin response")
    };

    let mut identity_request = Request::builder()
        .method(Method::GET)
        .uri("http://example.com/resource")
        .body(Body::empty())
        .expect("request without Accept-Encoding");
    let mut identity_execution = chain.start_for_request(&state, &identity_request, init);
    assert!(identity_execution.has_context());
    assert!(matches!(
        identity_execution
            .on_request_headers(&mut identity_request)
            .await
            .expect("identity request headers"),
        RequestHeadersOutcome::Continue
    ));
    let identity = identity_execution
        .prepare_downstream_response(response())
        .await
        .expect("identity downstream response");
    assert!(
        !identity
            .headers()
            .contains_key(http::header::CONTENT_ENCODING)
    );
    assert!(
        identity
            .headers()
            .get_all(http::header::VARY)
            .iter()
            .any(|value| value.as_bytes().eq_ignore_ascii_case(b"Accept-Encoding")),
        "the first identity response must vary so a downstream cache misses for gzip"
    );
    assert_eq!(
        qpx_http::body::to_bytes(identity.into_body())
            .await
            .expect("identity body"),
        body.as_str()
    );

    let mut gzip_request = Request::builder()
        .method(Method::GET)
        .uri("http://example.com/resource")
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .expect("gzip request");
    let mut gzip_execution = chain.start_for_request(&state, &gzip_request, init);
    assert!(matches!(
        gzip_execution
            .on_request_headers(&mut gzip_request)
            .await
            .expect("gzip request headers"),
        RequestHeadersOutcome::Continue
    ));
    let compressed = gzip_execution
        .prepare_downstream_response(response())
        .await
        .expect("gzip downstream response");
    assert_eq!(
        compressed.headers().get(http::header::CONTENT_ENCODING),
        Some(&HeaderValue::from_static("gzip"))
    );
    assert!(
        compressed
            .headers()
            .get_all(http::header::VARY)
            .iter()
            .any(|value| value.as_bytes().eq_ignore_ascii_case(b"Accept-Encoding"))
    );
    assert!(
        !qpx_http::body::to_bytes(compressed.into_body())
            .await
            .expect("compressed body")
            .is_empty()
    );
}

#[test]
fn subrequest_template_compile_rejects_implicit_raw_placeholder() {
    let err = compile_template("http://127.0.0.1/check?path={request.path}")
        .expect_err("implicit raw placeholder should be rejected");

    assert!(
        err.to_string()
            .contains("must include an explicit modifier")
    );
}

#[test]
fn subrequest_template_render_applies_urlquery_modifier() {
    let ctx = module_test_context();
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/a/b?x=1&y=two")
        .body(Body::empty())
        .expect("request");
    let request = HttpModuleRequestView::from_request(&req);
    let template = compile_template(
        "http://127.0.0.1/check?path={request.path:urlquery}&q={request.query:urlquery}",
    )
    .expect("template");

    let rendered = render_template(&template, &request, &ctx).expect("rendered");

    assert_eq!(
        rendered,
        "http://127.0.0.1/check?path=%2Fa%2Fb&q=x%3D1%26y%3Dtwo"
    );
}

#[test]
fn subrequest_template_render_applies_pathsegment_header_host_and_identity_modifiers() {
    let ctx = module_test_context();
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/a/b?token=a%2Fb")
        .header("x-request-id", "req-1")
        .body(Body::empty())
        .expect("request");
    let request = HttpModuleRequestView::from_request(&req);
    let template = compile_template(
            "http://{request.host:host}/u/{identity.user:pathsegment}/{request.path:pathsegment}?token={request.query.token:urlquery}&rid={request.header.X-Request-Id:header}&sni={request.sni:host}",
        )
        .expect("template");

    let rendered = render_template(&template, &request, &ctx).expect("rendered");

    assert_eq!(
        rendered,
        "http://example.com/u/alice/%2Fa%2Fb?token=a%2Fb&rid=req-1&sni=example.com"
    );
}

#[test]
fn subrequest_template_rejects_raw_unknown_modifier_and_bad_host() {
    let raw = compile_template("http://example.com/{request.path:raw}")
        .expect_err("raw should be rejected");
    assert!(raw.to_string().contains("raw template expansion"));

    let modifier = compile_template("http://example.com/{request.path:html}")
        .expect_err("unknown modifier should be rejected");
    assert!(
        modifier
            .to_string()
            .contains("unknown template placeholder modifier")
    );

    let ctx = module_test_context();
    let req = Request::builder()
        .uri("/")
        .header(HOST, "bad/host")
        .body(Body::empty())
        .expect("request");
    let request = HttpModuleRequestView::from_request(&req);
    let template = compile_template("http://{request.host:host}/check").expect("template");
    let err = render_template(&template, &request, &ctx).expect_err("host should fail");
    assert!(err.to_string().contains("template host value"));
}

#[test]
fn subrequest_template_header_modifier_rejects_control_characters() {
    let ctx = module_test_context();
    let req = Request::builder()
        .uri("https://example.com/")
        .body(Body::empty())
        .expect("request");
    let template = CompiledTemplate {
        parts: vec![TemplatePart::Placeholder {
            variable: TemplateVariable::RequestHeader(HeaderName::from_static("x-request-id")),
            modifier: TemplateModifier::Header,
        }]
        .into(),
    };
    let mut req = req;
    req.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_bytes(b"ok\tbad").expect("header"),
    );
    let request = HttpModuleRequestView::from_request(&req);

    let err =
        render_template(&template, &request, &ctx).expect_err("control character should fail");

    assert!(err.to_string().contains("control character"));
}

fn subrequest_config(url: &str) -> SubrequestModuleConfig {
    SubrequestModuleConfig {
        name: "authz".to_string(),
        phase: SubrequestPhase::RequestHeaders,
        url: url.to_string(),
        method: None,
        timeout_ms: None,
        max_response_bytes: Some(1024),
        allowed_schemes: vec!["http".to_string(), "https".to_string()],
        allowed_hosts: vec![
            "auth.example.com".to_string(),
            "203.0.113.10".to_string(),
            "127.0.0.1".to_string(),
        ],
        deny_redirects: false,
        deny_private_ip_redirects: true,
        pass_headers: Vec::new(),
        request_headers: HashMap::new(),
        copy_response_headers_to_request: Vec::new(),
        copy_response_headers_to_response: Vec::new(),
        response_mode: None,
    }
}

#[test]
fn subrequest_config_rejects_missing_allowlists() {
    let mut cfg = subrequest_config("http://auth.example.com/check");
    cfg.allowed_hosts.clear();

    let err = match SubrequestModule::new(cfg) {
        Ok(_) => panic!("allowlist should be required"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("allowed_hosts must not be empty"));
}

#[test]
fn subrequest_rejects_disallowed_target_host() {
    let module =
        SubrequestModule::new(subrequest_config("http://evil.example.com/check")).expect("module");

    let err = match module.validate_url("http://evil.example.com/check") {
        Ok(_) => panic!("host should be rejected"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("URL host is not allowed"));
}

#[tokio::test]
async fn subrequest_rejects_private_ip_redirect_location() {
    let module =
        SubrequestModule::new(subrequest_config("http://auth.example.com/check")).expect("module");
    let response = Response::builder()
        .status(StatusCode::FOUND)
        .header(LOCATION, "http://127.0.0.1/admin")
        .body(Body::empty())
        .expect("response");

    let err = match module
        .validate_redirect_location(response.headers().get(LOCATION), Duration::from_secs(1))
        .await
    {
        Ok(_) => panic!("private redirect should be rejected"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("private IP"));
}

#[test]
fn sync_frozen_request_skips_rebuild_for_unchanged_request() {
    let mut ctx = module_test_context();
    let req = Request::builder()
        .uri("https://example.com/resource?x=1")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("request");

    assert!(ctx.sync_frozen_request(&req));
    assert!(!ctx.sync_frozen_request(&req));
}

#[test]
fn sync_frozen_request_rebuilds_after_request_change() {
    let mut ctx = module_test_context();
    let mut req = Request::builder()
        .uri("https://example.com/resource?x=1")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("request");

    assert!(ctx.sync_frozen_request(&req));
    assert!(!ctx.sync_frozen_request(&req));

    req.headers_mut()
        .insert("x-module", HeaderValue::from_static("changed"));

    assert!(ctx.sync_frozen_request(&req));
    let frozen = ctx.frozen_request().expect("frozen request");
    let template = compile_template("{request.header.X-Module:header}").expect("template");
    assert_eq!(
        render_template(&template, &frozen, &ctx).expect("rendered"),
        "changed"
    );
}

#[test]
fn predicate_request_view_has_header_matches_live_and_frozen() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/resource")
        .header("x-probe", "1")
        .body(Body::empty())
        .expect("request");
    let live = HttpModuleRequestView::from_request(&req);
    assert!(live.has_header(&HeaderName::from_static("x-probe")));
    assert!(!live.has_header(&HeaderName::from_static("x-missing")));

    let mut ctx = module_test_context();
    assert!(ctx.sync_frozen_request(&req));
    let frozen = ctx.frozen_request().expect("frozen request");
    assert!(frozen.has_header(&HeaderName::from_static("x-probe")));
    assert!(!frozen.has_header(&HeaderName::from_static("x-missing")));
}

#[test]
fn predicate_response_view_exposes_status_and_header_presence() {
    use super::HttpModuleResponseView;
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("x-probe", "1")
        .body(Body::empty())
        .expect("response");
    let view = HttpModuleResponseView::from_response(&response);
    assert_eq!(view.status(), StatusCode::OK);
    assert_eq!(view.version(), response.version());
    assert!(view.has_header(&HeaderName::from_static("x-probe")));
    assert!(!view.has_header(&HeaderName::from_static("x-missing")));
}

struct PredicateProbeModule;

#[async_trait::async_trait]
impl crate::module_api::HttpModule for PredicateProbeModule {
    fn capabilities(&self) -> crate::module_api::HttpModuleCapabilities {
        crate::module_api::HttpModuleCapabilities::headers_only(
            crate::module_api::ModuleStages::REQUEST_HEADERS,
        )
    }

    fn applies_to_request_headers(
        &self,
        request: &crate::module_api::HttpModuleRequestView<'_>,
    ) -> bool {
        request.has_header(&HeaderName::from_static("x-probe"))
    }

    fn is_inactive_for_request(
        &self,
        request: &crate::module_api::HttpModuleRequestView<'_>,
    ) -> bool {
        !request.has_header(&HeaderName::from_static("x-probe"))
    }

    fn applies_to_downstream_response(
        &self,
        _ctx: &crate::module_api::HttpModuleContext,
        response: &crate::module_api::HttpModuleResponseView<'_>,
    ) -> bool {
        response.status() == StatusCode::OK
            && response.has_header(&HeaderName::from_static("x-probe"))
    }

    async fn call<'a>(
        &self,
        _stage: crate::module_api::HttpModuleStage,
        _ctx: &mut crate::module_api::HttpModuleContext,
        event: crate::module_api::HttpModuleEvent<'a>,
    ) -> anyhow::Result<crate::module_api::HttpModuleEvent<'a>> {
        Ok(event)
    }
}

#[test]
fn predicate_probe_module_uses_semantic_views() {
    use super::HttpModuleResponseView;
    let module = PredicateProbeModule;
    let req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/resource")
        .header("x-probe", "1")
        .body(Body::empty())
        .expect("request");
    let view = crate::module_api::HttpModuleRequestView::from_request(&req);
    assert!(module.applies_to_request_headers(&view));
    assert!(!module.is_inactive_for_request(&view));

    let plain = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/resource")
        .body(Body::empty())
        .expect("request");
    let plain_view = crate::module_api::HttpModuleRequestView::from_request(&plain);
    assert!(!module.applies_to_request_headers(&plain_view));
    assert!(module.is_inactive_for_request(&plain_view));

    let ctx = module_test_context();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("x-probe", "1")
        .body(Body::empty())
        .expect("response");
    let response_view = HttpModuleResponseView::from_response(&response);
    assert!(module.applies_to_downstream_response(
        &ctx as &crate::module_api::HttpModuleContext,
        &response_view
    ));

    let missing = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .expect("response");
    let missing_view = HttpModuleResponseView::from_response(&missing);
    assert!(!module.applies_to_downstream_response(
        &ctx as &crate::module_api::HttpModuleContext,
        &missing_view
    ));
}

#[test]
fn event_facade_response_mutations_preserve_same_name_value_order() {
    use super::{HttpModuleResponse, RequestHeadersOutcome};
    use http::HeaderName;

    let raw = Response::builder()
        .status(StatusCode::OK)
        .header("x-first", "1")
        .header("x-second", "2")
        .body(Body::empty())
        .expect("response");
    let mut response = HttpModuleResponse::from_inner(raw);

    response.set_header(
        HeaderName::from_static("x-event"),
        HeaderValue::from_static("one"),
    );
    response.append_header(
        HeaderName::from_static("x-event"),
        HeaderValue::from_static("two"),
    );
    let values: Vec<_> = response
        .as_inner_mut()
        .headers()
        .get_all("x-event")
        .iter()
        .map(|value| value.to_str().expect("value").to_owned())
        .collect();
    assert_eq!(values, vec!["one".to_owned(), "two".to_owned()]);

    // Replacing collapses duplicates while preserving other headers.
    response.set_header(
        HeaderName::from_static("x-event"),
        HeaderValue::from_static("three"),
    );
    let values: Vec<_> = response
        .as_inner_mut()
        .headers()
        .get_all("x-event")
        .iter()
        .map(|value| value.to_str().expect("value").to_owned())
        .collect();
    assert_eq!(values, vec!["three".to_owned()]);
    assert!(response.has_header(&HeaderName::from_static("x-first")));
    assert!(response.has_header(&HeaderName::from_static("x-second")));

    assert!(response.remove_header(&HeaderName::from_static("x-event")));
    assert!(!response.has_header(&HeaderName::from_static("x-event")));

    // Short-circuit keeps the Box shape and the mutated headers.
    response.set_header(
        HeaderName::from_static("x-short"),
        HeaderValue::from_static("1"),
    );
    response.set_status(StatusCode::FORBIDDEN);
    let outcome = RequestHeadersOutcome::Respond(Box::new(response));
    let RequestHeadersOutcome::Respond(boxed) = outcome else {
        panic!("expected respond");
    };
    assert_eq!(boxed.status(), StatusCode::FORBIDDEN);
    assert!(boxed.has_header(&HeaderName::from_static("x-short")));
}

#[test]
fn event_facade_header_mutations_preserve_obs_text_bytes() {
    use super::{HttpModuleRequest, HttpModuleResponse};

    let name = HeaderName::from_static("x-octets");
    let first = b"first-\x80\xff";
    let second = b"second-\xfe\x81";
    let mut request = Request::new(Body::empty());
    {
        let mut facade = HttpModuleRequest::new(&mut request);
        facade.set_header(
            name.clone(),
            HeaderValue::from_bytes(first).expect("valid obs-text"),
        );
        facade.append_header(
            name.clone(),
            HeaderValue::from_bytes(second).expect("valid obs-text"),
        );
    }
    let values: Vec<_> = request
        .headers()
        .get_all(&name)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    assert_eq!(values, vec![first.as_slice(), second.as_slice()]);

    let mut response = HttpModuleResponse::new(StatusCode::OK, Body::empty());
    response.set_header(
        name.clone(),
        HeaderValue::from_bytes(first).expect("valid obs-text"),
    );
    response.append_header(
        name.clone(),
        HeaderValue::from_bytes(second).expect("valid obs-text"),
    );
    let raw = response.into_inner();
    let values: Vec<_> = raw
        .headers()
        .get_all(&name)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    assert_eq!(values, vec![first.as_slice(), second.as_slice()]);
}

#[tokio::test]
async fn event_facade_body_move_round_trip() {
    use super::{HttpModuleRequest, HttpModuleResponse};

    let mut response = HttpModuleResponse::new(StatusCode::OK, Body::from("downstream"));
    let body = response.take_body();
    assert_eq!(
        qpx_http::body::to_bytes(body)
            .await
            .expect("bytes")
            .as_ref(),
        b"downstream"
    );
    // take_body leaves an empty body behind.
    assert_eq!(
        qpx_http::body::to_bytes(response.take_body())
            .await
            .expect("bytes")
            .as_ref(),
        b""
    );
    response.set_body(Body::from("again"));
    assert_eq!(
        qpx_http::body::to_bytes(response.take_body())
            .await
            .expect("bytes")
            .as_ref(),
        b"again"
    );

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/resource")
        .body(Body::from("upstream"))
        .expect("request");
    let mut facade = HttpModuleRequest::new(&mut req);
    assert_eq!(facade.method(), Method::GET);
    facade.set_method(Method::POST);
    assert_eq!(facade.method(), Method::POST);
    facade.set_header(
        HeaderName::from_static("x-event"),
        HeaderValue::from_static("1"),
    );
    assert!(facade.has_header(&HeaderName::from_static("x-event")));
    let body = facade.take_body();
    assert_eq!(
        qpx_http::body::to_bytes(body)
            .await
            .expect("bytes")
            .as_ref(),
        b"upstream"
    );
    facade.set_body(Body::from("replaced"));
    assert_eq!(
        qpx_http::body::to_bytes(facade.take_body())
            .await
            .expect("bytes")
            .as_ref(),
        b"replaced"
    );
}

#[tokio::test]
async fn event_facade_moves_a_live_channel_body() {
    use super::HttpModuleResponse;

    let (mut sender, body) = Body::channel_with_capacity(1);
    let mut response = HttpModuleResponse::new(StatusCode::OK, Body::empty());
    response.set_body(body);
    let body = response.take_body();

    let producer = tokio::spawn(async move {
        sender.send_data(Bytes::from_static(b"first")).await?;
        sender.send_data(Bytes::from_static(b"second")).await?;
        Ok::<(), qpx_http::body::BodyError>(())
    });
    let bytes = qpx_http::body::to_bytes(body).await.expect("stream bytes");
    producer.await.expect("producer task").expect("send chunks");
    assert_eq!(bytes.as_ref(), b"firstsecond");
}

#[test]
fn event_facade_request_mutations_sync_to_frozen_snapshot() {
    use super::HttpModuleRequest;
    use http::HeaderName;

    let mut ctx = module_test_context();
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/resource")
        .body(Body::empty())
        .expect("request");
    assert!(ctx.sync_frozen_request(&req));

    {
        let mut facade = HttpModuleRequest::new(&mut req);
        facade.set_method(Method::POST);
        facade.set_header(
            HeaderName::from_static("x-event"),
            HeaderValue::from_static("1"),
        );
    }
    assert!(ctx.sync_frozen_request(&req));
    let frozen = ctx.frozen_request().expect("frozen");
    assert_eq!(frozen.method(), Method::POST);
    assert!(frozen.has_header(&HeaderName::from_static("x-event")));
}

fn cache_test_policy() -> qpx_core::config::CachePolicyConfig {
    qpx_core::config::CachePolicyConfig {
        enabled: true,
        backend: "test".to_string(),
        namespace: None,
        default_ttl_secs: None,
        max_object_bytes: 1024 * 1024,
        allow_set_cookie_store: false,
        allow_authorization_without_vary_store: false,
    }
}

fn cache_test_context(
    policy: Option<qpx_core::config::CachePolicyConfig>,
    default_scheme: Option<&str>,
) -> HttpModuleContext {
    HttpModuleContext::new(
        module_test_runtime().state(),
        HttpModuleSessionInit {
            proxy_kind: crate::http::dispatch::ProxyKind::Forward,
            proxy_name: "test-proxy",
            scope_name: "test-scope",
            route_name: Some("test-route"),
            remote_ip: "127.0.0.1".parse::<IpAddr>().expect("ip"),
            sni: None,
            identity_user: None,
            cache_policy: policy,
            cache_default_scheme: default_scheme,
        },
    )
}

fn cache_key_parts(key: &qpxd_cache::CacheRequestKey) -> (String, String, String, String) {
    (
        key.method.to_string(),
        key.scheme.to_string(),
        key.authority.to_string(),
        key.path_and_query.to_string(),
    )
}

#[test]
fn cache_request_key_live_and_frozen_agree_on_authority_vs_host() {
    let ctx = cache_test_context(Some(cache_test_policy()), Some("http"));
    let absolute = Request::builder()
        .method(Method::GET)
        .uri("http://example.com/resource?x=1")
        .header(HOST, "conflicting.example")
        .body(Body::empty())
        .expect("absolute request");
    let origin = Request::builder()
        .method(Method::GET)
        .uri("/resource?x=1")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("origin request");

    let live_absolute = HttpModuleRequestView::from_request(&absolute);
    let live_origin = HttpModuleRequestView::from_request(&origin);
    let absolute_key = ctx
        .cache_request_key(&live_absolute)
        .expect("absolute key")
        .expect("some key");
    let origin_key = ctx
        .cache_request_key(&live_origin)
        .expect("origin key")
        .expect("some key");
    assert_eq!(cache_key_parts(&absolute_key), cache_key_parts(&origin_key));

    let mut frozen_ctx = cache_test_context(Some(cache_test_policy()), Some("http"));
    assert!(frozen_ctx.sync_frozen_request(&origin));
    let frozen = frozen_ctx.frozen_request().expect("frozen");
    let frozen_key = frozen_ctx
        .cache_request_key(&frozen)
        .expect("frozen key")
        .expect("some key");
    assert_eq!(cache_key_parts(&origin_key), cache_key_parts(&frozen_key));

    let mut frozen_absolute_ctx = cache_test_context(Some(cache_test_policy()), Some("http"));
    assert!(frozen_absolute_ctx.sync_frozen_request(&absolute));
    let frozen_absolute = frozen_absolute_ctx.frozen_request().expect("frozen");
    let frozen_absolute_key = frozen_absolute_ctx
        .cache_request_key(&frozen_absolute)
        .expect("frozen absolute key")
        .expect("some key");
    assert_eq!(
        cache_key_parts(&absolute_key),
        cache_key_parts(&frozen_absolute_key)
    );
}

#[test]
fn cache_request_key_applies_default_scheme_and_strips_default_port() {
    let ctx = cache_test_context(Some(cache_test_policy()), Some("http"));
    // Origin-form without a scheme falls back to the configured default.
    let origin = Request::builder()
        .method(Method::GET)
        .uri("/asset")
        .header(HOST, "Example.COM:80")
        .body(Body::empty())
        .expect("origin request");
    let live = HttpModuleRequestView::from_request(&origin);
    let key = ctx
        .cache_request_key(&live)
        .expect("key")
        .expect("some key");
    assert_eq!(key.scheme.as_ref(), "http");
    assert_eq!(key.authority.as_ref(), "example.com");

    let mut frozen_ctx = cache_test_context(Some(cache_test_policy()), Some("http"));
    assert!(frozen_ctx.sync_frozen_request(&origin));
    let frozen = frozen_ctx.frozen_request().expect("frozen");
    let frozen_key = frozen_ctx
        .cache_request_key(&frozen)
        .expect("frozen key")
        .expect("some key");
    assert_eq!(cache_key_parts(&key), cache_key_parts(&frozen_key));

    // A non-default port is preserved byte-exactly after normalization.
    let explicit = Request::builder()
        .method(Method::GET)
        .uri("http://example.com:8080/asset")
        .body(Body::empty())
        .expect("explicit port request");
    let live_explicit = HttpModuleRequestView::from_request(&explicit);
    let explicit_key = ctx
        .cache_request_key(&live_explicit)
        .expect("explicit key")
        .expect("some key");
    assert_eq!(explicit_key.authority.as_ref(), "example.com:8080");

    // HTTPS default ports and IPv6 authorities use the same cache owner.
    let https_ctx = cache_test_context(Some(cache_test_policy()), Some("https"));
    let ipv6 = Request::builder()
        .method(Method::GET)
        .uri("/asset")
        .header(HOST, "[2001:db8::1]:443")
        .body(Body::empty())
        .expect("IPv6 request");
    let ipv6_view = HttpModuleRequestView::from_request(&ipv6);
    let ipv6_key = https_ctx
        .cache_request_key(&ipv6_view)
        .expect("IPv6 key")
        .expect("some key");
    assert_eq!(ipv6_key.scheme.as_ref(), "https");
    // Keep the adapter aligned with the cache owner's authority normalization.
    let direct_ipv6_key = qpxd_cache::CacheRequestKey::for_target(&ipv6, "https")
        .expect("direct IPv6 key")
        .expect("some direct key");
    assert_eq!(
        cache_key_parts(&ipv6_key),
        cache_key_parts(&direct_ipv6_key)
    );
    let mut frozen_ipv6_ctx = cache_test_context(Some(cache_test_policy()), Some("https"));
    assert!(frozen_ipv6_ctx.sync_frozen_request(&ipv6));
    let frozen_ipv6 = frozen_ipv6_ctx.frozen_request().expect("frozen IPv6");
    let frozen_ipv6_key = frozen_ipv6_ctx
        .cache_request_key(&frozen_ipv6)
        .expect("frozen IPv6 key")
        .expect("some key");
    assert_eq!(
        cache_key_parts(&ipv6_key),
        cache_key_parts(&frozen_ipv6_key)
    );
}

#[test]
fn cache_request_key_preserves_method_and_rejects_missing_or_invalid_host() {
    let ctx = cache_test_context(Some(cache_test_policy()), Some("http"));
    let get = Request::builder()
        .method(Method::GET)
        .uri("http://example.com/resource")
        .body(Body::empty())
        .expect("GET request");
    let get_key = ctx
        .cache_request_key(&HttpModuleRequestView::from_request(&get))
        .expect("GET key")
        .expect("some key");
    assert_eq!(get_key.method.as_ref(), "GET");

    let head = Request::builder()
        .method(Method::HEAD)
        .uri("http://example.com/resource")
        .body(Body::empty())
        .expect("HEAD request");
    let head_key = ctx
        .cache_request_key(&HttpModuleRequestView::from_request(&head))
        .expect("HEAD key")
        .expect("some key");
    assert_eq!(head_key.method.as_ref(), "HEAD");
    assert_ne!(get_key.method, head_key.method);

    let purge = Request::builder()
        .method("PURGE")
        .uri("http://example.com/resource")
        .body(Body::empty())
        .expect("purge request");
    let live_purge = HttpModuleRequestView::from_request(&purge);
    let purge_key = ctx
        .cache_request_key(&live_purge)
        .expect("purge key")
        .expect("some key");
    assert_eq!(purge_key.method.as_ref(), "PURGE");

    let mut frozen_ctx = cache_test_context(Some(cache_test_policy()), Some("http"));
    assert!(frozen_ctx.sync_frozen_request(&purge));
    let frozen = frozen_ctx.frozen_request().expect("frozen");
    let frozen_purge_key = frozen_ctx
        .cache_request_key(&frozen)
        .expect("frozen purge key")
        .expect("some key");
    assert_eq!(
        cache_key_parts(&purge_key),
        cache_key_parts(&frozen_purge_key)
    );

    // Origin-form without any Host or authority names no key.
    let missing = Request::builder()
        .method(Method::GET)
        .uri("/resource")
        .body(Body::empty())
        .expect("missing host request");
    let live_missing = HttpModuleRequestView::from_request(&missing);
    assert!(ctx.cache_request_key(&live_missing).expect("key").is_none());
    let mut missing_ctx = cache_test_context(Some(cache_test_policy()), Some("http"));
    assert!(missing_ctx.sync_frozen_request(&missing));
    let frozen_missing = missing_ctx.frozen_request().expect("frozen");
    assert!(
        missing_ctx
            .cache_request_key(&frozen_missing)
            .expect("frozen key")
            .is_none()
    );

    // An empty Host value is invalid and also names no key.
    let empty = Request::builder()
        .method(Method::GET)
        .uri("/resource")
        .header(HOST, "")
        .body(Body::empty())
        .expect("empty host request");
    let live_empty = HttpModuleRequestView::from_request(&empty);
    assert!(ctx.cache_request_key(&live_empty).expect("key").is_none());
    let mut empty_ctx = cache_test_context(Some(cache_test_policy()), Some("http"));
    assert!(empty_ctx.sync_frozen_request(&empty));
    let frozen_empty = empty_ctx.frozen_request().expect("frozen");
    assert!(
        empty_ctx
            .cache_request_key(&frozen_empty)
            .expect("frozen key")
            .is_none()
    );

    // Obs-text cannot be lossily treated as a URI authority.
    let mut obs_text_host = Request::builder()
        .method(Method::GET)
        .uri("/resource")
        .body(Body::empty())
        .expect("obs-text Host request");
    obs_text_host.headers_mut().insert(
        HOST,
        HeaderValue::from_bytes(b"\x80").expect("obs-text HeaderValue"),
    );
    let live_obs_text = HttpModuleRequestView::from_request(&obs_text_host);
    assert!(
        ctx.cache_request_key(&live_obs_text)
            .expect("key")
            .is_none()
    );
    let mut obs_text_ctx = cache_test_context(Some(cache_test_policy()), Some("http"));
    assert!(obs_text_ctx.sync_frozen_request(&obs_text_host));
    let frozen_obs_text = obs_text_ctx.frozen_request().expect("frozen");
    assert!(
        obs_text_ctx
            .cache_request_key(&frozen_obs_text)
            .expect("frozen key")
            .is_none()
    );
}

#[test]
fn cache_request_key_live_mutation_does_not_change_frozen_view() {
    let mut ctx = cache_test_context(Some(cache_test_policy()), Some("https"));
    let mut request = Request::builder()
        .method(Method::GET)
        .uri("/before?q=1")
        .header(HOST, "before.example:443")
        .body(Body::empty())
        .expect("request");
    assert!(ctx.sync_frozen_request(&request));
    let frozen = ctx.frozen_request().expect("frozen");
    let before = ctx
        .cache_request_key(&frozen)
        .expect("frozen key")
        .expect("some key");

    *request.method_mut() = Method::HEAD;
    *request.uri_mut() = "/after?x=2".parse().expect("updated URI");
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_static("after.example:8443"));
    let live = HttpModuleRequestView::from_request(&request);
    let after = ctx
        .cache_request_key(&live)
        .expect("live key")
        .expect("some key");
    assert_eq!(
        cache_key_parts(&before),
        (
            "GET".to_string(),
            "https".to_string(),
            "before.example".to_string(),
            "/before?q=1".to_string(),
        )
    );
    assert_eq!(
        cache_key_parts(&after),
        (
            "HEAD".to_string(),
            "https".to_string(),
            "after.example:8443".to_string(),
            "/after?x=2".to_string(),
        )
    );
    let frozen_after = ctx
        .cache_request_key(&frozen)
        .expect("frozen key after live mutation")
        .expect("some frozen key");
    assert_eq!(cache_key_parts(&before), cache_key_parts(&frozen_after));
}

#[test]
fn cache_request_key_no_policy_returns_none_and_missing_default_scheme_errors() {
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://example.com/resource")
        .body(Body::empty())
        .expect("request");
    let live = HttpModuleRequestView::from_request(&request);

    let no_policy = cache_test_context(None, Some("http"));
    assert!(no_policy.cache_request_key(&live).expect("key").is_none());
    let mut no_policy_frozen = cache_test_context(None, Some("http"));
    assert!(no_policy_frozen.sync_frozen_request(&request));
    let frozen = no_policy_frozen.frozen_request().expect("frozen");
    assert!(
        no_policy_frozen
            .cache_request_key(&frozen)
            .expect("frozen key")
            .is_none()
    );

    let missing_scheme = cache_test_context(Some(cache_test_policy()), None);
    let err = missing_scheme
        .cache_request_key(&live)
        .expect_err("missing default scheme must fail");
    assert!(err.to_string().contains("missing default scheme"));
    let mut missing_frozen_ctx = cache_test_context(Some(cache_test_policy()), None);
    assert!(missing_frozen_ctx.sync_frozen_request(&request));
    let frozen = missing_frozen_ctx.frozen_request().expect("frozen");
    let frozen_err = missing_frozen_ctx
        .cache_request_key(&frozen)
        .expect_err("frozen missing default scheme must fail");
    assert!(frozen_err.to_string().contains("missing default scheme"));
}
