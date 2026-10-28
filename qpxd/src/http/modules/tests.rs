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
use qpx_core::http_message::{OrdinaryHeaderName, Request as OwnerRequest};
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
    let mut request = OwnerRequest::from_http(
        Request::builder()
            .uri("https://example.com/resource")
            .body(Body::empty())
            .expect("request"),
    );
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

    let ordinary = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("http://example.com/resource")
            .body(Body::empty())
            .expect("ordinary request"),
    );
    assert!(
        !chain
            .start_for_request(&state, &ordinary, init)
            .has_context()
    );

    let compressed = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("http://example.com/resource")
            .header(http::header::ACCEPT_ENCODING, "gzip")
            .body(Body::empty())
            .expect("compression request"),
    );
    assert!(
        !chain
            .start_for_request(&state, &compressed, init)
            .has_context()
    );

    let purge = OwnerRequest::from_http(
        Request::builder()
            .method("PURGE")
            .uri("http://example.com/resource")
            .body(Body::empty())
            .expect("purge request"),
    );
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

    let mut identity_request = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("http://example.com/resource")
            .body(Body::empty())
            .expect("request without Accept-Encoding"),
    );
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

    let mut gzip_request = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("http://example.com/resource")
            .header(http::header::ACCEPT_ENCODING, "gzip")
            .body(Body::empty())
            .expect("gzip request"),
    );
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
    let req = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("https://example.com/a/b?x=1&y=two")
            .body(Body::empty())
            .expect("request"),
    );
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
    let req = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("https://example.com/a/b?token=a%2Fb")
            .header("x-request-id", "req-1")
            .body(Body::empty())
            .expect("request"),
    );
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
    let req = OwnerRequest::from_http(
        Request::builder()
            .uri("/")
            .header(HOST, "bad/host")
            .body(Body::empty())
            .expect("request"),
    );
    let request = HttpModuleRequestView::from_request(&req);
    let template = compile_template("http://{request.host:host}/check").expect("template");
    let err = render_template(&template, &request, &ctx).expect_err("host should fail");
    assert!(err.to_string().contains("template host value"));
}

#[test]
fn subrequest_template_header_modifier_rejects_control_characters() {
    let ctx = module_test_context();
    let req = OwnerRequest::from_http(
        Request::builder()
            .uri("https://example.com/")
            .body(Body::empty())
            .expect("request"),
    );
    let template = CompiledTemplate {
        parts: vec![TemplatePart::Placeholder {
            variable: TemplateVariable::RequestHeader(HeaderName::from_static("x-request-id")),
            modifier: TemplateModifier::Header,
        }]
        .into(),
    };
    let mut req = req;
    req.headers_mut().insert(
        OrdinaryHeaderName::try_from(HeaderName::from_static("x-request-id")).unwrap(),
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
    let req = OwnerRequest::from_http(
        Request::builder()
            .uri("https://example.com/resource?x=1")
            .header(HOST, "example.com")
            .body(Body::empty())
            .expect("request"),
    );

    assert!(ctx.sync_frozen_request(&req));
    assert!(!ctx.sync_frozen_request(&req));
}

#[test]
fn sync_frozen_request_rebuilds_after_request_change() {
    let mut ctx = module_test_context();
    let mut req = OwnerRequest::from_http(
        Request::builder()
            .uri("https://example.com/resource?x=1")
            .header(HOST, "example.com")
            .body(Body::empty())
            .expect("request"),
    );

    assert!(ctx.sync_frozen_request(&req));
    assert!(!ctx.sync_frozen_request(&req));

    req.headers_mut().insert(
        OrdinaryHeaderName::try_from(HeaderName::from_static("x-module")).unwrap(),
        HeaderValue::from_static("changed"),
    );

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
    let req = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("https://example.com/resource")
            .header("x-probe", "1")
            .body(Body::empty())
            .expect("request"),
    );
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
    let req = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("https://example.com/resource")
            .header("x-probe", "1")
            .body(Body::empty())
            .expect("request"),
    );
    let view = crate::module_api::HttpModuleRequestView::from_request(&req);
    assert!(module.applies_to_request_headers(&view));
    assert!(!module.is_inactive_for_request(&view));

    let plain = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("https://example.com/resource")
            .body(Body::empty())
            .expect("request"),
    );
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
    let mut request = OwnerRequest::new(Body::empty());
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
        .get_all(&OrdinaryHeaderName::try_from(name.clone()).unwrap())
        .map(HeaderValue::as_bytes)
        .collect();
    assert_eq!(values, vec![first.as_slice(), second.as_slice()]);

    let mut response = HttpModuleResponse::new(StatusCode::OK, super::Body::empty());
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

    let mut response = HttpModuleResponse::new(StatusCode::OK, super::Body::from("downstream"));
    let body = response.take_body();
    assert_eq!(
        body.to_bytes().await.expect("bytes").as_ref(),
        b"downstream"
    );
    // take_body leaves an empty body behind.
    assert_eq!(
        response
            .take_body()
            .to_bytes()
            .await
            .expect("bytes")
            .as_ref(),
        b""
    );
    response.set_body(super::Body::from("again"));
    assert_eq!(
        response
            .take_body()
            .to_bytes()
            .await
            .expect("bytes")
            .as_ref(),
        b"again"
    );

    let mut req = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("https://example.com/resource")
            .body(Body::from("upstream"))
            .expect("request"),
    );
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
    assert_eq!(body.to_bytes().await.expect("bytes").as_ref(), b"upstream");
    facade.set_body(super::Body::from("replaced"));
    assert_eq!(
        facade.take_body().to_bytes().await.expect("bytes").as_ref(),
        b"replaced"
    );
}

#[tokio::test]
async fn module_body_reentry_preserves_an_observed_stream_error() {
    use super::HttpModuleResponse;

    let (mut sender, body) = super::Body::channel_with_capacity(2);
    sender
        .send_data(Bytes::from_static(b"partial"))
        .await
        .expect("queue partial data");
    sender.abort();

    let mut response = HttpModuleResponse::new(StatusCode::OK, body);
    let mut body = response.take_body();
    assert!(matches!(
        body.next_frame().await,
        Some(Ok(super::BodyFrame::Data(data))) if data.as_ref() == b"partial"
    ));
    let observed = body
        .next_frame()
        .await
        .expect("stream error")
        .expect_err("aborted stream");
    assert_eq!(observed.to_string(), "body aborted");

    response.set_body(body);
    let mut response = response.into_inner();
    crate::http::protocol::l7::finalize_response_in_place(
        &Method::GET,
        http::Version::HTTP_11,
        "qpx",
        &mut response,
        false,
    );
    let preserved = response
        .body_mut()
        .data()
        .await
        .expect("finalized stream error")
        .expect_err("error must not become successful EOF");
    assert_eq!(preserved.to_string(), observed.to_string());
    assert!(response.body_mut().data().await.is_none());
}

#[tokio::test]
async fn collecting_after_an_observed_stream_error_does_not_succeed_empty() {
    let (mut sender, mut body) = super::Body::channel_with_capacity(1);
    sender.abort();
    let error = body
        .next_frame()
        .await
        .expect("stream error")
        .expect_err("aborted stream");
    assert_eq!(body.to_bytes().await.expect_err("preserve failure"), error);
}

#[tokio::test]
async fn event_facade_moves_a_live_channel_body() {
    use super::HttpModuleResponse;

    let (mut sender, body) = super::Body::channel_with_capacity(1);
    let mut response = HttpModuleResponse::new(StatusCode::OK, super::Body::empty());
    response.set_body(body);
    let body = response.take_body();

    let producer = tokio::spawn(async move {
        sender.send_data(Bytes::from_static(b"first")).await?;
        sender.send_data(Bytes::from_static(b"second")).await?;
        Ok::<(), super::BodyError>(())
    });
    let bytes = body.to_bytes().await.expect("stream bytes");
    producer.await.expect("producer task").expect("send chunks");
    assert_eq!(bytes.as_ref(), b"firstsecond");
}

#[test]
fn event_facade_request_mutations_sync_to_frozen_snapshot() {
    use super::HttpModuleRequest;
    use http::HeaderName;

    let mut ctx = module_test_context();
    let mut req = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("https://example.com/resource")
            .body(Body::empty())
            .expect("request"),
    );
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
    let absolute = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("http://example.com/resource?x=1")
            .header(HOST, "conflicting.example")
            .body(Body::empty())
            .expect("absolute request"),
    );
    let origin = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("/resource?x=1")
            .header(HOST, "example.com")
            .body(Body::empty())
            .expect("origin request"),
    );

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
    let origin = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("/asset")
            .header(HOST, "Example.COM:80")
            .body(Body::empty())
            .expect("origin request"),
    );
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
    let explicit = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("http://example.com:8080/asset")
            .body(Body::empty())
            .expect("explicit port request"),
    );
    let live_explicit = HttpModuleRequestView::from_request(&explicit);
    let explicit_key = ctx
        .cache_request_key(&live_explicit)
        .expect("explicit key")
        .expect("some key");
    assert_eq!(explicit_key.authority.as_ref(), "example.com:8080");

    // HTTPS default ports and IPv6 authorities use the same cache owner.
    let https_ctx = cache_test_context(Some(cache_test_policy()), Some("https"));
    let ipv6 = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("/asset")
            .header(HOST, "[2001:db8::1]:443")
            .body(Body::empty())
            .expect("IPv6 request"),
    );
    let ipv6_view = HttpModuleRequestView::from_request(&ipv6);
    let ipv6_key = https_ctx
        .cache_request_key(&ipv6_view)
        .expect("IPv6 key")
        .expect("some key");
    assert_eq!(ipv6_key.scheme.as_ref(), "https");
    // Keep the adapter aligned with the cache owner's authority normalization.
    let mut ipv6_head = OwnerRequest::new(());
    *ipv6_head.method_mut() = ipv6.method().clone();
    *ipv6_head.uri_mut() = ipv6.uri().clone();
    {
        let host = OrdinaryHeaderName::try_from(HOST).expect("ordinary host");
        if let Some(value) = ipv6.headers().get(&host).cloned() {
            ipv6_head.headers_mut().insert(host, value);
        }
    }
    let direct_ipv6_key = qpxd_cache::CacheRequestKey::for_target(&ipv6_head, "https")
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
    let get = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("http://example.com/resource")
            .body(Body::empty())
            .expect("GET request"),
    );
    let get_key = ctx
        .cache_request_key(&HttpModuleRequestView::from_request(&get))
        .expect("GET key")
        .expect("some key");
    assert_eq!(get_key.method.as_ref(), "GET");

    let head = OwnerRequest::from_http(
        Request::builder()
            .method(Method::HEAD)
            .uri("http://example.com/resource")
            .body(Body::empty())
            .expect("HEAD request"),
    );
    let head_key = ctx
        .cache_request_key(&HttpModuleRequestView::from_request(&head))
        .expect("HEAD key")
        .expect("some key");
    assert_eq!(head_key.method.as_ref(), "HEAD");
    assert_ne!(get_key.method, head_key.method);

    let purge = OwnerRequest::from_http(
        Request::builder()
            .method("PURGE")
            .uri("http://example.com/resource")
            .body(Body::empty())
            .expect("purge request"),
    );
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
    let missing = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("/resource")
            .body(Body::empty())
            .expect("missing host request"),
    );
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
    let empty = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("/resource")
            .header(HOST, "")
            .body(Body::empty())
            .expect("empty host request"),
    );
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
    let mut obs_text_host = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("/resource")
            .body(Body::empty())
            .expect("obs-text Host request"),
    );
    obs_text_host.headers_mut().insert(
        OrdinaryHeaderName::try_from(HOST).unwrap(),
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
    let mut request = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("/before?q=1")
            .header(HOST, "before.example:443")
            .body(Body::empty())
            .expect("request"),
    );
    assert!(ctx.sync_frozen_request(&request));
    let frozen = ctx.frozen_request().expect("frozen");
    let before = ctx
        .cache_request_key(&frozen)
        .expect("frozen key")
        .expect("some key");

    *request.method_mut() = Method::HEAD;
    *request.uri_mut() = "/after?x=2".parse().expect("updated URI");
    request.headers_mut().insert(
        OrdinaryHeaderName::try_from(HOST).unwrap(),
        HeaderValue::from_static("after.example:8443"),
    );
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
    let request = OwnerRequest::from_http(
        Request::builder()
            .method(Method::GET)
            .uri("http://example.com/resource")
            .body(Body::empty())
            .expect("request"),
    );
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

fn module_test_trailers() -> super::Trailers {
    let mut trailers = super::Trailers::new();
    trailers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_static("999"),
    );
    trailers.insert(
        http::header::HOST,
        http::HeaderValue::from_static("forbidden.example"),
    );
    trailers.insert(
        http::HeaderName::from_static("grpc-status"),
        http::HeaderValue::from_static("0"),
    );
    trailers.append(
        http::HeaderName::from_static("x-allowed"),
        http::HeaderValue::from_static("first"),
    );
    trailers.append(
        http::HeaderName::from_static("x-allowed"),
        http::HeaderValue::from_static("second"),
    );
    trailers
}

async fn assert_module_finalized_trailers(response: super::HttpModuleResponse) {
    let mut response = response.into_inner();
    assert!(
        !response.body().trailers_are_sanitized(),
        "module re-entry must clear trust"
    );
    crate::http::protocol::l7::finalize_response_in_place(
        &Method::GET,
        http::Version::HTTP_11,
        "qpx",
        &mut response,
        false,
    );
    let body = response.body_mut();
    assert_eq!(body.data().await.unwrap().unwrap(), "first-data");
    assert_eq!(body.data().await.unwrap().unwrap(), "second-data");
    assert!(body.data().await.is_none());
    let trailers = body.trailers().await.unwrap().expect("trailers");
    assert!(!trailers.contains_key(http::header::CONTENT_LENGTH));
    assert!(!trailers.contains_key(http::header::HOST));
    assert_eq!(trailers["grpc-status"], "0");
    let allowed = trailers.get_all("x-allowed").iter().collect::<Vec<_>>();
    assert_eq!(allowed, ["first", "second"]);
    assert!(body.data().await.is_none());
}

#[tokio::test]
async fn module_explicit_and_frame_forwarded_trailers_are_sanitized_by_finalization() {
    use super::{Body as ModuleBody, HttpModuleResponse};
    let body = ModuleBody::replay_chunks(
        vec![
            Bytes::from_static(b"first-data"),
            Bytes::from_static(b"second-data"),
        ],
        Some(module_test_trailers()),
    );
    assert_module_finalized_trailers(HttpModuleResponse::new(StatusCode::OK, body)).await;

    let mut input = ModuleBody::replay_chunks(
        vec![
            Bytes::from_static(b"first-data"),
            Bytes::from_static(b"second-data"),
        ],
        Some(module_test_trailers()),
    );
    let (mut sender, out) = ModuleBody::channel_with_capacity(3);
    while let Some(frame) = input.next_frame().await {
        sender.send_frame(frame.unwrap()).await.unwrap();
    }
    drop(sender);
    let mut response = HttpModuleResponse::new(StatusCode::OK, ModuleBody::empty());
    response.set_body(out);
    assert_module_finalized_trailers(response).await;
}

#[tokio::test]
async fn module_forwarded_transport_sanitized_assertion_is_not_trusted() {
    use super::{HttpModuleRequest, HttpModuleResponse};
    // Model a transport body whose producer incorrectly asserted trust. Module
    // request/response body moves must not launder that assertion into finalization.
    for via_request in [false, true] {
        let mut trailers = http::HeaderMap::new();
        trailers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("999"),
        );
        trailers.insert(
            http::header::HOST,
            http::HeaderValue::from_static("forbidden.example"),
        );
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        trailers.append("x-allowed", http::HeaderValue::from_static("first"));
        trailers.append("x-allowed", http::HeaderValue::from_static("second"));
        let raw = Body::replay_chunks(
            vec![
                Bytes::from_static(b"first-data"),
                Bytes::from_static(b"second-data"),
            ],
            Some(trailers),
        )
        .mark_trailers_sanitized();
        let body = if via_request {
            let mut request = OwnerRequest::new(raw);
            let mut request = HttpModuleRequest::new(&mut request);
            let body = request.take_body();
            request.set_body(body);
            assert!(!request.as_owner().body().trailers_are_sanitized());
            request.take_body()
        } else {
            let mut response = HttpModuleResponse::from_inner(hyper::Response::new(raw));
            let body = response.take_body();
            response.set_body(body);
            assert!(!response.as_inner_mut().body().trailers_are_sanitized());
            response.take_body()
        };
        assert_module_finalized_trailers(HttpModuleResponse::new(StatusCode::OK, body)).await;
    }
}

#[test]
fn module_untouched_internal_response_preserves_transport_trust_and_timeout() {
    let raw = Body::from("trusted")
        .mark_trailers_sanitized()
        .mark_read_timeout_enforced();
    let mut response = super::HttpModuleResponse::from_inner(hyper::Response::new(raw));
    response.set_status(StatusCode::CREATED);
    let response = response.into_inner();
    assert!(response.body().trailers_are_sanitized());
    assert!(response.body().read_timeout_is_enforced());

    let mut response = super::HttpModuleResponse::from_inner(response);
    let body = response.take_body();
    response.set_body(body);
    let response = response.into_inner();
    assert!(!response.body().trailers_are_sanitized());
    assert!(response.body().read_timeout_is_enforced());
}

#[tokio::test(start_paused = true)]
async fn module_body_finalization_preserves_idle_timeout_and_abort() {
    use super::{Body as ModuleBody, HttpModuleResponse};
    use std::future::Future as _;
    use std::task::{Context, Poll, Waker};

    let (mut sender, body) = ModuleBody::channel_with_capacity(1);
    let mut response = HttpModuleResponse::new(StatusCode::OK, body).into_inner();
    crate::http::protocol::l7::finalize_response_in_place(
        &Method::GET,
        http::Version::HTTP_11,
        "qpx",
        &mut response,
        false,
    );
    let mut read = Box::pin(response.body_mut().data());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(read.as_mut().poll(&mut cx).is_pending());
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    assert!(matches!(
        read.as_mut().poll(&mut cx),
        Poll::Ready(Some(Err(_)))
    ));
    drop(read);
    drop(response);
    assert!(sender.is_closed());
    assert!(sender.send_data(Bytes::new()).await.is_err());

    let (mut sender, body) = ModuleBody::channel();
    sender.abort();
    let mut response = HttpModuleResponse::new(StatusCode::OK, body).into_inner();
    crate::http::protocol::l7::finalize_response_in_place(
        &Method::GET,
        http::Version::HTTP_11,
        "qpx",
        &mut response,
        false,
    );
    assert_eq!(
        response
            .body_mut()
            .data()
            .await
            .unwrap()
            .unwrap_err()
            .to_string(),
        "body aborted"
    );
}

#[test]
fn module_body_bridge_retains_transport_resources_until_drop() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Resource(Arc<AtomicUsize>);
    impl Drop for Resource {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let mut body = Body::from("resource");
    body.retain_resource(Resource(drops.clone()));
    let mut response = super::HttpModuleResponse::from_inner(hyper::Response::new(body));
    let body = response.take_body();
    response.set_body(body);
    let response = response.into_inner();
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(response);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

struct ReplacingBodyFactory;

impl HttpModuleFactory for ReplacingBodyFactory {
    fn build(&self, _spec: &HttpModuleConfig) -> anyhow::Result<Arc<dyn HttpModule>> {
        Ok(Arc::new(ReplacingBodyModule))
    }
}

struct ReplacingBodyModule;

#[async_trait::async_trait]
impl HttpModule for ReplacingBodyModule {
    fn capabilities(&self) -> HttpModuleCapabilities {
        HttpModuleCapabilities {
            stages: ModuleStages::UPSTREAM_REQUEST,
            body_access: BodyAccess::Streaming,
            ..HttpModuleCapabilities::default()
        }
    }

    async fn call<'a>(
        &self,
        stage: HttpModuleStage,
        _context: &mut HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> anyhow::Result<HttpModuleEvent<'a>> {
        match (stage, event) {
            (HttpModuleStage::UpstreamRequest, HttpModuleEvent::UpstreamRequest(mut request)) => {
                let mut trailers = super::Trailers::new();
                trailers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("99"));
                request.set_body(super::Body::replay_chunks(
                    vec![Bytes::from_static(b"module payload")],
                    Some(trailers),
                ));
                Ok(HttpModuleEvent::Complete)
            }
            (_, event) => Ok(event),
        }
    }
}

#[tokio::test]
async fn upstream_module_stage_validates_replaced_http11_body_trailers() {
    use http_body_util::BodyExt as _;

    let configs: Vec<HttpModuleConfig> =
        serde_yaml::from_str("- type: replacing_body").expect("module config");
    let mut registry = HttpModuleRegistryBuilder::new();
    registry
        .register_factory("replacing_body", ReplacingBodyFactory)
        .expect("register module");
    let chain = compile_http_modules(&configs, &registry.build()).expect("module chain");
    let runtime = module_test_runtime();
    let state = runtime.state();
    let mut request = OwnerRequest::from_http(
        Request::builder()
            .version(http::Version::HTTP_11)
            .body(Body::from("original"))
            .expect("request"),
    );
    let mut execution = chain.start_for_request(&state, &request, || HttpModuleSessionInit {
        proxy_kind: crate::http::dispatch::ProxyKind::Forward,
        proxy_name: "test-proxy",
        scope_name: "test-scope",
        route_name: Some("test-route"),
        remote_ip: "127.0.0.1".parse::<IpAddr>().expect("ip"),
        sni: None,
        identity_user: None,
        cache_policy: None,
        cache_default_scheme: Some("http"),
    });

    execution
        .on_upstream_request(&mut request)
        .await
        .expect("upstream request module");
    let mut body = request.into_head_and_body().1;
    assert_eq!(
        body.frame()
            .await
            .expect("data frame")
            .expect("data frame result")
            .into_data()
            .expect("data"),
        Bytes::from_static(b"module payload")
    );
    assert_eq!(
        body.frame()
            .await
            .expect("trailer validation error")
            .expect_err("forbidden Content-Length trailer")
            .to_string(),
        "body aborted"
    );
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn module_replaced_request_trailers_are_validated_after_mitm_preparation() {
    use crate::http::protocol::l7::{
        prepare_module_request_body_in_place, prepare_request_with_headers_in_place,
    };
    use http_body_util::BodyExt as _;

    for version in [http::Version::HTTP_2, http::Version::HTTP_11] {
        for declared in [false, true] {
            for forbidden in [false, true] {
                let mut request = OwnerRequest::from_http(
                    Request::builder()
                        .version(version)
                        .uri("https://example.test/upload")
                        .body(Body::from("original"))
                        .unwrap(),
                );
                if declared {
                    request.headers_mut().insert(
                        OrdinaryHeaderName::try_from(http::header::TRAILER).unwrap(),
                        HeaderValue::from_static("x-allowed"),
                    );
                }
                // The actual MITM order: prepare, normalize, module events,
                // then prepare only a replaced body before upstream consumption.
                prepare_request_with_headers_in_place(&mut request, "qpx", None, false);
                *request.version_mut() = http::Version::HTTP_11;
                assert!(
                    !request.headers().contains_key(
                        &OrdinaryHeaderName::try_from(http::header::TRAILER).unwrap()
                    )
                );
                let mut trailers = super::Trailers::new();
                trailers.append(
                    HeaderName::from_static("x-allowed"),
                    HeaderValue::from_static("first"),
                );
                trailers.append(
                    HeaderName::from_static("x-allowed"),
                    HeaderValue::from_static("second"),
                );
                if forbidden {
                    trailers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("99"));
                }
                super::HttpModuleRequest::new(&mut request).set_body(super::Body::replay_chunks(
                    vec![Bytes::from_static(b"one"), Bytes::from_static(b"two")],
                    Some(trailers),
                ));
                prepare_module_request_body_in_place(&mut request);
                // This is the prepared body's upstream-sender boundary: forbidden
                // trailers become an error, never a frame the sender could emit.
                let mut body = request.into_head_and_body().1;
                for expected in ["one", "two"] {
                    assert_eq!(
                        body.frame().await.unwrap().unwrap().into_data().unwrap(),
                        expected
                    );
                }
                let frame = body.frame().await.unwrap();
                if forbidden {
                    assert_eq!(frame.unwrap_err().to_string(), "body aborted");
                } else {
                    let trailers = frame.unwrap().into_trailers().unwrap();
                    let values = trailers.get_all("x-allowed").iter().collect::<Vec<_>>();
                    assert_eq!(values, ["first", "second"]);
                }
                assert!(body.frame().await.is_none());
            }
        }
    }
}

#[tokio::test]
async fn module_request_preparation_leaves_untouched_bodies_and_consumes_replacement_once() {
    use crate::http::protocol::l7::{
        prepare_module_request_body_in_place, prepare_request_with_headers_in_place,
    };
    for preparation in ["untouched", "backend", "mitm"] {
        let mut request = OwnerRequest::from_http(
            Request::builder()
                .version(http::Version::HTTP_2)
                .body(Body::from("original"))
                .unwrap(),
        );
        prepare_request_with_headers_in_place(&mut request, "qpx", None, false);
        if preparation != "untouched" {
            *request.version_mut() = http::Version::HTTP_11;
            super::HttpModuleRequest::new(&mut request).set_body(super::Body::from("replacement"));
            if preparation == "backend" {
                prepare_request_with_headers_in_place(&mut request, "qpx", None, false);
            } else {
                prepare_module_request_body_in_place(&mut request);
            }
        }
        // A transport marker is observable only inside the owner. Reboxing would
        // clear it, so it detects unnecessary validation passes without exposing
        // the raw body publicly. No replacement, or an already consumed marker,
        // must not add another wrapper to the prepared body.
        let body = std::mem::replace(request.body_mut(), Body::empty());
        *request.body_mut() = body.mark_read_timeout_enforced();
        prepare_module_request_body_in_place(&mut request);
        assert!(request.body().read_timeout_is_enforced());
    }
}

#[tokio::test]
async fn module_wrapped_transport_trust_is_reset_and_response_finalized() {
    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_static("999"),
    );
    trailers.insert(
        http::header::HOST,
        HeaderValue::from_static("forbidden.example"),
    );
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    trailers.append("x-allowed", HeaderValue::from_static("first"));
    trailers.append("x-allowed", HeaderValue::from_static("second"));
    let body = super::Body::wrap(
        Body::replay_chunks(
            vec![
                Bytes::from_static(b"first-data"),
                Bytes::from_static(b"second-data"),
            ],
            Some(trailers),
        )
        .mark_trailers_sanitized(),
    );
    assert_module_finalized_trailers(super::HttpModuleResponse::new(StatusCode::OK, body)).await;
}

#[tokio::test]
async fn module_context_absolute_dispatch_keeps_backend_request_trailer_validation() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    // Exercise both public helpers, not just the body conversion. Module-owned
    // bodies are validated at backend preparation even when HTTP/1.1 omitted a
    // Trailer declaration.
    for pinned in [false, true] {
        for version in [http::Version::HTTP_2, http::Version::HTTP_11] {
            for forbidden in [false, true] {
                for declared in [false, true] {
                    if version == http::Version::HTTP_2 && !declared {
                        continue;
                    }
                    if version == http::Version::HTTP_11 && !forbidden && !declared {
                        continue;
                    }
                    tokio::time::timeout(Duration::from_secs(5), async {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = listener.local_addr().unwrap();
                    let server = async {
                        let (mut socket, _) = listener.accept().await.unwrap();
                        let mut received = Vec::new();
                        loop {
                            let mut buffer = [0; 1024];
                            let count = socket.read(&mut buffer).await.unwrap();
                            if count == 0 {
                                break;
                            }
                            received.extend_from_slice(&buffer[..count]);
                            assert!(received.len() <= 16 * 1024);
                            if received.windows(5).any(|w| w == b"\r\n0\r\n")
                                && received.ends_with(b"\r\n\r\n")
                            {
                                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                                break;
                            }
                        }
                        received
                    };
                    let context = module_test_context();
                    // Channel bodies have unknown size so the sender must poll
                    // the trailer frame rather than stopping at a byte count.
                    let (mut sender, body) = super::Body::channel_with_capacity(2);
                    sender.try_send_data(Bytes::from_static(b"payload")).unwrap();
                    let mut trailers = super::Trailers::new();
                    trailers.insert(
                        if forbidden { http::header::CONTENT_LENGTH } else { HeaderName::from_static("x-allowed") },
                        HeaderValue::from_static("99"),
                    );
                    sender.try_send_trailers(trailers).unwrap();
                    drop(sender);
                    let mut request = OwnerRequest::from_http(Request::builder()
                        .method(Method::POST)
                        .version(version)
                        .uri(format!("http://{addr}/upload"))
                        .body(body)
                        .unwrap());
                    if version == http::Version::HTTP_11 && declared {
                        request.headers_mut().insert(OrdinaryHeaderName::try_from(http::header::TRAILER).unwrap(), HeaderValue::from_static("x-allowed"));
                    }
                    let client = async {
                        if pinned {
                            context.send_absolute_request_to_addr(request, addr).await
                        } else {
                            context.send_absolute_request(request).await
                        }
                    };
                    let (result, received) = tokio::join!(client, server);
                    if forbidden {
                        assert!(result.is_err(), "backend must reject the body, not silently drop forbidden trailers");
                        assert!(!received.windows(b"content-length: 99".len()).any(|w| w.eq_ignore_ascii_case(b"content-length: 99")));
                    } else {
                        assert_eq!(result.unwrap().status(), StatusCode::OK);
                    }
                    }).await.expect("bounded local context dispatch");
                }
            }
        }
    }
}

#[test]
fn owned_module_request_keeps_literal_framing_in_live_and_frozen_templates() {
    use http::header::CONTENT_LENGTH;

    let template = compile_template("{request.header.content-length:urlquery}").unwrap();
    let mut ctx = module_test_context();
    let mut req = OwnerRequest::new(Body::empty());
    assert!(!HttpModuleRequestView::from_request(&req).has_header(&CONTENT_LENGTH));
    for (first, second, output, length) in [
        ("0", None, "0", Some(0)),
        (" 007 ", Some("7"), "%20007%20", Some(7)),
        ("invalid", None, "invalid", None),
        ("1", Some("2"), "1", None),
    ] {
        {
            let mut module = HttpModuleRequest::new(&mut req);
            module.set_header(CONTENT_LENGTH, HeaderValue::from_str(first).unwrap());
            if let Some(second) = second {
                module.append_header(CONTENT_LENGTH, HeaderValue::from_str(second).unwrap());
            }
            assert!(module.has_header(&CONTENT_LENGTH));
        }
        assert_eq!(
            req.headers().declared_content_length().ok().flatten(),
            length
        );
        assert!(ctx.sync_frozen_request(&req));
        assert!(!ctx.sync_frozen_request(&req));
        for view in [
            HttpModuleRequestView::from_request(&req),
            ctx.frozen_request().unwrap(),
        ] {
            assert!(view.has_header(&CONTENT_LENGTH));
            assert_eq!(render_template(&template, &view, &ctx).unwrap(), output);
        }
    }
    assert!(HttpModuleRequest::new(&mut req).remove_header(&CONTENT_LENGTH));
    assert!(!HttpModuleRequest::new(&mut req).remove_header(&CONTENT_LENGTH));
    assert_eq!(req.headers().declared_content_length().unwrap(), None);
}

#[test]
fn owned_subrequest_passes_only_first_occurrence_then_applies_configured_replacements() {
    use http::header::CONTENT_LENGTH;

    let ctx = module_test_context();
    let mut req = OwnerRequest::new(Body::empty());
    let octets = HeaderName::from_static("x-octets");
    {
        let mut module = HttpModuleRequest::new(&mut req);
        module.set_header(
            octets.clone(),
            HeaderValue::from_bytes(b"first-\x80").unwrap(),
        );
        module.append_header(octets.clone(), HeaderValue::from_static("second"));
        module.set_header(CONTENT_LENGTH, HeaderValue::from_static(" 007 "));
        module.append_header(CONTENT_LENGTH, HeaderValue::from_static("9"));
    }
    let mut config = subrequest_config("https://auth.example.com/check");
    config.pass_headers = vec![
        "x-octets".into(),
        "content-length".into(),
        "x-absent".into(),
    ];
    let module = SubrequestModule::new(config.clone()).unwrap();
    let subrequest = module
        .build_subrequest(&ctx, &HttpModuleRequestView::from_request(&req))
        .unwrap();
    assert_eq!(
        subrequest.headers().declared_content_length().unwrap(),
        Some(7)
    );
    let values: Vec<_> = subrequest
        .headers()
        .get_all(&OrdinaryHeaderName::try_from(octets.clone()).unwrap())
        .map(HeaderValue::as_bytes)
        .collect();
    assert_eq!(values, [b"first-\x80".as_slice()]);
    let template = compile_template("{request.header.content-length:urlquery}").unwrap();
    assert_eq!(
        render_template(
            &template,
            &HttpModuleRequestView::from_request(&subrequest),
            &ctx
        )
        .unwrap(),
        "%20007%20"
    );
    assert!(
        !HttpModuleRequestView::from_request(&subrequest)
            .has_header(&HeaderName::from_static("x-absent"))
    );

    config
        .request_headers
        .insert("x-octets".into(), "replaced".into());
    config
        .request_headers
        .insert("content-length".into(), "0".into());
    let module = SubrequestModule::new(config).unwrap();
    let subrequest = module
        .build_subrequest(&ctx, &HttpModuleRequestView::from_request(&req))
        .unwrap();
    assert_eq!(
        subrequest.headers().declared_content_length().unwrap(),
        Some(0)
    );
    assert_eq!(
        subrequest
            .headers()
            .get(&OrdinaryHeaderName::try_from(octets).unwrap())
            .unwrap(),
        "replaced"
    );
    // Construction does not mutate or resolve the source's conflicting declaration.
    assert!(req.headers().declared_content_length().is_err());
}

struct DownstreamBoundaryFactory {
    phase: u8,
    framing: Vec<&'static str>,
}

impl HttpModuleFactory for DownstreamBoundaryFactory {
    fn build(&self, _: &HttpModuleConfig) -> anyhow::Result<Arc<dyn HttpModule>> {
        Ok(Arc::new(Self {
            phase: self.phase,
            framing: self.framing.clone(),
        }))
    }
}

#[async_trait::async_trait]
impl HttpModule for DownstreamBoundaryFactory {
    fn capabilities(&self) -> HttpModuleCapabilities {
        HttpModuleCapabilities {
            stages: ModuleStages::DOWNSTREAM_RESPONSE,
            body_access: BodyAccess::Streaming,
            ..HttpModuleCapabilities::default()
        }
    }

    fn applies_to_downstream_response(
        &self,
        _: &HttpModuleContext,
        response: &HttpModuleResponseView<'_>,
    ) -> bool {
        assert!(response.has_header(&HeaderName::from_static("x-duplicate")));
        assert_eq!(
            response.has_header(&http::header::CONTENT_LENGTH),
            !self.framing.is_empty() || self.phase != 1
        );
        if self.phase != 1 {
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            assert_eq!(response.version(), http::Version::HTTP_2);
        }
        self.phase != 0 // Check the owned predicate path without crossing the library boundary.
    }

    async fn call<'a>(
        &self,
        _: HttpModuleStage,
        context: &mut HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> anyhow::Result<HttpModuleEvent<'a>> {
        let HttpModuleEvent::DownstreamResponse(mut response) = event else {
            panic!("unexpected event");
        };
        assert_ne!(self.phase, 0, "inapplicable module must not run");
        let raw = response.as_inner_mut();
        let mut expected = self.framing.clone();
        if self.phase == 2 {
            expected.push("module-invalid");
        }
        assert_eq!(
            raw.headers()
                .get_all(http::header::CONTENT_LENGTH)
                .iter()
                .map(|value| (value.as_bytes(), value.is_sensitive()))
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|value| (value.as_bytes(), true))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            raw.headers()
                .get_all("x-duplicate")
                .iter()
                .map(|value| (value.as_bytes(), value.is_sensitive()))
                .collect::<Vec<_>>(),
            vec![(b"first".as_slice(), false), (b"\x80last".as_slice(), true)]
        );
        assert_eq!(
            raw.headers()["x-pending"],
            if self.phase == 1 {
                "initial-last"
            } else {
                "between"
            }
        );
        assert_eq!(
            raw.extensions().get::<usize>(),
            Some(&usize::from(self.phase - 1))
        );
        if self.phase == 1 {
            assert_eq!(raw.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(raw.version(), http::Version::HTTP_11);
            let mut value = HeaderValue::from_static("module-invalid");
            value.set_sensitive(true);
            response.append_header(http::header::CONTENT_LENGTH, value);
            response.set_status(StatusCode::ACCEPTED);
            response.set_version(http::Version::HTTP_2);
            response.as_inner_mut().extensions_mut().insert(1_usize);
            context.queue_response_header(
                HeaderName::from_static("x-pending"),
                HeaderValue::from_static("between"),
            );
        } else {
            let mut value = HeaderValue::from_static("final-invalid");
            value.set_sensitive(true);
            context.queue_response_header(http::header::CONTENT_LENGTH, value);
        }
        Ok(HttpModuleEvent::DownstreamResponse(response))
    }
}

async fn check_downstream_library_boundary<R: super::execution::DownstreamResponse>(
    framing: Vec<&'static str>,
    abort_body: bool,
) {
    use http_body_util::BodyExt as _;

    let mut registry = HttpModuleRegistryBuilder::new();
    for (name, phase) in [
        ("boundary_first", 1),
        ("boundary_skip", 0),
        ("boundary_second", 2),
    ] {
        registry
            .register_factory(
                name,
                DownstreamBoundaryFactory {
                    phase,
                    framing: framing.clone(),
                },
            )
            .unwrap();
    }
    let configs: Vec<HttpModuleConfig> = serde_yaml::from_str(
        "- type: boundary_first\n- type: boundary_skip\n- type: boundary_second",
    )
    .unwrap();
    let chain = compile_http_modules(&configs, &registry.build()).unwrap();
    let mut context = module_test_context();
    for value in ["initial", "initial-last"] {
        context.queue_response_header(
            HeaderName::from_static("x-pending"),
            HeaderValue::from_static(value),
        );
    }
    let mut execution = HttpModuleExecution::new(chain, context);
    let body = if abort_body {
        let (mut sender, body) = Body::channel();
        sender.abort();
        body
    } else {
        let mut trailers = http::HeaderMap::new();
        trailers.append("x-trailer", HeaderValue::from_static("one"));
        trailers.append("x-trailer", HeaderValue::from_static("two"));
        Body::replay_chunks(vec![Bytes::from_static(b"payload")], Some(trailers))
    };
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::PARTIAL_CONTENT;
    response.extensions_mut().insert(0_usize);
    for declaration in framing {
        let mut value = HeaderValue::from_static(declaration);
        value.set_sensitive(true);
        response
            .headers_mut()
            .append(http::header::CONTENT_LENGTH, value);
    }
    response
        .headers_mut()
        .append("x-duplicate", HeaderValue::from_static("first"));
    let mut value = HeaderValue::from_bytes(b"\x80last").unwrap();
    value.set_sensitive(true);
    response.headers_mut().append("x-duplicate", value);
    let response = execution
        .prepare_downstream_response(R::from_module_response(response))
        .await
        .unwrap();
    let mut response = response.into_module_response();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.version(), http::Version::HTTP_2);
    assert_eq!(response.extensions().get::<usize>(), Some(&1));
    let lengths = response
        .headers()
        .get_all(http::header::CONTENT_LENGTH)
        .iter()
        .collect::<Vec<_>>();
    assert_eq!(lengths.len(), 1);
    assert_eq!(lengths[0], "final-invalid");
    assert!(lengths[0].is_sensitive());
    if abort_body {
        assert_eq!(
            response
                .body_mut()
                .frame()
                .await
                .unwrap()
                .unwrap_err()
                .to_string(),
            "body aborted"
        );
    } else {
        assert_eq!(
            response
                .body_mut()
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            "payload"
        );
        let trailers = response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_trailers()
            .unwrap();
        assert_eq!(
            trailers
                .get_all("x-trailer")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
    }
    if !abort_body {
        assert!(response.body_mut().frame().await.is_none());
    }
}

#[tokio::test]
async fn downstream_module_library_boundary_preserves_and_mutates_both_carriers() {
    use qpx_core::http_message::Response as OwnerResponse;
    for framing in [
        vec![],
        vec!["0"],
        vec!["0007", "7"],
        vec!["malformed"],
        vec!["7", "8"],
    ] {
        for abort_body in [false, true] {
            check_downstream_library_boundary::<Response<Body>>(framing.clone(), abort_body).await;
            check_downstream_library_boundary::<OwnerResponse<Body>>(framing.clone(), abort_body)
                .await;
        }
    }
}

#[tokio::test]
async fn downstream_owner_without_module_calls_keeps_exact_framing_and_applies_pending_headers() {
    use qpx_core::http_message::Response as OwnerResponse;
    for active in [false, true] {
        let mut context = module_test_context();
        let mut value = HeaderValue::from_static("pending-invalid");
        value.set_sensitive(true);
        context.queue_response_header(http::header::CONTENT_LENGTH, value);
        let mut execution = if active {
            HttpModuleExecution::new(Arc::new(CompiledHttpModuleChain::default()), context)
        } else {
            HttpModuleExecution::empty()
        };
        let mut response = Response::new(Body::from("untouched"));
        for value in ["invalid", "7"] {
            response.headers_mut().append(
                http::header::CONTENT_LENGTH,
                HeaderValue::from_static(value),
            );
        }
        let response = execution
            .prepare_downstream_response(OwnerResponse::from_http(response))
            .await
            .unwrap()
            .into_http_for_library();
        let values = response
            .headers()
            .get_all(http::header::CONTENT_LENGTH)
            .iter()
            .collect::<Vec<_>>();
        if active {
            assert_eq!(values.len(), 1);
            assert_eq!(values[0], "pending-invalid");
            assert!(values[0].is_sensitive());
        } else {
            assert_eq!(
                values,
                [
                    HeaderValue::from_static("invalid"),
                    HeaderValue::from_static("7")
                ]
                .iter()
                .collect::<Vec<_>>()
            );
        }
        assert_eq!(
            qpx_http::body::to_bytes(response.into_body())
                .await
                .unwrap(),
            "untouched"
        );
    }
}
