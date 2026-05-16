use super::template::{
    CompiledTemplate, TemplateModifier, TemplatePart, TemplateVariable, compile_template,
    render_template,
};
use super::*;
use crate::http::body::Body;
use crate::runtime::Runtime;
use http::header::{HOST, LOCATION};
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use qpx_core::config::{
    AccessLogConfig, AuditLogConfig, AuthConfig, Config, IdentityConfig, MessagesConfig,
    RuntimeConfig, SubrequestModuleConfig, SubrequestPhase, SystemLogConfig,
};
use std::collections::HashMap;
use std::net::IpAddr;
use subrequest::SubrequestModule;

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
                ext_authz: Vec::new(),
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

fn module_test_context() -> HttpModuleContext {
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

#[test]
fn subrequest_rejects_private_ip_redirect_location() {
    let module =
        SubrequestModule::new(subrequest_config("http://auth.example.com/check")).expect("module");
    let response = Response::builder()
        .status(StatusCode::FOUND)
        .header(LOCATION, "http://127.0.0.1/admin")
        .body(Body::empty())
        .expect("response");

    let err = match module.validate_redirect_location(response.headers().get(LOCATION)) {
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
    assert_eq!(
        frozen.headers().get("x-module"),
        Some(&HeaderValue::from_static("changed"))
    );
}
