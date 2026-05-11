mod cache_purge;
mod execution;
mod response_compression;
mod subrequest;
mod template;

use crate::http::body::Body;
use crate::runtime::RuntimeState;
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
#[cfg(test)]
use http::header::HOST;
use http::{HeaderName, HeaderValue, StatusCode};
use hyper::{Request, Response};
use qpx_core::config::HttpModuleConfig;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

pub use execution::{HttpModuleContext, HttpModuleRequestView};
pub(crate) use execution::{HttpModuleExecution, HttpModuleSessionInit};
use template::{CompiledTemplate, compile_template, render_template};
#[cfg(test)]
use template::{TemplateModifier, TemplatePart, TemplateVariable};

static DEFAULT_HTTP_MODULE_REGISTRY: OnceLock<Arc<HttpModuleRegistry>> = OnceLock::new();

pub fn default_http_module_registry() -> Arc<HttpModuleRegistry> {
    DEFAULT_HTTP_MODULE_REGISTRY
        .get_or_init(|| Arc::new(HttpModuleRegistryBuilder::with_builtins().build()))
        .clone()
}

pub struct HttpModuleRegistryBuilder {
    factories: HashMap<String, Arc<dyn HttpModuleFactory>>,
}

impl Default for HttpModuleRegistryBuilder {
    fn default() -> Self {
        Self::with_builtins()
    }
}

impl HttpModuleRegistryBuilder {
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    pub fn with_builtins() -> Self {
        let mut builder = Self::new();
        builder
            .register_factory("cache_purge", cache_purge::CachePurgeModuleFactory)
            .expect("cache_purge module registration must succeed");
        builder
            .register_factory("subrequest", subrequest::SubrequestModuleFactory)
            .expect("subrequest module registration must succeed");
        builder
            .register_factory(
                "response_compression",
                response_compression::ResponseCompressionModuleFactory,
            )
            .expect("response_compression module registration must succeed");
        builder
    }

    pub fn register_factory<F>(
        &mut self,
        type_name: impl Into<String>,
        factory: F,
    ) -> Result<&mut Self>
    where
        F: HttpModuleFactory + 'static,
    {
        self.register_factory_arc(type_name, Arc::new(factory))
    }

    pub fn register_factory_arc(
        &mut self,
        type_name: impl Into<String>,
        factory: Arc<dyn HttpModuleFactory>,
    ) -> Result<&mut Self> {
        let type_name = type_name.into();
        if type_name.trim().is_empty() {
            return Err(anyhow!("http module type name must not be empty"));
        }
        if self.factories.insert(type_name.clone(), factory).is_some() {
            return Err(anyhow!("http module type already registered: {type_name}"));
        }
        Ok(self)
    }

    pub fn build(self) -> HttpModuleRegistry {
        HttpModuleRegistry {
            factories: self
                .factories
                .into_iter()
                .map(|(type_name, factory)| (Arc::<str>::from(type_name), factory))
                .collect(),
        }
    }
}

#[derive(Clone)]
pub struct HttpModuleRegistry {
    factories: HashMap<Arc<str>, Arc<dyn HttpModuleFactory>>,
}

impl HttpModuleRegistry {
    pub fn builder() -> HttpModuleRegistryBuilder {
        HttpModuleRegistryBuilder::with_builtins()
    }

    pub fn get(&self, type_name: &str) -> Option<&Arc<dyn HttpModuleFactory>> {
        self.factories.get(type_name)
    }
}

pub trait HttpModuleFactory: Send + Sync {
    fn build(&self, spec: &HttpModuleConfig) -> Result<Arc<dyn HttpModule>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheLookupStatus {
    Hit,
    Miss,
}

#[derive(Clone, Copy, Debug)]
pub struct RetryEvent<'a> {
    pub attempt: usize,
    pub reason: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleStages(u32);

impl ModuleStages {
    pub const REQUEST_HEADERS: Self = Self(1 << 0);
    pub const CACHE_LOOKUP: Self = Self(1 << 1);
    pub const UPSTREAM_REQUEST: Self = Self(1 << 2);
    pub const UPSTREAM_RESPONSE: Self = Self(1 << 3);
    pub const DOWNSTREAM_RESPONSE: Self = Self(1 << 4);
    pub const RETRY: Self = Self(1 << 5);
    pub const ERROR: Self = Self(1 << 6);
    pub const LOG: Self = Self(1 << 7);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn all() -> Self {
        Self(
            Self::REQUEST_HEADERS.0
                | Self::CACHE_LOOKUP.0
                | Self::UPSTREAM_REQUEST.0
                | Self::UPSTREAM_RESPONSE.0
                | Self::DOWNSTREAM_RESPONSE.0
                | Self::RETRY.0
                | Self::ERROR.0
                | Self::LOG.0,
        )
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyAccess {
    HeadersOnly,
    RequestBodyBuffered {
        max_bytes: usize,
    },
    ResponseBodyBuffered {
        max_bytes: usize,
    },
    RequestAndResponseBodyBuffered {
        max_request_bytes: usize,
        max_response_bytes: usize,
    },
    Streaming,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpModuleCapabilities {
    pub stages: ModuleStages,
    pub body_access: BodyAccess,
    pub mutates_request_headers: bool,
    pub mutates_response_headers: bool,
    pub may_short_circuit: bool,
    pub needs_frozen_request: bool,
    pub safe_on_retry: bool,
}

impl HttpModuleCapabilities {
    pub fn headers_only(stages: ModuleStages) -> Self {
        Self {
            stages,
            body_access: BodyAccess::HeadersOnly,
            mutates_request_headers: false,
            mutates_response_headers: false,
            may_short_circuit: false,
            needs_frozen_request: false,
            safe_on_retry: true,
        }
    }

    fn merge(&mut self, other: Self) {
        self.stages.insert(other.stages);
        self.body_access = merge_body_access(self.body_access, other.body_access);
        self.mutates_request_headers |= other.mutates_request_headers;
        self.mutates_response_headers |= other.mutates_response_headers;
        self.may_short_circuit |= other.may_short_circuit;
        self.needs_frozen_request |= other.needs_frozen_request;
        self.safe_on_retry &= other.safe_on_retry;
    }
}

impl Default for HttpModuleCapabilities {
    fn default() -> Self {
        Self {
            stages: ModuleStages::empty(),
            body_access: BodyAccess::HeadersOnly,
            mutates_request_headers: false,
            mutates_response_headers: false,
            may_short_circuit: false,
            needs_frozen_request: false,
            safe_on_retry: true,
        }
    }
}

fn merge_body_access(left: BodyAccess, right: BodyAccess) -> BodyAccess {
    match (left, right) {
        (BodyAccess::Streaming, _) | (_, BodyAccess::Streaming) => BodyAccess::Streaming,
        (
            BodyAccess::RequestAndResponseBodyBuffered {
                max_request_bytes,
                max_response_bytes,
            },
            other,
        )
        | (
            other,
            BodyAccess::RequestAndResponseBodyBuffered {
                max_request_bytes,
                max_response_bytes,
            },
        ) => match other {
            BodyAccess::RequestBodyBuffered { max_bytes } => {
                BodyAccess::RequestAndResponseBodyBuffered {
                    max_request_bytes: max_request_bytes.max(max_bytes),
                    max_response_bytes,
                }
            }
            BodyAccess::ResponseBodyBuffered { max_bytes } => {
                BodyAccess::RequestAndResponseBodyBuffered {
                    max_request_bytes,
                    max_response_bytes: max_response_bytes.max(max_bytes),
                }
            }
            _ => BodyAccess::RequestAndResponseBodyBuffered {
                max_request_bytes,
                max_response_bytes,
            },
        },
        (
            BodyAccess::RequestBodyBuffered { max_bytes: request },
            BodyAccess::ResponseBodyBuffered {
                max_bytes: response,
            },
        )
        | (
            BodyAccess::ResponseBodyBuffered {
                max_bytes: response,
            },
            BodyAccess::RequestBodyBuffered { max_bytes: request },
        ) => BodyAccess::RequestAndResponseBodyBuffered {
            max_request_bytes: request,
            max_response_bytes: response,
        },
        (
            BodyAccess::RequestBodyBuffered { max_bytes: left },
            BodyAccess::RequestBodyBuffered { max_bytes: right },
        ) => BodyAccess::RequestBodyBuffered {
            max_bytes: left.max(right),
        },
        (
            BodyAccess::ResponseBodyBuffered { max_bytes: left },
            BodyAccess::ResponseBodyBuffered { max_bytes: right },
        ) => BodyAccess::ResponseBodyBuffered {
            max_bytes: left.max(right),
        },
        (BodyAccess::HeadersOnly, other) | (other, BodyAccess::HeadersOnly) => other,
    }
}

pub enum RequestHeadersOutcome {
    Continue,
    Respond(Box<Response<Body>>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpModuleStage {
    RequestHeaders,
    CacheLookup,
    UpstreamRequest,
    UpstreamResponse,
    DownstreamResponse,
    Retry,
    Error,
    Log,
}

pub enum HttpModuleEvent<'a> {
    RequestHeaders(&'a mut Request<Body>),
    RequestHeadersResult(RequestHeadersOutcome),
    CacheLookup(CacheLookupStatus),
    UpstreamRequest(&'a mut Request<Body>),
    UpstreamResponse(Response<Body>),
    DownstreamResponse(Response<Body>),
    Retry(RetryEvent<'a>),
    Error(&'a anyhow::Error),
    Log {
        response_status: Option<StatusCode>,
        err: Option<&'a anyhow::Error>,
    },
    Complete,
}

impl<'a> HttpModuleEvent<'a> {
    fn request_headers_result(self, module: &str) -> Result<RequestHeadersOutcome> {
        match self {
            Self::RequestHeadersResult(outcome) => Ok(outcome),
            Self::Complete => Ok(RequestHeadersOutcome::Continue),
            _ => Err(anyhow!(
                "http module {module} returned invalid request_headers event"
            )),
        }
    }

    fn into_complete(self, module: &str, stage: HttpModuleStage) -> Result<()> {
        match self {
            Self::Complete => Ok(()),
            _ => Err(anyhow!(
                "http module {module} returned invalid {stage:?} event"
            )),
        }
    }

    fn upstream_response(self, module: &str) -> Result<Response<Body>> {
        match self {
            Self::UpstreamResponse(response) => Ok(response),
            _ => Err(anyhow!(
                "http module {module} returned invalid upstream_response event"
            )),
        }
    }

    fn downstream_response(self, module: &str) -> Result<Response<Body>> {
        match self {
            Self::DownstreamResponse(response) => Ok(response),
            _ => Err(anyhow!(
                "http module {module} returned invalid downstream_response event"
            )),
        }
    }
}

#[async_trait]
pub trait HttpModule: Send + Sync {
    fn order(&self) -> i16 {
        0
    }

    fn capabilities(&self) -> HttpModuleCapabilities;

    fn explain(&self) -> Vec<String> {
        Vec::new()
    }

    async fn call<'a>(
        &self,
        stage: HttpModuleStage,
        ctx: &mut HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> Result<HttpModuleEvent<'a>>;
}

#[derive(Clone)]
struct CompiledHttpModule {
    type_name: Arc<str>,
    id: Option<Arc<str>>,
    module: Arc<dyn HttpModule>,
}

impl CompiledHttpModule {
    fn label(&self) -> String {
        match &self.id {
            Some(id) => format!("{} ({id})", self.type_name),
            None => self.type_name.to_string(),
        }
    }

    fn explain(&self) -> Option<(String, Vec<String>)> {
        let detail = self.module.explain();
        (!detail.is_empty()).then(|| (self.label(), detail))
    }
}

#[derive(Clone)]
pub(crate) struct CompiledHttpModuleChain {
    request_headers: Arc<[CompiledHttpModule]>,
    cache_lookup: Arc<[CompiledHttpModule]>,
    upstream_request: Arc<[CompiledHttpModule]>,
    upstream_response: Arc<[CompiledHttpModule]>,
    downstream_response: Arc<[CompiledHttpModule]>,
    retry: Arc<[CompiledHttpModule]>,
    error: Arc<[CompiledHttpModule]>,
    log: Arc<[CompiledHttpModule]>,
    aggregate: HttpModuleCapabilities,
}

impl Default for CompiledHttpModuleChain {
    fn default() -> Self {
        let empty: Arc<[CompiledHttpModule]> = Vec::<CompiledHttpModule>::new().into();
        Self {
            request_headers: empty.clone(),
            cache_lookup: empty.clone(),
            upstream_request: empty.clone(),
            upstream_response: empty.clone(),
            downstream_response: empty.clone(),
            retry: empty.clone(),
            error: empty.clone(),
            log: empty,
            aggregate: HttpModuleCapabilities::default(),
        }
    }
}

impl CompiledHttpModuleChain {
    pub(crate) fn aggregate(&self) -> HttpModuleCapabilities {
        self.aggregate
    }

    pub(crate) fn has_request_side_modules(&self) -> bool {
        !self.request_headers.is_empty()
            || !self.cache_lookup.is_empty()
            || !self.upstream_request.is_empty()
    }

    pub(crate) fn has_response_side_modules(&self) -> bool {
        !self.upstream_response.is_empty()
            || !self.downstream_response.is_empty()
            || !self.retry.is_empty()
            || !self.error.is_empty()
            || !self.log.is_empty()
    }

    pub(crate) fn needs_frozen_request(&self) -> bool {
        self.aggregate.needs_frozen_request
    }

    pub(crate) fn stage_labels(&self) -> Vec<(&'static str, Vec<String>)> {
        vec![
            ("request_headers", module_labels(&self.request_headers)),
            ("cache_lookup", module_labels(&self.cache_lookup)),
            ("upstream_request", module_labels(&self.upstream_request)),
            ("upstream_response", module_labels(&self.upstream_response)),
            (
                "downstream_response",
                module_labels(&self.downstream_response),
            ),
            ("retry", module_labels(&self.retry)),
            ("error", module_labels(&self.error)),
            ("log", module_labels(&self.log)),
        ]
    }

    pub(crate) fn explain_details(&self) -> Vec<(String, Vec<String>)> {
        [
            self.request_headers.as_ref(),
            self.cache_lookup.as_ref(),
            self.upstream_request.as_ref(),
            self.upstream_response.as_ref(),
            self.downstream_response.as_ref(),
            self.retry.as_ref(),
            self.error.as_ref(),
            self.log.as_ref(),
        ]
        .into_iter()
        .flat_map(|modules| modules.iter().filter_map(CompiledHttpModule::explain))
        .collect()
    }

    pub(crate) fn start(
        &self,
        runtime: Arc<RuntimeState>,
        init: HttpModuleSessionInit,
    ) -> HttpModuleExecution {
        HttpModuleExecution::new(self.clone(), HttpModuleContext::new(runtime, init))
    }
}

fn module_labels(modules: &[CompiledHttpModule]) -> Vec<String> {
    modules.iter().map(CompiledHttpModule::label).collect()
}

pub(crate) fn compile_http_modules(
    configs: &[HttpModuleConfig],
    registry: &HttpModuleRegistry,
) -> Result<Arc<CompiledHttpModuleChain>> {
    if configs.is_empty() {
        return Ok(Arc::new(CompiledHttpModuleChain::default()));
    }

    let mut modules = Vec::with_capacity(configs.len());
    for (idx, config) in configs.iter().enumerate() {
        let Some(factory) = registry.get(config.r#type.as_str()) else {
            return Err(anyhow!(
                "unknown http module type {} at index {}",
                config.r#type,
                idx
            ));
        };
        let module = factory
            .build(config)
            .with_context(|| format!("failed to build http module {}", config.r#type))?;
        let order = config.order.unwrap_or(module.order());
        modules.push((
            order,
            idx,
            CompiledHttpModule {
                type_name: Arc::<str>::from(config.r#type.as_str()),
                id: config.id.as_deref().map(Arc::<str>::from),
                module,
            },
        ));
    }
    modules.sort_by_key(|(order, idx, _)| (*order, *idx));
    let modules = modules
        .into_iter()
        .map(|(_, _, module)| module)
        .collect::<Vec<_>>();
    let mut aggregate = HttpModuleCapabilities::default();
    let mut request_headers = Vec::new();
    let mut cache_lookup = Vec::new();
    let mut upstream_request = Vec::new();
    let mut upstream_response = Vec::new();
    let mut downstream_response = Vec::new();
    let mut retry = Vec::new();
    let mut error = Vec::new();
    let mut log = Vec::new();
    for module in modules {
        let capabilities = module.module.capabilities();
        aggregate.merge(capabilities);
        if capabilities.stages.contains(ModuleStages::REQUEST_HEADERS) {
            request_headers.push(module.clone());
        }
        if capabilities.stages.contains(ModuleStages::CACHE_LOOKUP) {
            cache_lookup.push(module.clone());
        }
        if capabilities.stages.contains(ModuleStages::UPSTREAM_REQUEST) {
            upstream_request.push(module.clone());
        }
        if capabilities
            .stages
            .contains(ModuleStages::UPSTREAM_RESPONSE)
        {
            upstream_response.push(module.clone());
        }
        if capabilities
            .stages
            .contains(ModuleStages::DOWNSTREAM_RESPONSE)
        {
            downstream_response.push(module.clone());
        }
        if capabilities.stages.contains(ModuleStages::RETRY) {
            retry.push(module.clone());
        }
        if capabilities.stages.contains(ModuleStages::ERROR) {
            error.push(module.clone());
        }
        if capabilities.stages.contains(ModuleStages::LOG) {
            log.push(module);
        }
    }
    Ok(Arc::new(CompiledHttpModuleChain {
        request_headers: request_headers.into(),
        cache_lookup: cache_lookup.into(),
        upstream_request: upstream_request.into(),
        upstream_response: upstream_response.into(),
        downstream_response: downstream_response.into(),
        retry: retry.into(),
        error: error.into(),
        log: log.into(),
        aggregate,
    }))
}

fn parse_module_settings<T>(spec: &HttpModuleConfig) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    spec.parse_settings()
        .with_context(|| format!("invalid settings for http module {}", spec.r#type))
}

pub(super) fn compile_literal_headers(
    headers: HashMap<String, String>,
) -> Result<Vec<(HeaderName, HeaderValue)>> {
    headers
        .into_iter()
        .map(|(name, value)| {
            Ok((
                parse_header_name(name)?,
                HeaderValue::from_str(value.as_str())
                    .with_context(|| format!("invalid header value for {value}"))?,
            ))
        })
        .collect()
}

fn parse_header_name(name: impl AsRef<str>) -> Result<HeaderName> {
    HeaderName::from_bytes(name.as_ref().trim().as_bytes())
        .map_err(|_| anyhow!("invalid header name: {}", name.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Runtime;
    use http::Method;
    use http::header::LOCATION;
    use qpx_core::config::{
        AccessLogConfig, AuditLogConfig, AuthConfig, Config, IdentityConfig, MessagesConfig,
        RuntimeConfig, SubrequestModuleConfig, SubrequestPhase, SystemLogConfig,
    };
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
                proxy_kind: "forward",
                proxy_name: "test-proxy".to_string(),
                scope_name: "test-scope".to_string(),
                route_name: Some("test-route".to_string()),
                remote_ip: "127.0.0.1".parse::<IpAddr>().expect("ip"),
                sni: Some("example.com".to_string()),
                identity_user: Some("alice".to_string()),
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
        let module = SubrequestModule::new(subrequest_config("http://evil.example.com/check"))
            .expect("module");

        let err = match module.validate_url("http://evil.example.com/check") {
            Ok(_) => panic!("host should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("URL host is not allowed"));
    }

    #[test]
    fn subrequest_rejects_private_ip_redirect_location() {
        let module = SubrequestModule::new(subrequest_config("http://auth.example.com/check"))
            .expect("module");
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
}
