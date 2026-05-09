use crate::cache::purge_cache_key;
use crate::cache::CacheRequestKey;
mod response_compression;

use crate::http::body::Body;
use crate::runtime::RuntimeState;
use crate::upstream::origin::{proxy_http, OriginEndpoint};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use http::header::{CONTENT_LENGTH, HOST, LOCATION};
use http::{Extensions, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};
use hyper::{Request, Response};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use qpx_core::config::{
    CachePolicyConfig, CachePurgeModuleConfig, HeaderCaptureConfig, HttpModuleConfig,
    SubrequestModuleConfig, SubrequestPhase, SubrequestResponseMode,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use tokio::time::{timeout, Duration};
use tracing::warn;

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
            .register_factory("cache_purge", CachePurgeModuleFactory)
            .expect("cache_purge module registration must succeed");
        builder
            .register_factory("subrequest", SubrequestModuleFactory)
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
        HttpModuleExecution {
            chain: self.clone(),
            context: HttpModuleContext::new(runtime, init),
        }
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

pub(crate) struct HttpModuleSessionInit {
    pub(crate) proxy_kind: &'static str,
    pub(crate) proxy_name: String,
    pub(crate) scope_name: String,
    pub(crate) route_name: Option<String>,
    pub(crate) remote_ip: IpAddr,
    pub(crate) sni: Option<String>,
    pub(crate) identity_user: Option<String>,
    pub(crate) cache_policy: Option<CachePolicyConfig>,
    pub(crate) cache_default_scheme: Option<String>,
}

#[derive(Debug, Clone)]
struct FrozenRequestSnapshot {
    method: Method,
    version: Version,
    uri: http::Uri,
    uri_string: String,
    host: Option<String>,
    headers: HeaderMap,
}

impl FrozenRequestSnapshot {
    fn from_request(req: &Request<Body>) -> Self {
        Self {
            method: req.method().clone(),
            version: req.version(),
            uri: req.uri().clone(),
            uri_string: req.uri().to_string(),
            host: req.uri().host().map(str::to_string).or_else(|| {
                req.headers()
                    .get(HOST)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string)
            }),
            headers: req.headers().clone(),
        }
    }

    fn authority(&self) -> Option<&str> {
        self.uri.authority().map(|value| value.as_str())
    }

    fn scheme(&self) -> Option<&str> {
        self.uri.scheme_str()
    }

    fn path(&self) -> &str {
        self.uri.path()
    }

    fn query(&self) -> Option<&str> {
        self.uri.query()
    }

    fn matches_request(&self, req: &Request<Body>) -> bool {
        self.method == *req.method()
            && self.version == req.version()
            && self.uri == *req.uri()
            && self.headers == *req.headers()
    }
}

pub struct HttpModuleRequestView<'a> {
    inner: RequestViewInner<'a>,
}

enum RequestViewInner<'a> {
    Live(&'a Request<Body>),
    Frozen(&'a FrozenRequestSnapshot),
}

impl<'a> HttpModuleRequestView<'a> {
    pub fn from_request(request: &'a Request<Body>) -> Self {
        Self {
            inner: RequestViewInner::Live(request),
        }
    }

    fn from_frozen(request: &'a FrozenRequestSnapshot) -> Self {
        Self {
            inner: RequestViewInner::Frozen(request),
        }
    }

    pub fn method(&self) -> &Method {
        match self.inner {
            RequestViewInner::Live(request) => request.method(),
            RequestViewInner::Frozen(request) => &request.method,
        }
    }

    pub fn version(&self) -> Version {
        match self.inner {
            RequestViewInner::Live(request) => request.version(),
            RequestViewInner::Frozen(request) => request.version,
        }
    }

    pub fn scheme(&self) -> Option<&str> {
        match self.inner {
            RequestViewInner::Live(request) => request.uri().scheme_str(),
            RequestViewInner::Frozen(request) => request.scheme(),
        }
    }

    pub fn host(&self) -> Option<&str> {
        match self.inner {
            RequestViewInner::Live(request) => request.uri().host().or_else(|| {
                request
                    .headers()
                    .get(HOST)
                    .and_then(|value| value.to_str().ok())
            }),
            RequestViewInner::Frozen(request) => request.host.as_deref(),
        }
    }

    pub fn path(&self) -> &str {
        match self.inner {
            RequestViewInner::Live(request) => request.uri().path(),
            RequestViewInner::Frozen(request) => request.path(),
        }
    }

    pub fn query(&self) -> Option<&str> {
        match self.inner {
            RequestViewInner::Live(request) => request.uri().query(),
            RequestViewInner::Frozen(request) => request.query(),
        }
    }

    pub fn authority(&self) -> Option<&str> {
        match self.inner {
            RequestViewInner::Live(request) => {
                request.uri().authority().map(|value| value.as_str())
            }
            RequestViewInner::Frozen(request) => request.authority(),
        }
    }

    pub fn headers(&self) -> &HeaderMap {
        match self.inner {
            RequestViewInner::Live(request) => request.headers(),
            RequestViewInner::Frozen(request) => &request.headers,
        }
    }

    pub fn uri(&self) -> &http::Uri {
        match self.inner {
            RequestViewInner::Live(request) => request.uri(),
            RequestViewInner::Frozen(request) => &request.uri,
        }
    }

    pub fn uri_string(&self) -> Cow<'_, str> {
        match self.inner {
            RequestViewInner::Live(request) => Cow::Owned(request.uri().to_string()),
            RequestViewInner::Frozen(request) => Cow::Borrowed(request.uri_string.as_str()),
        }
    }
}

#[derive(Debug)]
struct HttpModuleSession {
    proxy_kind: &'static str,
    proxy_name: String,
    scope_name: String,
    route_name: Option<String>,
    remote_ip: IpAddr,
    sni: Option<String>,
    identity_user: Option<String>,
    request: Option<FrozenRequestSnapshot>,
    response_status: Option<StatusCode>,
    cache_policy: Option<CachePolicyConfig>,
    cache_default_scheme: Option<String>,
    pending_response_headers: Vec<(HeaderName, HeaderValue)>,
    extensions: Extensions,
}

impl HttpModuleSession {
    fn new(init: HttpModuleSessionInit) -> Self {
        Self {
            proxy_kind: init.proxy_kind,
            proxy_name: init.proxy_name,
            scope_name: init.scope_name,
            route_name: init.route_name,
            remote_ip: init.remote_ip,
            sni: init.sni,
            identity_user: init.identity_user,
            request: None,
            response_status: None,
            cache_policy: init.cache_policy,
            cache_default_scheme: init.cache_default_scheme,
            pending_response_headers: Vec::new(),
            extensions: Extensions::new(),
        }
    }
}

pub struct HttpModuleContext {
    runtime: Arc<RuntimeState>,
    session: HttpModuleSession,
}

impl HttpModuleContext {
    fn new(runtime: Arc<RuntimeState>, init: HttpModuleSessionInit) -> Self {
        Self {
            runtime,
            session: HttpModuleSession::new(init),
        }
    }

    fn sync_frozen_request(&mut self, req: &Request<Body>) -> bool {
        if self
            .session
            .request
            .as_ref()
            .is_some_and(|snapshot| snapshot.matches_request(req))
        {
            return false;
        }
        self.session.request = Some(FrozenRequestSnapshot::from_request(req));
        true
    }

    fn remember_request_header(&mut self, name: HeaderName, value: HeaderValue) {
        if let Some(request) = self.session.request.as_mut() {
            if name == HOST {
                request.host = value.to_str().ok().map(str::to_string);
            }
            request.headers.insert(name, value);
        }
    }

    fn set_response_status(&mut self, status: StatusCode) {
        self.session.response_status = Some(status);
    }

    fn apply_pending_response_headers(&mut self, headers: &mut HeaderMap) {
        for (name, value) in self.session.pending_response_headers.drain(..) {
            headers.insert(name, value);
        }
    }

    pub fn proxy_kind(&self) -> &'static str {
        self.session.proxy_kind
    }

    pub fn proxy_name(&self) -> &str {
        self.session.proxy_name.as_str()
    }

    pub fn scope_name(&self) -> &str {
        self.session.scope_name.as_str()
    }

    pub fn route_name(&self) -> Option<&str> {
        self.session.route_name.as_deref()
    }

    pub fn remote_ip(&self) -> IpAddr {
        self.session.remote_ip
    }

    pub fn sni(&self) -> Option<&str> {
        self.session.sni.as_deref()
    }

    pub fn identity_user(&self) -> Option<&str> {
        self.session.identity_user.as_deref()
    }

    pub fn frozen_request(&self) -> Option<HttpModuleRequestView<'_>> {
        self.session
            .request
            .as_ref()
            .map(HttpModuleRequestView::from_frozen)
    }

    pub fn response_status(&self) -> Option<StatusCode> {
        self.session.response_status
    }

    pub fn cache_policy(&self) -> Option<&CachePolicyConfig> {
        self.session.cache_policy.as_ref()
    }

    pub fn cache_default_scheme(&self) -> Option<&str> {
        self.session.cache_default_scheme.as_deref()
    }

    pub fn extensions(&self) -> &Extensions {
        &self.session.extensions
    }

    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.session.extensions
    }

    pub fn queue_response_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.session.pending_response_headers.push((name, value));
    }

    pub async fn send_absolute_request(&self, req: Request<Body>) -> Result<Response<Body>> {
        let url = req.uri().to_string();
        let origin = OriginEndpoint::direct(url.as_str());
        proxy_http(req, &origin, self.session.proxy_name.as_str(), None).await
    }

    pub fn cache_request_key(&self, req: &Request<Body>) -> Result<Option<CacheRequestKey>> {
        let Some(_) = self.session.cache_policy.as_ref() else {
            return Ok(None);
        };
        let default_scheme = self
            .session
            .cache_default_scheme
            .as_deref()
            .ok_or_else(|| anyhow!("cache purge missing default scheme"))?;
        CacheRequestKey::for_target(req, default_scheme)
    }

    pub async fn purge_cache_key(&self, key: &CacheRequestKey) -> Result<bool> {
        let Some(policy) = self.session.cache_policy.clone() else {
            return Ok(false);
        };
        let backends = self.runtime.cache.backends.clone();
        let _ = purge_cache_key(key, &policy, &backends).await?;
        Ok(true)
    }
}

pub(crate) struct HttpModuleExecution {
    chain: CompiledHttpModuleChain,
    context: HttpModuleContext,
}

impl HttpModuleExecution {
    pub(crate) async fn on_request_headers(
        &mut self,
        req: &mut Request<Body>,
    ) -> Result<RequestHeadersOutcome> {
        for module in self.chain.request_headers.iter() {
            let label = module.label();
            let outcome = module
                .module
                .call(
                    HttpModuleStage::RequestHeaders,
                    &mut self.context,
                    HttpModuleEvent::RequestHeaders(req),
                )
                .await
                .with_context(|| format!("http module {label} request_headers failed"))?
                .request_headers_result(label.as_str())?;
            match outcome {
                RequestHeadersOutcome::Continue => {}
                RequestHeadersOutcome::Respond(response) => {
                    if self.chain.aggregate.needs_frozen_request {
                        self.context.sync_frozen_request(req);
                    }
                    return Ok(RequestHeadersOutcome::Respond(response));
                }
            }
        }
        if self.chain.aggregate.needs_frozen_request {
            self.context.sync_frozen_request(req);
        }
        Ok(RequestHeadersOutcome::Continue)
    }

    pub(crate) async fn on_cache_lookup(&mut self, hit: bool) -> Result<()> {
        let status = if hit {
            CacheLookupStatus::Hit
        } else {
            CacheLookupStatus::Miss
        };
        for module in self.chain.cache_lookup.iter() {
            let label = module.label();
            module
                .module
                .call(
                    HttpModuleStage::CacheLookup,
                    &mut self.context,
                    HttpModuleEvent::CacheLookup(status),
                )
                .await
                .with_context(|| format!("http module {label} cache_lookup failed"))?
                .into_complete(label.as_str(), HttpModuleStage::CacheLookup)?;
        }
        Ok(())
    }

    pub(crate) async fn on_upstream_request(&mut self, req: &mut Request<Body>) -> Result<()> {
        for module in self.chain.upstream_request.iter() {
            let label = module.label();
            module
                .module
                .call(
                    HttpModuleStage::UpstreamRequest,
                    &mut self.context,
                    HttpModuleEvent::UpstreamRequest(req),
                )
                .await
                .with_context(|| format!("http module {label} upstream_request failed"))?
                .into_complete(label.as_str(), HttpModuleStage::UpstreamRequest)?;
        }
        if self.chain.aggregate.needs_frozen_request {
            self.context.sync_frozen_request(req);
        }
        Ok(())
    }

    pub(crate) async fn on_upstream_response(
        &mut self,
        mut response: Response<Body>,
    ) -> Result<Response<Body>> {
        self.context.set_response_status(response.status());
        self.context
            .apply_pending_response_headers(response.headers_mut());
        for module in self.chain.upstream_response.iter() {
            let label = module.label();
            response = module
                .module
                .call(
                    HttpModuleStage::UpstreamResponse,
                    &mut self.context,
                    HttpModuleEvent::UpstreamResponse(response),
                )
                .await
                .with_context(|| format!("http module {label} upstream_response failed"))?
                .upstream_response(label.as_str())?;
            self.context.set_response_status(response.status());
            self.context
                .apply_pending_response_headers(response.headers_mut());
        }
        Ok(response)
    }

    pub(crate) async fn prepare_downstream_response(
        &mut self,
        mut response: Response<Body>,
    ) -> Result<Response<Body>> {
        self.context.set_response_status(response.status());
        self.context
            .apply_pending_response_headers(response.headers_mut());
        for module in self.chain.downstream_response.iter() {
            let label = module.label();
            response = module
                .module
                .call(
                    HttpModuleStage::DownstreamResponse,
                    &mut self.context,
                    HttpModuleEvent::DownstreamResponse(response),
                )
                .await
                .with_context(|| format!("http module {label} downstream_response failed"))?
                .downstream_response(label.as_str())?;
            self.context.set_response_status(response.status());
            self.context
                .apply_pending_response_headers(response.headers_mut());
        }
        Ok(response)
    }

    pub(crate) async fn on_retry(&mut self, attempt: usize, reason: &str) -> Result<()> {
        let event = RetryEvent { attempt, reason };
        for module in self.chain.retry.iter() {
            let label = module.label();
            module
                .module
                .call(
                    HttpModuleStage::Retry,
                    &mut self.context,
                    HttpModuleEvent::Retry(event),
                )
                .await
                .with_context(|| format!("http module {label} retry failed"))?
                .into_complete(label.as_str(), HttpModuleStage::Retry)?;
        }
        Ok(())
    }

    pub(crate) async fn on_error(&mut self, err: &anyhow::Error) {
        for module in self.chain.error.iter() {
            let label = module.label();
            if let Err(err) = module
                .module
                .call(
                    HttpModuleStage::Error,
                    &mut self.context,
                    HttpModuleEvent::Error(err),
                )
                .await
                .and_then(|event| event.into_complete(label.as_str(), HttpModuleStage::Error))
            {
                warn!(error = ?err, module = label.as_str(), "http module error hook failed");
            }
        }
    }

    pub(crate) async fn on_logging(
        &mut self,
        response_status: Option<StatusCode>,
        err: Option<&anyhow::Error>,
    ) {
        if let Some(status) = response_status {
            self.context.set_response_status(status);
        }
        for module in self.chain.log.iter() {
            let label = module.label();
            if let Err(err) = module
                .module
                .call(
                    HttpModuleStage::Log,
                    &mut self.context,
                    HttpModuleEvent::Log {
                        response_status,
                        err,
                    },
                )
                .await
                .and_then(|event| event.into_complete(label.as_str(), HttpModuleStage::Log))
            {
                warn!(error = ?err, module = label.as_str(), "http module log hook failed");
            }
        }
    }
}

struct CachePurgeModuleFactory;

impl HttpModuleFactory for CachePurgeModuleFactory {
    fn build(&self, spec: &HttpModuleConfig) -> Result<Arc<dyn HttpModule>> {
        Ok(Arc::new(CachePurgeModule::new(parse_module_settings(
            spec,
        )?)?))
    }
}

#[derive(Clone)]
struct CachePurgeModule {
    methods: Vec<Method>,
    response_status: StatusCode,
    response_body: String,
    response_headers: Vec<(HeaderName, HeaderValue)>,
}

impl CachePurgeModule {
    fn new(config: CachePurgeModuleConfig) -> Result<Self> {
        let methods = config
            .methods
            .into_iter()
            .map(|method| {
                Method::from_bytes(method.trim().as_bytes())
                    .map_err(|_| anyhow!("invalid purge method: {method}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            methods,
            response_status: StatusCode::from_u16(config.response_status)
                .context("invalid cache purge response_status")?,
            response_body: config.response_body,
            response_headers: compile_literal_headers(config.response_headers)?,
        })
    }

    fn matches(&self, method: &Method) -> bool {
        self.methods.iter().any(|candidate| candidate == method)
    }

    fn build_response(&self) -> Response<Body> {
        let mut response = Response::builder()
            .status(self.response_status)
            .body(Body::from(self.response_body.clone()))
            .expect("static cache purge response");
        for (name, value) in &self.response_headers {
            response.headers_mut().insert(name.clone(), value.clone());
        }
        response
    }
}

#[async_trait]
impl HttpModule for CachePurgeModule {
    fn order(&self) -> i16 {
        -100
    }

    fn capabilities(&self) -> HttpModuleCapabilities {
        let mut capabilities = HttpModuleCapabilities::headers_only(ModuleStages::REQUEST_HEADERS);
        capabilities.may_short_circuit = true;
        capabilities
    }

    async fn call<'a>(
        &self,
        stage: HttpModuleStage,
        ctx: &mut HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> Result<HttpModuleEvent<'a>> {
        let HttpModuleStage::RequestHeaders = stage else {
            return Ok(event);
        };
        let HttpModuleEvent::RequestHeaders(request) = event else {
            return Err(anyhow!(
                "cache_purge received invalid request_headers event"
            ));
        };
        if !self.matches(request.method()) {
            return Ok(HttpModuleEvent::RequestHeadersResult(
                RequestHeadersOutcome::Continue,
            ));
        }
        if let Some(key) = ctx.cache_request_key(request)? {
            let _ = ctx.purge_cache_key(&key).await?;
        }
        Ok(HttpModuleEvent::RequestHeadersResult(
            RequestHeadersOutcome::Respond(Box::new(self.build_response())),
        ))
    }
}

struct SubrequestModuleFactory;

impl HttpModuleFactory for SubrequestModuleFactory {
    fn build(&self, spec: &HttpModuleConfig) -> Result<Arc<dyn HttpModule>> {
        Ok(Arc::new(SubrequestModule::new(parse_module_settings(
            spec,
        )?)?))
    }
}

#[derive(Clone)]
struct SubrequestModule {
    name: Arc<str>,
    phase: SubrequestPhase,
    method: Method,
    url_template: CompiledTemplate,
    timeout: Option<Duration>,
    max_response_bytes: usize,
    allowed_schemes: Vec<Arc<str>>,
    allowed_hosts: Vec<Arc<str>>,
    deny_redirects: bool,
    deny_private_ip_redirects: bool,
    pass_headers: Vec<HeaderName>,
    request_headers: Vec<(HeaderName, CompiledTemplate)>,
    copy_to_request: Vec<(HeaderName, HeaderName)>,
    copy_to_response: Vec<(HeaderName, HeaderName)>,
    response_mode: SubrequestResponseMode,
}

impl SubrequestModule {
    fn new(config: SubrequestModuleConfig) -> Result<Self> {
        if config.allowed_schemes.is_empty() {
            return Err(anyhow!(
                "subrequest {} allowed_schemes must not be empty",
                config.name
            ));
        }
        if config.allowed_hosts.is_empty() {
            return Err(anyhow!(
                "subrequest {} allowed_hosts must not be empty",
                config.name
            ));
        }
        let max_response_bytes = config.max_response_bytes.ok_or_else(|| {
            anyhow!(
                "subrequest {} max_response_bytes must be explicitly set",
                config.name
            )
        })?;
        if max_response_bytes == 0 {
            return Err(anyhow!(
                "subrequest {} max_response_bytes must be >= 1",
                config.name
            ));
        }
        let method = config
            .method
            .as_deref()
            .map(|method| {
                Method::from_bytes(method.trim().as_bytes())
                    .map_err(|_| anyhow!("invalid subrequest method: {method}"))
            })
            .transpose()?
            .unwrap_or(Method::GET);
        let pass_headers = config
            .pass_headers
            .into_iter()
            .map(parse_header_name)
            .collect::<Result<Vec<_>>>()?;
        let request_headers = config
            .request_headers
            .into_iter()
            .map(|(name, value)| {
                let header_name = parse_header_name(name)?;
                let template = compile_template(value.as_str()).with_context(|| {
                    format!("invalid subrequest header template for {header_name}")
                })?;
                Ok((header_name, template))
            })
            .collect::<Result<Vec<_>>>()?;
        let url_template = compile_template(config.url.as_str())
            .with_context(|| format!("invalid subrequest URL template for {}", config.name))?;
        Ok(Self {
            name: Arc::from(config.name),
            phase: config.phase,
            method,
            url_template,
            timeout: config.timeout_ms.map(Duration::from_millis),
            max_response_bytes,
            allowed_schemes: config
                .allowed_schemes
                .into_iter()
                .map(Arc::<str>::from)
                .collect(),
            allowed_hosts: config
                .allowed_hosts
                .into_iter()
                .map(Arc::<str>::from)
                .collect(),
            deny_redirects: config.deny_redirects,
            deny_private_ip_redirects: config.deny_private_ip_redirects,
            pass_headers,
            request_headers,
            copy_to_request: compile_header_captures(config.copy_response_headers_to_request)?,
            copy_to_response: compile_header_captures(config.copy_response_headers_to_response)?,
            response_mode: config
                .response_mode
                .unwrap_or(SubrequestResponseMode::Ignore),
        })
    }

    fn build_subrequest(
        &self,
        ctx: &HttpModuleContext,
        request: &HttpModuleRequestView<'_>,
    ) -> Result<Request<Body>> {
        let url = render_template(&self.url_template, request, ctx)?;
        let uri = self.validate_url(url.as_str())?;
        let mut builder = Request::builder().method(self.method.clone()).uri(uri);
        for header in &self.pass_headers {
            if let Some(value) = request.headers().get(header) {
                builder = builder.header(header, value);
            }
        }
        let mut req = builder.body(Body::empty())?;
        for (name, value_template) in &self.request_headers {
            let value = render_template(value_template, request, ctx)?;
            let value = HeaderValue::from_str(value.as_str())
                .with_context(|| format!("invalid subrequest header value for {name}"))?;
            req.headers_mut().insert(name.clone(), value);
        }
        Ok(req)
    }

    fn validate_url(&self, url: &str) -> Result<http::Uri> {
        let uri: http::Uri = url
            .parse()
            .with_context(|| format!("invalid subrequest URL for {}", self.name))?;
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| anyhow!("subrequest {} URL must include a scheme", self.name))?;
        if !self
            .allowed_schemes
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(scheme))
        {
            return Err(anyhow!(
                "subrequest {} URL scheme is not allowed: {}",
                self.name,
                scheme
            ));
        }
        let host = uri
            .host()
            .ok_or_else(|| anyhow!("subrequest {} URL must include a host", self.name))?;
        if !self
            .allowed_hosts
            .iter()
            .any(|allowed| allowed_host_matches(allowed, host))
        {
            return Err(anyhow!(
                "subrequest {} URL host is not allowed: {}",
                self.name,
                host
            ));
        }
        Ok(uri)
    }

    async fn run_frozen(&self, ctx: &HttpModuleContext) -> Result<Response<Body>> {
        let req = {
            let request = ctx
                .frozen_request()
                .ok_or_else(|| anyhow!("response-phase subrequest missing frozen request"))?;
            self.build_subrequest(ctx, &request)?
        };
        self.run_built_request(ctx, req).await
    }

    async fn run_built_request(
        &self,
        ctx: &HttpModuleContext,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        let future = ctx.send_absolute_request(req);
        let timeout_dur = self.timeout.unwrap_or_else(|| {
            Duration::from_millis(ctx.runtime.plan.limits.upstream_http_timeout_ms)
        });
        let response = timeout(timeout_dur, future)
            .await
            .with_context(|| format!("subrequest {} timed out", self.name))?
            .with_context(|| format!("subrequest {} failed", self.name))?;
        if self.deny_redirects && response.status().is_redirection() {
            return Err(anyhow!("subrequest {} received a redirect", self.name));
        }
        if self.deny_private_ip_redirects && response.status().is_redirection() {
            self.validate_redirect_location(response.headers().get(LOCATION))?;
        }
        if let Some(content_length) = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
        {
            if content_length > self.max_response_bytes {
                return Err(anyhow!(
                    "subrequest {} response exceeds max_response_bytes",
                    self.name
                ));
            }
        }
        let max_response_bytes = self.max_response_bytes;
        let name = self.name.clone();
        Ok(response.map(move |body| {
            limit_subrequest_response_body(body, max_response_bytes, timeout_dur, name)
        }))
    }

    fn validate_redirect_location(&self, location: Option<&HeaderValue>) -> Result<()> {
        let Some(location) = location else {
            return Ok(());
        };
        let location = location
            .to_str()
            .with_context(|| format!("subrequest {} redirect Location is invalid", self.name))?;
        let Ok(uri) = location.parse::<http::Uri>() else {
            return Ok(());
        };
        if uri.scheme().is_none() && uri.host().is_none() {
            return Ok(());
        }
        self.validate_url(location)?;
        let Some(host) = uri.host() else {
            return Ok(());
        };
        if redirect_host_is_private_ip(host) {
            return Err(anyhow!(
                "subrequest {} redirect Location points to a private IP: {}",
                self.name,
                host
            ));
        }
        if redirect_host_resolves_to_private_ip(&uri, host) {
            return Err(anyhow!(
                "subrequest {} redirect Location resolves to a private IP: {}",
                self.name,
                host
            ));
        }
        Ok(())
    }

    fn should_return_response(&self, response: &Response<Body>) -> bool {
        match self.response_mode {
            SubrequestResponseMode::Ignore => false,
            SubrequestResponseMode::ReturnAlways => true,
            SubrequestResponseMode::ReturnOnError => !response.status().is_success(),
        }
    }

    fn apply_request_response_headers(
        &self,
        subresponse: &Response<Body>,
        ctx: &mut HttpModuleContext,
        req: &mut Request<Body>,
    ) {
        for (from, to) in &self.copy_to_request {
            if let Some(value) = subresponse.headers().get(from) {
                req.headers_mut().insert(to.clone(), value.clone());
                ctx.remember_request_header(to.clone(), value.clone());
            }
        }
        for (from, to) in &self.copy_to_response {
            if let Some(value) = subresponse.headers().get(from) {
                ctx.queue_response_header(to.clone(), value.clone());
            }
        }
    }

    fn apply_response_headers(
        &self,
        subresponse: &Response<Body>,
        ctx: &mut HttpModuleContext,
        response: &mut Response<Body>,
    ) {
        for (from, to) in &self.copy_to_request {
            if let Some(value) = subresponse.headers().get(from) {
                ctx.remember_request_header(to.clone(), value.clone());
            }
        }
        for (from, to) in &self.copy_to_response {
            if let Some(value) = subresponse.headers().get(from) {
                response.headers_mut().insert(to.clone(), value.clone());
            }
        }
    }
}

#[async_trait]
impl HttpModule for SubrequestModule {
    fn capabilities(&self) -> HttpModuleCapabilities {
        match self.phase {
            SubrequestPhase::RequestHeaders => {
                let mut capabilities =
                    HttpModuleCapabilities::headers_only(ModuleStages::REQUEST_HEADERS);
                capabilities.mutates_request_headers = true;
                capabilities.mutates_response_headers = !self.copy_to_response.is_empty();
                capabilities.may_short_circuit =
                    !matches!(self.response_mode, SubrequestResponseMode::Ignore);
                capabilities
            }
            SubrequestPhase::ResponseHeaders => {
                let mut capabilities =
                    HttpModuleCapabilities::headers_only(ModuleStages::DOWNSTREAM_RESPONSE);
                capabilities.mutates_request_headers = !self.copy_to_request.is_empty();
                capabilities.mutates_response_headers = true;
                capabilities.may_short_circuit =
                    !matches!(self.response_mode, SubrequestResponseMode::Ignore);
                capabilities.needs_frozen_request = true;
                capabilities
            }
        }
    }

    fn explain(&self) -> Vec<String> {
        vec![
            format!("template: {}", self.url_template.summary()),
            format!("allowed_schemes: {}", self.allowed_schemes.join(",")),
            format!("allowed_hosts: {}", self.allowed_hosts.join(",")),
            format!(
                "redirect_policy: deny_redirects={}, deny_private_ip_redirects={}",
                self.deny_redirects, self.deny_private_ip_redirects
            ),
            format!("max_response_bytes: {}", self.max_response_bytes),
        ]
    }

    async fn call<'a>(
        &self,
        stage: HttpModuleStage,
        ctx: &mut HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> Result<HttpModuleEvent<'a>> {
        match stage {
            HttpModuleStage::RequestHeaders => {
                let HttpModuleEvent::RequestHeaders(request) = event else {
                    return Err(anyhow!("subrequest received invalid request_headers event"));
                };
                if !matches!(self.phase, SubrequestPhase::RequestHeaders) {
                    return Ok(HttpModuleEvent::RequestHeadersResult(
                        RequestHeadersOutcome::Continue,
                    ));
                }
                let subrequest = {
                    let request_view = HttpModuleRequestView::from_request(request);
                    self.build_subrequest(ctx, &request_view)?
                };
                let subresponse = self.run_built_request(ctx, subrequest).await?;
                if self.should_return_response(&subresponse) {
                    return Ok(HttpModuleEvent::RequestHeadersResult(
                        RequestHeadersOutcome::Respond(Box::new(subresponse)),
                    ));
                }
                self.apply_request_response_headers(&subresponse, ctx, request);
                Ok(HttpModuleEvent::RequestHeadersResult(
                    RequestHeadersOutcome::Continue,
                ))
            }
            HttpModuleStage::DownstreamResponse => {
                let HttpModuleEvent::DownstreamResponse(mut response) = event else {
                    return Err(anyhow!(
                        "subrequest received invalid downstream_response event"
                    ));
                };
                if !matches!(self.phase, SubrequestPhase::ResponseHeaders) {
                    return Ok(HttpModuleEvent::DownstreamResponse(response));
                }
                let subresponse = self.run_frozen(ctx).await?;
                if self.should_return_response(&subresponse) {
                    return Ok(HttpModuleEvent::DownstreamResponse(subresponse));
                }
                self.apply_response_headers(&subresponse, ctx, &mut response);
                Ok(HttpModuleEvent::DownstreamResponse(response))
            }
            _ => Ok(event),
        }
    }
}

fn limit_subrequest_response_body(
    mut body: Body,
    max_response_bytes: usize,
    body_read_timeout: Duration,
    name: Arc<str>,
) -> Body {
    let (mut sender, out) = Body::channel();
    tokio::spawn(async move {
        let result: Result<()> = async {
            let mut seen = 0usize;
            loop {
                let chunk = tokio::select! {
                    _ = sender.closed() => return Ok(()),
                    chunk = timeout(body_read_timeout, body.data()) => match chunk {
                        Ok(chunk) => chunk,
                        Err(_) => return Err(anyhow!("subrequest {name} response body read timed out")),
                    },
                };
                let Some(chunk) = chunk else {
                    break;
                };
                let chunk = chunk?;
                seen = seen
                    .checked_add(chunk.len())
                    .ok_or_else(|| anyhow!("subrequest {name} response body length overflow"))?;
                if seen > max_response_bytes {
                    return Err(anyhow!(
                        "subrequest {name} response exceeds max_response_bytes"
                    ));
                }
                if sender.is_closed() {
                    return Ok(());
                }
                sender.send_data(chunk).await?;
            }
            let trailers = tokio::select! {
                _ = sender.closed() => return Ok(()),
                trailers = timeout(body_read_timeout, body.trailers()) => match trailers {
                    Ok(trailers) => trailers?,
                    Err(_) => return Err(anyhow!("subrequest {name} response trailers read timed out")),
                },
            };
            if let Some(trailers) = trailers {
                sender.send_trailers(trailers).await?;
            }
            Ok(())
        }
        .await;
        if let Err(err) = result {
            warn!(
                error = ?err,
                subrequest = name.as_ref(),
                "subrequest response body limit failed"
            );
            sender.abort();
        }
    });
    out
}

fn parse_module_settings<T>(spec: &HttpModuleConfig) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    spec.parse_settings()
        .with_context(|| format!("invalid settings for http module {}", spec.r#type))
}

fn allowed_host_matches(pattern: &str, host: &str) -> bool {
    pattern.eq_ignore_ascii_case(host)
        || pattern == "*"
        || pattern
            .strip_prefix("*.")
            .map(|suffix| host.ends_with(suffix))
            .unwrap_or(false)
}

fn redirect_host_is_private_ip(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.octets()[0] == 0
        }
        Ok(IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
        }
        Err(_) => false,
    }
}

fn redirect_host_resolves_to_private_ip(uri: &http::Uri, host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    let port = uri
        .port_u16()
        .or_else(|| match uri.scheme_str() {
            Some("https") => Some(443),
            Some("http") => Some(80),
            _ => None,
        })
        .unwrap_or(80);
    (host, port)
        .to_socket_addrs()
        .map(|mut addrs| addrs.any(|addr| redirect_ip_is_private(addr.ip())))
        .unwrap_or(false)
}

fn redirect_ip_is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.octets()[0] == 0
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledTemplate {
    parts: Arc<[TemplatePart]>,
}

impl CompiledTemplate {
    fn summary(&self) -> String {
        self.parts
            .iter()
            .map(TemplatePart::summary)
            .collect::<Vec<_>>()
            .join("")
    }
}

#[derive(Debug, Clone)]
enum TemplatePart {
    Literal(Arc<str>),
    Placeholder {
        variable: TemplateVariable,
        modifier: TemplateModifier,
    },
}

impl TemplatePart {
    fn summary(&self) -> String {
        match self {
            TemplatePart::Literal(value) => value.to_string(),
            TemplatePart::Placeholder { variable, modifier } => {
                format!("{{{}:{}}}", variable.summary(), modifier.summary())
            }
        }
    }
}

#[derive(Debug, Clone)]
enum TemplateVariable {
    ProxyKind,
    ProxyName,
    ScopeName,
    RouteName,
    RequestMethod,
    RequestUri,
    RequestScheme,
    RequestHost,
    RequestSni,
    RequestPath,
    RequestQuery,
    RequestQueryKey(Arc<str>),
    RequestHeader(HeaderName),
    RequestAuthority,
    RemoteIp,
    IdentityUser,
    ResponseStatus,
}

impl TemplateVariable {
    fn summary(&self) -> String {
        match self {
            TemplateVariable::ProxyKind => "proxy.kind".to_string(),
            TemplateVariable::ProxyName => "proxy.name".to_string(),
            TemplateVariable::ScopeName => "scope.name".to_string(),
            TemplateVariable::RouteName => "route.name".to_string(),
            TemplateVariable::RequestMethod => "request.method".to_string(),
            TemplateVariable::RequestUri => "request.uri".to_string(),
            TemplateVariable::RequestScheme => "request.scheme".to_string(),
            TemplateVariable::RequestHost => "request.host".to_string(),
            TemplateVariable::RequestSni => "request.sni".to_string(),
            TemplateVariable::RequestPath => "request.path".to_string(),
            TemplateVariable::RequestQuery => "request.query".to_string(),
            TemplateVariable::RequestQueryKey(key) => format!("request.query.{key}"),
            TemplateVariable::RequestHeader(name) => format!("request.header.{name}"),
            TemplateVariable::RequestAuthority => "request.authority".to_string(),
            TemplateVariable::RemoteIp => "remote.ip".to_string(),
            TemplateVariable::IdentityUser => "identity.user".to_string(),
            TemplateVariable::ResponseStatus => "response.status".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum TemplateModifier {
    UrlQuery,
    PathSegment,
    Header,
    Host,
}

impl TemplateModifier {
    fn summary(self) -> &'static str {
        match self {
            TemplateModifier::UrlQuery => "urlquery",
            TemplateModifier::PathSegment => "pathsegment",
            TemplateModifier::Header => "header",
            TemplateModifier::Host => "host",
        }
    }
}

fn compile_template(template: &str) -> Result<CompiledTemplate> {
    let mut parts = Vec::new();
    let mut rest = template;
    loop {
        let Some(open) = rest.find('{') else {
            if !rest.is_empty() {
                parts.push(TemplatePart::Literal(Arc::from(rest)));
            }
            break;
        };
        if open > 0 {
            parts.push(TemplatePart::Literal(Arc::from(&rest[..open])));
        }
        let after_open = &rest[open + 1..];
        let close = after_open
            .find('}')
            .ok_or_else(|| anyhow!("template placeholder is missing closing '}}'"))?;
        let placeholder = &after_open[..close];
        let (variable, modifier) = parse_template_placeholder(placeholder)?;
        parts.push(TemplatePart::Placeholder { variable, modifier });
        rest = &after_open[close + 1..];
    }
    Ok(CompiledTemplate {
        parts: parts.into(),
    })
}

fn parse_template_placeholder(placeholder: &str) -> Result<(TemplateVariable, TemplateModifier)> {
    let (variable, modifier) = placeholder.split_once(':').ok_or_else(|| {
        anyhow!("template placeholder {{{placeholder}}} must include an explicit modifier")
    })?;
    let variable = match variable {
        "proxy.kind" => TemplateVariable::ProxyKind,
        "proxy.name" => TemplateVariable::ProxyName,
        "scope.name" => TemplateVariable::ScopeName,
        "route.name" => TemplateVariable::RouteName,
        "request.method" => TemplateVariable::RequestMethod,
        "request.uri" => TemplateVariable::RequestUri,
        "request.scheme" => TemplateVariable::RequestScheme,
        "request.host" => TemplateVariable::RequestHost,
        "request.sni" => TemplateVariable::RequestSni,
        "request.path" => TemplateVariable::RequestPath,
        "request.query" => TemplateVariable::RequestQuery,
        "request.authority" => TemplateVariable::RequestAuthority,
        "remote.ip" => TemplateVariable::RemoteIp,
        "identity.user" => TemplateVariable::IdentityUser,
        "response.status" => TemplateVariable::ResponseStatus,
        _ if variable.starts_with("request.header.") => {
            let name = variable
                .strip_prefix("request.header.")
                .expect("prefix checked");
            TemplateVariable::RequestHeader(parse_header_name(name)?)
        }
        _ if variable.starts_with("request.query.") => {
            let name = variable
                .strip_prefix("request.query.")
                .expect("prefix checked");
            if name.is_empty() {
                return Err(anyhow!("request.query placeholder key must not be empty"));
            }
            TemplateVariable::RequestQueryKey(Arc::from(name))
        }
        _ => return Err(anyhow!("unknown template placeholder variable: {variable}")),
    };
    let modifier = match modifier {
        "raw" => return Err(anyhow!("raw template expansion is not allowed")),
        "urlquery" => TemplateModifier::UrlQuery,
        "pathsegment" => TemplateModifier::PathSegment,
        "header" => TemplateModifier::Header,
        "host" => TemplateModifier::Host,
        _ => return Err(anyhow!("unknown template placeholder modifier: {modifier}")),
    };
    Ok((variable, modifier))
}

fn render_template(
    template: &CompiledTemplate,
    request: &HttpModuleRequestView<'_>,
    ctx: &HttpModuleContext,
) -> Result<String> {
    let remote_ip = ctx.remote_ip().to_string();
    let response_status = ctx
        .response_status()
        .map(|status| status.as_str().to_string())
        .unwrap_or_default();
    let request_uri = request.uri_string();
    let mut out = String::new();
    for part in template.parts.iter() {
        match part {
            TemplatePart::Literal(value) => out.push_str(value),
            TemplatePart::Placeholder { variable, modifier } => {
                let value = match variable {
                    TemplateVariable::ProxyKind => ctx.proxy_kind(),
                    TemplateVariable::ProxyName => ctx.proxy_name(),
                    TemplateVariable::ScopeName => ctx.scope_name(),
                    TemplateVariable::RouteName => ctx.route_name().unwrap_or_default(),
                    TemplateVariable::RequestMethod => request.method().as_str(),
                    TemplateVariable::RequestUri => request_uri.as_ref(),
                    TemplateVariable::RequestScheme => request.scheme().unwrap_or_default(),
                    TemplateVariable::RequestHost => request.host().unwrap_or_default(),
                    TemplateVariable::RequestSni => ctx.sni().unwrap_or_default(),
                    TemplateVariable::RequestPath => request.path(),
                    TemplateVariable::RequestQuery => request.query().unwrap_or_default(),
                    TemplateVariable::RequestQueryKey(key) => {
                        let value = request
                            .query()
                            .and_then(|query| query_value(query, key.as_ref()))
                            .unwrap_or_default();
                        push_template_value(&mut out, value.as_ref(), *modifier)?;
                        continue;
                    }
                    TemplateVariable::RequestHeader(name) => {
                        let value = request
                            .headers()
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default();
                        push_template_value(&mut out, value, *modifier)?;
                        continue;
                    }
                    TemplateVariable::RequestAuthority => request.authority().unwrap_or_default(),
                    TemplateVariable::RemoteIp => remote_ip.as_str(),
                    TemplateVariable::IdentityUser => ctx.identity_user().unwrap_or_default(),
                    TemplateVariable::ResponseStatus => response_status.as_str(),
                };
                push_template_value(&mut out, value, *modifier)?;
            }
        }
    }
    Ok(out)
}

fn push_template_value(out: &mut String, value: &str, modifier: TemplateModifier) -> Result<()> {
    match modifier {
        TemplateModifier::UrlQuery | TemplateModifier::PathSegment => {
            out.push_str(
                utf8_percent_encode(value, NON_ALPHANUMERIC)
                    .to_string()
                    .as_str(),
            );
        }
        TemplateModifier::Header => {
            if value.as_bytes().iter().any(|byte| byte.is_ascii_control()) {
                return Err(anyhow!(
                    "template header value contains a control character"
                ));
            }
            HeaderValue::from_str(value)
                .with_context(|| format!("invalid template header value: {value}"))?;
            out.push_str(value);
        }
        TemplateModifier::Host => {
            validate_template_host(value)?;
            out.push_str(value);
        }
    }
    Ok(())
}

fn query_value(query: &str, key: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes())
        .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
}

fn validate_template_host(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(anyhow!("template host value must not be empty"));
    }
    if value.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if value.as_bytes().iter().any(|byte| byte.is_ascii_control())
        || value.contains(['/', '?', '#', '@', ':'])
    {
        return Err(anyhow!("template host value contains invalid characters"));
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(anyhow!("template host value is not a valid host name"));
        }
    }
    Ok(())
}

fn compile_header_captures(
    captures: Vec<HeaderCaptureConfig>,
) -> Result<Vec<(HeaderName, HeaderName)>> {
    captures
        .into_iter()
        .map(|capture| {
            Ok((
                parse_header_name(capture.from)?,
                parse_header_name(capture.to)?,
            ))
        })
        .collect()
}

fn compile_literal_headers(
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
    use qpx_core::config::{
        AccessLogConfig, AuditLogConfig, AuthConfig, Config, IdentityConfig, MessagesConfig,
        RuntimeConfig, SystemLogConfig,
    };
    use std::str::FromStr;

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
                remote_ip: IpAddr::from_str("127.0.0.1").expect("ip"),
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

        assert!(err
            .to_string()
            .contains("must include an explicit modifier"));
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
        assert!(modifier
            .to_string()
            .contains("unknown template placeholder modifier"));

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
        let frozen = ctx.session.request.as_ref().expect("frozen request");
        assert_eq!(
            frozen.headers.get("x-module"),
            Some(&HeaderValue::from_static("changed"))
        );
    }
}
