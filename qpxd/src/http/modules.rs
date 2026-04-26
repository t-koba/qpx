use crate::cache::purge_cache_key;
use crate::cache::CacheRequestKey;
mod response_compression;

use crate::http::body::Body;
use crate::runtime::RuntimeState;
use crate::upstream::origin::{proxy_http, OriginEndpoint};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use http::header::HOST;
use http::{Extensions, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};
use hyper::{Request, Response};
use qpx_core::config::{
    CachePolicyConfig, CachePurgeModuleConfig, HeaderCaptureConfig, HttpModuleConfig,
    SubrequestModuleConfig, SubrequestPhase, SubrequestResponseMode,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use tokio::time::{timeout, Duration};

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

pub enum RequestHeadersOutcome {
    Continue,
    Respond(Box<Response<Body>>),
}

#[async_trait]
pub trait HttpModule: Send + Sync {
    fn order(&self) -> i16 {
        0
    }

    async fn on_request_headers(
        &self,
        _ctx: &mut HttpModuleContext,
        _request: &mut Request<Body>,
    ) -> Result<RequestHeadersOutcome> {
        Ok(RequestHeadersOutcome::Continue)
    }

    async fn on_cache_lookup(
        &self,
        _ctx: &mut HttpModuleContext,
        _status: CacheLookupStatus,
    ) -> Result<()> {
        Ok(())
    }

    async fn on_upstream_request(
        &self,
        _ctx: &mut HttpModuleContext,
        _request: &mut Request<Body>,
    ) -> Result<()> {
        Ok(())
    }

    async fn on_upstream_response(
        &self,
        _ctx: &mut HttpModuleContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        Ok(response)
    }

    async fn on_downstream_response(
        &self,
        _ctx: &mut HttpModuleContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        Ok(response)
    }

    async fn on_retry(&self, _ctx: &mut HttpModuleContext, _event: RetryEvent<'_>) -> Result<()> {
        Ok(())
    }

    fn on_error(&self, _ctx: &mut HttpModuleContext, _err: &anyhow::Error) {}

    fn on_log(
        &self,
        _ctx: &mut HttpModuleContext,
        _response: Option<&Response<Body>>,
        _err: Option<&anyhow::Error>,
    ) {
    }
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
}

#[derive(Clone)]
pub(crate) struct CompiledHttpModuleChain {
    modules: Arc<[CompiledHttpModule]>,
}

impl Default for CompiledHttpModuleChain {
    fn default() -> Self {
        Self {
            modules: Vec::<CompiledHttpModule>::new().into(),
        }
    }
}

impl CompiledHttpModuleChain {
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
    Ok(Arc::new(CompiledHttpModuleChain {
        modules: modules.into_iter().map(|(_, _, module)| module).collect(),
    }))
}

pub(crate) struct HttpModuleSessionInit {
    pub(crate) proxy_kind: &'static str,
    pub(crate) proxy_name: String,
    pub(crate) scope_name: String,
    pub(crate) route_name: Option<String>,
    pub(crate) remote_ip: IpAddr,
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
        for module in self.chain.modules.iter() {
            match module
                .module
                .on_request_headers(&mut self.context, req)
                .await
                .with_context(|| {
                    format!("http module {} on_request_headers failed", module.label())
                })? {
                RequestHeadersOutcome::Continue => {}
                RequestHeadersOutcome::Respond(response) => {
                    self.context.sync_frozen_request(req);
                    return Ok(RequestHeadersOutcome::Respond(response));
                }
            }
        }
        self.context.sync_frozen_request(req);
        Ok(RequestHeadersOutcome::Continue)
    }

    pub(crate) async fn on_cache_lookup(&mut self, hit: bool) -> Result<()> {
        let status = if hit {
            CacheLookupStatus::Hit
        } else {
            CacheLookupStatus::Miss
        };
        for module in self.chain.modules.iter() {
            module
                .module
                .on_cache_lookup(&mut self.context, status)
                .await
                .with_context(|| {
                    format!("http module {} on_cache_lookup failed", module.label())
                })?;
        }
        Ok(())
    }

    pub(crate) async fn on_upstream_request(&mut self, req: &mut Request<Body>) -> Result<()> {
        for module in self.chain.modules.iter() {
            module
                .module
                .on_upstream_request(&mut self.context, req)
                .await
                .with_context(|| {
                    format!("http module {} on_upstream_request failed", module.label())
                })?;
        }
        self.context.sync_frozen_request(req);
        Ok(())
    }

    pub(crate) async fn on_upstream_response(
        &mut self,
        mut response: Response<Body>,
    ) -> Result<Response<Body>> {
        self.context.set_response_status(response.status());
        self.context
            .apply_pending_response_headers(response.headers_mut());
        for module in self.chain.modules.iter() {
            response = module
                .module
                .on_upstream_response(&mut self.context, response)
                .await
                .with_context(|| {
                    format!("http module {} on_upstream_response failed", module.label())
                })?;
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
        for module in self.chain.modules.iter() {
            response = module
                .module
                .on_downstream_response(&mut self.context, response)
                .await
                .with_context(|| {
                    format!(
                        "http module {} on_downstream_response failed",
                        module.label()
                    )
                })?;
            self.context.set_response_status(response.status());
            self.context
                .apply_pending_response_headers(response.headers_mut());
        }
        Ok(response)
    }

    pub(crate) async fn on_retry(&mut self, attempt: usize, reason: &str) -> Result<()> {
        let event = RetryEvent { attempt, reason };
        for module in self.chain.modules.iter() {
            module
                .module
                .on_retry(&mut self.context, event)
                .await
                .with_context(|| format!("http module {} on_retry failed", module.label()))?;
        }
        Ok(())
    }

    pub(crate) fn on_error(&mut self, err: &anyhow::Error) {
        for module in self.chain.modules.iter() {
            module.module.on_error(&mut self.context, err);
        }
    }

    pub(crate) fn on_logging(
        &mut self,
        response: Option<&Response<Body>>,
        err: Option<&anyhow::Error>,
    ) {
        if let Some(response) = response {
            self.context.set_response_status(response.status());
        }
        for module in self.chain.modules.iter() {
            module.module.on_log(&mut self.context, response, err);
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

    async fn on_request_headers(
        &self,
        ctx: &mut HttpModuleContext,
        request: &mut Request<Body>,
    ) -> Result<RequestHeadersOutcome> {
        if !self.matches(request.method()) {
            return Ok(RequestHeadersOutcome::Continue);
        }
        if let Some(key) = ctx.cache_request_key(request)? {
            let _ = ctx.purge_cache_key(&key).await?;
        }
        Ok(RequestHeadersOutcome::Respond(Box::new(
            self.build_response(),
        )))
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
    url_template: Arc<str>,
    timeout: Option<Duration>,
    pass_headers: Vec<HeaderName>,
    request_headers: Vec<(HeaderName, Arc<str>)>,
    copy_to_request: Vec<(HeaderName, HeaderName)>,
    copy_to_response: Vec<(HeaderName, HeaderName)>,
    response_mode: SubrequestResponseMode,
}

impl SubrequestModule {
    fn new(config: SubrequestModuleConfig) -> Result<Self> {
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
            .map(|(name, value)| Ok((parse_header_name(name)?, Arc::<str>::from(value))))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            name: Arc::from(config.name),
            phase: config.phase,
            method,
            url_template: Arc::from(config.url),
            timeout: config.timeout_ms.map(Duration::from_millis),
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
        let url = render_template(self.url_template.as_ref(), request, ctx);
        let mut builder = Request::builder()
            .method(self.method.clone())
            .uri(url.as_str());
        for header in &self.pass_headers {
            if let Some(value) = request.headers().get(header) {
                builder = builder.header(header, value);
            }
        }
        let mut req = builder.body(Body::empty())?;
        for (name, value_template) in &self.request_headers {
            let value = render_template(value_template.as_ref(), request, ctx);
            let value = HeaderValue::from_str(value.as_str())
                .with_context(|| format!("invalid subrequest header value for {name}"))?;
            req.headers_mut().insert(name.clone(), value);
        }
        Ok(req)
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
            Duration::from_millis(ctx.runtime.config.runtime.upstream_http_timeout_ms)
        });
        timeout(timeout_dur, future)
            .await
            .with_context(|| format!("subrequest {} timed out", self.name))?
            .with_context(|| format!("subrequest {} failed", self.name))
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
    async fn on_request_headers(
        &self,
        ctx: &mut HttpModuleContext,
        request: &mut Request<Body>,
    ) -> Result<RequestHeadersOutcome> {
        if !matches!(self.phase, SubrequestPhase::RequestHeaders) {
            return Ok(RequestHeadersOutcome::Continue);
        }
        let subrequest = {
            let request_view = HttpModuleRequestView::from_request(request);
            self.build_subrequest(ctx, &request_view)?
        };
        let subresponse = self.run_built_request(ctx, subrequest).await?;
        if self.should_return_response(&subresponse) {
            return Ok(RequestHeadersOutcome::Respond(Box::new(subresponse)));
        }
        self.apply_request_response_headers(&subresponse, ctx, request);
        Ok(RequestHeadersOutcome::Continue)
    }

    async fn on_downstream_response(
        &self,
        ctx: &mut HttpModuleContext,
        mut response: Response<Body>,
    ) -> Result<Response<Body>> {
        if !matches!(self.phase, SubrequestPhase::ResponseHeaders) {
            return Ok(response);
        }
        let subresponse = self.run_frozen(ctx).await?;
        if self.should_return_response(&subresponse) {
            return Ok(subresponse);
        }
        self.apply_response_headers(&subresponse, ctx, &mut response);
        Ok(response)
    }
}

fn parse_module_settings<T>(spec: &HttpModuleConfig) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    spec.parse_settings()
        .with_context(|| format!("invalid settings for http module {}", spec.r#type))
}

fn render_template(
    template: &str,
    request: &HttpModuleRequestView<'_>,
    ctx: &HttpModuleContext,
) -> String {
    let remote_ip = ctx.remote_ip().to_string();
    let response_status = ctx
        .response_status()
        .map(|status| status.as_str().to_string())
        .unwrap_or_default();
    let request_uri = request.uri_string();
    let mut out = template.to_string();
    for (token, value) in [
        ("{proxy.kind}", ctx.proxy_kind()),
        ("{proxy.name}", ctx.proxy_name()),
        ("{scope.name}", ctx.scope_name()),
        ("{route.name}", ctx.route_name().unwrap_or_default()),
        ("{request.method}", request.method().as_str()),
        ("{request.uri}", request_uri.as_ref()),
        ("{request.scheme}", request.scheme().unwrap_or_default()),
        ("{request.host}", request.host().unwrap_or_default()),
        ("{request.path}", request.path()),
        ("{request.query}", request.query().unwrap_or_default()),
        (
            "{request.authority}",
            request.authority().unwrap_or_default(),
        ),
        ("{remote.ip}", remote_ip.as_str()),
        ("{response.status}", response_status.as_str()),
    ] {
        out = out.replace(token, value);
    }
    out
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
        AccessLogConfig, AuditLogConfig, AuthConfig, CacheConfig, Config, IdentityConfig,
        MessagesConfig, RuntimeConfig, SystemLogConfig,
    };
    use std::str::FromStr;

    fn module_test_runtime() -> Runtime {
        Runtime::new(Config {
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
            named_sets: Vec::new(),
            http_guard_profiles: Vec::new(),
            rate_limit_profiles: Vec::new(),
            upstream_trust_profiles: Vec::new(),
            listeners: Vec::new(),
            reverse: Vec::new(),
            upstreams: Vec::new(),
            cache: CacheConfig::default(),
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
                cache_policy: None,
                cache_default_scheme: None,
            },
        )
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
