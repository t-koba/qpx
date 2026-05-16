use super::{
    CacheLookupStatus, CompiledHttpModuleChain, HttpModuleEvent, HttpModuleStage,
    RequestHeadersOutcome, RetryEvent,
};
use crate::cache::{CacheRequestKey, purge_cache_key};
use crate::http::body::Body;
use crate::http::dispatch::ProxyKind;
use crate::runtime::RuntimeState;
use crate::upstream::origin::{OriginEndpoint, proxy_http};
use anyhow::{Context, Result, anyhow};
use http::header::HOST;
use http::{Extensions, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};
use hyper::{Request, Response};
use qpx_core::config::CachePolicyConfig;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::warn;

pub(crate) struct HttpModuleSessionInit<'a> {
    pub(crate) proxy_kind: ProxyKind,
    pub(crate) proxy_name: &'a str,
    pub(crate) scope_name: &'a str,
    pub(crate) route_name: Option<&'a str>,
    pub(crate) remote_ip: IpAddr,
    pub(crate) sni: Option<&'a str>,
    pub(crate) identity_user: Option<&'a str>,
    pub(crate) cache_policy: Option<CachePolicyConfig>,
    pub(crate) cache_default_scheme: Option<&'a str>,
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
    proxy_kind: ProxyKind,
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
    fn new(init: HttpModuleSessionInit<'_>) -> Self {
        Self {
            proxy_kind: init.proxy_kind,
            proxy_name: init.proxy_name.to_string(),
            scope_name: init.scope_name.to_string(),
            route_name: init.route_name.map(str::to_string),
            remote_ip: init.remote_ip,
            sni: init.sni.map(str::to_string),
            identity_user: init.identity_user.map(str::to_string),
            request: None,
            response_status: None,
            cache_policy: init.cache_policy,
            cache_default_scheme: init.cache_default_scheme.map(str::to_string),
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
    pub(super) fn new(runtime: Arc<RuntimeState>, init: HttpModuleSessionInit<'_>) -> Self {
        Self {
            runtime,
            session: HttpModuleSession::new(init),
        }
    }

    pub(super) fn sync_frozen_request(&mut self, req: &Request<Body>) -> bool {
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

    pub(super) fn remember_request_header(&mut self, name: HeaderName, value: HeaderValue) {
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
        self.session.proxy_kind.as_str()
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

    pub(super) fn runtime_state(&self) -> &RuntimeState {
        &self.runtime
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
    pub(super) fn new(chain: CompiledHttpModuleChain, context: HttpModuleContext) -> Self {
        Self { chain, context }
    }

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
