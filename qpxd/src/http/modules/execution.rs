#[path = "subrequest/mod.rs"]
pub(super) mod subrequest;
#[path = "template.rs"]
pub(super) mod template;

use super::Body as ModuleBody;
use super::{
    CacheLookupStatus, CompiledHttpModuleChain, HttpModuleEvent, HttpModuleStage,
    RequestHeadersOutcome, RetryEvent,
};
use crate::http::dispatch::ProxyKind;
use crate::http::response_carrier::ResponseCarrier;
use crate::runtime::RuntimeState;
use crate::upstream::origin::{OriginEndpoint, proxy_http};
use anyhow::{Context, Result, anyhow};
use http::header::HOST;
use http::{Extensions, HeaderName, HeaderValue, Method, StatusCode, Version};
use hyper::Response;
use qpx_core::config::CachePolicyConfig;
use qpx_core::http_message::{
    Headers, OrdinaryHeaderName, Request as OwnerRequest, Response as OwnerResponse,
};
use qpx_http::body::Body;
use qpxd_cache::{CacheRequestKey, purge_cache_key};
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
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
    headers: Headers,
}

impl FrozenRequestSnapshot {
    fn from_request(req: &OwnerRequest<Body>) -> Self {
        Self {
            method: req.method().clone(),
            version: req.version(),
            uri: req.uri().clone(),
            headers: req.headers().clone(),
        }
    }

    fn matches_request(&self, req: &OwnerRequest<Body>) -> bool {
        self.method == *req.method()
            && self.version == req.version()
            && self.uri == *req.uri()
            && self.headers == *req.headers()
    }
}

/// A semantic view of an HTTP module request. Raw headers are intentionally private.
///
/// ```compile_fail
/// use qpxd::module_api::HttpModuleRequestView;
/// fn cannot_read_raw_headers(view: &HttpModuleRequestView<'_>) {
///     let _ = view.headers();
/// }
/// ```
pub struct HttpModuleRequestView<'a> {
    method: &'a Method,
    version: Version,
    uri: &'a http::Uri,
    headers: &'a Headers,
}

impl<'a> HttpModuleRequestView<'a> {
    /// Borrows only the head of a caller-owned request, independent of its body type.
    pub fn from_request<B>(request: &'a OwnerRequest<B>) -> Self {
        Self {
            method: request.method(),
            version: request.version(),
            uri: request.uri(),
            headers: request.headers(),
        }
    }

    fn from_frozen(request: &'a FrozenRequestSnapshot) -> Self {
        Self {
            method: &request.method,
            version: request.version,
            uri: &request.uri,
            headers: &request.headers,
        }
    }

    pub fn method(&self) -> &Method {
        self.method
    }
    pub fn version(&self) -> Version {
        self.version
    }
    pub fn scheme(&self) -> Option<&str> {
        self.uri.scheme_str()
    }
    pub fn host(&self) -> Option<&str> {
        self.uri.host().or_else(|| {
            self.headers
                .get(&OrdinaryHeaderName::try_from(HOST).expect("ordinary host"))
                .and_then(|value| value.to_str().ok())
        })
    }
    pub fn path(&self) -> &str {
        self.uri.path()
    }
    pub fn query(&self) -> Option<&str> {
        self.uri.query()
    }
    pub fn authority(&self) -> Option<&str> {
        self.uri.authority().map(|value| value.as_str())
    }
    fn headers(&self) -> &Headers {
        self.headers
    }
    /// Returns whether this request contains the named header.
    pub fn has_header(&self, name: &HeaderName) -> bool {
        match OrdinaryHeaderName::try_from(name.clone()) {
            Ok(name) => self.headers.contains_key(&name),
            Err(_) => self.headers.contains_content_length(),
        }
    }
    pub fn uri(&self) -> &http::Uri {
        self.uri
    }
    pub fn uri_string(&self) -> Cow<'_, str> {
        Cow::Owned(self.uri.to_string())
    }
}

/// An opaque borrowed view of a downstream response for module predicates.
///
/// Raw headers are intentionally private.
///
/// ```compile_fail
/// use qpxd::module_api::HttpModuleResponseView;
/// fn cannot_read_raw_headers(view: &HttpModuleResponseView<'_>) {
///     let _ = view.headers();
/// }
/// ```
pub struct HttpModuleResponseView<'a> {
    response: ResponseViewInner<'a>,
}

enum ResponseViewInner<'a> {
    Standard(&'a Response<Body>),
    Owned(&'a OwnerResponse<Body>),
}

impl<'a> HttpModuleResponseView<'a> {
    pub(super) fn from_response(response: &'a Response<Body>) -> Self {
        Self {
            response: ResponseViewInner::Standard(response),
        }
    }

    /// Returns the response status.
    pub fn status(&self) -> StatusCode {
        match self.response {
            ResponseViewInner::Standard(response) => response.status(),
            ResponseViewInner::Owned(response) => response.status(),
        }
    }

    /// Returns the response HTTP version.
    pub fn version(&self) -> Version {
        match self.response {
            ResponseViewInner::Standard(response) => response.version(),
            ResponseViewInner::Owned(response) => response.version(),
        }
    }

    /// Returns whether this response contains the named header.
    pub fn has_header(&self, name: &HeaderName) -> bool {
        match self.response {
            ResponseViewInner::Standard(response) => response.headers().contains_key(name),
            ResponseViewInner::Owned(response) => {
                match OrdinaryHeaderName::try_from(name.clone()) {
                    Ok(name) => response.headers().contains_key(&name),
                    Err(_) => response.headers().contains_content_length(),
                }
            }
        }
    }
}

/// Private bridge for the single downstream hook. Conversions happen only
/// when an applicable module is actually called, never for predicate checks.
pub(crate) trait DownstreamResponse: ResponseCarrier {
    fn module_view(&self) -> HttpModuleResponseView<'_>;
    fn insert_pending_header(&mut self, name: HeaderName, value: HeaderValue);
    fn into_module_response(self) -> Response<Body>;
    fn from_module_response(response: Response<Body>) -> Self;
}

impl DownstreamResponse for Response<Body> {
    fn module_view(&self) -> HttpModuleResponseView<'_> {
        HttpModuleResponseView::from_response(self)
    }
    fn insert_pending_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.headers_mut().insert(name, value);
    }
    fn into_module_response(self) -> Response<Body> {
        self
    }
    fn from_module_response(response: Response<Body>) -> Self {
        response
    }
}

impl DownstreamResponse for OwnerResponse<Body> {
    fn module_view(&self) -> HttpModuleResponseView<'_> {
        HttpModuleResponseView {
            response: ResponseViewInner::Owned(self),
        }
    }
    fn insert_pending_header(&mut self, name: HeaderName, value: HeaderValue) {
        match OrdinaryHeaderName::try_from(name) {
            Ok(name) => {
                self.headers_mut().insert(name, value);
            }
            Err(_) => self.headers_mut().set_content_length_value(value),
        }
    }
    fn into_module_response(self) -> Response<Body> {
        self.into_http_for_library()
    }
    fn from_module_response(response: Response<Body>) -> Self {
        Self::from_http(response)
    }
}

/// An opaque borrowed mutable HTTP request for module events.
///
/// The [`OwnerRequest`] stays inside the module envelope; modules see only
/// semantic views, scalar operations, named header operations and body
/// moves. There is intentionally no access to the raw header map, raw
/// values, iterators, callbacks, `Deref`, parts or transport conversions.
///
/// ```compile_fail
/// use qpxd::module_api::{Body, HttpModuleRequest};
/// fn no_raw(request: &HttpModuleRequest<'_>) {
///     let _ = request.headers();
/// }
/// ```
///
/// ```compile_fail
/// use qpxd::module_api::{Body, HttpModuleRequest};
/// fn no_raw_mut(request: &mut HttpModuleRequest<'_>) {
///     let _ = request.headers_mut();
/// }
/// ```
/// Caller-supplied header values are mutation inputs only; setters do not
/// return a previous value.
///
/// ```compile_fail
/// use http::{HeaderName, HeaderValue};
/// use qpxd::module_api::HttpModuleRequest;
/// fn no_previous_value(facade: &mut HttpModuleRequest<'_>) {
///     let _: Option<HeaderValue> = facade.set_header(
///         HeaderName::from_static("x-example"), HeaderValue::from_static("new"));
/// }
/// ```
pub struct HttpModuleRequest<'a> {
    inner: &'a mut OwnerRequest<Body>,
}

impl<'a> HttpModuleRequest<'a> {
    pub(super) fn new(request: &'a mut OwnerRequest<Body>) -> Self {
        Self { inner: request }
    }

    /// Returns the request method.
    pub fn method(&self) -> &Method {
        self.inner.method()
    }

    /// Replaces the request method.
    pub fn set_method(&mut self, method: Method) {
        *self.inner.method_mut() = method;
    }

    /// Returns the request version.
    pub fn version(&self) -> Version {
        self.inner.version()
    }

    /// Replaces the request version.
    pub fn set_version(&mut self, version: Version) {
        *self.inner.version_mut() = version;
    }

    /// Returns the request URI.
    pub fn uri(&self) -> &http::Uri {
        self.inner.uri()
    }

    /// Replaces the request URI.
    pub fn set_uri(&mut self, uri: http::Uri) {
        *self.inner.uri_mut() = uri;
    }

    /// Returns the request scheme, if present.
    pub fn scheme(&self) -> Option<&str> {
        self.inner.uri().scheme_str()
    }

    /// Returns the request host, falling back to the Host header.
    pub fn host(&self) -> Option<&str> {
        self.inner.uri().host().or_else(|| {
            self.inner
                .headers()
                .get(&OrdinaryHeaderName::try_from(HOST).expect("ordinary host"))
                .and_then(|value| value.to_str().ok())
        })
    }

    /// Returns the request path.
    pub fn path(&self) -> &str {
        self.inner.uri().path()
    }

    /// Returns the request query, if present.
    pub fn query(&self) -> Option<&str> {
        self.inner.uri().query()
    }

    /// Returns the request authority, if present.
    pub fn authority(&self) -> Option<&str> {
        self.inner.uri().authority().map(|value| value.as_str())
    }

    /// Returns the request URI as a string.
    pub fn uri_string(&self) -> Cow<'_, str> {
        Cow::Owned(self.inner.uri().to_string())
    }

    /// Returns a semantic view of this request.
    pub fn as_view(&self) -> HttpModuleRequestView<'_> {
        HttpModuleRequestView::from_request(&*self.inner)
    }

    /// Returns whether this request contains the named header.
    pub fn has_header(&self, name: &HeaderName) -> bool {
        self.as_view().has_header(name)
    }

    /// Replaces all values of the named request header.
    pub fn set_header(&mut self, name: HeaderName, value: HeaderValue) {
        match OrdinaryHeaderName::try_from(name) {
            Ok(name) => {
                self.inner.headers_mut().insert(name, value);
            }
            Err(_) => self.inner.headers_mut().set_content_length_value(value),
        }
    }

    /// Appends a value to the named request header, preserving order.
    pub fn append_header(&mut self, name: HeaderName, value: HeaderValue) {
        match OrdinaryHeaderName::try_from(name) {
            Ok(name) => self.inner.headers_mut().append(name, value),
            Err(_) => self.inner.headers_mut().append_content_length_value(value),
        }
    }

    /// Removes the named request header, returning whether it was present.
    pub fn remove_header(&mut self, name: &HeaderName) -> bool {
        let present = self.as_view().has_header(name);
        if present {
            match OrdinaryHeaderName::try_from(name.clone()) {
                Ok(name) => {
                    self.inner.headers_mut().remove(&name);
                }
                Err(_) => self.inner.headers_mut().remove_content_length(),
            }
        }
        present
    }

    /// Takes the request body, leaving an empty body behind.
    pub fn take_body(&mut self) -> ModuleBody {
        ModuleBody::from_transport(std::mem::replace(self.inner.body_mut(), Body::empty()))
    }

    /// Replaces the request body.
    pub fn set_body(&mut self, body: ModuleBody) {
        crate::http::protocol::l7::replace_module_request_body(self.inner, body.into_transport());
    }

    pub(super) fn as_owner(&self) -> &OwnerRequest<Body> {
        self.inner
    }
}

/// An opaque owned HTTP response for module events and short-circuits.
///
/// Transport storage stays private; modules use semantic views, scalar
/// setters, named header operations and body moves. There is intentionally
/// no access to the raw header map, raw values, iterators, callbacks,
/// `Deref`, parts, builders or transport conversions.
///
/// ```compile_fail
/// use qpxd::module_api::HttpModuleResponse;
/// fn no_raw(response: &HttpModuleResponse) {
///     let _ = response.headers();
/// }
/// ```
///
/// ```compile_fail
/// use qpxd::module_api::HttpModuleResponse;
/// fn no_parts(response: HttpModuleResponse) {
///     let _ = response.into_parts();
/// }
/// ```
/// Caller-supplied header values are mutation inputs only; setters do not
/// return a previous value.
///
/// ```compile_fail
/// use http::{HeaderName, HeaderValue};
/// use qpxd::module_api::HttpModuleResponse;
/// fn no_previous_value(facade: &mut HttpModuleResponse) {
///     let _: Option<HeaderValue> = facade.set_header(
///         HeaderName::from_static("x-example"), HeaderValue::from_static("new"));
/// }
/// ```
pub struct HttpModuleResponse {
    inner: Response<Body>,
}

impl HttpModuleResponse {
    /// Builds a short-circuit response from a status and a body.
    pub fn new(status: StatusCode, body: ModuleBody) -> Self {
        let mut inner = Response::new(body.into_transport());
        *inner.status_mut() = status;
        Self { inner }
    }

    /// Returns the response status.
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    /// Replaces the response status.
    pub fn set_status(&mut self, status: StatusCode) {
        *self.inner.status_mut() = status;
    }

    /// Returns the response version.
    pub fn version(&self) -> Version {
        self.inner.version()
    }

    /// Replaces the response version.
    pub fn set_version(&mut self, version: Version) {
        *self.inner.version_mut() = version;
    }

    /// Returns a semantic view of this response.
    pub fn as_view(&self) -> HttpModuleResponseView<'_> {
        HttpModuleResponseView::from_response(&self.inner)
    }

    /// Returns whether this response contains the named header.
    pub fn has_header(&self, name: &HeaderName) -> bool {
        self.inner.headers().contains_key(name)
    }

    /// Replaces all values of the named response header.
    pub fn set_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.inner.headers_mut().insert(name, value);
    }

    /// Appends a value to the named response header, preserving order.
    pub fn append_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.inner.headers_mut().append(name, value);
    }

    /// Removes the named response header, returning whether it was present.
    pub fn remove_header(&mut self, name: &HeaderName) -> bool {
        let present = self.inner.headers().contains_key(name);
        if present {
            self.inner.headers_mut().remove(name);
        }
        present
    }

    /// Takes the response body, leaving an empty body behind.
    pub fn take_body(&mut self) -> ModuleBody {
        ModuleBody::from_transport(std::mem::replace(self.inner.body_mut(), Body::empty()))
    }

    /// Replaces the response body.
    pub fn set_body(&mut self, body: ModuleBody) {
        *self.inner.body_mut() = body.into_transport();
    }

    pub(super) fn from_inner(inner: Response<Body>) -> Self {
        Self { inner }
    }

    pub(crate) fn into_inner(self) -> Response<Body> {
        self.inner
    }

    pub(super) fn as_inner_mut(&mut self) -> &mut Response<Body> {
        &mut self.inner
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

    pub(super) fn sync_frozen_request(&mut self, req: &OwnerRequest<Body>) -> bool {
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
            match OrdinaryHeaderName::try_from(name) {
                Ok(name) => {
                    request.headers.insert(name, value);
                }
                Err(_) => request.headers.set_content_length_value(value),
            }
        }
    }

    fn set_response_status(&mut self, status: StatusCode) {
        self.session.response_status = Some(status);
    }

    fn apply_pending_response_headers<R: DownstreamResponse>(&mut self, response: &mut R) {
        for (name, value) in self.session.pending_response_headers.drain(..) {
            response.insert_pending_header(name, value);
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

    /// Queues a caller-supplied header for owner-managed response insertion.
    ///
    /// The value is an input only: this method returns no stored or displaced
    /// value. When pending entries are applied, later entries with the same
    /// name replace earlier ones, matching `HeaderMap::insert` semantics.
    pub fn queue_response_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.session.pending_response_headers.push((name, value));
    }

    /// Sends a caller-owned absolute-form request, returning an opaque module response.
    ///
    /// The `OwnerRequest` input is consumed; the returned envelope wraps the raw
    /// transport response without reading, buffering or cloning its body.
    ///
    /// ```compile_fail
    /// use qpx_core::http_message::Request;
    /// use qpxd::module_api::{Body, HttpModuleContext};
    /// async fn cannot_read_raw_headers(ctx: &HttpModuleContext) {
    ///     let response = ctx
    ///         .send_absolute_request(Request::new(Body::empty()))
    ///         .await
    ///         .expect("response");
    ///     let _ = response.headers();
    /// }
    /// ```
    /// ```compile_fail
    /// use qpx_core::http_message::Request;
    /// use qpxd::module_api::HttpModuleContext;
    /// async fn no_transport_body(ctx: &HttpModuleContext) {
    ///     let _ = ctx.send_absolute_request(Request::new(qpx_http::body::Body::empty())).await;
    /// }
    /// ```
    /// Raw transport requests cannot bypass the request owner:
    /// ```compile_fail
    /// use qpxd::module_api::{Body, HttpModuleContext};
    /// async fn no_raw_request(ctx: &HttpModuleContext) {
    ///     let _ = ctx.send_absolute_request(http::Request::new(Body::empty())).await;
    /// }
    /// ```
    pub async fn send_absolute_request(
        &self,
        req: OwnerRequest<ModuleBody>,
    ) -> Result<HttpModuleResponse> {
        let mut req = req.map_body(ModuleBody::into_transport);
        crate::http::protocol::l7::mark_module_request_body_replaced(&mut req);
        self.send_absolute_request_inner(req)
            .await
            .map(HttpModuleResponse::from_inner)
    }

    async fn send_absolute_request_inner(&self, req: OwnerRequest<Body>) -> Result<Response<Body>> {
        let url = req.uri().to_string();
        let origin = OriginEndpoint::direct(url.as_str());
        let inner = proxy_http(
            &self.runtime.pools,
            req,
            &origin,
            self.session.proxy_name.as_str(),
            None,
        )
        .await?;
        Ok(inner)
    }

    /// Sends a caller-owned absolute-form request to a pinned address.
    ///
    /// `connect_addr` is the physical socket while the request URI authority and
    /// logical port stay the Host/TLS identity. The response is wrapped opaquely
    /// without reading, buffering or cloning its body.
    pub async fn send_absolute_request_to_addr(
        &self,
        req: OwnerRequest<ModuleBody>,
        connect_addr: SocketAddr,
    ) -> Result<HttpModuleResponse> {
        let mut req = req.map_body(ModuleBody::into_transport);
        crate::http::protocol::l7::mark_module_request_body_replaced(&mut req);
        self.send_absolute_request_to_addr_inner(req, connect_addr)
            .await
            .map(HttpModuleResponse::from_inner)
    }

    async fn send_absolute_request_to_addr_inner(
        &self,
        req: OwnerRequest<Body>,
        connect_addr: SocketAddr,
    ) -> Result<Response<Body>> {
        let uri = req.uri();
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| anyhow!("subrequest URL missing scheme"))?;
        let host = uri
            .host()
            .ok_or_else(|| anyhow!("subrequest URL missing host"))?;
        let logical_port = uri.port_u16().unwrap_or(match scheme {
            "http" => 80,
            "https" => 443,
            _ => 443,
        });
        let url = uri.to_string();
        let origin = OriginEndpoint::discovered(
            url.as_str(),
            connect_addr.ip().to_string(),
            connect_addr.port(),
            host.to_string(),
            logical_port,
            host.to_string(),
        );
        let inner = proxy_http(
            &self.runtime.pools,
            req,
            &origin,
            self.session.proxy_name.as_str(),
            None,
        )
        .await?;
        Ok(inner)
    }

    /// Builds the cache key for a module request view.
    ///
    /// Normalization stays owned by `CacheRequestKey::for_target`. Only the
    /// method, target and first Host value are needed, for live and frozen views.
    pub fn cache_request_key(
        &self,
        request: &HttpModuleRequestView<'_>,
    ) -> Result<Option<CacheRequestKey>> {
        let Some(_) = self.session.cache_policy.as_ref() else {
            return Ok(None);
        };
        let default_scheme = self
            .session
            .cache_default_scheme
            .as_deref()
            .ok_or_else(|| anyhow!("cache purge missing default scheme"))?;
        // The cache owner needs only method, target and the first Host value.
        // Adapt borrowed head fields without exposing transport body storage.
        let mut minimal = OwnerRequest::new(());
        *minimal.method_mut() = request.method().clone();
        *minimal.uri_mut() = request.uri().clone();
        let host = OrdinaryHeaderName::try_from(HOST).expect("ordinary host");
        if let Some(value) = request.headers().get(&host).cloned() {
            minimal.headers_mut().insert(host, value);
        }
        CacheRequestKey::for_target(&minimal, default_scheme)
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

pub(crate) enum HttpModuleExecution {
    Empty,
    Active(Box<ActiveHttpModuleExecution>),
}

pub(crate) struct ActiveHttpModuleExecution {
    chain: Arc<CompiledHttpModuleChain>,
    context: HttpModuleContext,
}

impl HttpModuleExecution {
    pub(super) fn empty() -> Self {
        Self::Empty
    }

    pub(super) fn new(chain: Arc<CompiledHttpModuleChain>, context: HttpModuleContext) -> Self {
        Self::Active(Box::new(ActiveHttpModuleExecution { chain, context }))
    }

    pub(crate) fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    #[cfg(test)]
    pub(super) fn has_context(&self) -> bool {
        matches!(self, Self::Active(_))
    }

    fn active_mut(&mut self) -> Option<(&CompiledHttpModuleChain, &mut HttpModuleContext)> {
        match self {
            Self::Empty => None,
            Self::Active(active) => Some((active.chain.as_ref(), &mut active.context)),
        }
    }

    pub(crate) async fn on_request_headers(
        &mut self,
        req: &mut OwnerRequest<Body>,
    ) -> Result<RequestHeadersOutcome> {
        let Some((chain, context)) = self.active_mut() else {
            return Ok(RequestHeadersOutcome::Continue);
        };
        for module in chain.request_headers.iter() {
            let applies = {
                let request_view = HttpModuleRequestView::from_request(&*req);
                module.module.applies_to_request_headers(&request_view)
            };
            if !applies {
                continue;
            }
            let label = module.label();
            let outcome = module
                .module
                .call(
                    HttpModuleStage::RequestHeaders,
                    context,
                    HttpModuleEvent::RequestHeaders(HttpModuleRequest::new(&mut *req)),
                )
                .await
                .with_context(|| format!("http module {label} request_headers failed"))?
                .request_headers_result(label)?;
            match outcome {
                RequestHeadersOutcome::Continue => {}
                RequestHeadersOutcome::Respond(response) => {
                    if chain.aggregate.needs_frozen_request {
                        context.sync_frozen_request(req);
                    }
                    return Ok(RequestHeadersOutcome::Respond(response));
                }
            }
        }
        if chain.aggregate.needs_frozen_request {
            context.sync_frozen_request(req);
        }
        Ok(RequestHeadersOutcome::Continue)
    }

    pub(crate) async fn on_cache_lookup(&mut self, hit: bool) -> Result<()> {
        let Some((chain, context)) = self.active_mut() else {
            return Ok(());
        };
        let status = if hit {
            CacheLookupStatus::Hit
        } else {
            CacheLookupStatus::Miss
        };
        for module in chain.cache_lookup.iter() {
            let label = module.label();
            module
                .module
                .call(
                    HttpModuleStage::CacheLookup,
                    context,
                    HttpModuleEvent::CacheLookup(status),
                )
                .await
                .with_context(|| format!("http module {label} cache_lookup failed"))?
                .into_complete(label, HttpModuleStage::CacheLookup)?;
        }
        Ok(())
    }

    pub(crate) async fn on_upstream_request(&mut self, req: &mut OwnerRequest<Body>) -> Result<()> {
        let Some((chain, context)) = self.active_mut() else {
            return Ok(());
        };
        for module in chain.upstream_request.iter() {
            let label = module.label();
            module
                .module
                .call(
                    HttpModuleStage::UpstreamRequest,
                    context,
                    HttpModuleEvent::UpstreamRequest(HttpModuleRequest::new(&mut *req)),
                )
                .await
                .with_context(|| format!("http module {label} upstream_request failed"))?
                .into_complete(label, HttpModuleStage::UpstreamRequest)?;
        }
        crate::http::protocol::l7::prepare_module_request_body_in_place(req);
        if chain.aggregate.needs_frozen_request {
            context.sync_frozen_request(req);
        }
        Ok(())
    }

    pub(crate) async fn on_upstream_response(
        &mut self,
        mut response: Response<Body>,
    ) -> Result<Response<Body>> {
        let Some((chain, context)) = self.active_mut() else {
            return Ok(response);
        };
        context.set_response_status(response.status());
        context.apply_pending_response_headers(&mut response);
        for module in chain.upstream_response.iter() {
            let label = module.label();
            let wrapped = module
                .module
                .call(
                    HttpModuleStage::UpstreamResponse,
                    context,
                    HttpModuleEvent::UpstreamResponse(HttpModuleResponse::from_inner(response)),
                )
                .await
                .with_context(|| format!("http module {label} upstream_response failed"))?
                .upstream_response(label)?;
            context.set_response_status(wrapped.status());
            let mut wrapped = wrapped;
            context.apply_pending_response_headers(wrapped.as_inner_mut());
            response = wrapped.into_inner();
        }
        Ok(response)
    }

    pub(crate) async fn prepare_downstream_response<R: DownstreamResponse>(
        &mut self,
        mut response: R,
    ) -> Result<R> {
        let Some((chain, context)) = self.active_mut() else {
            return Ok(response);
        };
        context.set_response_status(response.status());
        context.apply_pending_response_headers(&mut response);
        for module in chain.downstream_response.iter() {
            let applies = {
                let response_view = response.module_view();
                module
                    .module
                    .applies_to_downstream_response(context, &response_view)
            };
            if !applies {
                continue;
            }
            let label = module.label();
            let wrapped = module
                .module
                .call(
                    HttpModuleStage::DownstreamResponse,
                    context,
                    HttpModuleEvent::DownstreamResponse(HttpModuleResponse::from_inner(
                        response.into_module_response(),
                    )),
                )
                .await
                .with_context(|| format!("http module {label} downstream_response failed"))?
                .downstream_response(label)?;
            context.set_response_status(wrapped.status());
            let mut wrapped = wrapped;
            context.apply_pending_response_headers(wrapped.as_inner_mut());
            response = R::from_module_response(wrapped.into_inner());
        }
        Ok(response)
    }

    pub(crate) async fn on_retry(&mut self, attempt: usize, reason: &str) -> Result<()> {
        let Some((chain, context)) = self.active_mut() else {
            return Ok(());
        };
        let event = RetryEvent { attempt, reason };
        for module in chain.retry.iter() {
            let label = module.label();
            module
                .module
                .call(
                    HttpModuleStage::Retry,
                    context,
                    HttpModuleEvent::Retry(event),
                )
                .await
                .with_context(|| format!("http module {label} retry failed"))?
                .into_complete(label, HttpModuleStage::Retry)?;
        }
        Ok(())
    }

    pub(crate) async fn on_error(&mut self, err: &anyhow::Error) {
        let Some((chain, context)) = self.active_mut() else {
            return;
        };
        for module in chain.error.iter() {
            let label = module.label();
            if let Err(err) = module
                .module
                .call(HttpModuleStage::Error, context, HttpModuleEvent::Error(err))
                .await
                .and_then(|event| event.into_complete(label, HttpModuleStage::Error))
            {
                warn!(error = ?err, module = label, "http module error hook failed");
            }
        }
    }

    pub(crate) async fn on_logging(
        &mut self,
        response_status: Option<StatusCode>,
        err: Option<&anyhow::Error>,
    ) {
        let Some((chain, context)) = self.active_mut() else {
            return;
        };
        if let Some(status) = response_status {
            context.set_response_status(status);
        }
        for module in chain.log.iter() {
            let label = module.label();
            if let Err(err) = module
                .module
                .call(
                    HttpModuleStage::Log,
                    context,
                    HttpModuleEvent::Log {
                        response_status,
                        err,
                    },
                )
                .await
                .and_then(|event| event.into_complete(label, HttpModuleStage::Log))
            {
                warn!(error = ?err, module = label, "http module log hook failed");
            }
        }
    }
}
