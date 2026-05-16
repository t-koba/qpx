use super::headers::{parse_header_name, parse_module_settings};
use super::template::{CompiledTemplate, compile_template, render_template};
use super::{
    HttpModule, HttpModuleCapabilities, HttpModuleContext, HttpModuleEvent, HttpModuleFactory,
    HttpModuleRequestView, HttpModuleStage, ModuleStages, RequestHeadersOutcome,
};
use crate::http::body::Body;
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use http::header::{CONTENT_LENGTH, LOCATION};
use http::{HeaderName, HeaderValue, Method};
use hyper::{Request, Response};
use qpx_core::config::{
    HeaderCaptureConfig, HttpModuleConfig, SubrequestModuleConfig, SubrequestPhase,
    SubrequestResponseMode,
};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use tracing::warn;

pub(super) struct SubrequestModuleFactory;

impl HttpModuleFactory for SubrequestModuleFactory {
    fn build(&self, spec: &HttpModuleConfig) -> Result<Arc<dyn HttpModule>> {
        Ok(Arc::new(SubrequestModule::new(parse_module_settings(
            spec,
        )?)?))
    }
}

#[derive(Clone)]
pub(super) struct SubrequestModule {
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
    pub(super) fn new(config: SubrequestModuleConfig) -> Result<Self> {
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

    pub(super) fn validate_url(&self, url: &str) -> Result<http::Uri> {
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
            Duration::from_millis(ctx.runtime_state().plan.limits.upstream_http_timeout_ms)
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
            && content_length > self.max_response_bytes
        {
            return Err(anyhow!(
                "subrequest {} response exceeds max_response_bytes",
                self.name
            ));
        }
        let max_response_bytes = self.max_response_bytes;
        let name = self.name.clone();
        Ok(response.map(move |body| {
            limit_subrequest_response_body(body, max_response_bytes, timeout_dur, name)
        }))
    }

    pub(super) fn validate_redirect_location(&self, location: Option<&HeaderValue>) -> Result<()> {
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
