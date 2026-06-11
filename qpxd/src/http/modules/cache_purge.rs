use super::headers::{compile_literal_headers, parse_module_settings};
use super::{
    HttpModule, HttpModuleCapabilities, HttpModuleContext, HttpModuleEvent, HttpModuleFactory,
    HttpModuleStage, ModuleStages, RequestHeadersOutcome,
};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use cidr::IpCidr;
use http::{HeaderName, HeaderValue, Method, StatusCode};
use hyper::Response;
use qpx_core::config::{CachePurgeModuleConfig, HttpModuleConfig};
use qpx_http::body::Body;
use std::sync::Arc;

pub(super) struct CachePurgeModuleFactory;

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
    require_identity: bool,
    allowed_peers: Vec<IpCidr>,
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
        let allowed_peers = config
            .allowed_peers
            .into_iter()
            .map(|peer| {
                peer.parse::<IpCidr>()
                    .map_err(|_| anyhow!("invalid cache purge allowed peer CIDR: {peer}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            methods,
            require_identity: config.require_identity,
            allowed_peers,
            response_status: StatusCode::from_u16(config.response_status)
                .context("invalid cache purge response_status")?,
            response_body: config.response_body,
            response_headers: compile_literal_headers(config.response_headers)?,
        })
    }

    fn matches(&self, method: &Method) -> bool {
        self.methods.iter().any(|candidate| candidate == method)
    }

    fn authorized(&self, ctx: &HttpModuleContext) -> bool {
        if self
            .allowed_peers
            .iter()
            .any(|peer| peer.contains(&ctx.remote_ip()))
        {
            return true;
        }
        !self.require_identity || ctx.identity_user().is_some()
    }

    fn build_response(&self) -> Response<Body> {
        let mut response = match Response::builder()
            .status(self.response_status)
            .body(Body::from(self.response_body.clone()))
        {
            Ok(response) => response,
            Err(_) => Response::new(Body::from(self.response_body.clone())),
        };
        for (name, value) in &self.response_headers {
            response.headers_mut().insert(name.clone(), value.clone());
        }
        response
    }

    fn build_forbidden_response(&self) -> Response<Body> {
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("cache purge requires authorization"))
            .unwrap_or_else(|_| Response::new(Body::from("cache purge requires authorization")))
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
        if !self.authorized(ctx) {
            return Ok(HttpModuleEvent::RequestHeadersResult(
                RequestHeadersOutcome::Respond(Box::new(self.build_forbidden_response())),
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
