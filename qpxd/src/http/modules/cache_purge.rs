use super::headers::{compile_literal_headers, parse_module_settings};
use super::{
    HttpModule, HttpModuleCapabilities, HttpModuleContext, HttpModuleEvent, HttpModuleFactory,
    HttpModuleStage, ModuleStages, RequestHeadersOutcome,
};
use crate::http::body::Body;
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use http::{HeaderName, HeaderValue, Method, StatusCode};
use hyper::Response;
use qpx_core::config::{CachePurgeModuleConfig, HttpModuleConfig};
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
