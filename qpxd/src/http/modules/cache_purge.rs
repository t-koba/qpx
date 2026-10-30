use super::headers::{compile_literal_headers, parse_module_settings};
use super::{
    HttpModule, HttpModuleCapabilities, HttpModuleContext, HttpModuleEvent, HttpModuleFactory,
    HttpModuleRequestView, HttpModuleResponse, HttpModuleStage, ModuleStages,
    RequestHeadersOutcome,
};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use cidr::IpCidr;
use http::{HeaderName, HeaderValue, Method, StatusCode};
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

    fn build_response(&self) -> HttpModuleResponse {
        let mut response = HttpModuleResponse::new(
            self.response_status,
            super::Body::from(self.response_body.clone()),
        );
        for (name, value) in &self.response_headers {
            response.set_header(name.clone(), value.clone());
        }
        response
    }

    fn build_forbidden_response(&self) -> HttpModuleResponse {
        HttpModuleResponse::new(
            StatusCode::FORBIDDEN,
            super::Body::from("cache purge requires authorization"),
        )
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

    fn applies_to_request_headers(&self, request: &HttpModuleRequestView<'_>) -> bool {
        self.matches(request.method())
    }

    fn is_inactive_for_request(&self, request: &HttpModuleRequestView<'_>) -> bool {
        !self.matches(request.method())
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
        let key = {
            let view = request.as_view();
            ctx.cache_request_key(&view)?
        };
        if let Some(key) = key {
            let _ = ctx.purge_cache_key(&key).await?;
        }
        Ok(HttpModuleEvent::RequestHeadersResult(
            RequestHeadersOutcome::Respond(Box::new(self.build_response())),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generated_purge_responses_keep_configured_literals_and_authorization() {
        let module = CachePurgeModule::new(
            serde_yaml::from_str(
                r#"
require_identity: true
response_status: 202
response_body: purged
response_headers: {content-length: invalid, x-purge: done}
"#,
            )
            .unwrap(),
        )
        .unwrap();
        let mut request = qpx_core::http_message::Request::new(qpx_http::body::Body::empty());
        *request.method_mut() = Method::from_bytes(b"PURGE").unwrap();
        for authorized in [true, false] {
            let mut ctx = super::super::tests::module_test_context_with_identity(
                authorized.then_some("alice"),
            );
            let event = module
                .call(
                    HttpModuleStage::RequestHeaders,
                    &mut ctx,
                    HttpModuleEvent::RequestHeaders(super::super::HttpModuleRequest::new(
                        &mut request,
                    )),
                )
                .await
                .unwrap();
            let RequestHeadersOutcome::Respond(response) =
                event.request_headers_result("purge").unwrap()
            else {
                panic!("must short circuit")
            };
            let owner = response.into_owner();
            assert_eq!(
                owner.status(),
                if authorized {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::FORBIDDEN
                }
            );
            if authorized {
                assert!(owner.headers().declared_content_length().is_err());
                assert_eq!(
                    owner
                        .headers()
                        .get(
                            &qpx_core::http_message::OrdinaryHeaderName::try_from("x-purge")
                                .unwrap()
                        )
                        .unwrap(),
                    "done"
                );
            } else {
                assert_eq!(owner.headers().declared_content_length().unwrap(), None);
            }
            assert_eq!(
                qpx_http::body::to_bytes(owner.into_head_and_body().1)
                    .await
                    .unwrap(),
                if authorized {
                    "purged"
                } else {
                    "cache purge requires authorization"
                }
            );
        }
    }
}
