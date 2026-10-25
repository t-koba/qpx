use anyhow::Result;
use async_trait::async_trait;
use http::{HeaderName, Method, Request};
use qpxd::module_api::{
    Body, HttpModule, HttpModuleCapabilities, HttpModuleContext, HttpModuleEvent,
    HttpModuleRequestView, HttpModuleResponseView, HttpModuleStage, ModuleStages,
};

struct ExternalPredicateModule;

#[async_trait]
impl HttpModule for ExternalPredicateModule {
    fn capabilities(&self) -> HttpModuleCapabilities {
        HttpModuleCapabilities::headers_only(ModuleStages::REQUEST_HEADERS)
    }

    fn applies_to_request_headers(&self, request: &HttpModuleRequestView<'_>) -> bool {
        request.has_header(&HeaderName::from_static("x-predicate"))
    }

    fn is_inactive_for_request(&self, request: &HttpModuleRequestView<'_>) -> bool {
        !request.has_header(&HeaderName::from_static("x-predicate"))
    }

    fn applies_to_downstream_response(
        &self,
        _ctx: &HttpModuleContext,
        response: &HttpModuleResponseView<'_>,
    ) -> bool {
        response.status().is_success()
            && response.has_header(&HeaderName::from_static("x-predicate"))
    }

    async fn call<'a>(
        &self,
        _stage: HttpModuleStage,
        _ctx: &mut HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> Result<HttpModuleEvent<'a>> {
        Ok(event)
    }
}

#[test]
fn external_module_implements_semantic_predicate_hooks() {
    let module = ExternalPredicateModule;
    let request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/resource")
        .header("x-predicate", "present")
        .body(Body::empty())
        .expect("request");
    let request_view = HttpModuleRequestView::from_request(&request);

    assert!(module.applies_to_request_headers(&request_view));
    assert!(!module.is_inactive_for_request(&request_view));
    assert!(
        module
            .capabilities()
            .stages
            .contains(ModuleStages::REQUEST_HEADERS)
    );
}
