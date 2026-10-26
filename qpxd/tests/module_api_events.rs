//! External event-facade API tests: opaque request/response facades only.
//!
//! Raw transport access (`headers()`, `headers_mut()`, parts, conversions)
//! is intentionally absent; these tests exercise only the public facade
//! operations plus short-circuit construction.
use anyhow::Result;
use async_trait::async_trait;
use http::{HeaderName, HeaderValue, Method, StatusCode, Version};
use qpxd::module_api::{
    Body, HttpModule, HttpModuleCapabilities, HttpModuleContext, HttpModuleEvent,
    HttpModuleResponse, HttpModuleStage, ModuleStages, RequestHeadersOutcome,
};

struct ExternalEventModule;

#[async_trait]
impl HttpModule for ExternalEventModule {
    fn capabilities(&self) -> HttpModuleCapabilities {
        let mut stages = ModuleStages::REQUEST_HEADERS;
        stages.insert(ModuleStages::DOWNSTREAM_RESPONSE);
        let mut capabilities = HttpModuleCapabilities::headers_only(stages);
        capabilities.mutates_request_headers = true;
        capabilities.mutates_response_headers = true;
        capabilities.may_short_circuit = true;
        capabilities
    }

    async fn call<'a>(
        &self,
        stage: HttpModuleStage,
        _ctx: &mut HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> Result<HttpModuleEvent<'a>> {
        match (stage, event) {
            (HttpModuleStage::RequestHeaders, HttpModuleEvent::RequestHeaders(mut request)) => {
                // Semantic reads.
                let _ = request.method();
                let _ = request.version();
                let _ = request.uri();
                let _ = request.scheme();
                let _ = request.host();
                let _ = request.path();
                let _ = request.query();
                let _ = request.authority();
                let _ = request.uri_string();
                let _ = request.as_view().method();
                let _ = request.has_header(&HeaderName::from_static("x-event"));
                // Named mutations.
                request.set_header(
                    HeaderName::from_static("x-event"),
                    HeaderValue::from_static("present"),
                );
                request.append_header(
                    HeaderName::from_static("x-event"),
                    HeaderValue::from_static("second"),
                );
                request.remove_header(&HeaderName::from_static("x-missing"));
                let octets = HeaderValue::from_bytes(b"opaque-\x80\xff")?;
                request.set_header(HeaderName::from_static("x-octets"), octets.clone());
                request.append_header(HeaderName::from_static("x-octets"), octets);
                // Scalar setters preserve the borrowed request.
                request.set_method(Method::GET);
                request.set_version(Version::HTTP_11);
                // Body move/replace round-trip.
                let body = request.take_body();
                request.set_body(body);
                Ok(HttpModuleEvent::RequestHeadersResult(
                    RequestHeadersOutcome::Continue,
                ))
            }
            (
                HttpModuleStage::DownstreamResponse,
                HttpModuleEvent::DownstreamResponse(mut response),
            ) => {
                let _ = response.status();
                let _ = response.version();
                let _ = response.as_view().status();
                let _ = response.has_header(&HeaderName::from_static("x-event"));
                response.set_header(
                    HeaderName::from_static("x-event"),
                    HeaderValue::from_static("present"),
                );
                response.append_header(
                    HeaderName::from_static("x-event"),
                    HeaderValue::from_static("second"),
                );
                response.remove_header(&HeaderName::from_static("x-missing"));
                response.set_status(StatusCode::OK);
                response.set_version(Version::HTTP_11);
                let body = response.take_body();
                response.set_body(body);
                Ok(HttpModuleEvent::DownstreamResponse(response))
            }
            (_, event) => Ok(event),
        }
    }
}

#[test]
fn external_response_facade_supports_ordered_mutations() {
    let mut response = HttpModuleResponse::new(StatusCode::OK, Body::empty());
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.has_header(&HeaderName::from_static("x-event")));

    response.set_header(
        HeaderName::from_static("x-event"),
        HeaderValue::from_static("one"),
    );
    assert!(response.has_header(&HeaderName::from_static("x-event")));

    response.append_header(
        HeaderName::from_static("x-event"),
        HeaderValue::from_static("two"),
    );
    assert!(response.has_header(&HeaderName::from_static("x-event")));

    // Replacing collapses back to a single value; presence remains.
    response.set_header(
        HeaderName::from_static("x-event"),
        HeaderValue::from_static("three"),
    );
    assert!(response.has_header(&HeaderName::from_static("x-event")));

    assert!(response.remove_header(&HeaderName::from_static("x-event")));
    assert!(!response.has_header(&HeaderName::from_static("x-event")));
    assert!(!response.remove_header(&HeaderName::from_static("x-event")));

    response.set_status(StatusCode::CREATED);
    assert_eq!(response.status(), StatusCode::CREATED);
    response.set_version(Version::HTTP_11);
    assert_eq!(response.version(), Version::HTTP_11);
}

#[test]
fn external_response_facade_accepts_obs_text_header_inputs() {
    let mut response = HttpModuleResponse::new(StatusCode::OK, Body::empty());
    let name = HeaderName::from_static("x-octets");
    let value = HeaderValue::from_bytes(b"opaque-\x80\xff").expect("valid obs-text");
    assert!(value.to_str().is_err());
    // The public operations accept owned values and return no stored value.
    let (): () = response.set_header(name.clone(), value.clone());
    let (): () = response.append_header(name.clone(), value);
    assert!(response.has_header(&name));
}

#[test]
fn external_short_circuit_builds_response_without_raw_builder() {
    let response = HttpModuleResponse::new(StatusCode::FORBIDDEN, Body::from("forbidden"));
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let outcome = RequestHeadersOutcome::Respond(Box::new(response));
    let HttpModuleEvent::RequestHeadersResult(RequestHeadersOutcome::Respond(boxed)) =
        HttpModuleEvent::RequestHeadersResult(outcome)
    else {
        panic!("expected short-circuit outcome");
    };
    assert_eq!(boxed.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn external_response_body_move_round_trip() {
    let mut response = HttpModuleResponse::new(StatusCode::OK, Body::from("stream me"));
    let body = response.take_body();
    let bytes = body.to_bytes().await.expect("bytes");
    assert_eq!(bytes.as_ref(), b"stream me");
    response.set_body(Body::from("stream me"));
    let body = response.take_body();
    let bytes = body.to_bytes().await.expect("bytes");
    assert_eq!(bytes.as_ref(), b"stream me");
}

#[test]
fn external_event_module_declares_facade_capabilities() {
    let module = ExternalEventModule;
    let capabilities = module.capabilities();
    assert!(capabilities.stages.contains(ModuleStages::REQUEST_HEADERS));
    assert!(
        capabilities
            .stages
            .contains(ModuleStages::DOWNSTREAM_RESPONSE)
    );
    assert!(capabilities.mutates_request_headers);
    assert!(capabilities.mutates_response_headers);
    assert!(capabilities.may_short_circuit);
}
