//! External dispatch-helper API tests: opaque response envelopes only.
//!
//! Raw transport access (`headers()`, `headers_mut()`, parts, conversions)
//! is intentionally absent; these tests exercise only the public facade
//! operations plus compile-time signature checks for both dispatch helpers.
use http::{HeaderName, HeaderValue, Request, StatusCode};
use qpxd::module_api::{Body, HttpModuleContext, HttpModuleRequestView, HttpModuleResponse};
use std::net::SocketAddr;

fn assert_send_absolute_request_signature(
    ctx: &HttpModuleContext,
    req: Request<Body>,
) -> impl std::future::Future<Output = anyhow::Result<HttpModuleResponse>> + '_ {
    ctx.send_absolute_request(req)
}

fn assert_send_absolute_request_to_addr_signature(
    ctx: &HttpModuleContext,
    req: Request<Body>,
    addr: SocketAddr,
) -> impl std::future::Future<Output = anyhow::Result<HttpModuleResponse>> + '_ {
    ctx.send_absolute_request_to_addr(req, addr)
}

fn assert_cache_request_key_signature(
    ctx: &HttpModuleContext,
    request: &HttpModuleRequestView<'_>,
) -> anyhow::Result<()> {
    ctx.cache_request_key(request).map(|_| ())
}

#[test]
fn dispatch_helpers_return_opaque_response_usable_via_facade() {
    // Signature checks: both helpers resolve to the opaque envelope type.
    let _ = assert_send_absolute_request_signature;
    let _ = assert_send_absolute_request_to_addr_signature;
    let _ = assert_cache_request_key_signature;

    let mut response = HttpModuleResponse::new(StatusCode::OK, Body::empty());
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.has_header(&HeaderName::from_static("x-dispatch")));
    response.set_header(
        HeaderName::from_static("x-dispatch"),
        HeaderValue::from_static("1"),
    );
    assert!(response.has_header(&HeaderName::from_static("x-dispatch")));
    response.append_header(
        HeaderName::from_static("x-dispatch"),
        HeaderValue::from_static("2"),
    );
    assert!(response.has_header(&HeaderName::from_static("x-dispatch")));
    assert!(response.remove_header(&HeaderName::from_static("x-dispatch")));
    assert!(!response.has_header(&HeaderName::from_static("x-dispatch")));

    response.set_status(StatusCode::CREATED);
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn dispatch_opaque_response_body_moves_without_raw_access() {
    let mut response = HttpModuleResponse::new(StatusCode::OK, Body::from("dispatch"));
    let body = response.take_body();
    assert_eq!(
        qpx_http::body::to_bytes(body)
            .await
            .expect("bytes")
            .as_ref(),
        b"dispatch"
    );
    // take_body leaves an empty body behind; set_body restores streaming.
    assert!(
        qpx_http::body::to_bytes(response.take_body())
            .await
            .expect("bytes")
            .is_empty()
    );
    response.set_body(Body::from("again"));
    assert_eq!(
        qpx_http::body::to_bytes(response.take_body())
            .await
            .expect("bytes")
            .as_ref(),
        b"again"
    );
    // Presence checks still work after body moves.
    assert!(!response.has_header(&HeaderName::from_static("x-missing")));
}
