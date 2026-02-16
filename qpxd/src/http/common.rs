use anyhow::{anyhow, Result};
use hyper::client::HttpConnector;
use hyper::{Body, Response, StatusCode};
use qpx_core::config::ActionConfig;
use std::sync::{Arc, OnceLock};

pub fn blocked_response(message: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(message.to_owned()))
        .expect("static response")
}

pub fn forbidden_response(message: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(message.to_owned()))
        .expect("static response")
}

pub fn bad_request_response(message: impl Into<String>) -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(message.into()))
        .expect("static response")
}

pub fn connect_established_response() -> Response<Body> {
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .expect("static response");
    crate::http::semantics::strip_message_body_headers(response.headers_mut());
    response
}

pub fn shared_http_client() -> &'static hyper::Client<HttpConnector, Body> {
    static CLIENT: OnceLock<hyper::Client<HttpConnector, Body>> = OnceLock::new();
    CLIENT.get_or_init(hyper::Client::new)
}

pub fn resolve_named_upstream(
    action: &ActionConfig,
    state: &Arc<crate::runtime::RuntimeState>,
    listener_upstream_proxy: Option<&str>,
) -> Result<Option<String>> {
    if matches!(action.kind, qpx_core::config::ActionKind::Direct) {
        return Ok(None);
    }

    if let Some(upstream_name) = action.upstream.as_deref().or(listener_upstream_proxy) {
        if upstream_name.contains("://") {
            return Ok(Some(upstream_name.to_string()));
        }
        if let Some(url) = state.upstreams.get(upstream_name) {
            return Ok(Some(url.clone()));
        }
        return Err(anyhow!(
            "unknown upstream reference: {} (define it in top-level upstreams[])",
            upstream_name
        ));
    }

    Ok(None)
}
