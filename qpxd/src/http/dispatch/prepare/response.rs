use crate::http::body::Body;
use crate::http::protocol::l7::finalize_response_for_request;
use anyhow::Result;
use hyper::{Method, Response, StatusCode};

pub(super) fn request_body_too_large_response(
    method: &Method,
    version: http::Version,
    proxy_name: &str,
) -> Result<Response<Body>> {
    Ok(finalize_response_for_request(
        method,
        version,
        proxy_name,
        Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(Body::from("request body too large"))?,
        false,
    ))
}
