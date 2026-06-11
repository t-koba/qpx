use crate::http::protocol::l7::finalize_response_with_headers;
use crate::http::rpc::build_rpc_local_response;
use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use qpx_core::config::LocalResponseConfig;
use qpx_http::body::Body;

pub(crate) fn build_local_response(config: &LocalResponseConfig) -> Result<Response<Body>> {
    let mut response = if let Some(rpc) = config.rpc.as_ref() {
        build_rpc_local_response(rpc, config.body.as_bytes())?
    } else {
        let status = StatusCode::from_u16(config.status)
            .map_err(|_| anyhow!("invalid local response status: {}", config.status))?;
        Response::builder()
            .status(status)
            .body(Body::from(config.body.clone()))?
    };

    if let Some(content_type) = config.content_type.as_ref() {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_str(content_type)?,
        );
    } else if config.rpc.is_none() && !config.body.is_empty() {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    }

    for (name, value) in &config.headers {
        let name = http::header::HeaderName::from_bytes(name.as_bytes())?;
        let value = http::HeaderValue::from_str(value)?;
        response.headers_mut().insert(name, value);
    }

    Ok(response)
}

pub(crate) fn finalized_local_response(
    request_method: &http::Method,
    request_version: http::Version,
    proxy_name: &str,
    local: &LocalResponseConfig,
    headers: Option<&qpx_core::rules::CompiledHeaderControl>,
) -> Result<Response<Body>> {
    Ok(finalize_response_with_headers(
        request_method,
        request_version,
        proxy_name,
        build_local_response(local)?,
        headers,
        false,
    ))
}
