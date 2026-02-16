use anyhow::{anyhow, Result};
use hyper::{Body, Response, StatusCode};
use qpx_core::config::LocalResponseConfig;

pub fn build_local_response(config: &LocalResponseConfig) -> Result<Response<Body>> {
    let status = StatusCode::from_u16(config.status)
        .map_err(|_| anyhow!("invalid local response status: {}", config.status))?;
    let mut response = Response::builder()
        .status(status)
        .body(Body::from(config.body.clone()))?;

    if let Some(content_type) = config.content_type.as_ref() {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_str(content_type)?,
        );
    } else if !config.body.is_empty() {
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
