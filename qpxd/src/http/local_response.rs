use crate::http::protocol::l7::finalize_response_with_headers;
use crate::http::rpc::build_rpc_local_response;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use hyper::{Response, StatusCode};
use qpx_core::config::LocalResponseConfig;
use qpx_http::body::Body;

#[derive(Debug, Clone)]
pub(crate) struct CompiledLocalResponse {
    config: LocalResponseConfig,
    static_response: Option<StaticLocalResponse>,
}

#[derive(Debug, Clone)]
struct StaticLocalResponse {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Bytes,
}

impl CompiledLocalResponse {
    pub(crate) fn compile(config: LocalResponseConfig) -> Result<Self> {
        let static_response = if config.rpc.is_none() {
            let response = build_local_response(&config)?;
            let (parts, mut body) = response.into_parts();
            let body = body.take_single_frame_without_trailers().ok_or_else(|| {
                anyhow!("static local response did not produce a single body frame")
            })?;
            Some(StaticLocalResponse {
                status: parts.status,
                headers: parts.headers,
                body,
            })
        } else {
            None
        };
        Ok(Self {
            config,
            static_response,
        })
    }

    fn build(&self) -> Result<Response<Body>> {
        let Some(compiled) = self.static_response.as_ref() else {
            return build_local_response(&self.config);
        };
        let mut response = Response::new(Body::from(compiled.body.clone()));
        *response.status_mut() = compiled.status;
        *response.headers_mut() = compiled.headers.clone();
        Ok(response)
    }
}

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

pub(crate) fn finalized_compiled_local_response(
    request_method: &http::Method,
    request_version: http::Version,
    proxy_name: &str,
    local: &CompiledLocalResponse,
    headers: Option<&qpx_core::rules::CompiledHeaderControl>,
) -> Result<Response<Body>> {
    Ok(finalize_response_with_headers(
        request_method,
        request_version,
        proxy_name,
        local.build()?,
        headers,
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn compiled_static_response_replays_body_and_headers_independently() {
        let compiled = CompiledLocalResponse::compile(LocalResponseConfig {
            status: 201,
            body: "payload".to_string(),
            content_type: Some("application/octet-stream".to_string()),
            headers: HashMap::from([("x-test".to_string(), "value".to_string())]),
            rpc: None,
        })
        .expect("compile local response");

        let first = compiled.build().expect("first response");
        let second = compiled.build().expect("second response");
        assert_eq!(first.status(), StatusCode::CREATED);
        assert_eq!(second.headers().get("x-test").unwrap(), "value");
        assert_eq!(
            qpx_http::body::to_bytes(first.into_body()).await.unwrap(),
            "payload"
        );
        assert_eq!(
            qpx_http::body::to_bytes(second.into_body()).await.unwrap(),
            "payload"
        );
    }
}
