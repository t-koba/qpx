use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use crate::http::rpc::build_rpc_local_response;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use hyper::{Response, StatusCode};
use qpx_core::config::LocalResponseConfig;
use qpx_http::body::Body;

#[derive(Debug, Clone)]
pub(crate) enum CompiledLocalResponse {
    Static(StaticLocalResponse),
    Dynamic(LocalResponseConfig),
}

#[derive(Debug, Clone)]
pub(crate) struct StaticLocalResponse {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Bytes,
}

impl CompiledLocalResponse {
    pub(crate) fn compile(config: LocalResponseConfig) -> Result<Self> {
        if config.rpc.is_none() {
            let response = build_local_response(&config)?;
            let (parts, _) = response.into_parts();
            return Ok(Self::Static(StaticLocalResponse {
                status: parts.status,
                headers: parts.headers,
                body: Bytes::from(config.body),
            }));
        }
        Ok(Self::Dynamic(config))
    }

    fn build(&self) -> Result<Response<Body>> {
        match self {
            Self::Static(compiled) => {
                let mut response =
                    Response::new(Body::from(compiled.body.clone()).mark_trailers_sanitized());
                *response.status_mut() = compiled.status;
                *response.headers_mut() = compiled.headers.clone();
                Ok(response)
            }
            Self::Dynamic(config) => build_local_response(config),
        }
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
) -> Result<qpx_core::http_message::Response<Body>> {
    let mut response = qpx_core::http_message::Response::from_http(build_local_response(local)?);
    finalize_response_with_headers_in_place(
        request_method,
        request_version,
        proxy_name,
        &mut response,
        headers,
        false,
    );
    Ok(response)
}

pub(crate) fn finalized_compiled_local_response(
    request_method: &http::Method,
    request_version: http::Version,
    proxy_name: &str,
    local: &CompiledLocalResponse,
    headers: Option<&qpx_core::rules::CompiledHeaderControl>,
) -> Result<qpx_core::http_message::Response<Body>> {
    let mut response = qpx_core::http_message::Response::from_http(local.build()?);
    crate::http::protocol::l7::finalize_response_with_headers_in_place(
        request_method,
        request_version,
        proxy_name,
        &mut response,
        headers,
        false,
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn finalized_local_response_preserves_standard_policy_and_normalization() {
        use crate::http::protocol::l7::finalize_response_with_headers;
        use http::{Method, Version};
        use qpx_core::http_message::Response as OwnerResponse;
        use qpx_core::rules::CompiledHeaderControl;

        let control = CompiledHeaderControl::compile(
            &serde_yaml::from_str(
                r#"
response_set: { x-policy: configured, connection: x-hop, x-hop: removed }
response_add: { x-duplicate: second }
response_remove: [x-remove]
"#,
            )
            .unwrap(),
        )
        .unwrap();
        for method in [Method::GET, Method::HEAD, Method::CONNECT] {
            for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
                for status in [200, 204, 205, 304, 407, 418] {
                    for length in [
                        None,
                        Some("0"),
                        Some("3"),
                        Some("03, 3"),
                        Some("3, 4"),
                        Some("invalid"),
                    ] {
                        let mut local = LocalResponseConfig {
                            status,
                            body: "abc".to_string(),
                            content_type: None,
                            headers: HashMap::from([
                                (
                                    "date".to_string(),
                                    "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
                                ),
                                ("x-policy".to_string(), "original".to_string()),
                                ("x-duplicate".to_string(), "first".to_string()),
                                ("x-remove".to_string(), "removed".to_string()),
                                (
                                    "proxy-authenticate".to_string(),
                                    "Basic realm=proxy".to_string(),
                                ),
                            ]),
                            rpc: None,
                        };
                        if let Some(length) = length {
                            local
                                .headers
                                .insert("content-length".to_string(), length.to_string());
                        }
                        for control in [None, Some(&control)] {
                            // The previous standard-response path is the behavior oracle.
                            let expected =
                                OwnerResponse::from_http(finalize_response_with_headers(
                                    &method,
                                    version,
                                    "qpx",
                                    build_local_response(&local).unwrap(),
                                    control,
                                    false,
                                ));
                            let actual: OwnerResponse<Body> =
                                finalized_local_response(&method, version, "qpx", &local, control)
                                    .unwrap();
                            assert_eq!(actual.status(), expected.status());
                            assert_eq!(actual.version(), expected.version());
                            let fields = |response: &OwnerResponse<Body>| {
                                let mut fields: Vec<_> = response
                                    .headers()
                                    .iter()
                                    .map(|(name, value)| {
                                        (name.as_str().to_string(), value.as_bytes().to_vec())
                                    })
                                    .collect();
                                // Stable name ordering retains each field's duplicate value order.
                                fields.sort_by(|a, b| a.0.cmp(&b.0));
                                fields
                            };
                            assert_eq!(fields(&actual), fields(&expected));
                            assert_eq!(
                                actual.headers().declared_content_length(),
                                expected.headers().declared_content_length()
                            );
                            assert_eq!(
                                qpx_http::body::to_bytes(actual.into_head_and_body().1)
                                    .await
                                    .unwrap(),
                                qpx_http::body::to_bytes(expected.into_head_and_body().1)
                                    .await
                                    .unwrap()
                            );
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn finalized_local_response_preserves_rpc_body_and_trailers() {
        use qpx_core::config::RpcLocalResponseConfig;
        for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
            let local = LocalResponseConfig {
                status: 200,
                body: "abc".to_string(),
                content_type: None,
                headers: HashMap::new(),
                rpc: Some(RpcLocalResponseConfig {
                    protocol: "grpc".to_string(),
                    status: Some("14".to_string()),
                    message: Some("unavailable".to_string()),
                    http_status: Some(418),
                    headers: HashMap::new(),
                    trailers: HashMap::from([("x-trailer".to_string(), "preserved".to_string())]),
                }),
            };
            let response =
                finalized_local_response(&http::Method::CONNECT, version, "qpx", &local, None)
                    .unwrap();
            assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
            let mut body = response.into_head_and_body().1;
            assert_eq!(
                body.data().await.unwrap().unwrap().as_ref(),
                b"\x00\x00\x00\x00\x03abc"
            );
            assert!(body.data().await.is_none());
            let trailers = body.trailers().await.unwrap().expect("RPC trailers");
            assert_eq!(trailers.get("grpc-status").unwrap(), "14");
            assert_eq!(trailers.get("grpc-message").unwrap(), "unavailable");
            assert_eq!(trailers.get("x-trailer").unwrap(), "preserved");
        }
    }

    #[test]
    fn finalized_local_response_preserves_build_errors() {
        let mut local = LocalResponseConfig {
            status: 99,
            body: String::new(),
            content_type: None,
            headers: HashMap::new(),
            rpc: None,
        };
        assert!(
            finalized_local_response(
                &http::Method::GET,
                http::Version::HTTP_11,
                "qpx",
                &local,
                None
            )
            .is_err()
        );
        local.status = 200;
        local
            .headers
            .insert("bad header".to_string(), "value".to_string());
        assert!(
            finalized_local_response(
                &http::Method::GET,
                http::Version::HTTP_11,
                "qpx",
                &local,
                None
            )
            .is_err()
        );
    }

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

    #[tokio::test]
    async fn compiled_static_response_preserves_an_empty_body() {
        let compiled = CompiledLocalResponse::compile(LocalResponseConfig {
            status: 204,
            body: String::new(),
            content_type: None,
            headers: HashMap::new(),
            rpc: None,
        })
        .expect("compile empty local response");

        let response = compiled.build().expect("empty response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            qpx_http::body::to_bytes(response.into_body())
                .await
                .unwrap()
                .is_empty()
        );
    }
}
