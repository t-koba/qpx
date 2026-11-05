use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use crate::http::rpc::build_rpc_local_response;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use hyper::{StatusCode, Version};
use qpx_core::config::LocalResponseConfig;
use qpx_core::http_message::{Headers, Response};
use qpx_http::body::Body;

#[derive(Debug, Clone)]
pub(crate) enum CompiledLocalResponse {
    Static(StaticLocalResponse),
    Dynamic(LocalResponseConfig),
}

#[derive(Debug, Clone)]
pub(crate) struct StaticLocalResponse {
    status: StatusCode,
    version: Version,
    headers: Headers,
    body: Bytes,
}

impl CompiledLocalResponse {
    pub(crate) fn compile(config: LocalResponseConfig) -> Result<Self> {
        if config.rpc.is_none() {
            let response = build_local_response(&config)?;
            return Ok(Self::Static(StaticLocalResponse {
                status: response.status(),
                version: response.version(),
                headers: response.headers().clone(),
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
                *response.version_mut() = compiled.version;
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
        let mut response = Response::new(Body::from(config.body.clone()));
        *response.status_mut() = status;
        response
    };

    if let Some(content_type) = config.content_type.as_ref() {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE.try_into()?,
            http::HeaderValue::from_str(content_type)?,
        );
    } else if config.rpc.is_none() && !config.body.is_empty() {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE.try_into()?,
            http::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    }

    apply_local_response_headers(response.headers_mut(), &config.headers)?;

    Ok(response)
}

// Config maps replace all occurrences of each parsed name, including Content-Length.
pub(super) fn apply_local_response_headers(
    headers: &mut Headers,
    custom: &std::collections::HashMap<String, String>,
) -> Result<()> {
    for (name, value) in custom {
        let name = http::header::HeaderName::from_bytes(name.as_bytes())?;
        let value = http::HeaderValue::from_str(value)?;
        if name == http::header::CONTENT_LENGTH {
            headers.set_content_length_value(value);
        } else {
            headers.insert(name.try_into()?, value);
        }
    }
    Ok(())
}

pub(crate) fn finalized_local_response(
    request_method: &http::Method,
    request_version: http::Version,
    proxy_name: &str,
    local: &LocalResponseConfig,
    headers: Option<&qpx_core::rules::CompiledHeaderControl>,
) -> Result<Response<Body>> {
    let mut response = build_local_response(local)?;
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
) -> Result<Response<Body>> {
    let mut response = local.build()?;
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
                        let compiled_response =
                            CompiledLocalResponse::compile(local.clone()).unwrap();
                        for (control, compiled) in [
                            (None, false),
                            (Some(&control), false),
                            (None, true),
                            (Some(&control), true),
                        ] {
                            // The previous standard-response path is the behavior oracle.
                            let expected =
                                OwnerResponse::from_http(finalize_response_with_headers(
                                    &method,
                                    version,
                                    "qpx",
                                    {
                                        let mut raw = http::Response::builder()
                                            .status(local.status)
                                            .header("content-type", "text/plain; charset=utf-8")
                                            .body(Body::from(local.body.clone()))
                                            .unwrap();
                                        for (name, value) in &local.headers {
                                            raw.headers_mut().insert(
                                                http::HeaderName::from_bytes(name.as_bytes())
                                                    .unwrap(),
                                                http::HeaderValue::from_str(value).unwrap(),
                                            );
                                        }
                                        raw
                                    },
                                    control,
                                    false,
                                ));
                            let actual: OwnerResponse<Body> = if compiled {
                                finalized_compiled_local_response(
                                    &method,
                                    version,
                                    "qpx",
                                    &compiled_response,
                                    control,
                                )
                            } else {
                                finalized_local_response(&method, version, "qpx", &local, control)
                            }
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
                                actual.headers().selected_fields_for_serialization(&[
                                    http::header::CONTENT_LENGTH
                                ]),
                                expected.headers().selected_fields_for_serialization(&[
                                    http::header::CONTENT_LENGTH
                                ])
                            );
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
            let compiled = CompiledLocalResponse::compile(local.clone()).unwrap();
            for response in [
                finalized_local_response(&http::Method::CONNECT, version, "qpx", &local, None)
                    .unwrap(),
                finalized_compiled_local_response(
                    &http::Method::CONNECT,
                    version,
                    "qpx",
                    &compiled,
                    None,
                )
                .unwrap(),
            ] {
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
    async fn compiled_local_responses_preserve_declarations_and_replay_independently() {
        use qpx_core::config::RpcLocalResponseConfig;
        use qpx_core::http_message::OrdinaryHeaderName;
        let field = OrdinaryHeaderName::try_from("x-test").unwrap();
        for protocol in [None, Some("grpc"), Some("grpc_web"), Some("connect")] {
            for length in [
                None,
                Some(""),
                Some("0"),
                Some("0007"),
                Some("07, 7"),
                Some("7, 8"),
                Some("invalid"),
            ] {
                let mut local = LocalResponseConfig {
                    status: 201,
                    body: "payload".into(),
                    content_type: Some("text/custom".into()),
                    headers: HashMap::from([("x-test".into(), "value".into())]),
                    rpc: protocol.map(|protocol| RpcLocalResponseConfig {
                        protocol: protocol.into(),
                        status: None,
                        message: None,
                        http_status: Some(201),
                        headers: HashMap::from([("x-test".into(), "rpc-original".into())]),
                        trailers: HashMap::new(),
                    }),
                };
                if let Some(length) = length {
                    // The outer config must replace the RPC declaration, not append it.
                    if let Some(rpc) = local.rpc.as_mut() {
                        rpc.headers.insert("content-length".into(), "9".into());
                    }
                    local.headers.insert("Content-Length".into(), length.into());
                }
                let compiled = CompiledLocalResponse::compile(local.clone()).unwrap();
                for index in 0..3 {
                    let mut response = match index {
                        0 => build_local_response(&local),
                        1 => compiled.build(),
                        _ => compiled.clone().build(),
                    }
                    .unwrap();
                    assert_eq!(response.status(), StatusCode::CREATED);
                    assert_eq!(response.version(), Version::HTTP_11);
                    assert_eq!(response.headers().get(&field).unwrap(), "value");
                    assert_eq!(
                        response
                            .headers()
                            .get(&OrdinaryHeaderName::try_from("content-type").unwrap())
                            .unwrap(),
                        "text/custom"
                    );
                    let literal = response
                        .headers()
                        .selected_fields_for_serialization(&[http::header::CONTENT_LENGTH]);
                    assert_eq!(
                        literal
                            .get("content-length")
                            .map(|values| values.iter().map(String::as_str).collect::<Vec<_>>()),
                        length.map(|value| vec![value])
                    );
                    let declaration = response.headers().declared_content_length();
                    let valid = declaration.is_ok();
                    match length {
                        None => assert_eq!(declaration.unwrap(), None),
                        Some("0") => assert_eq!(declaration.unwrap(), Some(0)),
                        Some("0007" | "07, 7") => assert_eq!(declaration.unwrap(), Some(7)),
                        _ => assert!(declaration.is_err()),
                    }
                    // Mutations of one replay must not reach the next response.
                    response
                        .headers_mut()
                        .insert(field.clone(), http::HeaderValue::from_static("changed"));
                    if protocol.is_none() {
                        assert_eq!(response.body().trailers_are_sanitized(), index != 0);
                    }
                    let exported = response.into_http_for_codec();
                    if !valid {
                        assert!(exported.is_err());
                        continue;
                    }
                    let response = exported.unwrap();
                    assert_eq!(
                        response
                            .headers()
                            .get(http::header::CONTENT_LENGTH)
                            .map(|value| value.to_str().unwrap()),
                        length.map(|value| if value == "0" { "0" } else { "7" })
                    );
                    if protocol.is_none() {
                        assert_eq!(
                            qpx_http::body::to_bytes(response.into_body())
                                .await
                                .unwrap(),
                            "payload"
                        );
                    }
                }
            }
        }
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
            qpx_http::body::to_bytes(response.into_head_and_body().1)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
