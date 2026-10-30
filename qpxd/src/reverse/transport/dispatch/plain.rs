use super::super::mirrors::{
    record_reverse_upstream_error, record_reverse_upstream_status, record_reverse_upstream_timeout,
};
use super::super::{InterimList, ReverseConnInfo};
use super::apply_reverse_route_metadata;
use super::route_constraints::{
    enforce_selected_reverse_route_constraints, reverse_security_rejection,
};
use crate::http::codec::lazy_timeout::timeout_after_pending;
use crate::reverse::ReloadableReverse;
use crate::reverse::router::HttpRoute;
use crate::upstream::origin::{
    PreparedPlainHttp1ConnectionAffinity, prepare_proxy_http1_request,
    proxy_direct_plain_http1_raw_response_with_interim,
    proxy_direct_plain_http1_raw_response_with_interim_on_connection,
};
use anyhow::{Result, anyhow};
use qpx_core::http_message::{Request as OwnerRequest, Response as OwnerResponse};
use qpx_http::body::Body;
use std::sync::Arc;

pub(in crate::reverse::transport) async fn try_dispatch_unconditional_plain_reverse_request<
    R: super::super::ReverseTerminalResponse,
>(
    req: OwnerRequest<Body>,
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
    state: &Arc<crate::runtime::RuntimeState>,
    connection_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<std::result::Result<(InterimList, R), OwnerRequest<Body>>> {
    let request_version = req.version();
    if state.destination_trace_enabled()
        || qpx_observability::metrics_enabled()
        || qpx_observability::request_spans_enabled()
        || !state.security.identity_sources.sources.is_empty()
        || req.method() == http::Method::CONNECT
        || !matches!(
            request_version,
            http::Version::HTTP_11 | http::Version::HTTP_2
        )
        || req.headers().contains_key(
            &qpx_core::http_message::OrdinaryHeaderName::try_from(http::header::UPGRADE)
                .expect("ordinary"),
        )
    {
        return Ok(Err(req));
    }
    let Some(compiled) = reverse.compiled_if_current(state) else {
        return Ok(Err(req));
    };
    let Some(route) = compiled.router.single_plain_http_route() else {
        return Ok(Err(req));
    };
    if !route.matches_every_request() || route.available_plain_http_upstream().is_none() {
        return Ok(Err(req));
    }
    if let Some(response) = reverse_security_rejection(&req, conn, state, &compiled)? {
        return Ok(Ok((response.0, R::from_finalized_owner(response.1))));
    }
    let request_method = req.method().clone();
    let req =
        match enforce_selected_reverse_route_constraints(req, route, &request_method, state, conn)?
        {
            Ok(req) => req,
            Err(mut response) => {
                apply_reverse_route_metadata(route, conn.tls_terminated, &mut response.1)?;
                return Ok(Ok((response.0, R::from_finalized_owner(response.1))));
            }
        };
    let (interim, mut response) = dispatch_plain_reverse_http(
        req,
        state,
        route,
        &request_method,
        request_version,
        state.plan.identity.proxy_name.as_ref(),
        connection_pool,
    )
    .await?;
    apply_reverse_route_metadata(route, conn.tls_terminated, &mut response)?;
    Ok(Ok((interim, R::from_finalized_owner(response))))
}

pub(super) async fn dispatch_plain_reverse_http(
    req: OwnerRequest<Body>,
    state: &crate::runtime::RuntimeState,
    route: &HttpRoute,
    request_method: &http::Method,
    request_version: http::Version,
    proxy_name: &str,
    connection_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<(InterimList, OwnerResponse<Body>)> {
    let selected_upstream = route
        .available_plain_http_upstream()
        .ok_or_else(|| anyhow!("plain HTTP fast path requires one static HTTP upstream"))?;
    let (connect_authority, host_authority) = selected_upstream
        .origin
        .direct_plain_http1_authorities()
        .ok_or_else(|| anyhow!("plain HTTP fast path requires a precompiled HTTP authority"))?;
    // Raw fast path keeps the hyper send boundary; preparation runs on the owner
    // with a single export immediately before the raw send.
    let req = prepare_proxy_http1_request(req, host_authority, proxy_name)?;
    let req = crate::upstream::http1::into_http1_for_codec(req)?;
    let started = route
        .policy
        .passive_health
        .as_ref()
        .is_some_and(|policy| policy.latency_threshold.is_some())
        .then(tokio::time::Instant::now);
    let response = timeout_after_pending(route.policy.timeout, async {
        if let Some(connection_pool) = connection_pool {
            proxy_direct_plain_http1_raw_response_with_interim_on_connection(
                &state.pools,
                req,
                connect_authority,
                host_authority,
                request_version,
                proxy_name,
                connection_pool,
            )
            .await
        } else {
            proxy_direct_plain_http1_raw_response_with_interim(
                &state.pools,
                req,
                connect_authority,
                host_authority,
                request_version,
                proxy_name,
            )
            .await
        }
    })
    .await;
    let (interim, response, response_finalized) = match response {
        Ok(Ok(response)) => (
            response.interim,
            // Import once from the network adapter; all remaining mutations use the owner.
            OwnerResponse::from_http(response.response),
            response.response_finalized,
        ),
        Ok(Err(err)) => {
            record_reverse_upstream_error(selected_upstream, &route.policy, &err);
            return Err(err);
        }
        Err(_) => {
            record_reverse_upstream_timeout(selected_upstream, &route.policy);
            return Err(anyhow!("upstream timeout"));
        }
    };
    record_reverse_upstream_status(selected_upstream, &route.policy, response.status(), started);
    let mut response = response;
    crate::http::capture::stream::limit_response_body_for_plan_in_place(&mut response, &route.plan);
    if !response_finalized {
        finalize_plain_reverse_response(request_method, proxy_name, &mut response);
    }
    debug_assert_ne!(request_version, http::Version::HTTP_3);
    Ok((interim, response))
}

fn finalize_plain_reverse_response(
    request_method: &http::Method,
    proxy_name: &str,
    response: &mut OwnerResponse<Body>,
) {
    // RFC 9110 §7.6.3: Via records the upstream response protocol, independently
    // of the downstream request version used for wire encoding.
    crate::http::protocol::l7::finalize_response_with_headers_in_place(
        request_method,
        response.version(),
        proxy_name,
        response,
        None,
        false,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Response;

    fn via_values(response: &Response<Body>) -> Vec<String> {
        response
            .headers()
            .get_all(http::header::VIA)
            .iter()
            .map(|value| value.to_str().expect("Via value").to_owned())
            .collect()
    }

    fn finalize_full_dispatch_reference(
        request_method: &http::Method,
        response: &mut Response<Body>,
    ) {
        // Full dispatch finalizes with the parsed upstream version
        // (`resp.version()` in `dispatch_http.rs`).
        let upstream_version = response.version();
        crate::http::protocol::l7::finalize_response_with_headers_in_place(
            request_method,
            upstream_version,
            "qpx",
            response,
            None,
            false,
        );
    }

    #[test]
    fn plain_response_via_uses_upstream_version_for_http2_downstream() {
        let request = http::Request::builder()
            .version(http::Version::HTTP_2)
            .body(Body::empty())
            .expect("downstream request");
        let response = Response::builder()
            .version(http::Version::HTTP_11)
            .header(http::header::VIA, "1.0 first")
            .header(http::header::VIA, "1.1 second")
            .body(Body::from("ok"))
            .expect("upstream response");

        let mut response = OwnerResponse::from_http(response);
        finalize_plain_reverse_response(request.method(), "qpx", &mut response);
        let response = response.into_http_for_library();

        assert_eq!(
            via_values(&response),
            ["1.0 first", "1.1 second", "1.1 qpx"]
        );
        assert_eq!(response.version(), http::Version::HTTP_11);
        assert_eq!(request.version(), http::Version::HTTP_2);
    }

    #[test]
    fn plain_response_via_uses_upstream_version_for_http10_upstream() {
        let request = http::Request::builder()
            .version(http::Version::HTTP_11)
            .body(Body::empty())
            .expect("downstream request");
        let response = Response::builder()
            .version(http::Version::HTTP_10)
            .header(http::header::VIA, "1.0 first")
            .header(http::header::VIA, "1.1 second")
            .body(Body::from("ok"))
            .expect("upstream response");

        let mut response = OwnerResponse::from_http(response);
        finalize_plain_reverse_response(request.method(), "qpx", &mut response);
        let response = response.into_http_for_library();

        assert_eq!(
            via_values(&response),
            ["1.0 first", "1.1 second", "1.0 qpx"]
        );
        assert_eq!(response.version(), http::Version::HTTP_10);
        assert_eq!(request.version(), http::Version::HTTP_11);
    }

    #[test]
    fn plain_fast_path_matches_full_dispatch_for_received_protocol() {
        for (downstream, upstream, expected) in [
            (http::Version::HTTP_2, http::Version::HTTP_11, "1.1 qpx"),
            (http::Version::HTTP_11, http::Version::HTTP_10, "1.0 qpx"),
        ] {
            let build_upstream = || {
                Response::builder()
                    .version(upstream)
                    .header(http::header::VIA, "1.0 first")
                    .header(http::header::VIA, "1.1 second")
                    .body(Body::from("ok"))
                    .expect("upstream response")
            };
            let mut fast = OwnerResponse::from_http(build_upstream());
            finalize_plain_reverse_response(&http::Method::GET, "qpx", &mut fast);
            let fast = fast.into_http_for_library();
            let mut full = build_upstream();
            finalize_full_dispatch_reference(&http::Method::GET, &mut full);
            assert_eq!(fast.version(), upstream);
            assert_eq!(full.version(), upstream);
            assert_eq!(via_values(&fast).last().map(String::as_str), Some(expected));
            assert_eq!(
                via_values(&fast),
                via_values(&full),
                "fast and full dispatch must agree for downstream {downstream:?}/upstream {upstream:?}"
            );
            // The downstream version must not leak into the received-protocol.
            let downstream_via = qpx_http::protocol::semantics::via_header_value(downstream, "qpx")
                .and_then(|value| value.to_str().ok().map(str::to_owned));
            if downstream_via.as_deref() != Some(expected) {
                assert_ne!(
                    via_values(&fast).last().map(String::as_str),
                    downstream_via.as_deref(),
                    "downstream {downstream:?} must not supply Via for upstream {upstream:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn plain_owned_finalization_matches_standard_headers_body_and_trailers() {
        use crate::http::capture::stream::limit_response_body_to_max_bytes;
        use bytes::Bytes;
        use http::{HeaderMap, HeaderValue, Method, StatusCode};

        for lengths in [
            vec![],
            vec!["0"],
            vec!["5"],
            vec!["05", "5"],
            vec!["invalid"],
            vec!["5", "6"],
        ] {
            for (method, status) in [
                (Method::GET, StatusCode::OK),
                (Method::HEAD, StatusCode::OK),
                (Method::GET, StatusCode::NO_CONTENT),
                (Method::GET, StatusCode::NOT_MODIFIED),
            ] {
                for max_bytes in [3, 8] {
                    let build = || {
                        let mut trailers = HeaderMap::new();
                        trailers.append("x-checksum", HeaderValue::from_static("first"));
                        trailers.append("x-checksum", HeaderValue::from_static("second"));
                        trailers
                            .insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("5"));
                        let mut response = Response::builder()
                            .version(http::Version::HTTP_11)
                            .status(status)
                            .header(http::header::VIA, "1.0 previous")
                            .header(http::header::CONNECTION, "x-hop")
                            .header("x-hop", "remove")
                            .header(http::header::TRAILER, "x-checksum")
                            .header("x-bytes", HeaderValue::from_bytes(b"a\x80b").unwrap())
                            .body(Body::replay(Bytes::from_static(b"hello"), Some(trailers)))
                            .unwrap();
                        for length in &lengths {
                            response.headers_mut().append(
                                http::header::CONTENT_LENGTH,
                                HeaderValue::from_str(length).unwrap(),
                            );
                        }
                        for value in ["first", "second"] {
                            let mut value = HeaderValue::from_static(value);
                            value.set_sensitive(true);
                            response.headers_mut().append("x-duplicate", value);
                        }
                        response.extensions_mut().insert(42_u32);
                        response
                    };
                    let mut owned = OwnerResponse::from_http(build());
                    limit_response_body_to_max_bytes(&mut owned, max_bytes);
                    finalize_plain_reverse_response(&method, "qpx", &mut owned);
                    // Export only for comparison with the standard library reference.
                    let mut owned = owned.into_http_for_library();
                    let mut standard = build();
                    limit_response_body_to_max_bytes(&mut standard, max_bytes);
                    finalize_full_dispatch_reference(&method, &mut standard);

                    assert_eq!(owned.status(), standard.status());
                    assert_eq!(owned.version(), standard.version());
                    assert_eq!(owned.headers(), standard.headers());
                    assert!(
                        owned
                            .headers()
                            .get_all("x-duplicate")
                            .iter()
                            .all(HeaderValue::is_sensitive)
                    );
                    assert_eq!(owned.extensions().get::<u32>(), Some(&42));
                    let mut bodies = Vec::new();
                    for response in [&mut owned, &mut standard] {
                        let mut bytes = Vec::new();
                        let mut error = None;
                        while let Some(data) = response.body_mut().data().await {
                            match data {
                                Ok(data) => bytes.extend_from_slice(&data),
                                Err(err) => {
                                    error = Some(err.to_string());
                                    break;
                                }
                            }
                        }
                        let trailers = response
                            .body_mut()
                            .trailers()
                            .await
                            .map_err(|err| err.to_string());
                        bodies.push((bytes, error, trailers));
                    }
                    if method == Method::GET && status == StatusCode::OK {
                        if max_bytes < 5 {
                            assert_eq!(
                                bodies[0].1.as_deref(),
                                Some("response body limit exceeded")
                            );
                        } else {
                            assert_eq!(bodies[0].0, b"hello");
                            let trailers = bodies[0].2.as_ref().unwrap().as_ref().unwrap();
                            assert!(!trailers.contains_key(http::header::CONTENT_LENGTH));
                            assert_eq!(trailers.get_all("x-checksum").iter().count(), 2);
                        }
                    }
                    assert_eq!(
                        bodies[0], bodies[1],
                        "{method} {status} {lengths:?} limit={max_bytes}"
                    );
                }
            }
        }
    }
}
