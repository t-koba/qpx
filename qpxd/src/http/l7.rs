use crate::http::body::Body;
use crate::http::header_control::{apply_request_headers, apply_response_headers};
use crate::http::semantics::{
    append_via_for_version, normalize_response_for_request_with_options,
    sanitize_hop_by_hop_headers, sync_host_header_from_absolute_target,
};
use hyper::{Method, Request, Response, StatusCode};
use qpx_core::rules::CompiledHeaderControl;
use std::time::{Duration, SystemTime};
use tokio::time::timeout;
use tracing::warn;

const TRAILER_WRAPPER_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub fn finalize_response_for_request(
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    mut response: Response<Body>,
    preserve_upgrade: bool,
) -> Response<Body> {
    finalize_response_in_place(
        request_method,
        request_version,
        proxy_name,
        &mut response,
        preserve_upgrade,
    );
    response
}

pub fn finalize_response_in_place(
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    response: &mut Response<Body>,
    preserve_upgrade: bool,
) {
    let preserve_proxy_auth = response.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    let proxy_authenticate = if preserve_proxy_auth {
        collect_header_values(response.headers(), "proxy-authenticate")
    } else {
        Vec::new()
    };
    let proxy_auth_info = if preserve_proxy_auth {
        collect_header_values(response.headers(), "proxy-authentication-info")
    } else {
        Vec::new()
    };

    sanitize_hop_by_hop_headers(response.headers_mut(), preserve_upgrade);
    if preserve_proxy_auth {
        restore_header_values(
            response.headers_mut(),
            "proxy-authenticate",
            &proxy_authenticate,
        );
        restore_header_values(
            response.headers_mut(),
            "proxy-authentication-info",
            &proxy_auth_info,
        );
    }
    ensure_date_header(response.headers_mut());
    append_via_for_version(response.headers_mut(), request_version, proxy_name);
    normalize_response_for_request_with_options(request_method, response, preserve_upgrade);
    wrap_body_sanitizing_response_trailers(response);
}

fn collect_header_values(headers: &http::HeaderMap, name: &str) -> Vec<http::HeaderValue> {
    headers
        .get_all(name)
        .iter()
        .cloned()
        .collect::<Vec<http::HeaderValue>>()
}

fn restore_header_values(headers: &mut http::HeaderMap, name: &str, values: &[http::HeaderValue]) {
    let Ok(name) = http::header::HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    for value in values {
        headers.append(name.clone(), value.clone());
    }
}

fn ensure_date_header(headers: &mut http::HeaderMap) {
    if headers.contains_key(http::header::DATE) {
        return;
    }
    let value = httpdate::fmt_http_date(SystemTime::now());
    if let Ok(hv) = http::HeaderValue::from_str(value.as_str()) {
        headers.insert(http::header::DATE, hv);
    }
}

fn finalize_extended_connect_response_in_place(
    request_version: http::Version,
    proxy_name: &str,
    response: &mut Response<Body>,
    preserve_upgrade: bool,
) {
    let preserve_proxy_auth = response.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    let proxy_authenticate = if preserve_proxy_auth {
        collect_header_values(response.headers(), "proxy-authenticate")
    } else {
        Vec::new()
    };
    let proxy_auth_info = if preserve_proxy_auth {
        collect_header_values(response.headers(), "proxy-authentication-info")
    } else {
        Vec::new()
    };

    sanitize_hop_by_hop_headers(response.headers_mut(), preserve_upgrade);
    if preserve_proxy_auth {
        restore_header_values(
            response.headers_mut(),
            "proxy-authenticate",
            &proxy_authenticate,
        );
        restore_header_values(
            response.headers_mut(),
            "proxy-authentication-info",
            &proxy_auth_info,
        );
    }
    ensure_date_header(response.headers_mut());
    append_via_for_version(response.headers_mut(), request_version, proxy_name);
    wrap_body_sanitizing_response_trailers(response);
}

pub fn finalize_response_with_headers(
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    mut response: Response<Body>,
    header_control: Option<&CompiledHeaderControl>,
    preserve_upgrade: bool,
) -> Response<Body> {
    finalize_response_with_headers_in_place(
        request_method,
        request_version,
        proxy_name,
        &mut response,
        header_control,
        preserve_upgrade,
    );
    response
}

pub fn finalize_response_with_headers_in_place(
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    response: &mut Response<Body>,
    header_control: Option<&CompiledHeaderControl>,
    preserve_upgrade: bool,
) {
    apply_response_headers(response.headers_mut(), header_control);
    finalize_response_in_place(
        request_method,
        request_version,
        proxy_name,
        response,
        preserve_upgrade,
    );
}

pub fn finalize_extended_connect_response_with_headers(
    request_version: http::Version,
    proxy_name: &str,
    mut response: Response<Body>,
    header_control: Option<&CompiledHeaderControl>,
    preserve_upgrade: bool,
) -> Response<Body> {
    finalize_extended_connect_response_with_headers_in_place(
        request_version,
        proxy_name,
        &mut response,
        header_control,
        preserve_upgrade,
    );
    response
}

pub fn finalize_extended_connect_response_with_headers_in_place(
    request_version: http::Version,
    proxy_name: &str,
    response: &mut Response<Body>,
    header_control: Option<&CompiledHeaderControl>,
    preserve_upgrade: bool,
) {
    apply_response_headers(response.headers_mut(), header_control);
    finalize_extended_connect_response_in_place(
        request_version,
        proxy_name,
        response,
        preserve_upgrade,
    );
}

pub fn prepare_request_with_headers_in_place(
    request: &mut Request<Body>,
    proxy_name: &str,
    header_control: Option<&CompiledHeaderControl>,
    preserve_upgrade: bool,
) {
    let request_version = request.version();
    let validate_trailers = request_version == http::Version::HTTP_2
        || request.headers().contains_key(http::header::TRAILER);
    apply_request_headers(request.headers_mut(), header_control);
    let request_uri = request.uri().clone();
    sync_host_header_from_absolute_target(request.headers_mut(), &request_uri);
    sanitize_hop_by_hop_headers(request.headers_mut(), preserve_upgrade);
    append_via_for_version(request.headers_mut(), request_version, proxy_name);
    qpx_observability::inject_trace_context(request.headers_mut());
    if validate_trailers {
        wrap_body_validating_request_trailers(request);
    }
}

pub async fn handle_max_forwards_in_place(
    request: &mut Request<Body>,
    proxy_name: &str,
    trace_reflect_all_headers: bool,
    max_trace_body_bytes: usize,
    trace_body_read_timeout: Duration,
) -> Option<Response<Body>> {
    if request.method() != Method::TRACE && request.method() != Method::OPTIONS {
        return None;
    }

    let values: Vec<_> = request
        .headers()
        .get_all(http::header::MAX_FORWARDS)
        .iter()
        .collect();
    if values.is_empty() {
        return None;
    }
    if values.len() != 1 {
        return Some(finalize_response_for_request(
            request.method(),
            request.version(),
            proxy_name,
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("invalid Max-Forwards"))
                .unwrap_or_else(|_| Response::new(Body::from("invalid Max-Forwards"))),
            false,
        ));
    }
    let Ok(raw) = values[0].to_str() else {
        return Some(finalize_response_for_request(
            request.method(),
            request.version(),
            proxy_name,
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("invalid Max-Forwards"))
                .unwrap_or_else(|_| Response::new(Body::from("invalid Max-Forwards"))),
            false,
        ));
    };
    let raw = raw.trim();
    let Ok(parsed) = raw.parse::<u32>() else {
        return Some(finalize_response_for_request(
            request.method(),
            request.version(),
            proxy_name,
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("invalid Max-Forwards"))
                .unwrap_or_else(|_| Response::new(Body::from("invalid Max-Forwards"))),
            false,
        ));
    };
    if parsed == 0 {
        let response = match *request.method() {
            Method::TRACE => {
                let body = match serialize_trace_loopback_message(
                    request,
                    trace_reflect_all_headers,
                    max_trace_body_bytes,
                    trace_body_read_timeout,
                )
                .await
                {
                    Ok(body) => body,
                    Err(err) => {
                        warn!(error = ?err, "failed to serialize TRACE loop-back body");
                        return Some(finalize_response_for_request(
                            request.method(),
                            request.version(),
                            proxy_name,
                            Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from("trace failed"))
                                .unwrap_or_else(|_| Response::new(Body::from("trace failed"))),
                            false,
                        ));
                    }
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "message/http; charset=utf-8")
                    .body(Body::from(body))
                    .unwrap_or_else(|_| Response::new(Body::from("trace failed")))
            }
            Method::OPTIONS => Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty())),
            _ => Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("invalid Max-Forwards"))
                .unwrap_or_else(|_| Response::new(Body::from("invalid Max-Forwards"))),
        };
        return Some(finalize_response_for_request(
            request.method(),
            request.version(),
            proxy_name,
            response,
            false,
        ));
    }

    let next = (parsed - 1).to_string();
    if let Ok(value) = http::HeaderValue::from_str(next.as_str()) {
        request
            .headers_mut()
            .insert(http::header::MAX_FORWARDS, value);
    }
    None
}

async fn serialize_trace_loopback_message(
    request: &mut Request<Body>,
    reflect_all_headers: bool,
    max_body_bytes: usize,
    read_timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    let version = match request.version() {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2",
        http::Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    };
    out.extend_from_slice(request.method().as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(request.uri().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(version.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in request.headers().iter() {
        if !should_reflect_trace_header(name, reflect_all_headers) {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    let mut body_bytes = 0usize;
    while let Some(frame) = timeout(read_timeout, request.body_mut().data())
        .await
        .map_err(|_| anyhow::anyhow!("TRACE request body read timed out"))?
    {
        let chunk = frame?;
        if !chunk.is_empty() {
            body_bytes = body_bytes
                .checked_add(chunk.len())
                .ok_or_else(|| anyhow::anyhow!("TRACE request body size overflow"))?;
            if body_bytes > max_body_bytes {
                return Err(anyhow::anyhow!(
                    "TRACE request body exceeds hard cap of {} bytes",
                    max_body_bytes
                ));
            }
            out.extend_from_slice(&chunk);
        }
    }
    Ok(out)
}

fn should_reflect_trace_header(name: &http::header::HeaderName, reflect_all_headers: bool) -> bool {
    if reflect_all_headers {
        return true;
    }

    let lower = name.as_str().to_ascii_lowercase();
    if crate::http::semantics::is_hop_by_hop_header_name(lower.as_str()) {
        return false;
    }

    !matches!(
        lower.as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-forwarded-port"
            | "x-real-ip"
            | "x-client-ip"
            | "true-client-ip"
            | "cf-connecting-ip"
            | "traceparent"
            | "tracestate"
            | "baggage"
    )
}

fn wrap_body_validating_request_trailers(request: &mut Request<Body>) {
    let mut inner = std::mem::take(request.body_mut());
    let (mut sender, out) = Body::channel();
    tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                _ = sender.closed() => return,
                frame = timeout(TRAILER_WRAPPER_BODY_IDLE_TIMEOUT, inner.data()) => match frame {
                    Ok(frame) => frame,
                    Err(_) => {
                        warn!("request body trailer wrapper timed out while idle");
                        sender.abort();
                        return;
                    }
                },
            };
            let Some(frame) = frame else {
                break;
            };
            let chunk = match frame {
                Ok(chunk) => chunk,
                Err(err) => {
                    warn!(error = ?err, "request body stream failed");
                    return;
                }
            };
            if sender.send_data(chunk).await.is_err() {
                return;
            }
        }
        let trailers = match tokio::select! {
            _ = sender.closed() => return,
            trailers = timeout(TRAILER_WRAPPER_BODY_IDLE_TIMEOUT, inner.trailers()) => match trailers {
                Ok(trailers) => trailers,
                Err(_) => {
                    warn!("request body trailers timed out while idle");
                    sender.abort();
                    return;
                }
            },
        } {
            Ok(trailers) => trailers,
            Err(err) => {
                warn!(error = ?err, "request body trailers failed");
                return;
            }
        };
        if let Some(trailers) = trailers {
            if let Err(err) = crate::http::semantics::validate_request_trailers(&trailers) {
                warn!(error = ?err, "dropping forbidden request trailers");
                return;
            }
            let _ = sender.send_trailers(trailers).await;
        }
    });
    *request.body_mut() = out;
}

fn wrap_body_sanitizing_response_trailers(response: &mut Response<Body>) {
    let mut inner = std::mem::take(response.body_mut());
    let (mut sender, out) = Body::channel();
    tokio::spawn(async move {
        loop {
            let frame = tokio::select! {
                _ = sender.closed() => return,
                frame = timeout(TRAILER_WRAPPER_BODY_IDLE_TIMEOUT, inner.data()) => match frame {
                    Ok(frame) => frame,
                    Err(_) => {
                        warn!("response body trailer wrapper timed out while idle");
                        sender.abort();
                        return;
                    }
                },
            };
            let Some(frame) = frame else {
                break;
            };
            let chunk = match frame {
                Ok(chunk) => chunk,
                Err(err) => {
                    warn!(error = ?err, "response body stream failed");
                    return;
                }
            };
            if sender.send_data(chunk).await.is_err() {
                return;
            }
        }
        let trailers = match tokio::select! {
            _ = sender.closed() => return,
            trailers = timeout(TRAILER_WRAPPER_BODY_IDLE_TIMEOUT, inner.trailers()) => match trailers {
                Ok(trailers) => trailers,
                Err(_) => {
                    warn!("response body trailers timed out while idle");
                    sender.abort();
                    return;
                }
            },
        } {
            Ok(trailers) => trailers,
            Err(err) => {
                warn!(error = ?err, "response body trailers failed");
                return;
            }
        };
        if let Some(mut trailers) = trailers {
            let removed = crate::http::semantics::sanitize_response_trailers(&mut trailers);
            if removed > 0 {
                warn!(removed, "dropping forbidden response trailers");
            }
            let _ = sender.send_trailers(trailers).await;
        }
    });
    *response.body_mut() = out;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn finalize_response_sanitizes_h2_trailers_for_h1_downstream() {
        let (mut sender, body) = Body::channel();
        tokio::spawn(async move {
            let _ = sender.send_data(Bytes::from_static(b"ok")).await;
            let mut trailers = http::HeaderMap::new();
            trailers.insert(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_static("99"),
            );
            trailers.insert("x-allowed", http::HeaderValue::from_static("kept"));
            let _ = sender.send_trailers(trailers).await;
        });

        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(body)
            .unwrap();
        finalize_response_in_place(
            &Method::GET,
            http::Version::HTTP_11,
            "qpx",
            &mut response,
            false,
        );

        let body = response.body_mut();
        let chunk = body.data().await.unwrap().unwrap();
        assert_eq!(chunk, Bytes::from_static(b"ok"));

        let trailers = body.trailers().await.unwrap().expect("trailers");
        assert!(!trailers.contains_key(http::header::CONTENT_LENGTH));
        assert_eq!(
            trailers
                .get("x-allowed")
                .and_then(|value| value.to_str().ok()),
            Some("kept")
        );
    }

    #[tokio::test]
    async fn trace_loopback_filters_sensitive_headers_by_default() {
        let mut request = Request::builder()
            .method(Method::TRACE)
            .uri("http://example.com/trace")
            .header(http::header::HOST, "example.com")
            .header(http::header::AUTHORIZATION, "Bearer secret")
            .header(http::header::COOKIE, "sid=abc")
            .header(http::header::CONNECTION, "keep-alive")
            .header("x-forwarded-for", "203.0.113.9")
            .header("traceparent", "00-abc-123-01")
            .header("x-visible", "kept")
            .body(Body::from("body"))
            .expect("request");

        let body =
            serialize_trace_loopback_message(&mut request, false, 1024, Duration::from_secs(1))
                .await
                .expect("trace body");
        let body = String::from_utf8(body).expect("utf8");

        assert!(body.contains("TRACE http://example.com/trace HTTP/1.1\r\n"));
        assert!(body.contains("host: example.com\r\n"));
        assert!(body.contains("x-visible: kept\r\n"));
        assert!(!body.contains("authorization:"));
        assert!(!body.contains("cookie:"));
        assert!(!body.contains("connection:"));
        assert!(!body.contains("x-forwarded-for:"));
        assert!(!body.contains("traceparent:"));
        assert!(body.ends_with("\r\n\r\nbody"));
    }

    #[tokio::test]
    async fn trace_loopback_can_reflect_all_headers_when_enabled() {
        let mut request = Request::builder()
            .method(Method::TRACE)
            .uri("http://example.com/trace")
            .header(http::header::HOST, "example.com")
            .header(http::header::AUTHORIZATION, "Bearer secret")
            .header("x-forwarded-for", "203.0.113.9")
            .body(Body::empty())
            .expect("request");

        let body =
            serialize_trace_loopback_message(&mut request, true, 1024, Duration::from_secs(1))
                .await
                .expect("trace body");
        let body = String::from_utf8(body).expect("utf8");

        assert!(body.contains("authorization: Bearer secret\r\n"));
        assert!(body.contains("x-forwarded-for: 203.0.113.9\r\n"));
    }

    #[tokio::test]
    async fn trace_loopback_rejects_body_above_hard_cap() {
        let mut request = Request::builder()
            .method(Method::TRACE)
            .uri("http://example.com/trace")
            .body(Body::from("body"))
            .expect("request");

        let err = serialize_trace_loopback_message(&mut request, false, 3, Duration::from_secs(1))
            .await
            .expect_err("trace body above cap");
        assert!(err.to_string().contains("TRACE request body exceeds"));
    }
}
