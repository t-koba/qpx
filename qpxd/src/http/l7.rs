use crate::http::header_control::{apply_request_headers, apply_response_headers};
use crate::http::semantics::{
    append_via_for_version, normalize_response_for_request, sanitize_hop_by_hop_headers,
    sync_host_header_from_absolute_target,
};
use hyper::{Body, Method, Request, Response, StatusCode};
use qpx_core::rules::CompiledHeaderControl;
use std::collections::HashSet;
use std::time::SystemTime;

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
    normalize_response_for_request(request_method, response);
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

pub fn prepare_request_with_headers_in_place(
    request: &mut Request<Body>,
    proxy_name: &str,
    header_control: Option<&CompiledHeaderControl>,
    preserve_upgrade: bool,
) {
    let request_version = request.version();
    apply_request_headers(request.headers_mut(), header_control);
    let request_uri = request.uri().clone();
    sync_host_header_from_absolute_target(request.headers_mut(), &request_uri);
    sanitize_hop_by_hop_headers(request.headers_mut(), preserve_upgrade);
    append_via_for_version(request.headers_mut(), request_version, proxy_name);
    qpx_core::observability::inject_trace_context(request.headers_mut());
}

pub fn handle_max_forwards_in_place(
    request: &mut Request<Body>,
    proxy_name: &str,
    trace_reflect_all_headers: bool,
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
                let body = serialize_request_headers_only(request, trace_reflect_all_headers);
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

fn serialize_request_headers_only(
    request: &Request<Body>,
    trace_reflect_all_headers: bool,
) -> String {
    let mut out = String::new();
    let version = match request.version() {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2",
        http::Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    };
    out.push_str(request.method().as_str());
    out.push(' ');
    out.push_str(request.uri().to_string().as_str());
    out.push(' ');
    out.push_str(version);
    out.push_str("\r\n");
    let connection_tokens = parse_connection_tokens(request.headers());
    for (name, value) in request.headers().iter() {
        let lower = name.as_str();
        if !should_reflect_trace_header(lower, &connection_tokens, trace_reflect_all_headers) {
            continue;
        }
        out.push_str(name.as_str());
        out.push_str(": ");
        if let Ok(v) = value.to_str() {
            out.push_str(v);
        }
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

fn parse_connection_tokens(headers: &http::HeaderMap) -> HashSet<String> {
    let mut out = HashSet::new();
    for value in headers.get_all(http::header::CONNECTION) {
        let Ok(s) = value.to_str() else {
            continue;
        };
        for token in s.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                out.insert(token.to_ascii_lowercase());
            }
        }
    }
    out
}

fn should_reflect_trace_header(
    lower_name: &str,
    connection_tokens: &HashSet<String>,
    trace_reflect_all_headers: bool,
) -> bool {
    if trace_reflect_all_headers {
        return true;
    }
    if connection_tokens.contains(lower_name) {
        return false;
    }
    if crate::http::semantics::is_hop_by_hop_header_name(lower_name) {
        return false;
    }
    // Prefer an allowlist in the default mode to avoid leaking custom secret headers.
    matches!(
        lower_name,
        "host"
            | "user-agent"
            | "accept"
            | "accept-language"
            | "accept-encoding"
            | "cache-control"
            | "pragma"
            | "content-type"
            | "content-length"
            | "range"
            | "if-match"
            | "if-none-match"
            | "if-modified-since"
            | "if-unmodified-since"
            | "if-range"
            | "via"
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "x-request-id"
            | "traceparent"
            | "tracestate"
    )
}
