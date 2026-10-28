use crate::http::protocol::common::trim_http_ows;
use crate::http::protocol::header_control::{
    ResponseHeaderControl, apply_request_headers, apply_response_headers,
};
use crate::http::protocol::trailer_body;
use hyper::{Method, Response, StatusCode};
use qpx_core::http_message::{OrdinaryHeaderMut, OrdinaryHeaderName, Request};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use qpx_http::protocol::finalization::FinalizeResponse;
use qpx_http::protocol::semantics::{
    append_via_for_version, normalize_response_for_request_with_options,
    sanitize_hop_by_hop_headers,
};
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::time::timeout;
use tracing::warn;

pub(crate) fn finalize_response_for_request(
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

pub(crate) fn finalize_response_in_place<R: FinalizeResponse<Body = Body>>(
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    response: &mut R,
    preserve_upgrade: bool,
) {
    if response
        .extensions()
        .get::<Arc<crate::upstream::raw_http1::RawHttp1ResponseHead>>()
        .is_some()
    {
        if response.status().is_informational() {
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            *response.body_mut() = Body::empty();
        }
        if let Some(raw) = response
            .extensions_mut()
            .get_mut::<Arc<crate::upstream::raw_http1::RawHttp1ResponseHead>>()
        {
            if !raw.is_finalized() {
                Arc::make_mut(raw).finalize(proxy_name);
            }
            wrap_body_sanitizing_response_trailers(response);
            return;
        }
    }
    finalize_response_headers_common(request_version, proxy_name, response, preserve_upgrade);
    normalize_response_for_request_with_options(request_method, response, preserve_upgrade);
    wrap_body_sanitizing_response_trailers(response);
}

fn finalize_response_headers_common<R: FinalizeResponse<Body = Body>>(
    request_version: http::Version,
    proxy_name: &str,
    response: &mut R,
    preserve_upgrade: bool,
) {
    let preserve_proxy_auth = response.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED;
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
    if let Err(error) =
        qpx_http::proxy_status::append_proxy_status(response.headers_mut(), proxy_name)
    {
        warn!(error = %error, "discarding invalid inbound Proxy-Status field");
        response
            .headers_mut()
            .ordinary_remove(&OrdinaryHeaderName::try_from("proxy-status").expect("ordinary"));
        if let Err(error) =
            qpx_http::proxy_status::append_proxy_status(response.headers_mut(), proxy_name)
        {
            warn!(error = %error, "failed to emit Proxy-Status field");
        }
    }
    append_via_for_version(response.headers_mut(), request_version, proxy_name);
}

fn collect_header_values(headers: &impl OrdinaryHeaderMut, name: &str) -> Vec<http::HeaderValue> {
    let name = OrdinaryHeaderName::try_from(name).expect("ordinary");
    headers.ordinary_values(&name).cloned().collect()
}

fn restore_header_values(
    headers: &mut impl OrdinaryHeaderMut,
    name: &str,
    values: &[http::HeaderValue],
) {
    let Ok(name) = OrdinaryHeaderName::try_from(name) else {
        return;
    };
    for value in values {
        headers.ordinary_append(name.clone(), value.clone());
    }
}

fn ensure_date_header(headers: &mut impl OrdinaryHeaderMut) {
    let date = OrdinaryHeaderName::try_from(http::header::DATE).expect("ordinary");
    if headers.ordinary_values(&date).next().is_some() {
        return;
    }
    headers.ordinary_insert(date, cached_date_header_value());
}

pub(crate) fn cached_date_header_value() -> http::HeaderValue {
    let epoch_second = cached_epoch_second();
    CACHED_DATE_HEADER.with_borrow_mut(|cached| {
        if let Some((cached_second, value)) = cached.as_ref()
            && *cached_second == epoch_second
        {
            return value.clone();
        }
        let rounded = SystemTime::UNIX_EPOCH + Duration::from_secs(epoch_second);
        let formatted = httpdate::fmt_http_date(rounded);
        let value = match http::HeaderValue::from_str(&formatted) {
            Ok(value) => value,
            Err(error) => {
                warn!(error = %error, "HTTP-date formatter produced an invalid field value");
                http::HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT")
            }
        };
        *cached = Some((epoch_second, value.clone()));
        value
    })
}

pub(crate) fn cached_epoch_second() -> u64 {
    let cached = CACHED_DATE_EPOCH_SECOND.load(Ordering::Relaxed);
    if cached == 0 {
        current_epoch_second()
    } else {
        cached
    }
}

pub(crate) fn start_cached_date_updater() {
    if CACHED_DATE_UPDATER_STARTED.swap(true, Ordering::Relaxed) {
        return;
    }
    CACHED_DATE_EPOCH_SECOND.store(current_epoch_second(), Ordering::Relaxed);
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            CACHED_DATE_EPOCH_SECOND.store(current_epoch_second(), Ordering::Relaxed);
        }
    });
}

fn current_epoch_second() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

static CACHED_DATE_UPDATER_STARTED: AtomicBool = AtomicBool::new(false);
static CACHED_DATE_EPOCH_SECOND: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static CACHED_DATE_HEADER: RefCell<Option<(u64, http::HeaderValue)>> = const {
        RefCell::new(None)
    };
}

fn finalize_extended_connect_response_in_place(
    request_version: http::Version,
    proxy_name: &str,
    response: &mut Response<Body>,
    preserve_upgrade: bool,
) {
    finalize_response_headers_common(request_version, proxy_name, response, preserve_upgrade);
    wrap_body_sanitizing_response_trailers(response);
}

pub(crate) fn finalize_response_with_headers(
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

pub(crate) fn finalize_response_with_headers_in_place<R>(
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    response: &mut R,
    header_control: Option<&CompiledHeaderControl>,
    preserve_upgrade: bool,
) where
    R: FinalizeResponse<Body = Body>,
    R::Headers: ResponseHeaderControl,
{
    apply_response_headers(response.headers_mut(), header_control);
    finalize_response_in_place(
        request_method,
        request_version,
        proxy_name,
        response,
        preserve_upgrade,
    );
}

pub(crate) fn finalize_extended_connect_response_with_headers(
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

pub(crate) fn finalize_extended_connect_response_with_headers_in_place(
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

/// Consume client hop metadata before synthesizing trusted request fields.
/// Upgrade candidates and Trailer declarations still belong to the later handshake
/// and body validation stages; the final request sanitizer removes them as needed.
pub(crate) fn consume_request_hop_headers(request: &mut Request<Body>) {
    let deferred: Vec<_> = [http::header::UPGRADE, http::header::TRAILER]
        .into_iter()
        .flat_map(|name| {
            request
                .headers()
                .get_all(&OrdinaryHeaderName::try_from(name.clone()).expect("ordinary field"))
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .map(move |value| (name.clone(), value))
        })
        .collect();
    qpx_http::protocol::semantics::sanitize_request_hop_by_hop_headers(request.headers_mut(), true);
    request
        .headers_mut()
        .remove(&OrdinaryHeaderName::try_from(http::header::UPGRADE).expect("ordinary field"));
    request
        .headers_mut()
        .remove(&OrdinaryHeaderName::try_from(http::header::TRAILER).expect("ordinary field"));
    for (name, value) in deferred {
        request.headers_mut().append(
            OrdinaryHeaderName::try_from(name).expect("ordinary field"),
            value,
        );
    }
}

// A module can supply trailers without a declaration, even after request
// preparation stripped Trailer or normalized HTTP/2 to HTTP/1.1. Validate only
// replaced bodies on re-entry, independent of the now-normalized request head.
#[derive(Clone)]
struct ModuleRequestBodyReplaced;

pub(crate) fn mark_module_request_body_replaced(request: &mut Request<Body>) {
    request.extensions_mut().insert(ModuleRequestBodyReplaced);
}

pub(crate) fn replace_module_request_body(request: &mut Request<Body>, body: Body) {
    *request.body_mut() = body;
    mark_module_request_body_replaced(request);
}

pub(crate) fn prepare_module_request_body_in_place(request: &mut Request<Body>) {
    if request
        .extensions_mut()
        .remove::<ModuleRequestBodyReplaced>()
        .is_some()
        && !http_body::Body::is_end_stream(request.body())
    {
        wrap_body_validating_request_trailers(request);
    }
}

pub(crate) fn prepare_request_with_headers_in_place(
    request: &mut Request<Body>,
    proxy_name: &str,
    header_control: Option<&CompiledHeaderControl>,
    preserve_upgrade: bool,
) {
    prepare_request_headers_in_place(request, proxy_name, header_control, preserve_upgrade, true);
}

pub(crate) fn prepare_request_for_fixed_authority_in_place(
    request: &mut Request<Body>,
    proxy_name: &str,
) {
    prepare_request_headers_in_place(request, proxy_name, None, false, false);
}

fn prepare_request_headers_in_place(
    request: &mut Request<Body>,
    proxy_name: &str,
    header_control: Option<&CompiledHeaderControl>,
    preserve_upgrade: bool,
    sync_target_authority: bool,
) {
    let request_version = request.version();
    let module_body_replaced = request
        .extensions_mut()
        .remove::<ModuleRequestBodyReplaced>()
        .is_some();
    let validate_trailers = module_body_replaced
        || request_version == http::Version::HTTP_2
        || request.headers().contains_key(
            &OrdinaryHeaderName::try_from(http::header::TRAILER).expect("ordinary field"),
        );
    qpx_http::protocol::semantics::sanitize_request_hop_by_hop_headers(
        request.headers_mut(),
        preserve_upgrade,
    );
    apply_request_headers(request.headers_mut(), header_control);
    if sync_target_authority && request.uri().authority().is_some() {
        let request_uri = request.uri().clone();
        if let Some(authority) = request_uri.authority()
            && let Ok(value) = http::HeaderValue::from_str(authority.as_str())
        {
            request.headers_mut().insert(
                OrdinaryHeaderName::try_from("host").expect("ordinary field"),
                value,
            );
        }
    }
    qpx_http::protocol::semantics::sanitize_request_hop_by_hop_headers(
        request.headers_mut(),
        preserve_upgrade,
    );
    if let Some(value) =
        qpx_http::protocol::semantics::via_header_value(request_version, proxy_name)
    {
        request.headers_mut().append(
            OrdinaryHeaderName::try_from("via").expect("ordinary field"),
            value,
        );
    }
    qpx_observability::inject_trace_context(request.headers_mut());
    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    if let Some(deadline) = request
        .extensions()
        .get::<crate::http::rpc::ResolvedGrpcDeadline>()
        .copied()
    {
        crate::http::rpc::apply_grpc_deadline_header(request.headers_mut(), deadline);
    }
    if validate_trailers && !http_body::Body::is_end_stream(request.body()) {
        wrap_body_validating_request_trailers(request);
    }
}

pub(crate) fn apply_request_header_control_in_place(
    request: &mut Request<Body>,
    header_control: Option<&CompiledHeaderControl>,
) {
    apply_request_headers(request.headers_mut(), header_control);
}

fn parse_max_forwards_value(raw: &str) -> Option<u64> {
    let raw = trim_http_ows(raw);
    if raw.is_empty() {
        return None;
    }

    // RFC 9110 §7.6.2 permits capping at the recipient's maximum supported value.
    // qpx's supported forwarding limit is u32::MAX; retain one above it so MAX + 1
    // decrements to the limit exactly.
    let cap = u64::from(u32::MAX) + 1;
    let mut parsed = 0u64;
    for digit in raw.bytes() {
        if !digit.is_ascii_digit() {
            return None;
        }
        parsed = parsed
            .saturating_mul(10)
            .saturating_add(u64::from(digit - b'0'))
            .min(cap);
    }
    Some(parsed)
}

pub(crate) async fn handle_max_forwards_in_place(
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
        .get_all(&OrdinaryHeaderName::try_from(http::header::MAX_FORWARDS).expect("ordinary field"))
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
    let Some(parsed) = parse_max_forwards_value(raw) else {
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

    let next = (parsed - 1).min(u64::from(u32::MAX)).to_string();
    if let Ok(value) = http::HeaderValue::from_str(next.as_str()) {
        request.headers_mut().insert(
            OrdinaryHeaderName::try_from(http::header::MAX_FORWARDS).expect("ordinary field"),
            value,
        );
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
    request.headers().write_http_field_lines(&mut out, |name| {
        should_reflect_trace_header(name, reflect_all_headers)
    });
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
    if qpx_http::protocol::semantics::is_hop_by_hop_header_name(lower.as_str()) {
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
    let inner = std::mem::take(request.body_mut());
    *request.body_mut() = trailer_body::validating_request(inner);
}

fn wrap_body_sanitizing_response_trailers<R: FinalizeResponse<Body = Body>>(response: &mut R) {
    if response.body().trailers_are_sanitized() {
        return;
    }
    let inner = std::mem::take(response.body_mut());
    *response.body_mut() = trailer_body::sanitizing_response(inner);
}

#[cfg(test)]
mod tests;
