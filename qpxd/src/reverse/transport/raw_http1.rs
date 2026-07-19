use super::mirrors::{
    record_reverse_upstream_error, record_reverse_upstream_status, record_reverse_upstream_timeout,
};
use super::{InterimList, ReverseConnInfo};
use crate::http::codec::lazy_timeout::timeout_after_pending;
use crate::reverse::{CompiledReverse, ReloadableReverse};
use crate::upstream::origin::{
    PreparedPlainHttp1Origin, PreparedPlainHttp1Session, prepare_plain_http1_origin,
    proxy_prepared_plain_http1_head_raw_response_with_interim,
};
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use http::uri::{Authority, Uri};
use http::{HeaderMap, Method, Request, Response, StatusCode, Version};
use qpx_core::rules::RuleMatchContext;
use qpx_http::body::Body;
use std::sync::Arc;

pub(in crate::reverse) struct RawHttp1RequestView<'a> {
    pub(in crate::reverse) raw_head: &'a [u8],
    pub(in crate::reverse) method: &'a str,
    pub(in crate::reverse) target: &'a str,
    pub(in crate::reverse) version: u8,
    pub(in crate::reverse) headers: &'a [httparse::Header<'a>],
}

pub(in crate::reverse) struct PreparedRawHttp1Request {
    state: Arc<crate::runtime::RuntimeState>,
    compiled: Arc<CompiledReverse>,
    target: PreparedRawHttp1Target,
    method: Method,
    keep_alive: bool,
}

enum PreparedRawHttp1Target {
    Origin {
        request_head: Bytes,
        origin: PreparedPlainHttp1Origin,
    },
    LocalResponse,
    Generic {
        uri: Uri,
        headers: HeaderMap,
    },
}

pub(in crate::reverse) enum PreparedRawHttp1Response {
    Direct(crate::upstream::raw_http1::RawHttp1ResponseRelay<tokio::net::TcpStream>),
    InMemory {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    },
    Generic(InterimList, Response<Body>),
}

impl PreparedRawHttp1Request {
    pub(in crate::reverse) fn method(&self) -> &Method {
        &self.method
    }

    pub(in crate::reverse) fn keep_alive(&self) -> bool {
        self.keep_alive
    }

    pub(in crate::reverse) fn generic_request(&self) -> Option<Request<Body>> {
        let PreparedRawHttp1Target::Generic { uri, headers } = &self.target else {
            return None;
        };
        let mut request = Request::new(Body::empty());
        *request.method_mut() = self.method.clone();
        *request.uri_mut() = uri.clone();
        *request.version_mut() = Version::HTTP_11;
        *request.headers_mut() = headers.clone();
        Some(request)
    }
}

#[derive(Default)]
pub(in crate::reverse) struct RawHttp1ConnectionCache {
    authority: Option<CachedAuthority>,
    target: Option<CachedOriginTarget>,
    serialized: Option<CachedSerializedRequest>,
}

struct CachedAuthority {
    raw: String,
    authority: Authority,
    normalized_host: String,
}

struct CachedOriginTarget {
    raw: String,
    query_offset: Option<usize>,
}

struct CachedSerializedRequest {
    downstream_head: Box<[u8]>,
    prepared: Arc<PreparedRawHttp1Request>,
}

impl RawHttp1ConnectionCache {
    pub(in crate::reverse) fn prepare_cached_prefix(
        &self,
        reverse: &ReloadableReverse,
        bytes: &[u8],
    ) -> Option<(usize, Arc<PreparedRawHttp1Request>)> {
        let cached = self.serialized.as_ref()?;
        let consumed = cached.downstream_head.len();
        if bytes.len() < consumed || &bytes[..consumed] != cached.downstream_head.as_ref() {
            return None;
        }
        self.prepared_request(reverse, cached.downstream_head.as_ref())
            .map(|request| (consumed, request))
    }

    fn prepared_request(
        &self,
        reverse: &ReloadableReverse,
        downstream_head: &[u8],
    ) -> Option<Arc<PreparedRawHttp1Request>> {
        if qpx_observability::metrics_enabled() || qpx_observability::request_spans_enabled() {
            return None;
        }
        let cached = self.serialized.as_ref()?;
        if cached.downstream_head.as_ref() != downstream_head
            || !reverse.runtime.is_current_state(&cached.prepared.state)
            || cached.prepared.state.destination_trace_enabled()
            || !cached
                .prepared
                .state
                .security
                .identity_sources
                .sources
                .is_empty()
        {
            return None;
        }
        Some(cached.prepared.clone())
    }

    fn routing_snapshot(
        &self,
        reverse: &ReloadableReverse,
    ) -> Option<(Arc<crate::runtime::RuntimeState>, Arc<CompiledReverse>)> {
        if let Some(cached) = self.serialized.as_ref()
            && reverse.runtime.is_current_state(&cached.prepared.state)
        {
            return Some((
                cached.prepared.state.clone(),
                cached.prepared.compiled.clone(),
            ));
        }
        let state = reverse.runtime.state();
        let compiled = reverse.compiled_if_current(&state)?;
        Some((state, compiled))
    }

    fn update_target(&mut self, raw: &str) -> Option<()> {
        if self.target.as_ref().is_some_and(|target| target.raw == raw) {
            return Some(());
        }
        let uri = raw.parse::<Uri>().ok()?;
        if !raw.starts_with('/') || uri.scheme().is_some() || uri.authority().is_some() {
            return None;
        }
        self.target = Some(CachedOriginTarget {
            raw: raw.to_owned(),
            query_offset: raw.find('?'),
        });
        Some(())
    }

    fn update_authority(&mut self, headers: &[httparse::Header<'_>]) -> Option<()> {
        let raw = request_authority_value(headers)?;
        if self
            .authority
            .as_ref()
            .is_some_and(|authority| authority.raw == raw)
        {
            return Some(());
        }
        let authority = raw.parse::<Authority>().ok()?;
        let normalized_host = authority.host().to_ascii_lowercase();
        self.authority = Some(CachedAuthority {
            raw: raw.to_owned(),
            authority,
            normalized_host,
        });
        Some(())
    }

    fn store_prepared_request(
        &mut self,
        downstream_head: &[u8],
        prepared: PreparedRawHttp1Request,
    ) -> Arc<PreparedRawHttp1Request> {
        let prepared = Arc::new(prepared);
        self.serialized = Some(CachedSerializedRequest {
            downstream_head: downstream_head.into(),
            prepared: prepared.clone(),
        });
        prepared
    }
}

impl CachedOriginTarget {
    fn path_and_query(&self) -> (&str, Option<&str>) {
        match self.query_offset {
            Some(offset) => (&self.raw[..offset], Some(&self.raw[offset + 1..])),
            None => (self.raw.as_str(), None),
        }
    }
}

pub(in crate::reverse) fn prepare_raw_http1_request(
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
    request: RawHttp1RequestView<'_>,
    cache: &mut RawHttp1ConnectionCache,
) -> Option<Arc<PreparedRawHttp1Request>> {
    if request.version != 1 || !matches!(request.method, "GET" | "HEAD") {
        return None;
    }
    if qpx_observability::metrics_enabled() || qpx_observability::request_spans_enabled() {
        return None;
    }
    if let Some(prepared) = cache.prepared_request(reverse, request.raw_head) {
        return Some(prepared);
    }
    let (state, compiled) = cache.routing_snapshot(reverse)?;
    if state.destination_trace_enabled() || !state.security.identity_sources.sources.is_empty() {
        return None;
    }
    if request_has_body_or_expect(request.headers) || request_has_upgrade(request.headers) {
        return None;
    }
    cache.update_target(request.target)?;
    cache.update_authority(request.headers)?;
    let method = if request.method == "GET" {
        Method::GET
    } else {
        Method::HEAD
    };
    let route_match_context = {
        let target = cache.target.as_ref()?;
        let authority = cache.authority.as_ref()?;
        let (path, query) = target.path_and_query();
        RuleMatchContext {
            src_ip: Some(conn.remote_addr.ip()),
            dst_port: Some(conn.dst_port),
            host: Some(authority.normalized_host.as_str()),
            method: Some(request.method),
            path: Some(path),
            query,
            authority: Some(authority.authority.as_str()),
            scheme: Some("http"),
            http_version: Some("HTTP/1.1"),
            client_cert_present: Some(false),
            ..Default::default()
        }
    };

    let keep_alive = !has_connection_token(request.headers, b"close");
    let direct_dispatch_allowed =
        !qpx_observability::access_log::access_log_service_required(&state.resources.access_log);
    let target = if let Some(route) = direct_dispatch_allowed
        .then(|| compiled.router.single_plain_http_route())
        .flatten()
        .filter(|route| route.supports_raw_http1_dispatch() && route.matches(&route_match_context))
    {
        let selected_upstream = route.available_plain_http_upstream()?;
        let (connect_authority, host_authority) =
            selected_upstream.origin.direct_plain_http1_authorities()?;
        let origin = prepare_plain_http1_origin(&state.pools, connect_authority, host_authority);
        let request_head = serialize_upstream_request_head(
            request.method,
            request.target,
            request.headers,
            host_authority,
            state.plan.identity.proxy_name.as_ref(),
        )?;
        PreparedRawHttp1Target::Origin {
            request_head,
            origin,
        }
    } else if direct_dispatch_allowed
        && compiled
            .router
            .single_direct_local_response_route()
            .is_some_and(|route| {
                route.supports_raw_local_response_dispatch() && route.matches(&route_match_context)
            })
    {
        PreparedRawHttp1Target::LocalResponse
    } else {
        let uri = request.target.parse::<Uri>().ok()?;
        let headers = crate::http::codec::h1_common::parse_header_map(request.headers).ok()?;
        PreparedRawHttp1Target::Generic { uri, headers }
    };
    Some(cache.store_prepared_request(
        request.raw_head,
        PreparedRawHttp1Request {
            state,
            compiled,
            target,
            method,
            keep_alive,
        },
    ))
}

pub(in crate::reverse) async fn dispatch_prepared_raw_http1_request(
    prepared: &PreparedRawHttp1Request,
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
    session: &mut PreparedPlainHttp1Session,
) -> Result<PreparedRawHttp1Response> {
    if let Some(request) = prepared.generic_request() {
        session.release();
        let (interim, response) =
            super::handle_request_with_interim_ref(request, reverse, conn).await?;
        let mut response = response;
        if let Some(body) = take_in_memory_body(&interim, &mut response) {
            let (parts, _) = response.into_parts();
            return Ok(PreparedRawHttp1Response::InMemory {
                status: parts.status,
                headers: parts.headers,
                body,
            });
        }
        return Ok(PreparedRawHttp1Response::Generic(interim, response));
    }
    if matches!(&prepared.target, PreparedRawHttp1Target::LocalResponse) {
        session.release();
        let route = prepared
            .compiled
            .router
            .single_direct_local_response_route()
            .ok_or_else(|| anyhow!("raw HTTP/1 local-response route is no longer available"))?;
        let local = route
            .local_response
            .as_ref()
            .ok_or_else(|| anyhow!("raw HTTP/1 local-response route has no response"))?;
        let mut response = crate::http::local_response::finalized_compiled_local_response(
            &prepared.method,
            Version::HTTP_11,
            prepared.state.plan.identity.proxy_name.as_ref(),
            local,
            None,
        )?;
        super::dispatch::apply_reverse_route_metadata(route, false, &mut response)?;
        if let Some(body) = take_in_memory_body(&[], &mut response) {
            let (parts, _) = response.into_parts();
            return Ok(PreparedRawHttp1Response::InMemory {
                status: parts.status,
                headers: parts.headers,
                body,
            });
        }
        return Ok(PreparedRawHttp1Response::Generic(Vec::new(), response));
    }
    let route = prepared
        .compiled
        .router
        .single_plain_http_route()
        .ok_or_else(|| anyhow!("raw HTTP/1 route is no longer available"))?;
    let selected_upstream = route
        .available_plain_http_upstream()
        .ok_or_else(|| anyhow!("raw HTTP/1 route requires one static upstream"))?;
    let started = route
        .policy
        .passive_health
        .as_ref()
        .is_some_and(|policy| policy.latency_threshold.is_some())
        .then(tokio::time::Instant::now);
    let PreparedRawHttp1Target::Origin {
        request_head,
        origin,
    } = &prepared.target
    else {
        unreachable!();
    };
    let response = timeout_after_pending(
        route.policy.timeout,
        proxy_prepared_plain_http1_head_raw_response_with_interim(
            origin,
            session,
            &prepared.method,
            request_head.as_ref(),
            Version::HTTP_11,
            prepared.state.plan.identity.proxy_name.as_ref(),
        ),
    )
    .await;
    let mut proxied = match response {
        Ok(Ok(proxied)) => proxied,
        Ok(Err(error)) => {
            record_reverse_upstream_error(selected_upstream, &route.policy, &error);
            return Err(error);
        }
        Err(_) => {
            record_reverse_upstream_timeout(selected_upstream, &route.policy);
            return Err(anyhow!("upstream timeout"));
        }
    };
    record_reverse_upstream_status(selected_upstream, &route.policy, proxied.status(), started);
    if proxied.supports_direct_relay(route.plan.streaming.max_response_body_bytes) {
        proxied.finalize(
            Version::HTTP_11,
            prepared.state.plan.identity.proxy_name.as_ref(),
        );
        return Ok(PreparedRawHttp1Response::Direct(proxied));
    }
    session.recycle_response_globally(&mut proxied);
    let proxied = proxied.into_http_response()?;
    let mut response = proxied.response;
    crate::http::capture::stream::limit_response_body_for_plan_in_place(&mut response, &route.plan);
    crate::http::protocol::l7::finalize_response_with_headers_in_place(
        &prepared.method,
        Version::HTTP_11,
        prepared.state.plan.identity.proxy_name.as_ref(),
        &mut response,
        None,
        false,
    );
    if let Some(body) = take_in_memory_body(&proxied.interim, &mut response) {
        let (parts, _) = response.into_parts();
        return Ok(PreparedRawHttp1Response::InMemory {
            status: parts.status,
            headers: parts.headers,
            body,
        });
    }
    Ok(PreparedRawHttp1Response::Generic(proxied.interim, response))
}

fn take_in_memory_body(
    interim: &[crate::upstream::raw_http1::InterimResponseHead],
    response: &mut Response<Body>,
) -> Option<Bytes> {
    if !interim.is_empty() {
        return None;
    }
    if response.body().has_file_region() {
        return None;
    }
    response.body_mut().take_single_frame_without_trailers()
}

fn serialize_upstream_request_head(
    method: &str,
    target: &str,
    headers: &[httparse::Header<'_>],
    host_authority: &str,
    proxy_name: &str,
) -> Option<Bytes> {
    let capacity = headers
        .iter()
        .map(|header| header.name.len() + header.value.len() + 4)
        .sum::<usize>()
        .saturating_add(method.len() + target.len() + host_authority.len() + proxy_name.len() + 64);
    let mut out = BytesMut::with_capacity(capacity);
    out.extend_from_slice(method.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for header in headers {
        let name = header.name.as_bytes();
        if name.eq_ignore_ascii_case(b"host")
            || is_hop_by_hop_header(name)
            || connection_lists_header(headers, name)
        {
            continue;
        }
        append_header_line(&mut out, name, header.value);
    }
    append_header_line(&mut out, b"Host", host_authority.as_bytes());
    let via = qpx_http::protocol::semantics::via_header_value(Version::HTTP_11, proxy_name)?;
    append_header_line(&mut out, b"Via", via.as_bytes());
    out.extend_from_slice(b"\r\n");
    Some(out.freeze())
}

fn request_authority_value<'a>(headers: &'a [httparse::Header<'a>]) -> Option<&'a str> {
    let mut hosts = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"));
    let raw = std::str::from_utf8(hosts.next()?.value).ok()?.trim();
    if raw.is_empty() || hosts.next().is_some() {
        return None;
    }
    Some(raw)
}

fn request_has_body_or_expect(headers: &[httparse::Header<'_>]) -> bool {
    if headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            || header.name.eq_ignore_ascii_case("expect")
    }) {
        return true;
    }
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
        .any(|header| {
            std::str::from_utf8(header.value).ok().is_none_or(|value| {
                value
                    .split(',')
                    .any(|part| part.trim().parse::<u64>().ok() != Some(0))
            })
        })
}

fn request_has_upgrade(headers: &[httparse::Header<'_>]) -> bool {
    headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("upgrade"))
        || has_connection_token(headers, b"upgrade")
}

fn has_connection_token(headers: &[httparse::Header<'_>], expected: &[u8]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("connection")
            && header
                .value
                .split(|byte| *byte == b',')
                .map(trim_ascii)
                .any(|token| token.eq_ignore_ascii_case(expected))
    })
}

fn connection_lists_header(headers: &[httparse::Header<'_>], name: &[u8]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("connection")
            && header
                .value
                .split(|byte| *byte == b',')
                .map(trim_ascii)
                .any(|token| token.eq_ignore_ascii_case(name))
    })
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_hop_by_hop_header(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"connection")
        || name.eq_ignore_ascii_case(b"keep-alive")
        || name.eq_ignore_ascii_case(b"proxy-authenticate")
        || name.eq_ignore_ascii_case(b"proxy-authentication-info")
        || name.eq_ignore_ascii_case(b"proxy-authorization")
        || name.eq_ignore_ascii_case(b"proxy-connection")
        || name.eq_ignore_ascii_case(b"te")
        || name.eq_ignore_ascii_case(b"trailer")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"upgrade")
}

fn append_header_line(out: &mut BytesMut, name: &[u8], value: &[u8]) {
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_raw_request_rewrites_host_and_strips_connection_fields() {
        let headers = [
            httparse::Header {
                name: "Host",
                value: b"public.example",
            },
            httparse::Header {
                name: "Connection",
                value: b"x-private",
            },
            httparse::Header {
                name: "X-Private",
                value: b"secret",
            },
            httparse::Header {
                name: "X-End-To-End",
                value: b"kept",
            },
        ];
        let serialized =
            serialize_upstream_request_head("GET", "/path", &headers, "127.0.0.1:80", "qpx")
                .expect("serialized request");
        let text = std::str::from_utf8(serialized.as_ref()).expect("UTF-8 request");

        assert!(text.starts_with("GET /path HTTP/1.1\r\n"));
        assert!(text.contains("X-End-To-End: kept\r\n"));
        assert!(text.contains("Host: 127.0.0.1:80\r\n"));
        assert!(text.contains("Via: 1.1 qpx\r\n"));
        assert!(!text.contains("X-Private"));
        assert!(!text.contains("Connection"));
    }

    #[test]
    fn connection_cache_reuses_validated_target_and_authority() {
        let mut cache = RawHttp1ConnectionCache::default();
        let headers = [httparse::Header {
            name: "Host",
            value: b"Bench.Local:8080",
        }];

        cache.update_target("/bench?q=1").expect("target");
        cache.update_authority(&headers).expect("authority");
        cache.update_target("/bench?q=1").expect("cached target");
        cache.update_authority(&headers).expect("cached authority");

        let (path, query) = cache
            .target
            .as_ref()
            .expect("target cache")
            .path_and_query();
        assert_eq!(path, "/bench");
        assert_eq!(query, Some("q=1"));
        let authority = cache.authority.as_ref().expect("authority cache");
        assert_eq!(authority.authority.as_str(), "Bench.Local:8080");
        assert_eq!(authority.normalized_host, "bench.local");
    }

    #[test]
    fn connection_cache_rejects_non_origin_target_and_duplicate_host() {
        let mut cache = RawHttp1ConnectionCache::default();
        assert!(cache.update_target("http://example.test/path").is_none());
        let headers = [
            httparse::Header {
                name: "Host",
                value: b"one.example",
            },
            httparse::Header {
                name: "Host",
                value: b"two.example",
            },
        ];
        assert!(cache.update_authority(&headers).is_none());
    }

    #[test]
    fn in_memory_response_fast_path_takes_only_a_trailerless_frame() {
        let mut response = Response::new(Body::from(Bytes::from_static(b"body")));
        let body = take_in_memory_body(&[], &mut response).expect("single body frame");
        assert_eq!(body, Bytes::from_static(b"body"));
        assert!(take_in_memory_body(&[], &mut response).is_none());
    }
}
