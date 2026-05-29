mod pool;

use self::pool::{QpxH3UpstreamSessionKey, open_pooled_qpx_h3_extended_connect_stream};
use super::super::connect::parse::{H3ConnectProtocol, validate_h3_connect_pseudo_headers};
use crate::http::body::Body;
use crate::http::protocol::common::connect_established_response as connect_established;
use crate::http::protocol::l7::{
    finalize_response_with_headers, prepare_request_with_headers_in_place,
};
use crate::http3::codec::http_headers_to_h1;
use anyhow::{Result, anyhow};
use qpx_core::rules::CompiledHeaderControl;
use tokio::time::Duration;

pub(super) fn configure_qpx_h3_upstream_session_pool(
    max_sessions_per_key: usize,
    max_inflight_streams_per_session: usize,
) {
    pool::configure_qpx_h3_upstream_session_pool(
        max_sessions_per_key,
        max_inflight_streams_per_session,
    );
}

pub(super) struct OpenUpstreamQpxExtendedConnectInput<'a> {
    pub(super) req_head: &'a http::Request<()>,
    pub(super) sanitized_headers: &'a http::HeaderMap,
    pub(super) proxy_name: &'a str,
    pub(super) upstream: Option<&'a str>,
    pub(super) verify_upstream: bool,
    pub(super) trust: Option<&'a crate::tls::CompiledUpstreamTlsTrust>,
    pub(super) protocol: qpx_h3::Protocol,
    pub(super) enable_datagram: bool,
    pub(super) timeout_dur: Duration,
}

pub(super) fn validate_qpx_connect_head(
    req_head: &http::Request<()>,
    headers: &http::HeaderMap,
    authority_host: &str,
    authority_port: u16,
    protocol: Option<&qpx_h3::Protocol>,
) -> Result<()> {
    crate::http::protocol::semantics::validate_h2_h3_request_headers(
        http::Version::HTTP_3,
        headers,
    )
    .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    crate::http::protocol::semantics::validate_expect_header(headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    crate::http3::codec::parse_content_length_fields(headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    let protocol = match protocol {
        Some(qpx_h3::Protocol::ConnectUdp) => H3ConnectProtocol::ConnectUdp,
        Some(_) => H3ConnectProtocol::Extended,
        None => H3ConnectProtocol::Plain,
    };
    validate_h3_connect_pseudo_headers(req_head, headers, authority_host, authority_port, protocol)
}

pub(super) fn build_qpx_connect_success_head(
    proxy_name: &str,
    capsule_protocol: bool,
    header_control: Option<&CompiledHeaderControl>,
) -> Result<http::Response<()>> {
    let mut response = connect_established();
    if capsule_protocol {
        response.headers_mut().insert(
            http::header::HeaderName::from_static("capsule-protocol"),
            http::HeaderValue::from_static("?1"),
        );
    }
    let response = finalize_response_with_headers(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        response,
        header_control,
        false,
    );
    let status = crate::http::protocol::semantics::validate_http_status_class(
        response.status(),
        "QPX HTTP/3 extended CONNECT response",
    )?;
    let mut out = http::Response::builder().status(status).body(())?;
    *out.headers_mut() = http_headers_to_h1(response.headers())?;
    Ok(out)
}

pub(super) async fn open_upstream_qpx_extended_connect_stream(
    input: OpenUpstreamQpxExtendedConnectInput<'_>,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let OpenUpstreamQpxExtendedConnectInput {
        req_head,
        sanitized_headers,
        proxy_name,
        upstream,
        verify_upstream,
        trust,
        protocol,
        enable_datagram,
        timeout_dur,
    } = input;
    let (connect_host, connect_port) =
        parse_qpx_extended_connect_upstream(req_head.uri(), upstream).await?;
    let normalized_headers =
        normalize_qpx_upstream_connect_headers(req_head.uri(), sanitized_headers, proxy_name)?;
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(req_head.uri().clone())
        .body(())?;
    *request.headers_mut() = normalized_headers;
    let enable_webtransport = protocol == qpx_h3::Protocol::WebTransport;
    let key = QpxH3UpstreamSessionKey {
        connect_host: connect_host.clone(),
        connect_port,
        verify_upstream,
        trust_key: trust.map(crate::tls::CompiledUpstreamTlsTrust::pool_key),
        enable_datagram,
        enable_webtransport,
    };
    open_pooled_qpx_h3_extended_connect_stream(key, trust, request, Some(protocol), timeout_dur)
        .await
}

pub(super) async fn open_upstream_qpx_connect_udp_stream(
    upstream: &str,
    target_host: &str,
    target_port: u16,
    proxy_name: &str,
    verify_upstream: bool,
    trust: Option<&crate::tls::CompiledUpstreamTlsTrust>,
    timeout_dur: Duration,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let (upstream_host, upstream_port, uri) =
        crate::forward::connect::udp_upstream::build_upstream_connect_udp_uri(
            upstream,
            target_host,
            target_port,
        )?;
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::HeaderName::from_static("capsule-protocol"),
        http::header::HeaderValue::from_static("?1"),
    );
    let normalized_headers = normalize_qpx_upstream_connect_headers(&uri, &headers, proxy_name)?;
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .body(())?;
    *request.headers_mut() = normalized_headers;

    let key = QpxH3UpstreamSessionKey {
        connect_host: upstream_host.clone(),
        connect_port: upstream_port,
        verify_upstream,
        trust_key: trust.map(crate::tls::CompiledUpstreamTlsTrust::pool_key),
        enable_datagram: true,
        enable_webtransport: false,
    };
    let stream = open_pooled_qpx_h3_extended_connect_stream(
        key,
        trust,
        request,
        Some(qpx_h3::Protocol::ConnectUdp),
        timeout_dur,
    )
    .await?;

    if !stream.response.status().is_success() {
        return Err(anyhow!(
            "upstream CONNECT-UDP failed with status {}",
            stream.response.status()
        ));
    }
    let capsule = stream
        .response
        .headers()
        .get(http::header::HeaderName::from_static("capsule-protocol"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    if capsule != Some("?1") {
        return Err(anyhow!(
            "upstream CONNECT-UDP missing required response header: Capsule-Protocol: ?1"
        ));
    }
    Ok(stream)
}

fn normalize_qpx_upstream_connect_headers(
    uri: &http::Uri,
    headers: &http::HeaderMap,
    proxy_name: &str,
) -> Result<http::HeaderMap> {
    let mut request = hyper::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri.to_string().parse::<http::Uri>()?)
        .body(Body::empty())?;
    *request.version_mut() = http::Version::HTTP_3;
    *request.headers_mut() = headers.clone();
    prepare_request_with_headers_in_place(&mut request, proxy_name, None, false);
    Ok(request.headers().clone())
}

async fn parse_qpx_extended_connect_upstream(
    uri: &http::Uri,
    upstream: Option<&str>,
) -> Result<(String, u16)> {
    if let Some(upstream) = upstream {
        if upstream.contains("://") {
            let parsed = url::Url::parse(upstream)?;
            match parsed.scheme() {
                "https" | "h3" => {}
                _ => return Err(anyhow!("extended CONNECT upstream requires https/h3 URL")),
            }
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow!("extended CONNECT upstream host missing"))?;
            let port = parsed.port().unwrap_or(443);
            return Ok((host.to_string(), port));
        }
        return crate::http::protocol::address::parse_authority_host_port(upstream, 443)
            .ok_or_else(|| anyhow!("invalid extended CONNECT upstream authority"));
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow!("extended CONNECT missing authority"))?;
    crate::http::protocol::address::parse_authority_host_port(authority.as_str(), 443)
        .ok_or_else(|| anyhow!("invalid extended CONNECT authority"))
}
