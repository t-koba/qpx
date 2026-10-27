mod pool;

pub(crate) use self::pool::QpxH3UpstreamSessionPool;
use self::pool::{QpxH3UpstreamSessionKey, open_pooled_qpx_h3_extended_connect_stream};
use super::super::connect::parse::{
    H3ConnectProtocol, parse_extended_connect_upstream, validate_h3_connect_pseudo_headers,
};
use crate::http::protocol::common::connect_established_response as connect_established;
use crate::http::protocol::l7::{
    finalize_response_with_headers, prepare_request_with_headers_in_place,
};
use crate::http3::codec::http_headers_to_h1;
use anyhow::{Result, anyhow};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use qpx_http::protocol::semantics::capsule_protocol_enabled;
use tokio::time::Duration;

pub(super) struct OpenUpstreamQpxExtendedConnectInput<'a> {
    pub(super) req_head: &'a qpx_core::http_message::Request<()>,
    pub(super) sanitized_headers: &'a qpx_core::http_message::Headers,
    pub(super) proxy_name: &'a str,
    pub(super) upstream: Option<&'a str>,
    pub(super) verify_upstream: bool,
    pub(super) trust: Option<&'a qpx_core::tls::CompiledUpstreamTlsTrust>,
    pub(super) protocol: qpx_h3::Protocol,
    pub(super) enable_datagram: bool,
    pub(super) timeout_dur: Duration,
}

pub(super) fn validate_qpx_connect_head(
    req_head: &qpx_core::http_message::Request<()>,
    headers: &qpx_core::http_message::Headers,
    authority_host: &str,
    authority_port: u16,
    protocol: Option<&qpx_h3::Protocol>,
) -> Result<()> {
    qpx_http::protocol::semantics::validate_h2_h3_request_headers(http::Version::HTTP_3, headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    qpx_http::protocol::semantics::validate_expect_header(headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    headers
        .declared_content_length()
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
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        response.status(),
        "QPX HTTP/3 extended CONNECT response",
    )?;
    let mut out = http::Response::builder().status(status).body(())?;
    *out.headers_mut() = http_headers_to_h1(response.headers())?;
    Ok(out)
}

pub(super) async fn open_upstream_qpx_extended_connect_stream(
    pools: &crate::pool::PoolRegistry,
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
    let (connect_host, connect_port) = parse_extended_connect_upstream(req_head.uri(), upstream)?;
    let request =
        normalized_qpx_upstream_connect_request(req_head.uri(), sanitized_headers, proxy_name);
    let enable_webtransport = protocol == qpx_h3::Protocol::WebTransport;
    let key = QpxH3UpstreamSessionKey {
        connect_host: connect_host.clone(),
        connect_port,
        verify_upstream,
        trust_key: trust.map(qpx_core::tls::CompiledUpstreamTlsTrust::pool_key),
        enable_datagram,
        enable_webtransport,
    };
    open_pooled_qpx_h3_extended_connect_stream(
        &pools.qpx_h3,
        key,
        trust,
        request,
        Some(protocol),
        timeout_dur,
    )
    .await
}

pub(super) async fn open_upstream_qpx_connect_udp_stream(
    pools: &crate::pool::PoolRegistry,
    upstream: &str,
    target: (&str, u16),
    proxy_name: &str,
    verify_upstream: bool,
    trust: Option<&qpx_core::tls::CompiledUpstreamTlsTrust>,
    timeout_dur: Duration,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let (target_host, target_port) = target;
    let (upstream_host, upstream_port, uri) =
        crate::forward::connect::udp_upstream::build_upstream_connect_udp_uri(
            upstream,
            target_host,
            target_port,
        )?;
    let mut headers = qpx_core::http_message::Headers::new();
    headers.insert(
        qpx_core::http_message::OrdinaryHeaderName::try_from("capsule-protocol").expect("ordinary"),
        http::HeaderValue::from_static("?1"),
    );
    let request = normalized_qpx_upstream_connect_request(&uri, &headers, proxy_name);

    let key = QpxH3UpstreamSessionKey {
        connect_host: upstream_host.clone(),
        connect_port: upstream_port,
        verify_upstream,
        trust_key: trust.map(qpx_core::tls::CompiledUpstreamTlsTrust::pool_key),
        enable_datagram: true,
        enable_webtransport: false,
    };
    let stream = open_pooled_qpx_h3_extended_connect_stream(
        &pools.qpx_h3,
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
    if !capsule_protocol_enabled(stream.response.headers()) {
        return Err(anyhow!(
            "upstream CONNECT-UDP missing required response header: Capsule-Protocol: ?1"
        ));
    }
    Ok(stream)
}

fn normalized_qpx_upstream_connect_request(
    uri: &http::Uri,
    headers: &qpx_core::http_message::Headers,
    proxy_name: &str,
) -> qpx_core::http_message::Request<()> {
    let mut request = qpx_core::http_message::Request::new(Body::empty());
    *request.method_mut() = http::Method::CONNECT;
    *request.uri_mut() = uri.clone();
    *request.version_mut() = http::Version::HTTP_3;
    *request.headers_mut() = headers.clone();
    prepare_request_with_headers_in_place(&mut request, proxy_name, None, false);
    request.map_body(|_| ())
}
