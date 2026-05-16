use super::*;
use crate::http::body::Body;
use crate::http::common::connect_established_response as connect_established;
use crate::http::l7::prepare_request_with_headers_in_place;
use crate::http3::codec::http_headers_to_h1;
use anyhow::{Result, anyhow};
use std::net::SocketAddr;
use tokio::net::lookup_host;

pub(super) struct OpenUpstreamQpxExtendedConnectInput<'a> {
    pub(super) req_head: &'a http::Request<()>,
    pub(super) sanitized_headers: &'a http::HeaderMap,
    pub(super) proxy_name: &'a str,
    pub(super) upstream: Option<&'a str>,
    pub(super) verify_upstream: bool,
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
    crate::http::semantics::validate_h2_h3_request_headers(http::Version::HTTP_3, headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    crate::http::semantics::validate_expect_header(headers)
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
    let status = http::StatusCode::from_u16(response.status().as_u16())?;
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
        protocol,
        enable_datagram,
        timeout_dur,
    } = input;
    let (connect_host, connect_port) =
        parse_qpx_extended_connect_upstream(req_head.uri(), upstream).await?;
    let upstream_addr = match timeout(
        timeout_dur,
        lookup_host((connect_host.as_str(), connect_port)),
    )
    .await
    {
        Ok(Ok(mut addrs)) => addrs
            .next()
            .ok_or_else(|| anyhow!("failed to resolve extended CONNECT upstream"))?,
        Ok(Err(err)) => return Err(anyhow!(err)),
        Err(_) => return Err(anyhow!("extended CONNECT upstream resolution timed out")),
    };

    let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint
        .set_default_client_config(crate::http3::quic::build_h3_client_config(verify_upstream)?);
    let connection =
        match timeout(timeout_dur, endpoint.connect(upstream_addr, &connect_host)?).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(err)) => return Err(anyhow!(err)),
            Err(_) => return Err(anyhow!("extended CONNECT upstream connect timed out")),
        };
    let normalized_headers =
        normalize_qpx_upstream_connect_headers(req_head.uri(), sanitized_headers, proxy_name)?;
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(req_head.uri().clone())
        .body(())?;
    *request.headers_mut() = normalized_headers;
    qpx_h3::open_extended_connect_stream(
        endpoint,
        connection,
        request,
        Some(protocol.clone()),
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram,
            enable_webtransport: protocol == qpx_h3::Protocol::WebTransport,
            max_webtransport_sessions: if protocol == qpx_h3::Protocol::WebTransport {
                1
            } else {
                0
            },
            max_request_body_bytes: 16 * 1024 * 1024,
            max_concurrent_streams_per_connection: 64,
            read_timeout: timeout_dur,
            ..Default::default()
        },
        timeout_dur,
    )
    .await
}

pub(super) async fn open_upstream_qpx_connect_udp_stream(
    upstream: &str,
    target_host: &str,
    target_port: u16,
    proxy_name: &str,
    verify_upstream: bool,
    timeout_dur: Duration,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let (upstream_host, upstream_port, uri) =
        crate::forward::connect_udp_upstream::build_upstream_connect_udp_uri(
            upstream,
            target_host,
            target_port,
        )?;
    let upstream_addr = timeout(
        timeout_dur,
        lookup_host((upstream_host.as_str(), upstream_port)),
    )
    .await??
    .next()
    .ok_or_else(|| anyhow!("failed to resolve CONNECT-UDP upstream proxy"))?;

    let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint
        .set_default_client_config(crate::http3::quic::build_h3_client_config(verify_upstream)?);

    let connection = timeout(
        timeout_dur,
        endpoint.connect(upstream_addr, &upstream_host)?,
    )
    .await??;

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

    let stream = qpx_h3::open_extended_connect_stream(
        endpoint,
        connection,
        request,
        Some(qpx_h3::Protocol::ConnectUdp),
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: false,
            max_webtransport_sessions: 0,
            max_request_body_bytes: 16 * 1024 * 1024,
            max_concurrent_streams_per_connection: 64,
            read_timeout: timeout_dur,
            ..Default::default()
        },
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
        return crate::http::address::parse_authority_host_port(upstream, 443)
            .ok_or_else(|| anyhow!("invalid extended CONNECT upstream authority"));
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow!("extended CONNECT missing authority"))?;
    crate::http::address::parse_authority_host_port(authority.as_str(), 443)
        .ok_or_else(|| anyhow!("invalid extended CONNECT authority"))
}
