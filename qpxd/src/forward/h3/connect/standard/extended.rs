use super::super::finalize_h3_connect_owner_response;
use super::super::parse::parse_extended_connect_upstream;
use crate::forward::h3::connect_response_body::define_upstream_error_response_body;
use crate::http::protocol::l7::prepare_request_with_headers_in_place;
use crate::http3::codec::{h1_headers_to_http, http_headers_to_h1};
use crate::http3::datagram::{H3DatagramDispatch, H3StreamDatagrams};
use crate::http3::listener::H3_MAX_FIELD_SECTION_SIZE;
use crate::http3::quic::{build_h3_client_config, enforce_h3_connection_trust};
use crate::upstream::raw_http1::InterimResponseHead;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use qpx_core::{
    http_message::{OrdinaryHeaderName, Response as OwnerResponse},
    rules::CompiledHeaderControl,
};
use qpx_http::body::Body;
use std::sync::Arc;
use tokio::net::lookup_host;
use tokio::time::{Duration, timeout};
use tracing::warn;

pub(super) struct UpstreamExtendedConnectStream {
    pub(super) interim: Vec<InterimResponseHead>,
    pub(super) response: ::http::Response<()>,
    pub(super) req_stream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    pub(super) datagrams: Option<H3StreamDatagrams>,
    pub(super) _endpoint: quinn::Endpoint,
    pub(super) driver: tokio::task::JoinHandle<()>,
    pub(super) datagram_task: Option<tokio::task::JoinHandle<()>>,
}

pub(super) struct OpenUpstreamExtendedConnectInput<'a> {
    pub(super) req_head: &'a qpx_core::http_message::Request<()>,
    pub(super) sanitized_headers: &'a qpx_core::http_message::Headers,
    pub(super) proxy_name: &'a str,
    pub(super) upstream: Option<&'a str>,
    pub(super) verify_upstream: bool,
    pub(super) trust: Option<&'a qpx_core::tls::CompiledUpstreamTlsTrust>,
    pub(super) protocol: ::h3::ext::Protocol,
    pub(super) enable_datagram: bool,
    pub(super) datagram_channel_capacity: usize,
    pub(super) timeout_dur: Duration,
}

fn http1_uri_to_http_uri(uri: &::http::Uri) -> Result<http::Uri> {
    uri.to_string()
        .parse::<http::Uri>()
        .or_else(|_| {
            let mut builder = http::Uri::builder();
            if let Some(scheme) = uri.scheme_str() {
                builder = builder.scheme(scheme);
            }
            if let Some(authority) = uri.authority() {
                builder = builder.authority(authority.as_str());
            }
            builder
                .path_and_query(uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"))
                .build()
        })
        .map_err(|e| anyhow!("invalid upstream CONNECT uri: {e}"))
}

pub(in crate::forward) fn normalize_h3_upstream_connect_headers(
    uri: &::http::Uri,
    headers: &qpx_core::http_message::Headers,
    proxy_name: &str,
) -> Result<::http::HeaderMap> {
    let mut request = qpx_core::http_message::Request::new(Body::empty());
    *request.method_mut() = http::Method::CONNECT;
    *request.uri_mut() = http1_uri_to_http_uri(uri)?;
    *request.version_mut() = http::Version::HTTP_3;
    *request.headers_mut() = headers.clone();
    prepare_request_with_headers_in_place(&mut request, proxy_name, None, false);
    let request = request.into_http_for_codec()?;
    http_headers_to_h1(request.headers())
}

pub(in crate::forward) async fn recv_upstream_h3_response_with_interim(
    req_stream: &mut ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    timeout_dur: Duration,
    context: &str,
) -> Result<(Vec<InterimResponseHead>, ::http::Response<()>)> {
    let mut interim = Vec::new();
    loop {
        let response = match timeout(timeout_dur, req_stream.recv_response()).await {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => return Err(anyhow!("{context} timed out")),
        };
        if response.status().is_informational() {
            if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
                return Err(anyhow!("{context} received forbidden 101 response"));
            }
            let (parts, ()) = response.into_parts();
            interim.push(InterimResponseHead::new(parts.status, parts.headers));
            continue;
        }
        return Ok((interim, response));
    }
}

pub(super) async fn open_upstream_extended_connect_stream(
    input: OpenUpstreamExtendedConnectInput<'_>,
) -> Result<UpstreamExtendedConnectStream> {
    let (connect_host, connect_port) =
        parse_extended_connect_upstream(input.req_head.uri(), input.upstream)?;
    let upstream_addr = match timeout(
        input.timeout_dur,
        lookup_host((connect_host.as_str(), connect_port)),
    )
    .await
    {
        Ok(Ok(mut addrs)) => addrs
            .next()
            .ok_or_else(|| anyhow!("failed to resolve extended CONNECT upstream"))?,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => return Err(anyhow!("extended CONNECT upstream resolution timed out")),
    };

    let bind_addr = crate::http3::quic::upstream_client_bind_addr(upstream_addr);
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(build_h3_client_config(input.verify_upstream, input.trust)?);

    let connection = match timeout(
        input.timeout_dur,
        endpoint.connect(upstream_addr, &connect_host)?,
    )
    .await
    {
        Ok(Ok(connection)) => connection,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => return Err(anyhow!("extended CONNECT upstream connect timed out")),
    };
    enforce_h3_connection_trust(&connection, &connect_host, input.trust)?;
    let quic_conn = h3_quinn::Connection::new(connection);
    let mut builder = ::h3::client::builder();
    builder.enable_extended_connect(true);
    builder.enable_datagram(input.enable_datagram);
    builder.max_field_section_size(H3_MAX_FIELD_SECTION_SIZE);
    let h3_build = builder.build::<_, _, Bytes>(quic_conn);
    let (mut h3_conn, mut sender) = match timeout(input.timeout_dur, h3_build).await {
        Ok(Ok(parts)) => parts,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => return Err(anyhow!("extended CONNECT upstream h3 setup timed out")),
    };
    let normalized_headers = normalize_h3_upstream_connect_headers(
        input.req_head.uri(),
        input.sanitized_headers,
        input.proxy_name,
    )?;

    let mut request = ::http::Request::builder()
        .method(::http::Method::CONNECT)
        .uri(input.req_head.uri().clone())
        .body(())?;
    request.extensions_mut().insert(input.protocol);
    *request.headers_mut() = normalized_headers;

    let mut req_stream = match timeout(input.timeout_dur, sender.send_request(request)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => return Err(anyhow!("extended CONNECT upstream request timed out")),
    };
    let mut datagram_handles = if input.enable_datagram {
        use h3_datagram::datagram_handler::HandleDatagramsExt as _;

        let stream_id = req_stream.id();
        Some((
            h3_conn.get_datagram_reader(),
            h3_conn.get_datagram_sender(stream_id),
        ))
    } else {
        None
    };
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });
    let (interim, response) = recv_upstream_h3_response_with_interim(
        &mut req_stream,
        input.timeout_dur,
        "extended CONNECT upstream response",
    )
    .await?;
    let (datagrams, datagram_task) = if input.enable_datagram && response.status().is_success() {
        let dispatch = Arc::new(H3DatagramDispatch::new(input.datagram_channel_capacity));
        let (reader, sender) = datagram_handles
            .take()
            .ok_or_else(|| anyhow!("missing HTTP/3 datagram handles"))?;
        let datagram_task = {
            let dispatch = dispatch.clone();
            tokio::spawn(async move {
                dispatch.run(reader).await;
            })
        };
        let datagrams = Some(dispatch.register_stream(req_stream.id(), sender).await);
        (datagrams, Some(datagram_task))
    } else {
        (None, None)
    };
    Ok(UpstreamExtendedConnectStream {
        interim,
        response,
        req_stream,
        datagrams,
        _endpoint: endpoint,
        driver,
        datagram_task,
    })
}

pub(super) fn upstream_extended_connect_error_response(
    response: ::http::Response<()>,
    upstream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    proxy_name: &str,
    header_control: Option<&CompiledHeaderControl>,
    body_read_timeout: Duration,
) -> Result<OwnerResponse<Body>> {
    let (parts, _) = response.into_parts();
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        parts.status,
        "HTTP/3 extended CONNECT response",
    )?;
    let headers = h1_headers_to_http(&parts.headers)?;
    let downstream = owner_h3_connect_error_response(
        status,
        &headers,
        body_from_upstream_h3_stream(upstream, body_read_timeout),
    )?;
    Ok(finalize_h3_connect_owner_response(
        proxy_name,
        downstream,
        header_control,
    ))
}

fn owner_h3_connect_error_response(
    status: ::http::StatusCode,
    headers: &::http::HeaderMap,
    body: Body,
) -> Result<OwnerResponse<Body>> {
    let mut response = OwnerResponse::new(body);
    *response.status_mut() = status;
    for (name, value) in headers {
        if name == ::http::header::CONTENT_LENGTH {
            response
                .headers_mut()
                .append_content_length_value(value.clone());
        } else {
            let name = OrdinaryHeaderName::try_from(name.clone())?;
            response.headers_mut().append(name, value.clone());
        }
    }
    Ok(response)
}

define_upstream_error_response_body!(
    body_from_upstream_h3_stream,
    ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    |chunk| crate::http3::h3_buf_to_bytes(chunk),
);

pub(super) async fn relay_h3_extended_connect_stream(
    downstream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut downstream_datagrams: Option<H3StreamDatagrams>,
    upstream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut upstream_datagrams: Option<H3StreamDatagrams>,
    idle_timeout: Duration,
) -> Result<()> {
    let (downstream_send, downstream_recv) = downstream.split();
    let (upstream_send, upstream_recv) = upstream.split();
    let activity = crate::tunnel::TunnelActivity::new();
    let stream_relay = crate::tunnel::relay_tunnel(
        downstream_recv,
        downstream_send,
        upstream_recv,
        upstream_send,
        crate::tunnel::TunnelPolicy::h3(Some(idle_timeout), "h3_extended_connect", "unknown")
            .with_activity(activity.clone()),
    );
    let datagram_relay = async {
        loop {
            tokio::select! {
                down_payload = async {
                    if let Some(datagrams) = downstream_datagrams.as_mut() {
                        datagrams.receiver.recv().await
                    } else {
                        std::future::pending::<Option<Bytes>>().await
                    }
                } => {
                    let Some(payload) = down_payload else {
                        break;
                    };
                    if let Some(datagrams) = upstream_datagrams.as_mut()
                        && let Err(err) = datagrams.sender.send_datagram(payload) {
                            warn!(error = ?err, "forward HTTP/3 extended CONNECT upstream datagram send failed");
                        }
                    activity.touch();
                }
                up_payload = async {
                    if let Some(datagrams) = upstream_datagrams.as_mut() {
                        datagrams.receiver.recv().await
                    } else {
                        std::future::pending::<Option<Bytes>>().await
                    }
                } => {
                    let Some(payload) = up_payload else {
                        break;
                    };
                    if let Some(datagrams) = downstream_datagrams.as_mut()
                        && let Err(err) = datagrams.sender.send_datagram(payload) {
                            warn!(error = ?err, "forward HTTP/3 extended CONNECT downstream datagram send failed");
                        }
                    activity.touch();
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = stream_relay => {
            let _stats = result?;
        }
        result = datagram_relay => {
            result?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{h1_headers_to_http, owner_h3_connect_error_response};
    use crate::forward::h3::connect::{
        finalize_h3_connect_head_response, finalize_h3_connect_owner_response,
        finalize_h3_connect_response,
    };
    use qpx_core::{config::HeaderControl, rules::CompiledHeaderControl};
    use qpx_http::body::Body;

    #[test]
    fn owner_h3_connect_error_response_preserves_content_length_states() {
        let cases: [Vec<&[u8]>; 4] = [vec![], vec![b"0"], vec![b"invalid"], vec![b"4", b"5"]];
        for expected in cases {
            let mut headers = ::http::HeaderMap::new();
            for value in &expected {
                headers.append(
                    ::http::header::CONTENT_LENGTH,
                    ::http::HeaderValue::from_bytes(value).expect("header value"),
                );
            }
            let response = owner_h3_connect_error_response(
                ::http::StatusCode::BAD_GATEWAY,
                &headers,
                Body::empty(),
            )
            .expect("import headers into owner")
            .into_http_for_library();
            let actual: Vec<_> = response
                .headers()
                .get_all(::http::header::CONTENT_LENGTH)
                .iter()
                .map(::http::HeaderValue::as_bytes)
                .collect();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn extended_connect_error_owner_preserves_finalized_h3_output() {
        let mut decoded = ::http::HeaderMap::new();
        decoded.append("x-repeat", ::http::HeaderValue::from_static("first"));
        decoded.append("x-repeat", ::http::HeaderValue::from_static("second"));
        decoded.append("cookie", ::http::HeaderValue::from_static("a=1"));
        let mut cookie = ::http::HeaderValue::from_static("b=2");
        cookie.set_sensitive(true);
        decoded.append("cookie", cookie);
        decoded.append("set-cookie", ::http::HeaderValue::from_static("first=1"));
        decoded.append("set-cookie", ::http::HeaderValue::from_static("second=2"));
        decoded.append(
            ::http::header::CONTENT_LENGTH,
            ::http::HeaderValue::from_static("0"),
        );

        let headers = h1_headers_to_http(&decoded).expect("convert H3 headers");
        let control = CompiledHeaderControl::compile(&HeaderControl {
            response_set: [("x-finalized".into(), "configured".into())].into(),
            ..Default::default()
        })
        .expect("header control");
        let status = ::http::StatusCode::BAD_GATEWAY;
        let owner = owner_h3_connect_error_response(status, &headers, Body::empty())
            .expect("import response headers into owner");
        let actual = finalize_h3_connect_owner_response("qpx-test", owner, Some(&control))
            .into_http_for_library();

        let mut standard = ::http::Response::builder()
            .status(status)
            .body(Body::empty())
            .expect("valid response");
        *standard.headers_mut() = headers;
        let expected = finalize_h3_connect_response("qpx-test", standard, Some(&control));

        assert_eq!(actual.status(), expected.status());
        assert_eq!(actual.version(), expected.version());
        assert_eq!(actual.version(), ::http::Version::HTTP_11);
        assert_eq!(actual.headers(), expected.headers());
        let repeated: Vec<_> = actual.headers().get_all("x-repeat").iter().collect();
        assert_eq!(repeated.len(), 2);
        assert_eq!(repeated[0].as_bytes(), b"first");
        assert_eq!(repeated[1].as_bytes(), b"second");
        assert_eq!(
            actual.headers().get("cookie").unwrap().as_bytes(),
            b"a=1; b=2"
        );
        assert!(actual.headers().get("cookie").unwrap().is_sensitive());
        let set_cookie: Vec<_> = actual.headers().get_all("set-cookie").iter().collect();
        assert_eq!(set_cookie.len(), 2);
        assert_eq!(set_cookie[0].as_bytes(), b"first=1");
        assert_eq!(set_cookie[1].as_bytes(), b"second=2");
        assert_eq!(actual.headers().get("x-finalized").unwrap(), "configured");
    }

    #[test]
    fn successful_extended_connect_head_strips_content_length_for_tunnel_data() {
        let response = ::http::Response::builder()
            .status(::http::StatusCode::OK)
            .header(::http::header::CONTENT_LENGTH, "0")
            .header("trailer", "x-end")
            .header("x-upstream", "preserved")
            .body(())
            .expect("upstream CONNECT response");

        let actual = finalize_h3_connect_head_response(
            response,
            "qpx-test",
            None,
            "HTTP/3 extended CONNECT response",
        )
        .expect("normalize successful CONNECT head");

        assert_eq!(actual.status(), ::http::StatusCode::OK);
        assert!(
            !actual
                .headers()
                .contains_key(::http::header::CONTENT_LENGTH)
        );
        assert!(!actual.headers().contains_key("transfer-encoding"));
        assert!(!actual.headers().contains_key("trailer"));
        assert_eq!(actual.headers().get("x-upstream").unwrap(), "preserved");
    }
}
