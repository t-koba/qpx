use super::super::super::connect::parse::{
    default_connect_port_for_scheme, parse_connect_authority_with_default,
};
use super::super::connect_upstream::validate_qpx_connect_head;
use crate::http3::codec::h1_headers_to_http;
use http::HeaderMap;
use tracing::warn;

pub(super) struct PreparedWebTransportHead {
    pub(super) req_authority: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) headers: HeaderMap,
}

pub(super) struct WebTransportHeadRejection {
    pub(super) body: &'static [u8],
}

pub(super) fn prepare_webtransport_connect_head(
    req_head: &http::Request<()>,
) -> Result<PreparedWebTransportHead, WebTransportHeadRejection> {
    let req_authority = req_head
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_string())
        .ok_or(WebTransportHeadRejection {
            body: b"missing CONNECT authority",
        })?;
    let default_port = default_connect_port_for_scheme(req_head.uri().scheme_str());
    let (host, port) =
        parse_connect_authority_with_default(&req_authority, default_port).map_err(|_| {
            WebTransportHeadRejection {
                body: b"invalid CONNECT authority",
            }
        })?;
    let headers =
        h1_headers_to_http(req_head.headers()).map_err(|_| WebTransportHeadRejection {
            body: b"invalid CONNECT headers",
        })?;
    if let Err(err) = validate_qpx_connect_head(
        req_head,
        &headers,
        host.as_str(),
        port,
        Some(&qpx_h3::Protocol::WebTransport),
    ) {
        warn!(error = ?err, "invalid forward HTTP/3 WebTransport request");
        return Err(WebTransportHeadRejection {
            body: b"bad CONNECT request",
        });
    }
    Ok(PreparedWebTransportHead {
        req_authority,
        host,
        port,
        headers,
    })
}
