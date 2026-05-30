use super::super::parse::{
    default_connect_port_for_scheme, default_port_for_scheme, parse_connect_authority_with_default,
    parse_connect_udp_target, validate_connect_udp_scheme,
};
use crate::http3::server::{H3ServerRequestStream, send_h3_static_response};
use anyhow::Result;
use qpx_core::config::ConnectUdpConfig;

pub(super) struct PreparedH3ConnectTarget {
    pub(super) req_authority: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) authority_host_for_validation: String,
    pub(super) authority_port_for_validation: u16,
    pub(super) auth_uri: String,
}

pub(super) struct H3ConnectTargetInput<'a> {
    pub(super) req_head: &'a ::http::Request<()>,
    pub(super) req_stream: &'a mut H3ServerRequestStream,
    pub(super) connect_udp_cfg: Option<&'a ConnectUdpConfig>,
    pub(super) proxy_name: &'a str,
    pub(super) max_h3_response_body_bytes: usize,
    pub(super) is_connect_udp: bool,
    pub(super) is_extended_connect: bool,
    pub(super) connect_udp_disabled_message: &'a str,
}

pub(super) async fn prepare_h3_connect_target(
    input: H3ConnectTargetInput<'_>,
) -> Result<Option<PreparedH3ConnectTarget>> {
    let H3ConnectTargetInput {
        req_head,
        req_stream,
        connect_udp_cfg,
        proxy_name,
        max_h3_response_body_bytes,
        is_connect_udp,
        is_extended_connect,
        connect_udp_disabled_message,
    } = input;
    if is_connect_udp && !connect_udp_cfg.map(|cfg| cfg.enabled).unwrap_or(false) {
        send_h3_static_response(
            req_stream,
            ::http::StatusCode::NOT_IMPLEMENTED,
            connect_udp_disabled_message.as_bytes(),
            &http::Method::CONNECT,
            proxy_name,
            max_h3_response_body_bytes,
        )
        .await?;
        return Ok(None);
    }

    let Some(req_authority) = req_head.uri().authority().map(|a| a.as_str().to_string()) else {
        let message = if is_connect_udp {
            b"missing CONNECT-UDP authority".as_slice()
        } else {
            b"missing CONNECT authority".as_slice()
        };
        send_h3_static_response(
            req_stream,
            ::http::StatusCode::BAD_REQUEST,
            message,
            &http::Method::CONNECT,
            proxy_name,
            max_h3_response_body_bytes,
        )
        .await?;
        return Ok(None);
    };

    if is_connect_udp {
        prepare_connect_udp_target(
            req_head,
            req_stream,
            proxy_name,
            max_h3_response_body_bytes,
            connect_udp_cfg.and_then(|cfg| cfg.uri_template.as_deref()),
            req_authority,
        )
        .await
    } else {
        prepare_connect_target(
            req_head,
            req_stream,
            proxy_name,
            max_h3_response_body_bytes,
            is_extended_connect,
            req_authority,
        )
        .await
    }
}

async fn prepare_connect_udp_target(
    req_head: &::http::Request<()>,
    req_stream: &mut H3ServerRequestStream,
    proxy_name: &str,
    max_h3_response_body_bytes: usize,
    uri_template: Option<&str>,
    req_authority: String,
) -> Result<Option<PreparedH3ConnectTarget>> {
    let (host, port) = match parse_connect_udp_target(req_head.uri(), uri_template) {
        Ok(parsed) => parsed,
        Err(_) => {
            send_bad_request(
                req_stream,
                proxy_name,
                max_h3_response_body_bytes,
                b"invalid CONNECT-UDP target",
            )
            .await?;
            return Ok(None);
        }
    };
    let scheme = match validate_connect_udp_scheme(req_head.uri(), uri_template) {
        Ok(scheme) => scheme,
        Err(_) => {
            let message = if req_head.uri().scheme_str().is_some() {
                b"invalid CONNECT-UDP :scheme".as_slice()
            } else {
                b"missing CONNECT-UDP :scheme".as_slice()
            };
            send_bad_request(req_stream, proxy_name, max_h3_response_body_bytes, message).await?;
            return Ok(None);
        }
    };
    if !scheme.eq_ignore_ascii_case("https") {
        send_bad_request(
            req_stream,
            proxy_name,
            max_h3_response_body_bytes,
            b"invalid CONNECT-UDP :scheme",
        )
        .await?;
        return Ok(None);
    }
    let default_port = default_port_for_scheme(scheme);
    let (authority_host_for_validation, authority_port_for_validation) =
        match parse_connect_authority_with_default(&req_authority, Some(default_port)) {
            Ok(parsed) => parsed,
            Err(_) => {
                send_bad_request(
                    req_stream,
                    proxy_name,
                    max_h3_response_body_bytes,
                    b"invalid CONNECT-UDP authority",
                )
                .await?;
                return Ok(None);
            }
        };
    let Some(path) = req_head.uri().path_and_query().map(|pq| pq.as_str()) else {
        send_bad_request(
            req_stream,
            proxy_name,
            max_h3_response_body_bytes,
            b"missing CONNECT-UDP :path",
        )
        .await?;
        return Ok(None);
    };
    let auth_uri = format!("{scheme}://{req_authority}{path}");
    Ok(Some(PreparedH3ConnectTarget {
        req_authority,
        host,
        port,
        authority_host_for_validation,
        authority_port_for_validation,
        auth_uri,
    }))
}

async fn prepare_connect_target(
    req_head: &::http::Request<()>,
    req_stream: &mut H3ServerRequestStream,
    proxy_name: &str,
    max_h3_response_body_bytes: usize,
    is_extended_connect: bool,
    req_authority: String,
) -> Result<Option<PreparedH3ConnectTarget>> {
    let default_port = is_extended_connect
        .then(|| default_connect_port_for_scheme(req_head.uri().scheme_str()))
        .flatten();
    let (host, port) = match parse_connect_authority_with_default(&req_authority, default_port) {
        Ok(parsed) => parsed,
        Err(_) => {
            send_bad_request(
                req_stream,
                proxy_name,
                max_h3_response_body_bytes,
                b"invalid CONNECT authority",
            )
            .await?;
            return Ok(None);
        }
    };
    let auth_uri = if is_extended_connect {
        let scheme = req_head.uri().scheme_str().unwrap_or("https");
        let path = req_head
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        format!("{scheme}://{req_authority}{path}")
    } else {
        req_authority.clone()
    };
    Ok(Some(PreparedH3ConnectTarget {
        req_authority,
        authority_host_for_validation: host.clone(),
        authority_port_for_validation: port,
        host,
        port,
        auth_uri,
    }))
}

async fn send_bad_request(
    req_stream: &mut H3ServerRequestStream,
    proxy_name: &str,
    max_h3_response_body_bytes: usize,
    message: &[u8],
) -> Result<()> {
    send_h3_static_response(
        req_stream,
        ::http::StatusCode::BAD_REQUEST,
        message,
        &http::Method::CONNECT,
        proxy_name,
        max_h3_response_body_bytes,
    )
    .await
}
