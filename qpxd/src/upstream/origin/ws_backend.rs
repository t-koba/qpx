use anyhow::Result;
use hyper::Response;
use hyper::header::HeaderValue;
use qpx_core::http_message::{OrdinaryHeaderName, Request as OwnerRequest};
use qpx_http::body::Body;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tracing::warn;

use crate::http::protocol::l7::prepare_request_with_headers_in_place;
use crate::http::protocol::websocket::spawn_upgrade_tunnel;
use crate::upstream::http1::{
    WebsocketProxyConfig, normalize_websocket_switching_protocols_response, proxy_websocket_http1,
};
use qpx_core::tls::CompiledUpstreamTlsTrust;
use qpx_http::tls::builder::connect_client_http1;

use super::OriginEndpoint;
use super::dispatch::{OriginScheme, origin_scheme};

pub(crate) async fn proxy_websocket(
    req: OwnerRequest<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    timeout_dur: Duration,
    upgrade_wait_timeout: Duration,
    tunnel_idle_timeout: Duration,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<Response<Body>> {
    let scheme = match origin_scheme(origin)? {
        OriginScheme::Ws | OriginScheme::Http => OriginScheme::Ws,
        OriginScheme::Wss | OriginScheme::Https => OriginScheme::Wss,
        OriginScheme::H3 => anyhow::bail!("websocket upstreams do not support h3 schemes"),
        OriginScheme::Ipc | OriginScheme::IpcUnix => {
            anyhow::bail!("websocket upstreams do not support ipc schemes")
        }
    };
    let default_port = match scheme {
        OriginScheme::Ws => 80,
        OriginScheme::Wss => 443,
        _ => unreachable!(),
    };
    let connect_authority = origin.connect_authority(default_port)?;
    let host_authority = origin.host_header_authority(default_port)?;
    let req = prepare_websocket_request(req, host_authority.as_str(), proxy_name)?;

    if scheme == OriginScheme::Ws {
        return proxy_websocket_http1(
            req,
            WebsocketProxyConfig {
                upstream_proxy: None,
                direct_connect_authority: connect_authority.as_str(),
                direct_host_header: host_authority.as_str(),
                timeout_dur,
                upgrade_wait_timeout,
                tunnel_idle_timeout,
                tunnel_label: "reverse_edges",
                upstream_context: "reverse_edges websocket upstream proxy",
                direct_context: "reverse_edges websocket direct",
            },
        )
        .await;
    }

    let server_name = origin.tls_server_name()?;
    proxy_wss(
        req,
        connect_authority.as_str(),
        server_name.as_str(),
        timeout_dur,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
        trust,
    )
    .await
}

fn prepare_websocket_request(
    mut req: OwnerRequest<Body>,
    host_authority: &str,
    proxy_name: &str,
) -> Result<OwnerRequest<Body>> {
    prepare_request_with_headers_in_place(&mut req, proxy_name, None, true);
    *req.version_mut() = http::Version::HTTP_11;
    crate::upstream::http1::ensure_origin_form_uri(&mut req)?;
    let host = OrdinaryHeaderName::try_from(http::header::HOST).expect("host is an ordinary field");
    req.headers_mut()
        .insert(host, HeaderValue::from_str(host_authority)?);
    Ok(req)
}

async fn proxy_wss(
    mut req: OwnerRequest<Body>,
    connect_authority: &str,
    server_name: &str,
    timeout_dur: Duration,
    upgrade_wait_timeout: Duration,
    tunnel_idle_timeout: Duration,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<Response<Body>> {
    let (expected_accept, offered_protocols) =
        crate::http::protocol::websocket::websocket_response_expectation(req.headers())?;
    let client_upgrade = crate::http::protocol::upgrade::on(req.extensions_mut());
    let tcp = timeout(timeout_dur, TcpStream::connect(connect_authority)).await??;
    let _ = tcp.set_nodelay(true);
    let tls = timeout(
        timeout_dur,
        connect_client_http1(server_name, tcp, true, trust),
    )
    .await??
    .0;
    let (mut sender, conn) = timeout(
        timeout_dur,
        qpx_http::protocol::common::handshake_http1(tls),
    )
    .await??;
    let authority = connect_authority.to_string();
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            warn!(error = ?err, upstream = %authority, "reverse_edges websocket TLS upstream closed");
        }
    });
    let hyper_req = crate::upstream::http1::into_http1_for_codec(req)?;
    let mut response = timeout(timeout_dur, sender.send_request(hyper_req))
        .await??
        .map(Body::from);
    crate::http::protocol::websocket::validate_websocket_switching_response(
        &response,
        &expected_accept,
        &offered_protocols,
    )?;
    normalize_websocket_switching_protocols_response(&mut response);
    spawn_upgrade_tunnel(
        &mut response,
        client_upgrade,
        "reverse_edges",
        upgrade_wait_timeout,
        tunnel_idle_timeout,
    );
    Ok(response)
}
