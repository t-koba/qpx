use crate::http::body::Body;
use anyhow::Result;
use hyper::header::{HeaderValue, HOST};
use hyper::{Request, Response, Uri};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::warn;

use crate::http::l7::prepare_request_with_headers_in_place;
use crate::http::websocket::spawn_upgrade_tunnel;
use crate::tls::client::connect_tls_http1_with_options;
use crate::tls::CompiledUpstreamTlsTrust;
use crate::upstream::http1::{
    normalize_websocket_switching_protocols_response, proxy_websocket_http1, WebsocketProxyConfig,
};

use super::dispatch::{origin_scheme, OriginScheme};
use super::OriginEndpoint;

pub(crate) async fn proxy_websocket(
    req: Request<Body>,
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
                tunnel_label: "reverse",
                upstream_context: "reverse websocket upstream proxy",
                direct_context: "reverse websocket direct",
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
    mut req: Request<Body>,
    host_authority: &str,
    proxy_name: &str,
) -> Result<Request<Body>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    prepare_request_with_headers_in_place(&mut req, proxy_name, None, true);
    *req.version_mut() = http::Version::HTTP_11;
    *req.uri_mut() = Uri::builder().path_and_query(path.as_str()).build()?;
    req.headers_mut()
        .insert(HOST, HeaderValue::from_str(host_authority)?);
    Ok(req)
}

async fn proxy_wss(
    mut req: Request<Body>,
    connect_authority: &str,
    server_name: &str,
    timeout_dur: Duration,
    upgrade_wait_timeout: Duration,
    tunnel_idle_timeout: Duration,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<Response<Body>> {
    let client_upgrade = crate::http::upgrade::on(&mut req);
    let tcp = timeout(timeout_dur, TcpStream::connect(connect_authority)).await??;
    let _ = tcp.set_nodelay(true);
    let tls = timeout(
        timeout_dur,
        connect_tls_http1_with_options(server_name, tcp, true, trust),
    )
    .await??;
    let (mut sender, conn) =
        timeout(timeout_dur, crate::http::common::handshake_http1(tls)).await??;
    let authority = connect_authority.to_string();
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            warn!(error = ?err, upstream = %authority, "reverse websocket TLS upstream closed");
        }
    });
    let mut response = timeout(timeout_dur, sender.send_request(req))
        .await??
        .map(Body::from);
    normalize_websocket_switching_protocols_response(&mut response);
    spawn_upgrade_tunnel(
        &mut response,
        client_upgrade,
        "reverse",
        upgrade_wait_timeout,
        tunnel_idle_timeout,
    );
    Ok(response)
}
