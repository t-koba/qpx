use crate::http::dispatch::{
    DispatchAuditContext, DispatchOutcome, DispatchWebsocketProxyInput, annotate_dispatch_response,
    emit_dispatch_websocket_response_preview, proxy_dispatch_websocket_http1,
};
use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use anyhow::Result;
use hyper::StatusCode;
use qpx_core::http_message::{Request, Response as OwnerResponse};
use qpx_http::body::Body;
use tokio::time::Duration;

pub(super) struct TransparentWebsocketInput<'a> {
    pub(super) req: Request<Body>,
    pub(super) upstream: Option<&'a crate::upstream::pool::ResolvedUpstreamProxy>,
    pub(super) authority: &'a str,
    pub(super) upstream_timeout: Duration,
    pub(super) upgrade_wait_timeout: Duration,
    pub(super) tunnel_idle_timeout: Duration,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) export_session: Option<&'a crate::exporter::ExportSession>,
    pub(super) request_method: &'a hyper::Method,
    pub(super) proxy_name: &'a str,
    pub(super) policy_headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    pub(super) audit: &'a DispatchAuditContext,
}

pub(super) async fn proxy_transparent_websocket(
    input: TransparentWebsocketInput<'_>,
) -> Result<OwnerResponse<Body>> {
    let TransparentWebsocketInput {
        req,
        upstream,
        authority,
        upstream_timeout,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
        http_modules,
        export_session,
        request_method,
        proxy_name,
        policy_headers,
        audit,
    } = input;
    let mut response = proxy_dispatch_websocket_http1(DispatchWebsocketProxyInput {
        req,
        upstream_proxy: upstream,
        direct_connect_authority: authority,
        direct_host_header: authority,
        timeout_dur: upstream_timeout,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
        tunnel_label: "transparent",
        upstream_context: "transparent websocket upstream proxy",
        direct_context: "transparent websocket direct",
        export_session,
    })
    .await?;
    response = http_modules.on_upstream_response(response).await?;
    response = http_modules.prepare_downstream_response(response).await?;
    let keep_upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS;
    finalize_response_with_headers_in_place(
        request_method,
        response.version(),
        proxy_name,
        &mut response,
        policy_headers,
        keep_upgrade,
    );
    emit_dispatch_websocket_response_preview(export_session, &response).await;
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_dispatch_response(&mut response, audit, DispatchOutcome::Allow, &[]);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::dispatch::ProxyKind;
    use qpx_core::http_message::Request as OwnerRequest;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    // Exercise the real library boundary, including the upgrade extension that
    // the network adapter consumes before handing the response to the owner.
    #[tokio::test]
    async fn websocket_owner_boundary_preserves_upgrade_rejection_and_errors() {
        timeout(Duration::from_secs(5), async {
            for status in [101, 403, 400] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let authority = listener.local_addr().unwrap().to_string();
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        head.push(stream.read_u8().await.unwrap());
                        assert!(head.len() < 8192);
                    }
                    let accept = if status == 400 { "invalid" } else { "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" };
                    let response = if status == 403 {
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\nX-Duplicate: first\r\nX-Duplicate: second\r\n\r\ndenied!".to_owned()
                    } else {
                        format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\nX-Duplicate: first\r\nX-Duplicate: second\r\n\r\n")
                    };
                    stream.write_all(response.as_bytes()).await.unwrap();
                    if status == 101 {
                        let mut data = [0; 4];
                        stream.read_exact(&mut data).await.unwrap();
                        assert_eq!(&data, b"ping");
                        stream.write_all(b"pong").await.unwrap();
                    }
                });
                let mut req = http::Request::builder()
                    .uri("/")
                    .header("connection", "upgrade")
                    .header("upgrade", "websocket")
                    .header("sec-websocket-version", "13")
                    .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                    .body(Body::empty()).unwrap();
                let commit = crate::http::protocol::upgrade::install(&mut req);
                let (io, mut client) = tokio::io::duplex(64);
                commit.resolve_with_io(io);
                let audit = DispatchAuditContext::new(None, ProxyKind::Transparent, None,
                    "127.0.0.1:1234".parse().unwrap(), hyper::Method::GET, None, Default::default());
                let control = qpx_core::rules::CompiledHeaderControl::compile(
                    &serde_yaml::from_str("response_set:\n  x-route: finalized").unwrap()).unwrap();
                let mut modules = crate::http::modules::HttpModuleExecution::Empty;
                let result = proxy_transparent_websocket(TransparentWebsocketInput {
                    req: OwnerRequest::from_http(req),
                    upstream: None,
                    authority: &authority,
                    upstream_timeout: Duration::from_secs(2),
                    upgrade_wait_timeout: Duration::from_secs(2),
                    tunnel_idle_timeout: Duration::from_secs(2),
                    http_modules: &mut modules,
                    request_method: &hyper::Method::GET,
                    proxy_name: "qpx-test",
                    policy_headers: Some(&control),
                    audit: &audit,
                    export_session: None,
                }).await;
                if status == 400 {
                    assert!(format!("{:#}", result.unwrap_err()).contains("accept"));
                } else {
                    // An explicit type prevents regression to an in-domain raw carrier.
                    let response: OwnerResponse<Body> = result.unwrap();
                    assert_eq!(response.status().as_u16(), status);
                    assert_eq!(response.version(), http::Version::HTTP_11);
                    assert_eq!(response.headers().get(&"x-route".try_into().unwrap()).unwrap(), "finalized");
                    assert_eq!(response.headers().get_all(&"x-duplicate".try_into().unwrap())
                        .map(|v| v.as_bytes()).collect::<Vec<_>>(), [b"first".as_slice(), b"second".as_slice()]);
                    if status == 101 {
                        assert_eq!(response.headers().get(&"upgrade".try_into().unwrap()).unwrap(), "websocket");
                        assert_eq!(response.headers().get(&"connection".try_into().unwrap()).unwrap(), "upgrade");
                        client.write_all(b"ping").await.unwrap();
                        let mut data = [0; 4];
                        client.read_exact(&mut data).await.unwrap();
                        assert_eq!(&data, b"pong");
                    } else {
                        assert_eq!(qpx_http::body::to_bytes(response.into_head_and_body().1).await.unwrap(), "denied!");
                    }
                }
                server.await.unwrap();
            }
        }).await.unwrap();
    }
}
