use crate::http::body::Body;
use crate::upstream::http1::{WebsocketProxyConfig, proxy_websocket_http1};
use anyhow::Result;
use hyper::{Request, Response};
use std::time::Duration;

pub(crate) struct DispatchWebsocketProxyInput<'a> {
    pub(crate) req: Request<Body>,
    pub(crate) upstream_proxy: Option<&'a crate::upstream::pool::ResolvedUpstreamProxy>,
    pub(crate) direct_connect_authority: &'a str,
    pub(crate) direct_host_header: &'a str,
    pub(crate) timeout_dur: Duration,
    pub(crate) upgrade_wait_timeout: Duration,
    pub(crate) tunnel_idle_timeout: Duration,
    pub(crate) tunnel_label: &'static str,
    pub(crate) upstream_context: &'a str,
    pub(crate) direct_context: &'a str,
    pub(crate) export_session: Option<&'a crate::exporter::ExportSession>,
}

pub(crate) async fn proxy_dispatch_websocket_http1(
    input: DispatchWebsocketProxyInput<'_>,
) -> Result<Response<Body>> {
    let DispatchWebsocketProxyInput {
        req,
        upstream_proxy,
        direct_connect_authority,
        direct_host_header,
        timeout_dur,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
        tunnel_label,
        upstream_context,
        direct_context,
        export_session,
    } = input;
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_request_preview_async(&req).await;
        session.emit_plaintext(true, &preview);
    }
    proxy_websocket_http1(
        req,
        WebsocketProxyConfig {
            upstream_proxy,
            direct_connect_authority,
            direct_host_header,
            timeout_dur,
            upgrade_wait_timeout,
            tunnel_idle_timeout,
            tunnel_label,
            upstream_context,
            direct_context,
        },
    )
    .await
}

pub(crate) fn emit_dispatch_websocket_response_preview(
    export_session: Option<&crate::exporter::ExportSession>,
    response: &Response<Body>,
) -> impl std::future::Future<Output = ()> + Send + 'static {
    let session = export_session.cloned();
    let preview = crate::exporter::serialize_response_preview_async(response);
    async move {
        let Some(session) = session else {
            return;
        };
        let preview = preview.await;
        session.emit_plaintext(false, &preview);
    }
}
