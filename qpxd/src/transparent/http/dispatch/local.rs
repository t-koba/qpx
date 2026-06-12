use crate::http::dispatch::{
    DispatchAuditContext, DispatchOutcome, DispatchWebsocketProxyInput, annotate_dispatch_response,
    emit_dispatch_websocket_response_preview, proxy_dispatch_websocket_http1,
};
use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use anyhow::Result;
use hyper::{Request, StatusCode};
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
) -> Result<hyper::Response<Body>> {
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
