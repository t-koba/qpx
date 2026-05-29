use crate::http::body::Body;
use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
use crate::http::protocol::preflight::{PreflightOptions, PreflightOutcome, preflight_validate};
use crate::runtime::Runtime;
use crate::tls::UpstreamCertificateInfo;
use anyhow::Result;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

mod dispatch;
mod upstream;

use self::dispatch::dispatch_mitm_request;

pub struct MitmRouteContext<'a> {
    pub listener_name: &'a str,
    pub src_addr: SocketAddr,
    pub dst_port: u16,
    pub host: &'a str,
    pub sni: &'a str,
    pub upstream_cert: Option<Arc<UpstreamCertificateInfo>>,
}

pub(crate) async fn proxy_mitm_request(
    req: Request<Body>,
    runtime: Runtime,
    sender: Arc<Mutex<SendRequest<Body>>>,
    route: MitmRouteContext<'_>,
) -> Result<Response<Body>> {
    let state = runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    if let PreflightOutcome::Reject(response) = preflight_validate(
        &req,
        proxy_name,
        PreflightOptions::allow_connect(
            state.plan.limits.general.trace_enabled,
            state.messages.trace_disabled.as_str(),
        ),
    ) {
        return Ok(*response);
    }
    let base = extract_base_request_fields(
        &req,
        BaseRequestContext {
            peer_ip: Some(route.src_addr.ip()),
            dst_port: Some(route.dst_port),
            host: Some(route.host),
            sni: Some(route.sni),
            scheme: Some("https"),
            ..Default::default()
        },
    );
    let response = dispatch_mitm_request(req, base, runtime, sender, route).await?;
    Ok(response)
}
