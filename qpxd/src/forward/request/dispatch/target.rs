use super::super::HostPort;
use crate::destination::DestinationInputs;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::l7::finalize_response_for_request;
use anyhow::Result;
use hyper::StatusCode;
use qpx_core::http_message::{Request, Response};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_http::body::Body;

pub(super) fn resolve_forward_target_or_response(
    req: &Request<Body>,
    base: &BaseRequestFields,
    state: &crate::runtime::RuntimeState,
    listener_cfg: &crate::runtime::CompiledListenerSettings,
    proxy_name: &str,
    is_ftp_request: bool,
) -> Result<std::result::Result<HostPort, Response<Body>>> {
    if is_ftp_request && !listener_cfg.ftp.enabled {
        let mut response = Response::new(Body::from(state.messages.ftp_disabled.clone()));
        *response.status_mut() = StatusCode::NOT_IMPLEMENTED;
        return Ok(Err(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            response,
            false,
        )));
    }
    let Some(host) = base.host() else {
        let mut response = Response::new(Body::from("missing Host/authority"));
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(Err(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            response,
            false,
        )));
    };
    Ok(Ok(HostPort {
        host: host.to_string(),
        port: base.dst_port,
    }))
}

pub(super) fn forward_prefilter_context<'a>(
    base: &'a BaseRequestFields,
    host: &'a HostPort,
) -> MatchPrefilterContext<'a> {
    MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: host.port,
        src_ip: base.peer_ip,
        host: Some(host.host.as_str()),
        sni: base.sni.as_deref(),
        path: base.path(),
    }
}

pub(super) fn forward_destination_metadata(
    state: &crate::runtime::RuntimeState,
    base: &BaseRequestFields,
    host: &HostPort,
    destination_resolution: Option<&qpx_core::config::DestinationResolutionOverrideConfig>,
) -> crate::destination::DestinationMetadata {
    state.classify_destination(
        &DestinationInputs {
            host: Some(host.host.as_str()),
            ip: host.host.parse().ok(),
            scheme: base.scheme.as_ref().map(http::uri::Scheme::as_str),
            port: host.port,
            ..Default::default()
        },
        destination_resolution,
    )
}
