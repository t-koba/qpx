use super::super::HostPort;
use crate::destination::DestinationInputs;
use crate::http::body::Body;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::common::bad_request_response as bad_request;
use crate::http::protocol::l7::finalize_response_for_request;
use anyhow::Result;
use hyper::{Request, Response, StatusCode};
use qpx_core::prefilter::MatchPrefilterContext;

pub(super) fn resolve_forward_target_or_response(
    req: &Request<Body>,
    base: &BaseRequestFields,
    state: &crate::runtime::RuntimeState,
    listener_cfg: &crate::runtime::CompiledListenerSettings,
    proxy_name: &str,
    is_ftp_request: bool,
) -> Result<std::result::Result<HostPort, Response<Body>>> {
    if is_ftp_request && !listener_cfg.ftp.enabled {
        return Ok(Err(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            Response::builder()
                .status(StatusCode::NOT_IMPLEMENTED)
                .body(Body::from(state.messages.ftp_disabled.clone()))?,
            false,
        )));
    }
    let Some(host) = base.host.as_deref() else {
        return Ok(Err(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("missing Host/authority"))
                .unwrap_or_else(|_| bad_request("missing Host/authority")),
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
        path: base.path.as_deref(),
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
            scheme: base.scheme.as_deref(),
            port: host.port,
            ..Default::default()
        },
        destination_resolution,
    )
}
