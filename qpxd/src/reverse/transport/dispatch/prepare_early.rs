use super::PreparedReverseRequest;
use super::prepare_cors::prepare_cors_preflight;
use super::prepare_single::{SingleHttpPrepare, try_prepare_single_http_reverse_request};
use super::route_constraints::{ReverseEarlyResult, reverse_security_rejection};
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::reverse::transport::ReverseConnInfo;
use anyhow::Result;
use hyper::Request;
use qpx_http::body::Body;
use std::sync::Arc;

pub(super) enum EarlyReversePrepare {
    Settled(Box<ReverseEarlyResult<PreparedReverseRequest>>),
    Continue(Box<Request<Body>>),
}

pub(super) async fn check_early_reverse_prepare(
    req: Request<Body>,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: &Arc<crate::runtime::RuntimeState>,
    compiled: &Arc<crate::reverse::CompiledReverse>,
    cors_request: Option<&qpx_core::cors::CorsRequest>,
) -> Result<EarlyReversePrepare> {
    if let Some(response) = reverse_security_rejection(&req, conn, state, compiled)? {
        return Ok(EarlyReversePrepare::Settled(Box::new(Err(response))));
    }
    if let Some(cors_request) = cors_request.filter(|request| request.is_preflight())
        && let Some(response) = prepare_cors_preflight(
            req.headers().clone(),
            req.version(),
            base,
            conn,
            state,
            &compiled.router,
            cors_request,
        )
        .await?
    {
        return Ok(EarlyReversePrepare::Settled(Box::new(Err(response))));
    }
    match try_prepare_single_http_reverse_request(req, base, conn, state, compiled, cors_request)? {
        SingleHttpPrepare::Hit(fast) => Ok(EarlyReversePrepare::Settled(fast)),
        SingleHttpPrepare::Miss(req_back) => Ok(EarlyReversePrepare::Continue(req_back)),
    }
}
