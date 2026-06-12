mod context;
mod frame;
mod inspect;
mod local_response;
mod protocol;

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
mod deadline;
mod metrics;
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) mod streaming;

pub(crate) use context::RpcMatchContext;
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) use frame::FramedBodySummary;
pub(crate) use frame::{
    PrecomputedRpcBodySummary, RpcBodySummaryObserver, request_body_summary_observer,
    response_body_summary_observer,
};
pub(crate) use inspect::{inspect_request, inspect_response};
pub(crate) use local_response::build_rpc_local_response;

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) use deadline::{
    ResolvedGrpcDeadline, apply_grpc_deadline_header, build_grpc_deadline_exceeded_response,
    resolve_rpc_deadline,
};
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) use metrics::{
    emit_grpc_body_metrics, emit_grpc_deadline_exceeded_metric, emit_grpc_status_metric,
    emit_grpc_stream_duration_metric,
};
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) use streaming::{grpc_streaming_label, streaming_rpc_observer, streaming_rpc_protocol};

#[cfg(test)]
use base64::Engine;
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(test)]
use bytes::Bytes;
#[cfg(all(test, any(feature = "http3-backend-h3", feature = "http3-backend-qpx")))]
use deadline::{RpcDeadlineProtocol, format_grpc_timeout, parse_grpc_timeout};
#[cfg(test)]
use frame::{DEFAULT_MAX_GRPC_WEB_TRAILER_BYTES, GrpcFrameError, GrpcFrameObserver};
#[cfg(test)]
use http::{HeaderMap, Request, StatusCode};
#[cfg(test)]
use local_response::{frame_grpc_message, frame_grpc_web_trailers};
#[cfg(test)]
use protocol::{
    extract_connect_status_and_message, extract_grpc_status_and_message, extract_service_and_method,
};
#[cfg(test)]
use qpx_http::body::Body;
#[cfg(all(test, any(feature = "http3-backend-h3", feature = "http3-backend-qpx")))]
use streaming::ConnectFrameObserver;
#[cfg(all(test, any(feature = "http3-backend-h3", feature = "http3-backend-qpx")))]
use tokio::time::Instant;

#[cfg(test)]
mod tests;
