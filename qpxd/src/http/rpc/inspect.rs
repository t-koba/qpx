// Extracted from rpc/mod.rs; keep public re-exports in mod.rs.
use super::context::RpcMatchContext;
use super::frame::{FramedBodySummary, GrpcFrameObserver, PrecomputedRpcBodySummary};
use super::protocol::{
    detect_rpc_protocol, extract_rpc_status_and_message, extract_service_and_method,
    infer_request_streaming, infer_response_streaming, response_content_type,
};
use crate::http::body::size::{
    ObservedBodyReader, observed_request_body_reader, observed_request_size,
    observed_request_trailers, observed_response_body_reader, observed_response_size,
    observed_response_trailers,
};
use anyhow::Result;
use http::{HeaderMap, Request, Response};
use qpx_http::body::Body;

const CONNECT_STATUS_BODY_PREFIX_BYTES: usize = 16 * 1024;

pub(crate) fn inspect_request(
    req: &Request<Body>,
) -> impl std::future::Future<Output = RpcMatchContext> + Send + 'static {
    let headers = req.headers().clone();
    let path = req.uri().path().to_string();
    let method_name = req.method().as_str().to_string();
    let observed_size = observed_request_size(req);
    let trailers = observed_request_trailers(req).cloned();
    let observed_body = observed_request_body_reader(req);
    let precomputed_body_summary = req.extensions().get::<PrecomputedRpcBodySummary>().cloned();

    async move {
        let protocol = detect_rpc_protocol(&headers, None);
        let (service, method) = extract_service_and_method(path.as_str())
            .map(|(service, method)| (Some(service.to_string()), Some(method.to_string())))
            .unwrap_or((None, None));
        let request_summary = match precomputed_body_summary {
            Some(summary) => Some(summary.0),
            None => summarize_observed_request_body(
                protocol.as_deref(),
                &headers,
                observed_body.as_ref(),
            )
            .await
            .ok()
            .flatten(),
        }
        .filter(|summary| summary.message_count > 0 || summary.message_bytes > 0);
        let message_size = request_summary
            .as_ref()
            .map(|summary| summary.message_bytes)
            .filter(|size| *size > 0)
            .or(observed_size);
        let request_message_count = request_summary
            .as_ref()
            .map(|summary| summary.message_count);
        let request_message_bytes = request_summary
            .as_ref()
            .map(|summary| summary.message_bytes);
        if let (Some(protocol), Some(summary)) = (protocol.as_deref(), request_summary.as_ref())
            && matches!(protocol, "grpc" | "grpc_web")
        {
            super::metrics::emit_inspected_body_metrics("request", "unknown", protocol, summary);
        }
        let streaming = infer_request_streaming(
            protocol.as_deref(),
            method_name.as_str(),
            request_message_count,
        )
        .map(str::to_string);
        RpcMatchContext {
            protocol,
            service,
            method,
            streaming,
            message_size,
            trailers,
            request_message_count,
            request_message_bytes,
            ..Default::default()
        }
    }
}

pub(crate) fn inspect_response(
    request: &RpcMatchContext,
    response: &Response<Body>,
) -> impl std::future::Future<Output = RpcMatchContext> + Send + 'static {
    let request = request.clone();
    let headers = response.headers().clone();
    let observed_size = observed_response_size(response);
    let observed_trailers = observed_response_trailers(response).cloned();
    let observed_body = observed_response_body_reader(response);
    let precomputed_body_summary = response
        .extensions()
        .get::<PrecomputedRpcBodySummary>()
        .cloned();

    async move {
        let protocol = detect_rpc_protocol(&headers, request.protocol.as_deref())
            .or_else(|| request.protocol.clone());
        let content_type = response_content_type(&headers);
        let body_summary = match precomputed_body_summary {
            Some(summary) => Some(summary.0),
            None => summarize_observed_response_body(
                protocol.as_deref(),
                content_type.as_deref(),
                observed_body.as_ref(),
            )
            .await
            .ok()
            .flatten(),
        };
        let connect_status_body = if matches!(protocol.as_deref(), Some("connect")) {
            match observed_body.as_ref() {
                Some(body) => body
                    .read_prefix(CONNECT_STATUS_BODY_PREFIX_BYTES)
                    .await
                    .ok(),
                None => None,
            }
        } else {
            None
        };
        let trailers = observed_trailers.or_else(|| {
            body_summary
                .as_ref()
                .and_then(|summary| summary.trailers.clone())
        });

        let (status, message) = extract_rpc_status_and_message(
            protocol.as_deref(),
            &headers,
            trailers.as_ref(),
            connect_status_body.as_ref(),
        );
        let streaming = infer_response_streaming(
            protocol.as_deref(),
            request.request_message_count,
            body_summary.as_ref().map(|summary| summary.message_count),
        )
        .map(str::to_string)
        .or_else(|| request.streaming.clone());
        let message_size = body_summary
            .as_ref()
            .map(|summary| summary.message_bytes)
            .filter(|size| *size > 0)
            .or(observed_size);
        let response_message_count = body_summary.as_ref().map(|summary| summary.message_count);
        let response_message_bytes = body_summary.as_ref().map(|summary| summary.message_bytes);
        if let (Some(protocol), Some(summary)) = (protocol.as_deref(), body_summary.as_ref())
            && matches!(protocol, "grpc" | "grpc_web")
        {
            super::metrics::emit_inspected_body_metrics("response", "unknown", protocol, summary);
        }
        if let (Some(protocol), Some(status)) = (protocol.as_deref(), status.as_deref())
            && matches!(protocol, "grpc" | "grpc_web")
        {
            super::metrics::emit_inspected_status("unknown", protocol, status);
        }

        RpcMatchContext {
            protocol,
            service: request.service.clone(),
            method: request.method.clone(),
            streaming,
            status,
            message_size,
            message,
            trailers,
            request_message_count: request.request_message_count,
            response_message_count,
            request_message_bytes: request.request_message_bytes,
            response_message_bytes,
            stream_duration_ms: request.stream_duration_ms,
        }
    }
}

async fn summarize_observed_request_body(
    protocol: Option<&str>,
    headers: &HeaderMap,
    body: Option<&ObservedBodyReader>,
) -> Result<Option<FramedBodySummary>> {
    let Some(body) = body else {
        return Ok(None);
    };
    let summary = match protocol {
        Some("grpc") => observe_grpc_observed_body(body, GrpcFrameObserver::new(None)).await?,
        Some("grpc_web") => {
            observe_grpc_observed_body(
                body,
                GrpcFrameObserver::grpc_web(
                    response_content_type(headers)
                        .as_deref()
                        .map(|value| value.starts_with("application/grpc-web-text"))
                        .unwrap_or(false),
                    None,
                    None,
                ),
            )
            .await?
        }
        _ => FramedBodySummary {
            message_count: usize::from(body.len() > 0),
            message_bytes: body.len(),
            trailers: None,
        },
    };
    Ok(Some(summary))
}

async fn summarize_observed_response_body(
    protocol: Option<&str>,
    content_type: Option<&str>,
    body: Option<&ObservedBodyReader>,
) -> Result<Option<FramedBodySummary>> {
    let Some(body) = body else {
        return Ok(None);
    };
    let summary = match protocol {
        Some("grpc") => observe_grpc_observed_body(body, GrpcFrameObserver::new(None)).await?,
        Some("grpc_web") => {
            observe_grpc_observed_body(
                body,
                GrpcFrameObserver::grpc_web(
                    content_type
                        .map(|value| value.starts_with("application/grpc-web-text"))
                        .unwrap_or(false),
                    None,
                    None,
                ),
            )
            .await?
        }
        Some("connect") => FramedBodySummary {
            message_count: usize::from(body.len() > 0),
            message_bytes: body.len(),
            trailers: None,
        },
        _ => FramedBodySummary {
            message_count: usize::from(body.len() > 0),
            message_bytes: body.len(),
            trailers: None,
        },
    };
    Ok(Some(summary))
}

async fn observe_grpc_observed_body(
    body: &ObservedBodyReader,
    mut observer: GrpcFrameObserver,
) -> Result<FramedBodySummary> {
    body.feed_chunks(|chunk| {
        observer.feed(chunk)?;
        Ok(())
    })
    .await?;
    observer.finish().map_err(Into::into)
}
