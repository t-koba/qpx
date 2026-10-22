use super::super::ReloadableReverse;
use super::streaming::ReverseH3RequestPeer;
pub(crate) use super::terminate_socket::prepare_reverse_terminate_socket;
pub(crate) use super::terminate_tls::build_reverse_tls_config;
use crate::http::body::size::set_observed_request_size;
use crate::http3::quinn_socket::{QuinnEndpointSocket, build_server_endpoint};
use crate::reverse::transport::{self, ReverseConnInfo};
use crate::runtime::ResolvedStreamingLimits;
use crate::server::control::SidecarControl;
use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use qpx_core::config::ReverseEdgeConfig;
use qpx_http::body::Body;
use std::net::SocketAddr;
use tokio::sync::watch;
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

pub(crate) async fn run_http3_terminate(
    reverse: ReverseEdgeConfig,
    listen_addr: SocketAddr,
    reverse_rt: ReloadableReverse,
    mut shutdown: watch::Receiver<SidecarControl>,
    endpoint_socket: QuinnEndpointSocket,
) -> Result<()> {
    let tls_config = build_reverse_tls_config(&reverse)?;
    let max_bidi = reverse_rt
        .runtime
        .state()
        .plan
        .limits
        .h3
        .max_h3_streams_per_connection
        .min(u32::MAX as usize) as u32;
    let server_config =
        crate::http3::quic::build_h3_server_config_from_tls(tls_config, max_bidi.max(1), 16)?;
    let endpoint = build_server_endpoint(endpoint_socket, server_config)?;
    let handler = ReverseQpxHandler {
        reverse: reverse_rt,
    };
    let connection_semaphore = handler.reverse.runtime.state().connection_semaphore.clone();

    // The h3 backend logs this same line when its listener starts, with the
    // same field, so a reader can compare the two backends: a Chromium
    // timeout in either one can be told apart from a listener that never
    // came up. The reverse edge's own name and address are in the sibling
    // "reverse TLS listener starting" line.
    info!(label = "reverse-terminate", "HTTP/3 listener starting");

    loop {
        let connecting = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || shutdown.borrow().should_stop() {
                    None
                } else {
                    continue;
                }
            }
            connecting = endpoint.accept() => connecting,
        };
        let Some(connecting) = connecting else {
            break;
        };
        let permit = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || shutdown.borrow().should_stop() {
                    None
                } else {
                    continue;
                }
            }
            permit = connection_semaphore.clone().acquire_owned() => Some(permit?),
        };
        let Some(permit) = permit else {
            break;
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) =
                qpx_h3::serve_connection(connecting, listen_addr.port(), handler).await
            {
                warn!(error = ?err, "reverse HTTP/3 qpx-h3 connection failed");
            }
        });
    }

    Ok(())
}

#[derive(Clone)]
struct ReverseQpxHandler {
    reverse: ReloadableReverse,
}

impl ReverseQpxHandler {
    fn edge_streaming_limits(&self) -> ResolvedStreamingLimits {
        let state = self.reverse.runtime.state();
        let limits = state.plan.limits;
        state
            .plan
            .reverse_edge(self.reverse.name.as_ref())
            .map(|edge| edge.streaming)
            .unwrap_or_else(|| ResolvedStreamingLimits::from(limits))
    }
}

impl qpx_h3::RequestHandler for ReverseQpxHandler {
    fn settings(&self) -> qpx_h3::Settings {
        let state = self.reverse.runtime.state();
        let limits = state.plan.limits;
        let mut streaming = self.edge_streaming_limits();
        streaming.max_request_body_bytes =
            super::streaming::max_reverse_h3_request_body_bytes(&self.reverse, streaming);
        qpx_h3::Settings {
            enable_extended_connect: false,
            enable_datagram: false,
            enable_webtransport: false,
            max_webtransport_sessions: 0,
            max_request_body_bytes: streaming.max_request_body_bytes,
            max_concurrent_streams_per_connection: limits.h3.max_h3_streams_per_connection,
            read_timeout: Duration::from_millis(limits.timeouts.h3_read_timeout_ms),
            datagram_channel_capacity: limits.h3.datagram_channel_capacity,
            webtransport_stream_channel_capacity: limits.h3.webtransport_stream_channel_capacity,
            ..Default::default()
        }
    }

    fn via_received_by(&self) -> impl AsRef<str> + Send + 'static {
        self.reverse
            .runtime
            .state()
            .plan
            .identity
            .proxy_name
            .clone()
    }

    async fn handle_request(
        &self,
        request: qpx_h3::Request,
        conn: qpx_h3::ConnectionInfo,
        req_stream: qpx_h3::RequestStream,
    ) -> qpx_h3::H3Result<()> {
        self.handle_request_inner(request, conn, req_stream)
            .await
            .map_err(Into::into)
    }
}

impl ReverseQpxHandler {
    async fn handle_request_inner(
        &self,
        request: qpx_h3::Request,
        conn: qpx_h3::ConnectionInfo,
        mut req_stream: qpx_h3::RequestStream,
    ) -> Result<()> {
        let state = self.reverse.runtime.state();
        let proxy_name = state.plan.identity.proxy_name.as_ref();
        let h3_read_timeout =
            Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms.max(1));
        let response_body_limit = state.plan.limits.body.max_h3_response_body_bytes;
        if request.head.method() == http::Method::CONNECT || request.protocol.is_some() {
            return send_reverse_qpx_local_response(
                &mut req_stream,
                request.head.method(),
                proxy_name,
                StatusCode::METHOD_NOT_ALLOWED,
                Body::from(state.messages.reverse_error.clone()),
                response_body_limit,
                h3_read_timeout,
            )
            .await;
        }

        let request_headers = request.head.headers().clone();
        if crate::http::protocol::sse::is_sse_reconnect(&request_headers) {
            crate::http::protocol::sse::emit_sse_reconnect(self.reverse.name.as_ref(), "unknown");
        }
        let grpc_protocol = crate::http::rpc::streaming_rpc_protocol(&request_headers, None);
        let grpc_request_content_type = request_headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let grpc_started = Instant::now();
        let edge_streaming = self.edge_streaming_limits();
        let request_streaming = super::streaming::request_streaming_limits_for_head(
            &self.reverse,
            &request.head,
            reverse_qpx_request_peer(&conn),
            edge_streaming,
        );
        let grpc_deadline = grpc_protocol.as_deref().map(|protocol| {
            crate::http::rpc::resolve_rpc_deadline(
                &request_headers,
                protocol,
                Duration::from_millis(request_streaming.max_grpc_stream_duration_ms),
                grpc_started,
            )
        });
        let request_method = request.head.method().clone();
        let declared_content_length =
            crate::http3::codec::parse_content_length_fields(request.head.headers())?;
        if let Some(content_length) = declared_content_length
            && content_length > request_streaming.max_request_body_bytes as u64
        {
            return send_reverse_qpx_local_response(
                &mut req_stream,
                &request_method,
                proxy_name,
                StatusCode::PAYLOAD_TOO_LARGE,
                Body::from("request payload too large"),
                response_body_limit,
                h3_read_timeout,
            )
            .await;
        }

        let (sender, body) = Body::channel_with_capacity(request_streaming.body_channel_capacity);
        let mut req = crate::http3::codec::h3_request_to_hyper(request.head, body)?;
        if let Some(content_length) = declared_content_length {
            set_observed_request_size(&mut req, content_length);
        }
        if let Some(deadline) = grpc_deadline {
            req.extensions_mut().insert(deadline);
        }
        let reverse_conn = ReverseConnInfo::terminated(
            conn.remote_addr,
            conn.dst_port,
            conn.tls_sni.clone(),
            conn.peer_certificates.clone(),
        );
        let response_fut = async {
            let fut =
                transport::handle_request_with_interim(req, self.reverse.clone(), reverse_conn);
            let result = if let Some(deadline) = grpc_deadline {
                match tokio::time::timeout_at(deadline.instant(), fut).await {
                    Ok(result) => result,
                    Err(_) => {
                        if let Some(protocol) = grpc_protocol.as_deref() {
                            crate::http::rpc::emit_grpc_deadline_exceeded_metric(
                                self.reverse.name.as_ref(),
                                protocol,
                            );
                            return Ok::<_, anyhow::Error>((
                                Vec::new(),
                                crate::http::rpc::build_grpc_deadline_exceeded_response(
                                    protocol,
                                    grpc_request_content_type.as_deref(),
                                )?,
                            ));
                        }
                        return Err(anyhow!(
                            "reverse qpx-h3 gRPC stream duration exceeded configured limit"
                        ));
                    }
                }
            } else {
                fut.await
            };
            Ok::<_, anyhow::Error>(result.unwrap_or_else(|impossible| match impossible {}))
        };
        let (mut response_stream, mut request_body_stream) = req_stream.split();
        let relay_body_fut = crate::http3::qpx_stream::relay_qpx_request_body_observed_from_recv(
            &mut request_body_stream,
            sender,
            crate::http3::qpx_stream::QpxRequestBodyRelayOptions {
                read_timeout: Duration::from_millis(request_streaming.body_read_timeout_ms),
                max_body_bytes: request_streaming.max_request_body_bytes,
                declared_content_length,
                request_headers: &request_headers,
                listener_name: Some(self.reverse.name.as_ref()),
                max_grpc_message_bytes: Some(request_streaming.max_grpc_message_bytes),
                max_grpc_web_trailer_bytes: Some(request_streaming.max_grpc_web_trailer_bytes),
                // The relay wrapper below owns the stream budget: it cancels
                // the relay at expiry instead of failing it, so the inner
                // relay must not abort the stream on the same instant.
                grpc_stream_deadline: None,
                observe_grpc_messages: request_streaming.observe_grpc_messages,
            },
        );
        // Cancel (do not fail) the relay when the stream budget expires: the
        // response is then the synthetic deadline reply, and a relay expiry
        // error must not win the race and reset the stream. Genuine relay
        // failures still surface before the deadline.
        let relay_fut = async {
            match grpc_deadline {
                Some(deadline) => tokio::time::timeout_at(deadline.instant(), relay_body_fut)
                    .await
                    .ok(),
                None => Some(relay_body_fut.await),
            }
        };
        tokio::pin!(relay_fut);
        tokio::pin!(response_fut);
        let mut request_summary = None;
        let mut relay_done = false;
        let (interim, response) = tokio::select! {
            relay_result = &mut relay_fut => {
                match relay_result {
                    Some(Ok((_bytes, summary))) => {
                        request_summary = summary;
                        relay_done = true;
                        response_fut.await?
                    }
                    Some(Err(err)) => {
                        warn!(error = ?err, "reverse qpx-h3 request body relay failed");
                        response_stream.abort_message_stream();
                        return Err(err);
                    }
                    // The budget expired with the body incomplete: only the
                    // synthetic deadline reply may proceed. A normal reply with
                    // an incomplete body ends like any relay failure, and the
                    // exhausted relay future must never be polled again.
                    None => {
                        let output = response_fut.await?;
                        if output
                            .1
                            .extensions()
                            .get::<crate::http::rpc::RpcDeadlineReply>()
                            .is_none()
                        {
                            warn!(
                                "reverse qpx-h3 request body relay exceeded the stream budget"
                            );
                            response_stream.abort_message_stream();
                            return Err(anyhow!(
                                "reverse qpx-h3 request body relay exceeded the stream budget"
                            ));
                        }
                        output
                    }
                }
            }
            response_result = &mut response_fut => response_result?,
        };

        for head in interim {
            send_reverse_qpx_interim_response(&mut response_stream, head, edge_streaming).await?;
        }

        let is_deadline_reply = response
            .extensions()
            .get::<crate::http::rpc::RpcDeadlineReply>()
            .is_some();
        let response_streaming = ResolvedStreamingLimits::from_response(&response, edge_streaming);
        let response_fut = crate::http3::qpx_stream::send_qpx_response_stream_observed_to_send(
            &mut response_stream,
            response,
            &request_method,
            crate::http3::qpx_stream::QpxResponseSendOptions {
                max_body_bytes: response_streaming.max_response_body_bytes,
                body_read_timeout: Duration::from_millis(response_streaming.body_read_timeout_ms),
                body_send_timeout: Duration::from_millis(response_streaming.body_send_timeout_ms),
                listener_name: Some(self.reverse.name.as_ref()),
                fallback_grpc_protocol: grpc_protocol.as_deref(),
                max_grpc_message_bytes: Some(response_streaming.max_grpc_message_bytes),
                max_grpc_web_trailer_bytes: Some(response_streaming.max_grpc_web_trailer_bytes),
                // The deadline reply is built after the stream budget expired;
                // enforcing the expired instant here would reset the reply
                // about the expiry. The send keeps its own body_send_timeout.
                grpc_stream_deadline: grpc_deadline
                    .map(|deadline| deadline.instant())
                    .filter(|instant| *instant > Instant::now()),
                sse_policy: Some(response_streaming.sse),
                observe_grpc_messages: response_streaming.observe_grpc_messages,
            },
        );
        let response_summary = if relay_done {
            reverse_qpx_response_summary(response_fut.await)?
        } else if is_deadline_reply {
            // The synthetic reply is self-contained: a still-pending relay
            // can only fail on the expired budget, so send the reply alone
            // instead of letting the relay reset the stream.
            reverse_qpx_response_summary(response_fut.await)?
        } else {
            let (response_result, relay_result) = tokio::join!(response_fut, relay_fut);
            request_summary = match relay_result {
                Some(Ok((_bytes, summary))) => summary,
                Some(Err(err)) => {
                    warn!(error = ?err, "reverse qpx-h3 request body relay failed");
                    response_stream.abort_message_stream();
                    return Err(err);
                }
                // No deadline reply is in flight on this path, so an expired
                // relay ends the exchange exactly like any relay failure.
                None => {
                    warn!("reverse qpx-h3 request body relay exceeded the stream budget");
                    response_stream.abort_message_stream();
                    return Err(anyhow!(
                        "reverse qpx-h3 request body relay exceeded the stream budget"
                    ));
                }
            };
            reverse_qpx_response_summary(response_result)?
        };
        if response_streaming.observe_grpc_messages
            && let Some(protocol) = grpc_protocol.as_deref()
        {
            crate::http::rpc::emit_grpc_stream_duration_metric_from_summaries(
                self.reverse.name.as_ref(),
                protocol,
                request_summary.as_ref(),
                response_summary.as_ref(),
                || grpc_started.elapsed(),
            );
        }
        Ok(())
    }
}

fn reverse_qpx_request_peer(conn: &qpx_h3::ConnectionInfo) -> ReverseH3RequestPeer<'_> {
    ReverseH3RequestPeer {
        remote_addr: conn.remote_addr,
        dst_port: conn.dst_port,
        tls_sni: conn.tls_sni.as_deref(),
        peer_certificates: conn.peer_certificates.as_deref().map(Vec::as_slice),
    }
}

fn reverse_qpx_response_summary(
    result: std::result::Result<
        Option<crate::http::rpc::FramedBodySummary>,
        crate::http3::response_error::H3ResponseSendError,
    >,
) -> Result<Option<crate::http::rpc::FramedBodySummary>> {
    result.map_err(|err| {
        crate::http3::response_error::emit_h3_response_send_error("qpx_h3", &err);
        err.into_inner()
    })
}

async fn send_reverse_qpx_local_response(
    req_stream: &mut qpx_h3::RequestStream,
    method: &http::Method,
    proxy_name: &str,
    status: StatusCode,
    body: Body,
    response_body_limit: usize,
    h3_read_timeout: Duration,
) -> Result<()> {
    let response = crate::http::protocol::l7::finalize_response_for_request(
        method,
        http::Version::HTTP_3,
        proxy_name,
        Response::builder().status(status).body(body)?,
        false,
    );
    crate::http3::qpx_stream::send_qpx_response_stream(
        req_stream,
        response,
        method,
        response_body_limit,
        h3_read_timeout,
    )
    .await
}

async fn send_reverse_qpx_interim_response(
    response_stream: &mut qpx_h3::RequestSendStream,
    head: crate::upstream::raw_http1::InterimResponseHead,
    streaming: ResolvedStreamingLimits,
) -> Result<()> {
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        head.status,
        "QPX HTTP/3 interim response",
    )?;
    let mut interim = http::Response::builder().status(status).body(())?;
    *interim.headers_mut() = head.headers;
    crate::http3::qpx_stream::send_qpx_interim_response_to_send(
        response_stream,
        interim,
        Duration::from_millis(streaming.body_send_timeout_ms),
    )
    .await
}
