use super::super::connect::parse::parse_connect_udp_target;
use super::connect::{handle_qpx_connect_stream, handle_qpx_traditional_connect_stream};
use super::response::{send_qpx_response_stream, send_qpx_static_response};
use super::webtransport_dispatch::handle_qpx_webtransport_connect as dispatch_qpx_webtransport_connect;
use crate::http::body::Body;
use crate::http::body::size::set_observed_request_size;
use crate::http3::codec::h3_request_to_hyper;
use crate::runtime::{ResolvedStreamingLimits, Runtime};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use hyper::{Response, StatusCode};
use qpx_core::config::ConnectUdpConfig;
use std::sync::Arc;
use tokio::time::{Duration, Instant};
use tracing::warn;

#[derive(Clone)]
pub(crate) struct ForwardQpxHandler {
    pub(crate) runtime: Runtime,
    pub(crate) listener_name: Arc<str>,
    pub(crate) connect_udp: ConnectUdpConfig,
}

#[async_trait]
impl qpx_h3::RequestHandler for ForwardQpxHandler {
    fn settings(&self) -> qpx_h3::Settings {
        let state = self.runtime.state();
        let limits = state.plan.limits;
        let streaming = self.listener_streaming_limits();
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: limits.h3.max_h3_streams_per_connection.max(1) as u64,
            max_request_body_bytes: streaming.max_request_body_bytes,
            max_concurrent_streams_per_connection: limits.h3.max_h3_streams_per_connection,
            read_timeout: Duration::from_millis(limits.timeouts.h3_read_timeout_ms),
            datagram_channel_capacity: limits.h3.datagram_channel_capacity,
            webtransport_datagram_channel_capacity: limits
                .h3
                .webtransport_datagram_channel_capacity,
            webtransport_stream_channel_capacity: limits.h3.webtransport_stream_channel_capacity,
            ..Default::default()
        }
    }

    fn via_received_by(&self) -> String {
        self.runtime.state().plan.identity.proxy_name.to_string()
    }

    async fn handle_request(
        &self,
        request: qpx_h3::Request,
        conn: qpx_h3::ConnectionInfo,
        req_stream: qpx_h3::RequestStream,
    ) -> Result<()> {
        if request.head.method() == http::Method::CONNECT {
            return self.handle_connect(request, conn, req_stream).await;
        }

        self.handle_http_request(request, conn.remote_addr, req_stream)
            .await
    }

    async fn handle_webtransport_connect(
        &self,
        req_head: http::Request<()>,
        req_stream: qpx_h3::RequestStream,
        conn: qpx_h3::ConnectionInfo,
        session: qpx_h3::WebTransportSession,
    ) -> Result<()> {
        self.handle_qpx_webtransport_connect(req_head, req_stream, conn, session)
            .await
    }

    async fn handle_connect_stream(
        &self,
        req_head: http::Request<()>,
        req_stream: qpx_h3::RequestStream,
        conn: qpx_h3::ConnectionInfo,
        protocol: qpx_h3::Protocol,
        datagrams: Option<qpx_h3::StreamDatagrams>,
    ) -> Result<()> {
        handle_qpx_connect_stream(self, req_head, req_stream, conn, protocol, datagrams).await
    }
}

impl ForwardQpxHandler {
    async fn handle_http_request(
        &self,
        request: qpx_h3::Request,
        remote_addr: std::net::SocketAddr,
        mut req_stream: qpx_h3::RequestStream,
    ) -> Result<()> {
        let request_headers = request.head.headers().clone();
        if crate::http::protocol::sse::is_sse_reconnect(&request_headers) {
            crate::http::protocol::sse::emit_sse_reconnect(self.listener_name.as_ref(), "unknown");
        }
        let grpc_protocol = crate::http::rpc::streaming_rpc_protocol(&request_headers, None);
        let grpc_started = Instant::now();
        let listener_streaming = self.listener_streaming_limits();
        let grpc_deadline = grpc_protocol.as_deref().map(|protocol| {
            crate::http::rpc::resolve_rpc_deadline(
                &request_headers,
                protocol,
                Duration::from_millis(listener_streaming.max_grpc_stream_duration_ms),
                grpc_started,
            )
        });
        let declared_content_length =
            crate::http3::codec::parse_content_length_fields(request.head.headers())?;
        if let Some(content_length) = declared_content_length
            && content_length > listener_streaming.max_request_body_bytes as u64
        {
            return send_qpx_static_response(
                &mut req_stream,
                StatusCode::PAYLOAD_TOO_LARGE,
                b"request payload too large",
                request.head.method(),
                self.runtime.state().plan.identity.proxy_name.as_ref(),
            )
            .await;
        }

        let (sender, body) = Body::channel_with_capacity(listener_streaming.body_channel_capacity);
        let mut req = h3_request_to_hyper(request.head, body)?;
        if let Some(content_length) = declared_content_length {
            set_observed_request_size(&mut req, content_length);
        }
        if let Some(deadline) = grpc_deadline {
            req.extensions_mut().insert(deadline);
        }
        let request_method = req.method().clone();
        let response_fut = async {
            let fut = crate::forward::request::handle_request_inner(
                req,
                self.runtime.clone(),
                self.listener_name.as_ref(),
                remote_addr,
            );
            if let Some(deadline) = grpc_deadline {
                match tokio::time::timeout_at(deadline.instant(), fut).await {
                    Ok(response) => response,
                    Err(_) => {
                        if let Some(protocol) = grpc_protocol.as_deref() {
                            crate::http::rpc::emit_grpc_deadline_exceeded_metric(
                                self.listener_name.as_ref(),
                                protocol,
                            );
                            crate::http::rpc::build_grpc_deadline_exceeded_response(protocol)
                        } else {
                            Err(anyhow!(
                                "qpx-h3 gRPC stream duration exceeded configured limit"
                            ))
                        }
                    }
                }
            } else {
                fut.await
            }
        };
        let (mut response_stream, mut request_body_stream) = req_stream.split();
        let relay_fut = crate::http3::qpx_stream::relay_qpx_request_body_observed_from_recv(
            &mut request_body_stream,
            sender,
            crate::http3::qpx_stream::QpxRequestBodyRelayOptions {
                read_timeout: Duration::from_millis(listener_streaming.body_read_timeout_ms),
                max_body_bytes: listener_streaming.max_request_body_bytes,
                declared_content_length,
                request_headers: &request_headers,
                listener_name: Some(self.listener_name.as_ref()),
                max_grpc_message_bytes: Some(listener_streaming.max_grpc_message_bytes),
                max_grpc_web_trailer_bytes: Some(listener_streaming.max_grpc_web_trailer_bytes),
                grpc_stream_deadline: grpc_deadline.map(|deadline| deadline.instant()),
                observe_grpc_messages: listener_streaming.observe_grpc_messages,
            },
        );
        tokio::pin!(relay_fut);
        tokio::pin!(response_fut);
        let mut request_summary = None;
        let mut relay_done = false;
        let response = tokio::select! {
            relay_result = &mut relay_fut => {
                match relay_result {
                    Ok((_bytes, summary)) => {
                        request_summary = summary;
                        relay_done = true;
                    }
                    Err(err) => {
                        warn!(error = ?err, "forward qpx-h3 request body relay failed");
                        response_stream.abort_message_stream();
                        return Err(err);
                    }
                }
                response_fut.await?
            }
            response = &mut response_fut => response?,
        };
        let response_streaming = response_streaming_limits(&response, listener_streaming);
        let response_fut = crate::http3::qpx_stream::send_qpx_response_stream_observed_to_send(
            &mut response_stream,
            response,
            &request_method,
            crate::http3::qpx_stream::QpxResponseSendOptions {
                max_body_bytes: response_streaming.max_response_body_bytes,
                body_read_timeout: Duration::from_millis(response_streaming.body_read_timeout_ms),
                body_send_timeout: Duration::from_millis(response_streaming.body_send_timeout_ms),
                listener_name: Some(self.listener_name.as_ref()),
                fallback_grpc_protocol: grpc_protocol.as_deref(),
                max_grpc_message_bytes: Some(response_streaming.max_grpc_message_bytes),
                max_grpc_web_trailer_bytes: Some(response_streaming.max_grpc_web_trailer_bytes),
                grpc_stream_deadline: grpc_deadline.map(|deadline| deadline.instant()),
                sse_policy: Some(response_streaming.sse),
                observe_grpc_messages: response_streaming.observe_grpc_messages,
            },
        );
        let response_summary = if relay_done {
            response_fut.await?
        } else {
            let (response_result, relay_result) = tokio::join!(response_fut, relay_fut);
            request_summary = match relay_result {
                Ok((_bytes, summary)) => summary,
                Err(err) => {
                    warn!(error = ?err, "forward qpx-h3 request body relay failed");
                    response_stream.abort_message_stream();
                    return Err(err);
                }
            };
            response_result?
        };
        if response_streaming.observe_grpc_messages
            && let Some(protocol) = grpc_protocol.as_deref()
        {
            let streaming = crate::http::rpc::grpc_streaming_label(
                protocol,
                request_summary
                    .as_ref()
                    .map(|summary| summary.message_count()),
                response_summary
                    .as_ref()
                    .map(|summary| summary.message_count()),
            );
            crate::http::rpc::emit_grpc_stream_duration_metric(
                self.listener_name.as_ref(),
                protocol,
                streaming,
                grpc_started.elapsed(),
            );
        }
        Ok(())
    }

    async fn handle_connect(
        &self,
        request: qpx_h3::Request,
        conn: qpx_h3::ConnectionInfo,
        mut req_stream: qpx_h3::RequestStream,
    ) -> Result<()> {
        match request.protocol {
            Some(qpx_h3::Protocol::ConnectUdp) => {
                self.handle_connect_udp(request, &mut req_stream).await
            }
            Some(_) => {
                self.static_response(
                    &mut req_stream,
                    http::Method::CONNECT,
                    StatusCode::NOT_IMPLEMENTED,
                    self.runtime.state().messages.proxy_error.clone(),
                )
                .await
            }
            None => {
                handle_qpx_traditional_connect_stream(self, request.head, req_stream, conn).await
            }
        }
    }

    async fn handle_connect_udp(
        &self,
        request: qpx_h3::Request,
        req_stream: &mut qpx_h3::RequestStream,
    ) -> Result<()> {
        if !self.connect_udp.enabled {
            return self
                .static_response(
                    req_stream,
                    http::Method::CONNECT,
                    StatusCode::NOT_IMPLEMENTED,
                    self.runtime.state().messages.proxy_error.clone(),
                )
                .await;
        }

        crate::http::protocol::semantics::validate_h2_h3_request_headers(
            http::Version::HTTP_3,
            request.head.headers(),
        )
        .map_err(|err| anyhow!("invalid CONNECT-UDP headers: {err}"))?;
        crate::http::protocol::semantics::validate_expect_header(request.head.headers())
            .map_err(|err| anyhow!("invalid CONNECT-UDP headers: {err}"))?;

        let capsule = request
            .head
            .headers()
            .get("capsule-protocol")
            .and_then(|value| value.to_str().ok());
        if capsule != Some("?1") {
            return self
                .static_response(
                    req_stream,
                    http::Method::CONNECT,
                    StatusCode::BAD_REQUEST,
                    "CONNECT-UDP requires Capsule-Protocol: ?1".to_string(),
                )
                .await;
        }

        let _ =
            parse_connect_udp_target(request.head.uri(), self.connect_udp.uri_template.as_deref())?;

        let mut response = crate::http::protocol::common::connect_established_response();
        response.headers_mut().insert(
            http::header::HeaderName::from_static("capsule-protocol"),
            http::HeaderValue::from_static("?1"),
        );
        let response = crate::http::protocol::l7::finalize_response_for_request(
            &http::Method::CONNECT,
            http::Version::HTTP_3,
            self.runtime.state().plan.identity.proxy_name.as_ref(),
            response,
            false,
        );
        send_qpx_response_stream(
            req_stream,
            response,
            &http::Method::CONNECT,
            self.runtime
                .state()
                .plan
                .limits
                .body
                .max_h3_response_body_bytes,
            h3_body_read_timeout(&self.runtime),
        )
        .await
    }

    async fn static_response(
        &self,
        req_stream: &mut qpx_h3::RequestStream,
        method: http::Method,
        status: StatusCode,
        body: String,
    ) -> Result<()> {
        let response = crate::http::protocol::l7::finalize_response_for_request(
            &method,
            http::Version::HTTP_3,
            self.runtime.state().plan.identity.proxy_name.as_ref(),
            Response::builder()
                .status(status)
                .body(crate::http::body::Body::from(body))?,
            false,
        );
        send_qpx_response_stream(
            req_stream,
            response,
            &method,
            self.runtime
                .state()
                .plan
                .limits
                .body
                .max_h3_response_body_bytes,
            h3_body_read_timeout(&self.runtime),
        )
        .await
    }

    async fn handle_qpx_webtransport_connect(
        &self,
        req_head: http::Request<()>,
        req_stream: qpx_h3::RequestStream,
        conn: qpx_h3::ConnectionInfo,
        session: qpx_h3::WebTransportSession,
    ) -> Result<()> {
        dispatch_qpx_webtransport_connect(self, req_head, req_stream, conn, session).await
    }

    fn listener_streaming_limits(&self) -> ResolvedStreamingLimits {
        let state = self.runtime.state();
        let limits = state.plan.limits;
        state
            .plan
            .forward_edge(self.listener_name.as_ref())
            .map(|edge| edge.default_plan.streaming)
            .unwrap_or_else(|| ResolvedStreamingLimits::from(limits))
    }
}

pub(crate) fn h3_body_read_timeout(runtime: &Runtime) -> Duration {
    Duration::from_millis(
        runtime
            .state()
            .plan
            .limits
            .timeouts
            .h3_read_timeout_ms
            .max(1),
    )
}

fn response_streaming_limits(
    response: &Response<Body>,
    fallback: ResolvedStreamingLimits,
) -> ResolvedStreamingLimits {
    response
        .extensions()
        .get::<ResolvedStreamingLimits>()
        .copied()
        .unwrap_or(fallback)
}
