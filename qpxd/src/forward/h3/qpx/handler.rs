use super::super::connect::parse::parse_connect_udp_target;
use super::connect::{handle_qpx_connect_stream, handle_qpx_traditional_connect_stream};
use super::response::{send_qpx_response_stream, send_qpx_static_response};
use super::webtransport_dispatch::handle_qpx_webtransport_connect as dispatch_qpx_webtransport_connect;
use crate::http::body::size::set_observed_request_size;
use crate::http3::response_options::H3ResponseSendOptions;
use crate::runtime::{ResolvedStreamingLimits, Runtime};
use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use qpx_core::config::{ConnectIpConfig, ConnectUdpConfig};
use qpx_core::http_message::{OrdinaryHeaderName, Request};
use qpx_http::body::Body;
use qpx_http::protocol::semantics::request_capsule_protocol_enabled;
use std::sync::Arc;
use tokio::time::{Duration, Instant};
use tracing::warn;

#[derive(Clone)]
pub(crate) struct ForwardQpxHandler {
    pub(crate) runtime: Runtime,
    pub(crate) listener_name: Arc<str>,
    pub(crate) connect_udp: ConnectUdpConfig,
    pub(crate) connect_ip: ConnectIpConfig,
}

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

    fn via_received_by(&self) -> impl AsRef<str> + Send + 'static {
        self.runtime.state().plan.identity.proxy_name.clone()
    }

    async fn handle_request(
        &self,
        request: qpx_h3::Request,
        conn: qpx_h3::ConnectionInfo,
        req_stream: qpx_h3::RequestStream,
    ) -> qpx_h3::H3Result<()> {
        let head = request.head;
        if head.method() == http::Method::CONNECT {
            return self
                .handle_connect(head, request.protocol, conn, req_stream)
                .await
                .map_err(Into::into);
        }

        self.handle_http_request(head, conn.remote_addr, req_stream)
            .await
            .map_err(Into::into)
    }

    async fn handle_webtransport_connect(
        &self,
        req_head: Request<()>,
        req_stream: qpx_h3::RequestStream,
        conn: qpx_h3::ConnectionInfo,
        session: qpx_h3::WebTransportSession,
    ) -> qpx_h3::H3Result<()> {
        self.handle_qpx_webtransport_connect(req_head, req_stream, conn, session)
            .await
            .map_err(Into::into)
    }

    async fn handle_connect_stream(
        &self,
        req_head: Request<()>,
        req_stream: qpx_h3::RequestStream,
        conn: qpx_h3::ConnectionInfo,
        protocol: qpx_h3::Protocol,
        datagrams: Option<qpx_h3::StreamDatagrams>,
    ) -> qpx_h3::H3Result<()> {
        handle_qpx_connect_stream(self, req_head, req_stream, conn, protocol, datagrams)
            .await
            .map_err(Into::into)
    }
}

impl ForwardQpxHandler {
    fn request_streaming_limits(
        &self,
        req_head: &Request<()>,
        remote_addr: std::net::SocketAddr,
    ) -> std::result::Result<
        ResolvedStreamingLimits,
        qpx_http::protocol::semantics::RequestValidationError,
    > {
        // Policy must see a valid H3 head and unambiguous authority, without
        // normalizing Cookie or other fields before selection.
        qpx_http::protocol::semantics::validate_h2_h3_request_headers(
            http::Version::HTTP_3,
            req_head.headers(),
        )?;
        qpx_http::protocol::semantics::resolve_request_authority(
            req_head.headers(),
            req_head.uri().authority(),
            req_head.uri().scheme_str(),
        )?
        .ok_or(qpx_http::protocol::semantics::RequestValidationError::MissingHost)?;
        Ok(super::super::streaming::request_streaming_limits_for_head(
            &self.runtime,
            self.listener_name.as_ref(),
            req_head,
            remote_addr,
            self.listener_streaming_limits(),
        ))
    }

    async fn handle_http_request(
        &self,
        request: Request<()>,
        remote_addr: std::net::SocketAddr,
        mut req_stream: qpx_h3::RequestStream,
    ) -> Result<()> {
        let request_headers = request.headers().clone();
        if crate::http::protocol::sse::is_sse_reconnect(&request_headers) {
            crate::http::protocol::sse::emit_sse_reconnect(self.listener_name.as_ref(), "unknown");
        }
        let grpc_protocol = crate::http::rpc::request_streaming_rpc_protocol(&request_headers);
        let grpc_request_content_type = request_headers
            .get(&OrdinaryHeaderName::try_from(http::header::CONTENT_TYPE).expect("ordinary"))
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let grpc_started = Instant::now();
        let listener_streaming = match self.request_streaming_limits(&request, remote_addr) {
            Ok(limits) => limits,
            Err(error) => {
                let body = error.to_string();
                return send_qpx_static_response(
                    &mut req_stream,
                    error.http_status(),
                    body.as_bytes(),
                    request.method(),
                    self.runtime.state().plan.identity.proxy_name.as_ref(),
                )
                .await;
            }
        };
        let grpc_deadline = grpc_protocol.as_deref().map(|protocol| {
            crate::http::rpc::resolve_rpc_deadline(
                &request_headers,
                protocol,
                Duration::from_millis(listener_streaming.max_grpc_stream_duration_ms),
                grpc_started,
            )
        });
        let declared_content_length = request.headers().declared_content_length()?;
        if let Some(content_length) = declared_content_length
            && content_length > listener_streaming.max_request_body_bytes as u64
        {
            return send_qpx_static_response(
                &mut req_stream,
                StatusCode::PAYLOAD_TOO_LARGE,
                b"request payload too large",
                request.method(),
                self.runtime.state().plan.identity.proxy_name.as_ref(),
            )
            .await;
        }

        let (sender, body) = Body::channel_with_capacity(listener_streaming.body_channel_capacity);
        if request.headers().field_count() > crate::http3::codec::H3_MAX_HEADER_COUNT {
            return Err(anyhow!(
                "HTTP/3 request header fields exceeded configured limits"
            ));
        }
        // Keep decoded field occurrences intact through common request policy;
        // protocol-specific normalization belongs at an upstream codec boundary.
        let mut req = request.map_body(|()| body);
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
                            crate::http::rpc::build_grpc_deadline_exceeded_response(
                                protocol,
                                grpc_request_content_type.as_deref(),
                            )
                            .map(qpx_core::http_message::Response::from_http)
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
        let grpc_observer = listener_streaming
            .observe_grpc_messages
            .then(|| {
                crate::http::rpc::request_streaming_rpc_observer(
                    &request_headers,
                    Some(listener_streaming.max_grpc_message_bytes),
                    Some(listener_streaming.max_grpc_web_trailer_bytes),
                )
            })
            .flatten();
        let relay_body_fut = crate::http3::qpx_stream::relay_qpx_request_body_observed_from_recv(
            &mut request_body_stream,
            sender,
            crate::http3::qpx_stream::QpxRequestBodyRelayOptions {
                read_timeout: Duration::from_millis(listener_streaming.body_read_timeout_ms),
                max_body_bytes: listener_streaming.max_request_body_bytes,
                declared_content_length,
                grpc_observer,
                listener_name: Some(self.listener_name.as_ref()),
                // The relay wrapper below owns the stream budget: it cancels
                // the relay at expiry instead of failing it, so the inner
                // relay must not abort the stream on the same instant.
                grpc_stream_deadline: None,
                observe_grpc_messages: listener_streaming.observe_grpc_messages,
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
        let response = tokio::select! {
            relay_result = &mut relay_fut => {
                match relay_result {
                    Some(Ok((_bytes, summary))) => {
                        request_summary = summary;
                        relay_done = true;
                        response_fut.await?
                    }
                    Some(Err(err)) => {
                        warn!(error = ?err, "forward qpx-h3 request body relay failed");
                        response_stream.abort_message_stream();
                        return Err(err);
                    }
                    // The budget expired with the body incomplete: only the
                    // synthetic deadline reply may proceed. A normal reply with
                    // an incomplete body ends like any relay failure, and the
                    // exhausted relay future must never be polled again.
                    None => {
                        let response = response_fut.await?;
                        if response
                            .extensions()
                            .get::<crate::http::rpc::RpcDeadlineReply>()
                            .is_none()
                        {
                            warn!(
                                "forward qpx-h3 request body relay exceeded the stream budget"
                            );
                            response_stream.abort_message_stream();
                            return Err(anyhow!(
                                "forward qpx-h3 request body relay exceeded the stream budget"
                            ));
                        }
                        response
                    }
                }
            }
            response = &mut response_fut => response?,
        };
        let is_deadline_reply = response
            .extensions()
            .get::<crate::http::rpc::RpcDeadlineReply>()
            .is_some();
        let response_streaming =
            ResolvedStreamingLimits::from_response(&response, listener_streaming);
        let response_fut = crate::http3::qpx_stream::send_qpx_response_stream_observed_to_send(
            &mut response_stream,
            response,
            &request_method,
            H3ResponseSendOptions {
                max_body_bytes: response_streaming.max_response_body_bytes,
                body_read_timeout: Duration::from_millis(response_streaming.body_read_timeout_ms),
                body_send_timeout: Duration::from_millis(response_streaming.body_send_timeout_ms),
                listener_name: Some(self.listener_name.as_ref()),
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
        let response_summary = if relay_done || is_deadline_reply {
            // A completed relay must never be polled again. The synthetic
            // deadline reply is self-contained: a still-pending relay can only
            // fail on the expired budget, so send the reply alone instead of
            // letting the relay reset the stream.
            match response_fut.await {
                Ok(summary) => summary,
                Err(err) => {
                    crate::http3::response_error::emit_h3_response_send_error("qpx_h3", &err);
                    return Err(err.into_inner());
                }
            }
        } else {
            let (response_result, relay_result) = tokio::join!(response_fut, relay_fut);
            request_summary = match relay_result {
                Some(Ok((_bytes, summary))) => summary,
                Some(Err(err)) => {
                    warn!(error = ?err, "forward qpx-h3 request body relay failed");
                    response_stream.abort_message_stream();
                    return Err(err);
                }
                // No deadline reply is in flight on this path, so an expired
                // relay ends the exchange exactly like any relay failure.
                None => {
                    warn!("forward qpx-h3 request body relay exceeded the stream budget");
                    response_stream.abort_message_stream();
                    return Err(anyhow!(
                        "forward qpx-h3 request body relay exceeded the stream budget"
                    ));
                }
            };
            match response_result {
                Ok(summary) => summary,
                Err(err) => {
                    crate::http3::response_error::emit_h3_response_send_error("qpx_h3", &err);
                    return Err(err.into_inner());
                }
            }
        };
        if response_streaming.observe_grpc_messages
            && let Some(protocol) = grpc_protocol.as_deref()
        {
            crate::http::rpc::emit_grpc_stream_duration_metric_from_summaries(
                self.listener_name.as_ref(),
                protocol,
                request_summary.as_ref(),
                response_summary.as_ref(),
                || grpc_started.elapsed(),
            );
        }
        Ok(())
    }

    async fn handle_connect(
        &self,
        request: Request<()>,
        protocol: Option<qpx_h3::Protocol>,
        conn: qpx_h3::ConnectionInfo,
        mut req_stream: qpx_h3::RequestStream,
    ) -> Result<()> {
        match protocol {
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
            None => handle_qpx_traditional_connect_stream(self, request, req_stream, conn).await,
        }
    }

    async fn handle_connect_udp(
        &self,
        request: Request<()>,
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

        qpx_http::protocol::semantics::validate_h2_h3_request_headers(
            http::Version::HTTP_3,
            request.headers(),
        )
        .map_err(|err| anyhow!("invalid CONNECT-UDP headers: {err}"))?;
        qpx_http::protocol::semantics::validate_expect_header(request.headers())
            .map_err(|err| anyhow!("invalid CONNECT-UDP headers: {err}"))?;

        if !request_capsule_protocol_enabled(request.headers()) {
            return self
                .static_response(
                    req_stream,
                    http::Method::CONNECT,
                    StatusCode::BAD_REQUEST,
                    "CONNECT-UDP requires Capsule-Protocol: ?1".to_string(),
                )
                .await;
        }

        let _ = parse_connect_udp_target(request.uri(), self.connect_udp.uri_template.as_deref())?;

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
                .body(qpx_http::body::Body::from(body))?,
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
        req_head: Request<()>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use qpx_core::config::Config;

    fn handler() -> ForwardQpxHandler {
        let config: Config = serde_yaml::from_str(
            r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action: {type: direct}
  streaming: {max_request_body_bytes: 17}
"#,
        )
        .expect("config");
        ForwardQpxHandler {
            runtime: Runtime::new(config).expect("runtime"),
            listener_name: Arc::from("forward"),
            connect_udp: serde_yaml::from_str("{}").expect("CONNECT-UDP config"),
            connect_ip: serde_yaml::from_str(
                "uri_template: 'https://proxy.test/ip/{target}/{ipproto}/'",
            )
            .expect("CONNECT-IP config"),
        }
    }

    #[test]
    fn conflicting_h3_host_is_rejected_at_streaming_policy_boundary() {
        let handler = handler();
        let remote = "127.0.0.1:12345".parse().expect("remote");
        let head = Request::from_http(
            http::Request::builder()
                .version(http::Version::HTTP_3)
                .uri("https://authority.test/upload")
                .header("host", "different.test")
                .body(())
                .expect("decoded head"),
        );
        // Call the actual production boundary, not just the semantic validator.
        // Before the guard, this selected the listener's streaming policy using
        // the unvalidated Host/URI pair and returned Ok(limits).
        let error = handler
            .request_streaming_limits(&head, remote)
            .expect_err("conflicting authority must not select limits");
        assert_eq!(
            error,
            qpx_http::protocol::semantics::RequestValidationError::HostAuthorityMismatch
        );
        assert_eq!(error.http_status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            error.to_string(),
            "Host header does not match request authority"
        );

        let mut valid = head;
        valid.headers_mut().insert(
            OrdinaryHeaderName::try_from("host").expect("ordinary"),
            http::HeaderValue::from_static("authority.test"),
        );
        assert_eq!(
            handler
                .request_streaming_limits(&valid, remote)
                .expect("valid head")
                .max_request_body_bytes,
            17
        );
    }

    #[test]
    fn owned_h3_head_preserves_duplicate_cookies_during_policy_selection() {
        let mut head = Request::from_http(
            http::Request::builder()
                .version(http::Version::HTTP_3)
                .uri("https://authority.test/")
                .header("cookie", "a=1")
                .header("cookie", "b=2")
                .header("x-repeat", " first ")
                .header("x-repeat", "second")
                .header("content-length", "000")
                .header("content-length", "0")
                .body(())
                .expect("head"),
        );
        let cookie = OrdinaryHeaderName::try_from("cookie").expect("ordinary");
        let repeat = OrdinaryHeaderName::try_from("x-repeat").expect("ordinary");
        assert_eq!(head.headers().get_all(&cookie).count(), 2);
        assert_eq!(head.headers().field_count(), 6);
        let mut cookies: Vec<_> = head.headers().get_all(&cookie).cloned().collect();
        cookies[1].set_sensitive(true);
        head.headers_mut().remove(&cookie);
        for value in cookies {
            head.headers_mut().append(cookie.clone(), value);
        }
        assert_eq!(head.version(), http::Version::HTTP_3);
        let original = head.headers().clone();
        let handler = handler();
        handler
            .request_streaming_limits(&head, "127.0.0.1:12345".parse().expect("remote"))
            .expect("policy");
        assert_eq!(head.headers(), &original);
        let attached = head.map_body(|()| Body::empty());
        assert_eq!(attached.headers().get_all(&cookie).count(), 2);
        assert_eq!(attached.headers().field_count(), 6);
        assert_eq!(attached.version(), http::Version::HTTP_3);
        assert_eq!(
            attached
                .headers()
                .get_all(&repeat)
                .map(|v| v.as_bytes())
                .collect::<Vec<_>>(),
            [b" first ".as_slice(), b"second".as_slice()]
        );
        assert_eq!(
            attached
                .headers()
                .declared_content_length()
                .expect("length"),
            Some(0)
        );
    }
}
