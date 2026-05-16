use crate::http::body::Body;
use crate::http::body_size::set_observed_request_size;
use crate::http3::quinn_socket::{
    PreparedServerEndpointSocket, QuinnBrokerKind, QuinnBrokerStream, QuinnEndpointSocket,
    QuinnUdpIngressFilter, build_server_endpoint, prepare_server_endpoint_socket,
};
use crate::sidecar_control::SidecarControl;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use hyper::{Response, StatusCode};
use qpx_core::config::ReverseEdgeConfig;
use qpx_core::tls::{load_cert_chain, load_private_key};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::{Duration, Instant};
use tracing::warn;

pub(crate) fn prepare_reverse_terminate_socket(
    reverse_name: &str,
    reverse_rt: super::ReloadableReverse,
    std_socket: std::net::UdpSocket,
    inherited_broker: Option<QuinnBrokerStream>,
) -> Result<PreparedServerEndpointSocket> {
    let local_port = std_socket.local_addr()?.port();
    prepare_server_endpoint_socket(
        reverse_name,
        QuinnBrokerKind::ReverseTerminate,
        std_socket,
        inherited_broker,
        Arc::new(ReverseQuicPacketFilter {
            reverse: reverse_rt,
            local_port,
        }),
    )
}

pub(crate) async fn run_http3_terminate(
    reverse: ReverseEdgeConfig,
    listen_addr: SocketAddr,
    reverse_rt: super::ReloadableReverse,
    mut shutdown: watch::Receiver<SidecarControl>,
    endpoint_socket: QuinnEndpointSocket,
) -> Result<()> {
    let tls_config = build_reverse_tls_config(&reverse)?;
    let max_bidi = reverse_rt
        .runtime
        .state()
        .plan
        .limits
        .max_h3_streams_per_connection
        .min(u32::MAX as usize) as u32;
    let server_config =
        crate::http3::quic::build_h3_server_config_from_tls(tls_config, max_bidi.max(1), 16)?;
    let endpoint = build_server_endpoint(endpoint_socket, server_config)?;
    let handler = ReverseQpxHandler {
        reverse: reverse_rt,
    };
    let connection_semaphore = handler.reverse.runtime.state().connection_semaphore.clone();

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

struct ReverseQuicPacketFilter {
    reverse: super::ReloadableReverse,
    local_port: u16,
}

impl QuinnUdpIngressFilter for ReverseQuicPacketFilter {
    fn allow(&self, remote_addr: SocketAddr, packet: &[u8]) -> bool {
        match super::reverse_quic_connection_filter_match(
            &self.reverse,
            remote_addr,
            self.local_port,
            packet,
        ) {
            Some((stage, matched_rule, sni)) => {
                super::record_reverse_connection_filter_block(
                    &self.reverse,
                    remote_addr,
                    self.local_port,
                    stage,
                    matched_rule.as_str(),
                    sni.as_deref(),
                );
                false
            }
            None => true,
        }
    }
}

pub(super) fn build_reverse_tls_config(
    reverse: &ReverseEdgeConfig,
) -> Result<quinn::rustls::ServerConfig> {
    let tls = reverse
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("reverse TLS config required for HTTP/3 terminate"))?;
    if tls.certificates.is_empty() {
        return Err(anyhow!(
            "at least one certificate is required for HTTP/3 terminate"
        ));
    }
    let resolver = Arc::new(QuicSniResolver::new(tls)?);

    let provider = quinn::rustls::crypto::ring::default_provider();
    let base = quinn::rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|_| anyhow!("failed to configure TLS versions for HTTP/3"))?;
    let tls_config = if let Some(client_ca) = tls
        .client_ca
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        use quinn::rustls::RootCertStore;
        use quinn::rustls::server::WebPkiClientVerifier;
        let certs = load_cert_chain(Path::new(client_ca))?;
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(anyhow!("no client CA certs loaded from {}", client_ca));
        }
        let verifier = WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(|_| anyhow!("invalid reverse.tls.client_ca"))?;
        base.with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver)
    } else {
        base.with_no_client_auth().with_cert_resolver(resolver)
    };
    Ok(tls_config)
}

#[derive(Debug)]
struct QuicSniResolver {
    certs: HashMap<String, Arc<quinn::rustls::sign::CertifiedKey>>,
    acme_snis: std::collections::HashSet<String>,
}

impl QuicSniResolver {
    fn new(tls: &qpx_core::config::ReverseTlsConfig) -> Result<Self> {
        let mut certs = HashMap::new();
        let mut acme_snis = std::collections::HashSet::new();
        for cert in &tls.certificates {
            let cert_path = cert.cert.as_deref().unwrap_or("").trim();
            let key_path = cert.key.as_deref().unwrap_or("").trim();
            if cert_path.is_empty() && key_path.is_empty() {
                acme_snis.insert(cert.sni.to_ascii_lowercase());
            } else {
                if cert_path.is_empty() {
                    return Err(anyhow!("reverse.tls.certificates[].cert must not be empty"));
                }
                if key_path.is_empty() {
                    return Err(anyhow!("reverse.tls.certificates[].key must not be empty"));
                }
                let chain = load_cert_chain(Path::new(cert_path))?;
                let key = load_private_key(Path::new(key_path))?;
                let signing_key = quinn::rustls::crypto::ring::sign::any_supported_type(&key)
                    .map_err(|_| anyhow!("unsupported key"))?;
                let certified =
                    Arc::new(quinn::rustls::sign::CertifiedKey::new(chain, signing_key));
                certs.insert(cert.sni.to_ascii_lowercase(), certified);
            }
        }
        Ok(Self { certs, acme_snis })
    }
}

impl quinn::rustls::server::ResolvesServerCert for QuicSniResolver {
    fn resolve(
        &self,
        client_hello: quinn::rustls::server::ClientHello<'_>,
    ) -> Option<Arc<quinn::rustls::sign::CertifiedKey>> {
        let name = client_hello.server_name()?.to_ascii_lowercase();
        if let Some(key) = self.certs.get(&name) {
            return Some(key.clone());
        }
        if self.acme_snis.contains(&name) {
            #[cfg(feature = "acme")]
            {
                return qpx_acme::quic_cert_store().and_then(|store| store.get(&name));
            }
            #[cfg(not(feature = "acme"))]
            {
                return None;
            }
        }
        None
    }
}

#[derive(Clone)]
struct ReverseQpxHandler {
    reverse: super::ReloadableReverse,
}

#[async_trait]
impl qpx_h3::RequestHandler for ReverseQpxHandler {
    fn settings(&self) -> qpx_h3::Settings {
        let state = self.reverse.runtime.state();
        let limits = state.plan.limits;
        qpx_h3::Settings {
            enable_extended_connect: false,
            enable_datagram: false,
            enable_webtransport: false,
            max_webtransport_sessions: 0,
            max_request_body_bytes: limits.max_h3_request_body_bytes,
            max_concurrent_streams_per_connection: limits.max_h3_streams_per_connection,
            read_timeout: Duration::from_millis(limits.h3_read_timeout_ms),
            datagram_channel_capacity: limits.datagram_channel_capacity,
            webtransport_stream_channel_capacity: limits.webtransport_stream_channel_capacity,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        request: qpx_h3::Request,
        conn: qpx_h3::ConnectionInfo,
        req_stream: &mut qpx_h3::RequestStream,
    ) -> Result<()> {
        let response_body_limit = self
            .reverse
            .runtime
            .state()
            .plan
            .limits
            .max_h3_response_body_bytes;
        if request.head.method() == http::Method::CONNECT || request.protocol.is_some() {
            let response = crate::http::l7::finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                self.reverse
                    .runtime
                    .state()
                    .plan
                    .identity
                    .proxy_name
                    .as_ref(),
                Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(crate::http::body::Body::from(
                        self.reverse.runtime.state().messages.reverse_error.clone(),
                    ))?,
                false,
            );
            return crate::http3::qpx_stream::send_qpx_response_stream(
                req_stream,
                response,
                request.head.method(),
                response_body_limit,
                Duration::from_millis(
                    self.reverse
                        .runtime
                        .state()
                        .plan
                        .limits
                        .h3_read_timeout_ms
                        .max(1),
                ),
            )
            .await;
        }

        let request_headers = request.head.headers().clone();
        let grpc_protocol = crate::http::rpc::streaming_grpc_protocol(&request_headers, None);
        let grpc_started = Instant::now();
        let grpc_deadline = grpc_protocol.as_ref().map(|_| {
            grpc_started
                + Duration::from_millis(
                    self.reverse
                        .runtime
                        .state()
                        .plan
                        .limits
                        .max_grpc_stream_duration_ms,
                )
        });
        let request_method = request.head.method().clone();
        let declared_content_length =
            crate::http3::codec::parse_content_length_fields(request.head.headers())?;
        if let Some(content_length) = declared_content_length
            && content_length
                > self
                    .reverse
                    .runtime
                    .state()
                    .plan
                    .limits
                    .max_h3_request_body_bytes as u64
        {
            let response = crate::http::l7::finalize_response_for_request(
                &request_method,
                http::Version::HTTP_3,
                self.reverse
                    .runtime
                    .state()
                    .plan
                    .identity
                    .proxy_name
                    .as_ref(),
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Body::from("request payload too large"))?,
                false,
            );
            return crate::http3::qpx_stream::send_qpx_response_stream(
                req_stream,
                response,
                &request_method,
                response_body_limit,
                Duration::from_millis(
                    self.reverse
                        .runtime
                        .state()
                        .plan
                        .limits
                        .h3_read_timeout_ms
                        .max(1),
                ),
            )
            .await;
        }

        let (sender, body) = Body::channel();
        let mut req = crate::http3::codec::h3_request_to_hyper(request.head, body)?;
        if let Some(content_length) = declared_content_length {
            set_observed_request_size(&mut req, content_length);
        }
        let reverse_conn = super::transport::ReverseConnInfo::terminated(
            conn.remote_addr,
            conn.dst_port,
            conn.tls_sni.clone(),
            conn.peer_certificates.clone(),
        );
        let read_timeout = Duration::from_millis(
            self.reverse
                .runtime
                .state()
                .plan
                .limits
                .h3_read_timeout_ms
                .max(1),
        );
        let request_limit = self
            .reverse
            .runtime
            .state()
            .plan
            .limits
            .max_h3_request_body_bytes;
        let response_fut = async {
            let fut = super::transport::handle_request_with_interim(
                req,
                self.reverse.clone(),
                reverse_conn,
            );
            let result = if let Some(deadline) = grpc_deadline {
                tokio::time::timeout_at(deadline, fut).await.map_err(|_| {
                    anyhow!("reverse qpx-h3 gRPC stream duration exceeded configured limit")
                })?
            } else {
                fut.await
            };
            Ok::<_, anyhow::Error>(result.unwrap_or_else(|impossible| match impossible {}))
        };
        let relay_fut = crate::http3::qpx_stream::relay_qpx_request_body_observed(
            req_stream,
            sender,
            crate::http3::qpx_stream::QpxRequestBodyRelayOptions {
                read_timeout,
                max_body_bytes: request_limit,
                declared_content_length,
                request_headers: &request_headers,
                listener_name: Some(self.reverse.name.as_ref()),
                max_grpc_message_bytes: Some(
                    self.reverse
                        .runtime
                        .state()
                        .plan
                        .limits
                        .max_grpc_message_bytes,
                ),
                grpc_stream_deadline: grpc_deadline,
            },
        );
        let (relay_result, response_result) = tokio::join!(relay_fut, response_fut);
        let request_summary = match relay_result {
            Ok((_bytes, summary)) => summary,
            Err(err) => {
                warn!(error = ?err, "reverse qpx-h3 request body relay failed");
                None
            }
        };
        let (interim, response) = response_result?;

        for head in interim {
            let mut interim = http::Response::builder().status(head.status).body(())?;
            *interim.headers_mut() = head.headers;
            crate::http3::qpx_stream::send_qpx_interim_response(req_stream, interim, read_timeout)
                .await?;
        }

        let response_summary = crate::http3::qpx_stream::send_qpx_response_stream_observed(
            req_stream,
            response,
            &request_method,
            crate::http3::qpx_stream::QpxResponseSendOptions {
                max_body_bytes: response_body_limit,
                body_read_timeout: read_timeout,
                listener_name: Some(self.reverse.name.as_ref()),
                fallback_grpc_protocol: grpc_protocol.as_deref(),
                max_grpc_message_bytes: Some(
                    self.reverse
                        .runtime
                        .state()
                        .plan
                        .limits
                        .max_grpc_message_bytes,
                ),
                grpc_stream_deadline: grpc_deadline,
            },
        )
        .await?;
        if let Some(protocol) = grpc_protocol.as_deref() {
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
                self.reverse.name.as_ref(),
                protocol,
                streaming,
                grpc_started.elapsed(),
            );
        }
        Ok(())
    }
}
