use crate::http3::quinn_socket::{
    build_server_endpoint, prepare_server_endpoint_socket, PreparedServerEndpointSocket,
    QuinnBrokerKind, QuinnBrokerStream, QuinnEndpointSocket, QuinnUdpIngressFilter,
};
use crate::sidecar_control::SidecarControl;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hyper::{Response, StatusCode};
use qpx_core::config::ReverseConfig;
use qpx_core::tls::{load_cert_chain, load_private_key};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::Duration;
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
    reverse: ReverseConfig,
    listen_addr: SocketAddr,
    reverse_rt: super::ReloadableReverse,
    mut shutdown: watch::Receiver<SidecarControl>,
    endpoint_socket: QuinnEndpointSocket,
) -> Result<()> {
    let tls_config = build_reverse_tls_config(&reverse)?;
    let runtime_cfg = reverse_rt.runtime.state().config.runtime.clone();
    let max_bidi = runtime_cfg
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
    reverse: &ReverseConfig,
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
        use quinn::rustls::server::WebPkiClientVerifier;
        use quinn::rustls::RootCertStore;
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
        let limits = state.config.runtime.clone();
        qpx_h3::Settings {
            enable_extended_connect: false,
            enable_datagram: false,
            enable_webtransport: false,
            max_webtransport_sessions: 0,
            max_request_body_bytes: limits.max_h3_request_body_bytes,
            max_concurrent_streams_per_connection: limits.max_h3_streams_per_connection,
            read_timeout: Duration::from_millis(limits.h3_read_timeout_ms),
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        request: qpx_h3::Request,
        conn: qpx_h3::ConnectionInfo,
    ) -> Result<qpx_h3::Response> {
        let response_body_limit = self
            .reverse
            .runtime
            .state()
            .config
            .runtime
            .max_h3_response_body_bytes;
        if request.head.method() == http::Method::CONNECT || request.protocol.is_some() {
            let response = crate::http::l7::finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                self.reverse
                    .runtime
                    .state()
                    .config
                    .identity
                    .proxy_name
                    .as_str(),
                Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(crate::http::body::Body::from(
                        self.reverse.runtime.state().messages.reverse_error.clone(),
                    ))?,
                false,
            );
            return collect_reverse_response(
                Vec::new(),
                response,
                request.head.method(),
                response_body_limit,
                Duration::from_millis(
                    self.reverse
                        .runtime
                        .state()
                        .config
                        .runtime
                        .h3_read_timeout_ms
                        .max(1),
                ),
            )
            .await;
        }

        let request_method = request.head.method().clone();
        let req =
            crate::http3::codec::h3_request_to_hyper(request.head, request.body, request.trailers)?;
        let reverse_conn = super::transport::ReverseConnInfo::terminated(
            conn.remote_addr,
            conn.dst_port,
            conn.tls_sni.clone(),
            conn.peer_certificates.clone(),
        );
        let (interim, response) =
            super::transport::handle_request_with_interim(req, self.reverse.clone(), reverse_conn)
                .await
                .unwrap_or_else(|impossible| match impossible {});
        collect_reverse_response(
            interim,
            response,
            &request_method,
            response_body_limit,
            Duration::from_millis(
                self.reverse
                    .runtime
                    .state()
                    .config
                    .runtime
                    .h3_read_timeout_ms
                    .max(1),
            ),
        )
        .await
    }
}

async fn collect_reverse_response(
    interim: Vec<crate::upstream::raw_http1::InterimResponseHead>,
    response: Response<crate::http::body::Body>,
    request_method: &http::Method,
    response_body_limit: usize,
    body_read_timeout: Duration,
) -> Result<qpx_h3::Response> {
    let interim = interim
        .into_iter()
        .filter_map(|head| {
            let mut response = http::Response::builder()
                .status(head.status)
                .body(())
                .ok()?;
            *response.headers_mut() = head.headers;
            Some(response)
        })
        .collect();
    let (head, body, trailers): (http::Response<()>, bytes::Bytes, Option<http::HeaderMap>) =
        crate::http3::codec::hyper_response_to_h3(
            response,
            request_method,
            response_body_limit,
            body_read_timeout,
        )
        .await?;
    Ok(qpx_h3::Response {
        interim,
        response: head.map(|_| body),
        trailers,
    })
}

#[cfg(test)]
mod tests {
    use super::collect_reverse_response;
    use crate::http::body::Body;
    use tokio::time::Duration;

    #[tokio::test]
    async fn reverse_qpx_h3_response_body_limit_is_enforced() {
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Body::from(vec![b'x'; 4]))
            .expect("response");

        let err = collect_reverse_response(
            Vec::new(),
            response,
            &http::Method::GET,
            3,
            Duration::from_secs(1),
        )
        .await
        .expect_err("body larger than configured limit must fail");

        assert!(
            err.to_string()
                .contains("HTTP/3 response body exceeds configured limit"),
            "{err}"
        );
    }
}
