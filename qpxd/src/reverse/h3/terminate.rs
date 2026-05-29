use super::super::{
    ReloadableReverse, record_reverse_connection_filter_block, reverse_quic_connection_filter_match,
};
use crate::http::body::Body;
use crate::http3::codec::http_headers_to_h1;
use crate::http3::listener::{
    H3ConnInfo, H3ConnectKind, H3HttpResponse, H3Limits, H3RequestHandler,
};
use crate::http3::quic::build_h3_server_config_from_tls;
use crate::http3::quinn_socket::{
    PreparedServerEndpointSocket, QuinnBrokerKind, QuinnBrokerStream, QuinnEndpointSocket,
    QuinnUdpIngressFilter, build_server_endpoint, prepare_server_endpoint_socket,
};
use crate::http3::server::{H3ServerRequestStream, send_h3_static_response};
use crate::reverse::transport::{self, ReverseConnInfo};
use crate::server::control::SidecarControl;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use hyper::{Request, Response};
use qpx_core::config::ReverseEdgeConfig;
use qpx_core::tls::{load_cert_chain, load_private_key};
use std::collections::HashMap;
#[cfg(test)]
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::Duration;
use tracing::warn;

pub(crate) fn prepare_reverse_terminate_socket(
    reverse_name: &str,
    reverse_rt: ReloadableReverse,
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
    reverse_rt: ReloadableReverse,
    shutdown: watch::Receiver<SidecarControl>,
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
    let server_config = build_h3_server_config_from_tls(tls_config, max_bidi.max(1), 1024)?;
    let endpoint = build_server_endpoint(endpoint_socket, server_config)?;

    let semaphore = reverse_rt.runtime.state().connection_semaphore.clone();
    let handler = ReverseH3Handler {
        reverse: reverse_rt,
    };
    crate::http3::listener::serve_endpoint(
        endpoint,
        listen_addr.port(),
        handler,
        "reverse-terminate",
        semaphore,
        shutdown,
    )
    .await
}

struct ReverseQuicPacketFilter {
    reverse: ReloadableReverse,
    local_port: u16,
}

impl QuinnUdpIngressFilter for ReverseQuicPacketFilter {
    fn allow(&self, remote_addr: SocketAddr, packet: &[u8]) -> bool {
        match reverse_quic_connection_filter_match(
            &self.reverse,
            remote_addr,
            self.local_port,
            packet,
        ) {
            Some((stage, matched_rule, sni)) => {
                record_reverse_connection_filter_block(
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

#[cfg(test)]
fn filter_quic_recv_batch(
    reverse: &ReloadableReverse,
    local_port: u16,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [quinn::udp::RecvMeta],
    count: usize,
) -> usize {
    let mut kept = 0usize;
    for idx in 0..count {
        let current = meta[idx];
        let (kept_len, kept_segments) = if kept == idx {
            filter_quic_buffer_in_place(reverse, local_port, current, &mut bufs[idx])
        } else {
            let (before, after) = bufs.split_at_mut(idx);
            let src = &mut after[0];
            let (kept_len, kept_segments) =
                filter_quic_buffer_in_place(reverse, local_port, current, src);
            if kept_len > 0 {
                let dst = &mut before[kept];
                dst[..kept_len].copy_from_slice(&src[..kept_len]);
            }
            (kept_len, kept_segments)
        };
        if kept_len == 0 {
            continue;
        }
        meta[kept] = current;
        meta[kept].len = kept_len;
        meta[kept].stride = if kept_segments <= 1 {
            kept_len
        } else {
            current.stride.max(1)
        };
        kept += 1;
    }
    kept
}

#[cfg(test)]
fn filter_quic_buffer_in_place(
    reverse: &ReloadableReverse,
    local_port: u16,
    meta: quinn::udp::RecvMeta,
    buf: &mut IoSliceMut<'_>,
) -> (usize, usize) {
    let total_len = meta.len.min(buf.len());
    let mut read_offset = 0usize;
    let mut write_offset = 0usize;
    let mut kept_segments = 0usize;
    while read_offset < total_len {
        let packet_len = if meta.stride == 0 {
            total_len - read_offset
        } else {
            meta.stride.min(total_len - read_offset)
        };
        let packet_end = read_offset + packet_len;
        let blocked = reverse_quic_connection_filter_match(
            reverse,
            meta.addr,
            local_port,
            &buf[read_offset..packet_end],
        );
        if let Some((stage, matched_rule, sni)) = blocked {
            record_reverse_connection_filter_block(
                reverse,
                meta.addr,
                local_port,
                stage,
                matched_rule.as_str(),
                sni.as_deref(),
            );
        } else {
            if write_offset != read_offset {
                buf.copy_within(read_offset..packet_end, write_offset);
            }
            write_offset += packet_len;
            kept_segments += 1;
        }
        read_offset = packet_end;
    }
    (write_offset, kept_segments)
}

pub(crate) fn build_reverse_tls_config(
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
struct ReverseH3Handler {
    reverse: ReloadableReverse,
}

#[async_trait]
impl H3RequestHandler for ReverseH3Handler {
    fn limits(&self) -> H3Limits {
        let state = self.reverse.runtime.state();
        let limits = state.plan.limits;
        let streaming = state
            .plan
            .reverse_edge(self.reverse.name.as_ref())
            .map(|edge| edge.streaming)
            .unwrap_or_else(|| crate::runtime::ResolvedStreamingLimits::from(limits));
        H3Limits {
            listener_name: Arc::<str>::from(self.reverse.name.as_ref()),
            max_concurrent_streams_per_connection: limits.h3.max_h3_streams_per_connection,
            datagram_channel_capacity: limits.h3.datagram_channel_capacity,
            streaming,
            read_timeout: Duration::from_millis(limits.timeouts.h3_read_timeout_ms),
            proxy_name: Arc::<str>::from(state.plan.identity.proxy_name.as_ref()),
            error_body: Arc::<str>::from(state.messages.reverse_error.as_str()),
        }
    }

    async fn handle_http(&self, req: Request<Body>, conn: H3ConnInfo) -> Response<Body> {
        let reverse_conn = ReverseConnInfo::terminated(
            conn.remote_addr,
            conn.dst_port,
            conn.tls_sni.clone(),
            conn.peer_certificates.clone(),
        );
        match transport::handle_request(req, self.reverse.clone(), reverse_conn).await {
            Ok(resp) => resp,
            Err(impossible) => match impossible {},
        }
    }

    async fn handle_http_with_interim(
        &self,
        req: Request<Body>,
        conn: H3ConnInfo,
    ) -> H3HttpResponse {
        let reverse_conn = ReverseConnInfo::terminated(
            conn.remote_addr,
            conn.dst_port,
            conn.tls_sni.clone(),
            conn.peer_certificates.clone(),
        );
        match transport::handle_request_with_interim(req, self.reverse.clone(), reverse_conn).await
        {
            Ok((interim, response)) => H3HttpResponse {
                interim: interim
                    .into_iter()
                    .filter_map(|head| {
                        let status = crate::http::protocol::semantics::validate_http_status_class(
                            head.status,
                            "HTTP/3 interim response",
                        )
                        .ok()?;
                        let mut response =
                            ::http::Response::builder().status(status).body(()).ok()?;
                        *response.headers_mut() = http_headers_to_h1(&head.headers).ok()?;
                        Some(response)
                    })
                    .collect(),
                response,
            },
            Err(impossible) => match impossible {},
        }
    }

    async fn handle_connect(
        &self,
        _req_head: ::http::Request<()>,
        mut req_stream: H3ServerRequestStream,
        _conn: H3ConnInfo,
        _kind: H3ConnectKind,
        _datagrams: Option<crate::http3::datagram::H3StreamDatagrams>,
    ) -> Result<()> {
        let state = self.reverse.runtime.state();
        let proxy_name = state.plan.identity.proxy_name.as_ref();
        if let Err(err) = send_h3_static_response(
            &mut req_stream,
            ::http::StatusCode::METHOD_NOT_ALLOWED,
            state.messages.reverse_error.as_bytes(),
            &http::Method::CONNECT,
            proxy_name,
            state.plan.limits.body.max_h3_response_body_bytes,
        )
        .await
        {
            warn!(error = ?err, "failed to send reverse HTTP/3 CONNECT rejection response");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
