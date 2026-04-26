use crate::http::body::Body;
use crate::http3::codec::http_headers_to_h1;
use crate::http3::listener::{
    H3ConnInfo, H3ConnectKind, H3HttpResponse, H3Limits, H3RequestHandler,
};
use crate::http3::quic::build_h3_server_config_from_tls;
use crate::http3::quinn_socket::{
    build_server_endpoint, prepare_server_endpoint_socket, PreparedServerEndpointSocket,
    QuinnBrokerKind, QuinnBrokerStream, QuinnEndpointSocket, QuinnUdpIngressFilter,
};
use crate::http3::server::{send_h3_static_response, H3ServerRequestStream};
use crate::sidecar_control::SidecarControl;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hyper::{Request, Response};
use qpx_core::config::ReverseConfig;
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
    shutdown: watch::Receiver<SidecarControl>,
    endpoint_socket: QuinnEndpointSocket,
) -> Result<()> {
    let tls_config = build_reverse_tls_config(&reverse)?;
    let runtime_cfg = reverse_rt.runtime.state().config.runtime.clone();
    let max_bidi = runtime_cfg
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

#[cfg(test)]
fn filter_quic_recv_batch(
    reverse: &super::ReloadableReverse,
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
    reverse: &super::ReloadableReverse,
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
        let blocked = super::reverse_quic_connection_filter_match(
            reverse,
            meta.addr,
            local_port,
            &buf[read_offset..packet_end],
        );
        if let Some((stage, matched_rule, sni)) = blocked {
            super::record_reverse_connection_filter_block(
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
struct ReverseH3Handler {
    reverse: super::ReloadableReverse,
}

#[async_trait]
impl H3RequestHandler for ReverseH3Handler {
    fn limits(&self) -> H3Limits {
        let state = self.reverse.runtime.state();
        let limits = state.config.runtime.clone();
        H3Limits {
            max_request_body_bytes: limits.max_h3_request_body_bytes,
            max_response_body_bytes: limits.max_h3_response_body_bytes,
            max_concurrent_streams_per_connection: limits.max_h3_streams_per_connection,
            read_timeout: Duration::from_millis(limits.h3_read_timeout_ms),
            proxy_name: Arc::<str>::from(state.config.identity.proxy_name.as_str()),
            error_body: Arc::<str>::from(state.messages.reverse_error.as_str()),
        }
    }

    async fn handle_http(&self, req: Request<Body>, conn: H3ConnInfo) -> Response<Body> {
        let reverse_conn = super::transport::ReverseConnInfo::terminated(
            conn.remote_addr,
            conn.dst_port,
            conn.tls_sni.clone(),
            conn.peer_certificates.clone(),
        );
        match super::transport::handle_request(req, self.reverse.clone(), reverse_conn).await {
            Ok(resp) => resp,
            Err(impossible) => match impossible {},
        }
    }

    async fn handle_http_with_interim(
        &self,
        req: Request<Body>,
        conn: H3ConnInfo,
    ) -> H3HttpResponse {
        let reverse_conn = super::transport::ReverseConnInfo::terminated(
            conn.remote_addr,
            conn.dst_port,
            conn.tls_sni.clone(),
            conn.peer_certificates.clone(),
        );
        match super::transport::handle_request_with_interim(req, self.reverse.clone(), reverse_conn)
            .await
        {
            Ok((interim, response)) => H3HttpResponse {
                interim: interim
                    .into_iter()
                    .filter_map(|head| {
                        let status = ::http::StatusCode::from_u16(head.status.as_u16()).ok()?;
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
        let proxy_name = state.config.identity.proxy_name.as_str();
        if let Err(err) = send_h3_static_response(
            &mut req_stream,
            ::http::StatusCode::METHOD_NOT_ALLOWED,
            state.messages.reverse_error.as_bytes(),
            &http::Method::CONNECT,
            proxy_name,
            state.config.runtime.max_h3_response_body_bytes,
        )
        .await
        {
            warn!(error = ?err, "failed to send reverse HTTP/3 CONNECT rejection response");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Runtime;
    use crate::tls::extract_client_hello_info_from_handshake;
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CacheConfig, Config,
        IdentityConfig, MatchConfig, MessagesConfig, ReverseConfig, ReverseRouteConfig, RuleConfig,
        RuntimeConfig, SystemLogConfig, UpstreamConfig,
    };
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::quic::{Keys, Version};
    use rustls::{CipherSuite, Side};
    use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
    use std::sync::Arc;

    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    fn build_reloadable_reverse_with_filter(
        connection_filter: Vec<RuleConfig>,
    ) -> super::super::ReloadableReverse {
        let reverse_cfg = ReverseConfig {
            name: "test".to_string(),
            listen: "127.0.0.1:0".to_string(),
            tls: None,
            http3: None,
            xdp: None,
            enforce_sni_host_match: false,
            sni_host_exceptions: Vec::new(),
            policy_context: None,
            connection_filter,
            destination_resolution: None,
            routes: vec![ReverseRouteConfig {
                name: Some("route".to_string()),
                r#match: MatchConfig::default(),
                upstreams: vec!["upstream".to_string()],
                backends: Vec::new(),
                mirrors: Vec::new(),
                local_response: None,
                headers: None,
                lb: "round_robin".to_string(),
                timeout_ms: None,
                health_check: None,
                cache: None,
                rate_limit: None,
                path_rewrite: None,
                upstream_trust_profile: None,
                upstream_trust: None,
                lifecycle: None,
                ipc: None,
                affinity: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
            }],
            tls_passthrough_routes: Vec::new(),
        };
        let config = Config {
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig::default(),
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            acme: None,
            exporter: None,
            auth: AuthConfig::default(),
            identity_sources: Vec::new(),
            ext_authz: Vec::new(),
            destination_resolution: Default::default(),
            listeners: Vec::new(),
            named_sets: Vec::new(),
            http_guard_profiles: Vec::new(),
            rate_limit_profiles: Vec::new(),
            upstream_trust_profiles: Vec::new(),
            reverse: vec![reverse_cfg.clone()],
            upstreams: vec![UpstreamConfig {
                name: "upstream".to_string(),
                url: "http://127.0.0.1:18080".to_string(),
                tls_trust_profile: None,
                tls_trust: None,
                discovery: None,
                resilience: None,
            }],
            cache: CacheConfig::default(),
        };
        let runtime = Runtime::new(config).expect("runtime");
        super::super::ReloadableReverse::new(
            reverse_cfg,
            runtime,
            Arc::<str>::from("reverse_upstreams_unhealthy"),
        )
        .expect("reloadable reverse")
    }

    #[tokio::test]
    async fn reverse_quic_connection_filter_matches_client_hello_metadata() {
        let reverse = build_reloadable_reverse_with_filter(vec![RuleConfig {
            name: "block-quic".to_string(),
            r#match: Some(MatchConfig {
                sni: vec!["blocked.example".to_string()],
                alpn: vec!["h3".to_string()],
                tls_version: vec!["tls1.3".to_string()],
                ..Default::default()
            }),
            auth: None,
            action: Some(ActionConfig {
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            }),
            headers: None,
            rate_limit: None,
        }]);
        let packet = build_client_initial("blocked.example", Some(b"h3"));
        let client_hello =
            crate::transparent::quic::extract_quic_client_hello_info(packet.as_slice())
                .expect("client hello");
        assert_eq!(client_hello.sni.as_deref(), Some("blocked.example"));
        assert_eq!(client_hello.alpn.as_deref(), Some("h3"));
        assert_eq!(client_hello.tls_version.as_deref(), Some("tls1.3"));
        let matched = super::super::reverse_quic_connection_filter_match(
            &reverse,
            "127.0.0.1:54000".parse().expect("remote"),
            443,
            packet.as_slice(),
        )
        .expect("matched");
        assert_eq!(
            matched.0,
            crate::connection_filter::ConnectionFilterStage::ClientHello
        );
        assert_eq!(matched.1, "block-quic");
        assert_eq!(matched.2.as_deref(), Some("blocked.example"));
    }

    #[tokio::test]
    async fn filter_quic_recv_batch_drops_blocked_initials_and_compacts_batch() {
        let reverse = build_reloadable_reverse_with_filter(vec![RuleConfig {
            name: "block-quic".to_string(),
            r#match: Some(MatchConfig {
                sni: vec!["blocked.example".to_string()],
                ..Default::default()
            }),
            auth: None,
            action: Some(ActionConfig {
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            }),
            headers: None,
            rate_limit: None,
        }]);
        let blocked = build_client_initial("blocked.example", Some(b"h3"));
        let allowed = build_client_initial("allowed.example", Some(b"h3"));
        assert_eq!(
            crate::transparent::quic::extract_quic_client_hello_info(blocked.as_slice())
                .and_then(|hello| hello.sni),
            Some("blocked.example".to_string())
        );
        assert_eq!(
            crate::transparent::quic::extract_quic_client_hello_info(allowed.as_slice())
                .and_then(|hello| hello.sni),
            Some("allowed.example".to_string())
        );
        let mut first = blocked.clone();
        first.extend_from_slice(allowed.as_slice());
        let second = blocked.clone();
        let mut meta = [
            quinn::udp::RecvMeta {
                addr: "127.0.0.1:54000".parse().expect("addr"),
                len: first.len(),
                stride: blocked.len(),
                ecn: None,
                dst_ip: None,
            },
            quinn::udp::RecvMeta {
                addr: "127.0.0.1:54001".parse().expect("addr"),
                len: second.len(),
                stride: second.len(),
                ecn: None,
                dst_ip: None,
            },
        ];
        let mut second_buf = second.clone();
        let mut bufs = [
            IoSliceMut::new(first.as_mut_slice()),
            IoSliceMut::new(second_buf.as_mut_slice()),
        ];
        let count = filter_quic_recv_batch(&reverse, 443, &mut bufs, &mut meta, 2);
        assert_eq!(count, 1);
        assert_eq!(meta[0].len, allowed.len());
        assert_eq!(meta[0].stride, allowed.len());
        assert_eq!(&bufs[0][..allowed.len()], allowed.as_slice());
    }

    fn build_client_initial(server_name: &str, alpn: Option<&[u8]>) -> Vec<u8> {
        let provider = rustls::crypto::ring::default_provider();
        let mut client = ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        if let Some(alpn) = alpn {
            client.alpn_protocols = vec![alpn.to_vec()];
        }

        let mut hs = Vec::new();
        let mut conn = rustls::quic::ClientConnection::new(
            Arc::new(client),
            Version::V1,
            ServerName::try_from(server_name)
                .expect("server name")
                .to_owned(),
            Vec::new(),
        )
        .expect("quic client");
        let _ = conn.write_hs(&mut hs);
        let raw = extract_client_hello_info_from_handshake(hs.as_slice()).expect("client hello");
        assert_eq!(raw.sni.as_deref(), Some(server_name));

        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let scid = [0x01, 0x02, 0x03, 0x04];
        let suite = initial_suite().expect("tls13 suite");
        let keys = Keys::initial(
            Version::V1,
            suite,
            suite.quic.expect("quic"),
            &dcid,
            Side::Client,
        );

        let mut plaintext = Vec::new();
        encode_quic_varint(0x06, &mut plaintext).expect("crypto type");
        encode_quic_varint(0, &mut plaintext).expect("crypto offset");
        encode_quic_varint(hs.len() as u64, &mut plaintext).expect("crypto length");
        plaintext.extend_from_slice(&hs);
        while plaintext.len() < 1180 {
            plaintext.push(0);
        }

        let packet_number = [0u8];
        let mut header = vec![0xc0];
        header.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(&dcid);
        header.push(scid.len() as u8);
        header.extend_from_slice(&scid);
        encode_quic_varint(0, &mut header).expect("token length");
        encode_quic_varint(
            (packet_number.len() + plaintext.len() + 16) as u64,
            &mut header,
        )
        .expect("packet length");
        let packet_number_offset = header.len();
        header.extend_from_slice(&packet_number);

        let mut ciphertext = plaintext;
        let tag = keys
            .local
            .packet
            .encrypt_in_place(0, &header, ciphertext.as_mut_slice())
            .expect("encrypt");
        ciphertext.extend_from_slice(tag.as_ref());

        let mut packet = header;
        packet.extend_from_slice(&ciphertext);
        let sample_len = keys.local.header.sample_len();
        let sample_start = packet_number_offset + 4;
        let sample_end = sample_start + sample_len;
        let mut first = packet[0];
        let mut packet_number_bytes =
            packet[packet_number_offset..packet_number_offset + packet_number.len()].to_vec();
        keys.local
            .header
            .encrypt_in_place(
                &packet[sample_start..sample_end],
                &mut first,
                packet_number_bytes.as_mut_slice(),
            )
            .expect("header protect");
        packet[0] = first;
        packet[packet_number_offset..packet_number_offset + packet_number.len()]
            .copy_from_slice(&packet_number_bytes);
        packet
    }

    fn initial_suite() -> Option<&'static rustls::Tls13CipherSuite> {
        rustls::crypto::ring::default_provider()
            .cipher_suites
            .iter()
            .find_map(|suite| match (suite.suite(), suite.tls13()) {
                (CipherSuite::TLS13_AES_128_GCM_SHA256, Some(tls13)) if tls13.quic.is_some() => {
                    Some(tls13)
                }
                _ => None,
            })
    }

    fn encode_quic_varint(value: u64, out: &mut Vec<u8>) -> Result<(), &'static str> {
        match value {
            0..=63 => out.push(value as u8),
            64..=16383 => {
                let encoded = 0x4000 | value as u16;
                out.extend_from_slice(&encoded.to_be_bytes());
            }
            16384..=1_073_741_823 => {
                let encoded = 0x8000_0000 | value as u32;
                out.extend_from_slice(&encoded.to_be_bytes());
            }
            1_073_741_824..=4_611_686_018_427_387_903 => {
                let encoded = 0xc000_0000_0000_0000 | value;
                out.extend_from_slice(&encoded.to_be_bytes());
            }
            _ => return Err("value too large"),
        }
        Ok(())
    }
}
