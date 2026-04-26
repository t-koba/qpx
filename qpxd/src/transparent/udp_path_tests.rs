use super::*;
use crate::http3::capsule::encode_quic_varint;
use crate::runtime::Runtime;
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CacheConfig, Config,
    Http3ListenerConfig, IdentityConfig, ListenerConfig, ListenerMode, MatchConfig, MessagesConfig,
    RuleConfig, RuntimeConfig, SystemLogConfig, TlsFingerprintMatchConfig,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::quic::{Keys, Version};
use rustls::{CipherSuite, ClientConfig, DigitallySignedStruct, Error, Side, SignatureScheme};
use std::net::{IpAddr, Ipv4Addr};
use tokio::time::Duration;

#[test]
fn parse_quic_long_header_extracts_connection_ids() {
    let packet = [
        0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 4, 9, 10, 11, 12,
    ];
    let header = parse_quic_long_header(&packet).expect("long header");
    assert_eq!(header.dcid_len, 8);
    assert_eq!(header.scid_len, 4);
    assert_eq!(header.dcid.expect("dcid").len, 8);
    assert_eq!(header.scid.expect("scid").len, 4);
}

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
    ) -> std::result::Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
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

fn initial_suite() -> &'static rustls::Tls13CipherSuite {
    rustls::crypto::ring::default_provider()
        .cipher_suites
        .iter()
        .find_map(|suite| match (suite.suite(), suite.tls13()) {
            (CipherSuite::TLS13_AES_128_GCM_SHA256, Some(tls13)) if tls13.quic.is_some() => {
                Some(tls13)
            }
            _ => None,
        })
        .expect("quic tls13 suite")
}

fn build_quic_client_initial(server_name: &str, alpn: Option<&[u8]>) -> Vec<u8> {
    const QUIC_V1: u32 = 0x0000_0001;

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

    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let scid = [0x01, 0x02, 0x03, 0x04];
    let suite = initial_suite();
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
    header.extend_from_slice(&QUIC_V1.to_be_bytes());
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
    let pn_offset = header.len();
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
    let sample_start = pn_offset + 4;
    let sample_end = sample_start + sample_len;
    let mut first = packet[0];
    let mut pn = packet[pn_offset..pn_offset + packet_number.len()].to_vec();
    keys.local
        .header
        .encrypt_in_place(
            &packet[sample_start..sample_end],
            &mut first,
            pn.as_mut_slice(),
        )
        .expect("header protect");
    packet[0] = first;
    packet[pn_offset..pn_offset + packet_number.len()].copy_from_slice(&pn);
    packet
}

fn runtime_for_quic_block(ja4: &str) -> Runtime {
    Runtime::new(Config {
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
        listeners: vec![ListenerConfig {
            name: "transparent".to_string(),
            mode: ListenerMode::Transparent,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Tunnel,
                upstream: None,
                local_response: None,
            },
            tls_inspection: None,
            rules: vec![RuleConfig {
                name: "block-quic-ja4".to_string(),
                r#match: Some(MatchConfig {
                    scheme: vec!["quic".to_string()],
                    sni: vec!["example.com".to_string()],
                    tls_fingerprint: Some(TlsFingerprintMatchConfig {
                        ja3: Vec::new(),
                        ja4: vec![ja4.to_string()],
                    }),
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
            }],
            connection_filter: Vec::new(),
            upstream_proxy: None,
            http3: Some(Http3ListenerConfig {
                enabled: true,
                listen: None,
                connect_udp: None,
            }),
            ftp: Default::default(),
            xdp: None,
            cache: None,
            rate_limit: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            http_modules: Vec::new(),
        }],
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        reverse: Vec::new(),
        upstreams: Vec::new(),
        cache: CacheConfig::default(),
    })
    .expect("runtime")
}

#[tokio::test]
async fn handle_new_udp_session_blocks_quic_by_fingerprint_rule() {
    let listener_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
    let sessions = Arc::new(RwLock::new(SessionIndex::new()));
    let packet = build_quic_client_initial("example.com", Some(b"h3"));
    let ja4 = extract_quic_client_hello_info(&packet)
        .and_then(|hello| hello.ja4)
        .expect("ja4");
    let runtime = runtime_for_quic_block(ja4.as_str());
    let result = handle_new_udp_session(NewUdpSessionContext {
        listener_socket,
        sessions,
        session_id: 1,
        listener_name: "transparent",
        runtime,
        client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44444),
        original_target: None,
        packet,
        run_started: Instant::now(),
        idle_timeout: Duration::from_secs(30),
    })
    .await
    .expect("result");
    assert_eq!(result, "blocked");
}

fn test_quic_long_header() -> Vec<u8> {
    vec![0xc0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 4, 5, 6, 7, 8, 0]
}

#[tokio::test]
async fn cid_lookup_does_not_migrate_transparent_quic_session() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
    let (close_tx, _close_rx) = watch::channel(false);
    let original = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41001);
    let limits = AppliedRateLimits::default();
    let ctx = RateLimitContext::default();
    let permits = AppliedRateLimits::default()
        .acquire_concurrency(&RateLimitContext::default())
        .expect("permits");
    let session = Arc::new(TransparentUdpSession::new(TransparentUdpSessionInit {
        socket,
        close_tx,
        client_addr: original,
        target_key: "198.51.100.7:443".to_string(),
        matched_rule: None,
        rate_limit_profile: None,
        seen_ms: 0,
        limits,
        rate_limit_ctx: ctx,
        concurrency_permits: permits,
    }));
    let mut index = SessionIndex::new();
    index
        .by_target
        .insert((original, "198.51.100.7:443".to_string()), 1);
    index.sessions.insert(1, session);
    let packet = test_quic_long_header();
    index.observe_client_packet(1, &packet);

    let attacker = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41002);
    assert_eq!(
        index.find_session_for_client_packet(original, Some("198.51.100.7:443"), &packet),
        Some(1)
    );
    assert_eq!(
        index.find_session_for_client_packet(attacker, Some("198.51.100.7:443"), &packet),
        None
    );
}
