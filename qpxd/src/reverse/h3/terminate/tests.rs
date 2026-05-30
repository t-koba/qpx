use crate::reverse::h3::terminate::*;
use crate::runtime::Runtime;
use crate::tls::sniff::extract_client_hello_info_from_handshake;
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config, IdentityConfig,
    MatchConfig, MessagesConfig, ReverseEdgeConfig, ReverseRouteConfig, RuleConfig, RuntimeConfig,
    SystemLogConfig, UpstreamConfig,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::quic::{Keys, Version};
use rustls::{CipherSuite, Side};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use std::io::IoSliceMut;
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

fn build_reloadable_reverse_with_filter(connection_filter: Vec<RuleConfig>) -> ReloadableReverse {
    let reverse_cfg = ReverseEdgeConfig {
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
        streaming: None,
        grpc: None,
        sse: None,
        routes: vec![ReverseRouteConfig {
            name: Some("route".to_string()),
            r#match: MatchConfig::default(),
            target: qpx_core::config::ReverseRouteTargetConfig::Upstream {
                upstreams: vec!["upstream".to_string()],
                lb: "round_robin".to_string(),
            },
            mirrors: Vec::new(),
            headers: None,
            timeout_ms: None,
            health_check: None,
            cache: None,
            capture: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            affinity: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: None,
        }],
        tls_passthrough_routes: Vec::new(),
    };
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        telemetry: qpx_core::config::TelemetryConfig {
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            exporter: None,
        },
        security: qpx_core::config::SecurityConfig {
            auth: AuthConfig::default(),
            identity_sources: Vec::new(),
            decisions: qpx_core::config::DecisionConfig {
                ext_authz: Vec::new(),
            },
            destination: Default::default(),
            named_sets: Vec::new(),
            upstream_trust_profiles: Vec::new(),
        },
        http: qpx_core::config::HttpGlobalConfig::default(),
        traffic: qpx_core::config::TrafficConfig::default(),
        acme: None,
        edges: vec![qpx_core::config::EdgeConfig::Reverse(reverse_cfg.clone())],
        upstreams: vec![UpstreamConfig {
            name: "upstream".to_string(),
            url: "http://127.0.0.1:18080".to_string(),
            tls_trust_profile: None,
            tls_trust: None,
            discovery: None,
            resilience: None,
        }],
        caches: Vec::new(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    ReloadableReverse::new(
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
    let client_hello = crate::transparent::quic::extract_quic_client_hello_info(packet.as_slice())
        .expect("client hello");
    assert_eq!(client_hello.sni.as_deref(), Some("blocked.example"));
    assert_eq!(client_hello.alpn.as_deref(), Some("h3"));
    assert_eq!(client_hello.tls_version.as_deref(), Some("tls1.3"));
    let matched = reverse_quic_connection_filter_match(
        &reverse,
        "127.0.0.1:54000".parse().expect("remote"),
        443,
        packet.as_slice(),
    )
    .expect("matched");
    assert_eq!(
        matched.0,
        crate::tcp_bindings::filter::ConnectionFilterStage::ClientHello
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
