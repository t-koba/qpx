use crate::http3::capsule::decode_quic_varint;
use crate::tls::{extract_client_hello_info_from_handshake, TlsClientHelloInfo};
use bytes::BytesMut;
use rustls::quic::{Keys, Version};
use rustls::CipherSuite;
use rustls::Side;

const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;

#[derive(Debug, Clone, Copy)]
struct ProtectedInitialHeader<'a> {
    version: Version,
    destination_cid: &'a [u8],
    packet_number_offset: usize,
    payload_len: usize,
}

pub(crate) fn looks_like_quic_initial(packet: &[u8]) -> bool {
    parse_protected_initial_header(packet).is_some()
}

pub(crate) fn extract_quic_client_hello_info(packet: &[u8]) -> Option<TlsClientHelloInfo> {
    let protected = parse_protected_initial_header(packet)?;
    let suite = initial_suite()?;
    let quic = suite.quic?;
    let keys = Keys::initial(
        protected.version,
        suite,
        quic,
        protected.destination_cid,
        Side::Server,
    );

    let sample_len = keys.remote.header.sample_len();
    let sample_start = protected.packet_number_offset.checked_add(4)?;
    let sample_end = sample_start.checked_add(sample_len)?;
    let sample = packet.get(sample_start..sample_end)?;

    let mut first = *packet.first()?;
    let mut packet_number = [0u8; 4];
    packet_number.copy_from_slice(
        packet.get(protected.packet_number_offset..protected.packet_number_offset + 4)?,
    );
    keys.remote
        .header
        .decrypt_in_place(sample, &mut first, &mut packet_number)
        .ok()?;

    let packet_number_len = 1usize + usize::from(first & 0x03);
    if protected.payload_len < packet_number_len {
        return None;
    }

    let packet_end = protected
        .packet_number_offset
        .checked_add(protected.payload_len)?;
    let header_len = protected
        .packet_number_offset
        .checked_add(packet_number_len)?;
    if header_len > packet_end || packet_end > packet.len() {
        return None;
    }

    let mut ciphertext = packet[header_len..packet_end].to_vec();
    let mut header = packet[..header_len].to_vec();
    header[0] = first;
    header[protected.packet_number_offset..header_len]
        .copy_from_slice(&packet_number[..packet_number_len]);
    let decrypted = keys
        .remote
        .packet
        .decrypt_in_place(
            decode_packet_number(&packet_number[..packet_number_len]),
            header.as_slice(),
            ciphertext.as_mut_slice(),
        )
        .ok()?;
    let crypto = collect_crypto_payload(decrypted)?;
    extract_client_hello_info_from_handshake(crypto.as_ref())
}

fn parse_protected_initial_header(packet: &[u8]) -> Option<ProtectedInitialHeader<'_>> {
    let first = *packet.first()?;
    if (first & 0x80) == 0 || (first & 0x40) == 0 {
        return None;
    }
    if ((first >> 4) & 0x03) != 0 {
        return None;
    }

    let version = match u32::from_be_bytes(packet.get(1..5)?.try_into().ok()?) {
        QUIC_V1 => Version::V1,
        QUIC_V2 => Version::V2,
        _ => return None,
    };

    let mut cursor = 5usize;
    let dcid_len = usize::from(*packet.get(cursor)?);
    cursor = cursor.checked_add(1)?;
    let destination_cid = packet.get(cursor..cursor.checked_add(dcid_len)?)?;
    cursor = cursor.checked_add(dcid_len)?;

    let scid_len = usize::from(*packet.get(cursor)?);
    cursor = cursor.checked_add(1)?;
    cursor = cursor.checked_add(scid_len)?;
    if cursor > packet.len() {
        return None;
    }

    let (token_len, token_len_len) = decode_quic_varint(packet.get(cursor..)?)?;
    cursor = cursor.checked_add(token_len_len)?;
    cursor = cursor.checked_add(usize::try_from(token_len).ok()?)?;
    if cursor > packet.len() {
        return None;
    }

    let (payload_len, payload_len_len) = decode_quic_varint(packet.get(cursor..)?)?;
    cursor = cursor.checked_add(payload_len_len)?;
    if cursor.checked_add(4)? > packet.len() {
        return None;
    }

    Some(ProtectedInitialHeader {
        version,
        destination_cid,
        packet_number_offset: cursor,
        payload_len: usize::try_from(payload_len).ok()?,
    })
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

fn decode_packet_number(buf: &[u8]) -> u64 {
    buf.iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
}

fn collect_crypto_payload(payload: &[u8]) -> Option<BytesMut> {
    let mut cursor = 0usize;
    let mut crypto = BytesMut::new();

    while cursor < payload.len() {
        let (frame_type, ty_len) = decode_quic_varint(payload.get(cursor..)?)?;
        cursor = cursor.checked_add(ty_len)?;

        match frame_type {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                cursor = skip_ack_frame(payload, cursor, frame_type == 0x03)?;
            }
            0x06 => {
                let (offset, offset_len) = decode_quic_varint(payload.get(cursor..)?)?;
                cursor = cursor.checked_add(offset_len)?;
                let (len, len_len) = decode_quic_varint(payload.get(cursor..)?)?;
                cursor = cursor.checked_add(len_len)?;
                let len = usize::try_from(len).ok()?;
                let end = cursor.checked_add(len)?;
                let chunk = payload.get(cursor..end)?;
                append_crypto_chunk(&mut crypto, usize::try_from(offset).ok()?, chunk);
                cursor = end;
            }
            _ => break,
        }
    }

    (!crypto.is_empty()).then_some(crypto)
}

fn append_crypto_chunk(out: &mut BytesMut, offset: usize, chunk: &[u8]) {
    if offset > out.len() {
        return;
    }
    let needed = offset.saturating_add(chunk.len());
    if needed > out.len() {
        out.resize(needed, 0);
    }
    out[offset..offset + chunk.len()].copy_from_slice(chunk);
}

fn skip_ack_frame(payload: &[u8], mut cursor: usize, ecn: bool) -> Option<usize> {
    let (_, len) = decode_quic_varint(payload.get(cursor..)?)?;
    cursor = cursor.checked_add(len)?;
    let (_, len) = decode_quic_varint(payload.get(cursor..)?)?;
    cursor = cursor.checked_add(len)?;
    let (range_count, len) = decode_quic_varint(payload.get(cursor..)?)?;
    cursor = cursor.checked_add(len)?;
    let (_, len) = decode_quic_varint(payload.get(cursor..)?)?;
    cursor = cursor.checked_add(len)?;
    for _ in 0..range_count {
        let (_, len) = decode_quic_varint(payload.get(cursor..)?)?;
        cursor = cursor.checked_add(len)?;
        let (_, len) = decode_quic_varint(payload.get(cursor..)?)?;
        cursor = cursor.checked_add(len)?;
    }
    if ecn {
        for _ in 0..3 {
            let (_, len) = decode_quic_varint(payload.get(cursor..)?)?;
            cursor = cursor.checked_add(len)?;
        }
    }
    Some(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http3::capsule::encode_quic_varint;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
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

    #[test]
    fn extract_quic_client_hello_info_parses_metadata() {
        let (packet, hs) = build_client_initial("example.com", Some(b"h3"));
        let raw = extract_client_hello_info_from_handshake(&hs).expect("raw handshake");
        assert_eq!(raw.sni.as_deref(), Some("example.com"));
        let protected = parse_protected_initial_header(&packet).expect("protected header");
        let suite = initial_suite().expect("initial suite");
        let keys = Keys::initial(
            protected.version,
            suite,
            suite.quic.expect("quic suite"),
            protected.destination_cid,
            Side::Server,
        );
        let sample_len = keys.remote.header.sample_len();
        let sample_start = protected.packet_number_offset + 4;
        let sample_end = sample_start + sample_len;
        let mut first = packet[0];
        let mut pn = [0u8; 4];
        pn.copy_from_slice(
            &packet[protected.packet_number_offset..protected.packet_number_offset + 4],
        );
        keys.remote
            .header
            .decrypt_in_place(&packet[sample_start..sample_end], &mut first, &mut pn)
            .expect("header decrypt");
        let pn_len = 1 + usize::from(first & 0x03);
        let header_len = protected.packet_number_offset + pn_len;
        let packet_end = protected.packet_number_offset + protected.payload_len;
        let mut ciphertext = packet[header_len..packet_end].to_vec();
        let mut header = packet[..header_len].to_vec();
        header[0] = first;
        header[protected.packet_number_offset..header_len].copy_from_slice(&pn[..pn_len]);
        let decrypted = keys
            .remote
            .packet
            .decrypt_in_place(
                decode_packet_number(&pn[..pn_len]),
                header.as_slice(),
                ciphertext.as_mut_slice(),
            )
            .expect("payload decrypt");
        let crypto = collect_crypto_payload(decrypted).expect("crypto payload");
        let from_crypto =
            extract_client_hello_info_from_handshake(crypto.as_ref()).expect("crypto handshake");
        assert_eq!(from_crypto.sni.as_deref(), Some("example.com"));
        let info = extract_quic_client_hello_info(&packet).expect("metadata");
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert_eq!(info.alpn.as_deref(), Some("h3"));
        assert_eq!(info.tls_version.as_deref(), Some("tls1.3"));
        assert!(info.ja3.is_some());
        assert!(info.ja4.is_some());
    }

    fn build_client_initial(server_name: &str, alpn: Option<&[u8]>) -> (Vec<u8>, Vec<u8>) {
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
        (packet, hs)
    }
}
