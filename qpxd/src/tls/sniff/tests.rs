use super::*;

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u24(out: &mut Vec<u8>, value: usize) {
    out.push(((value >> 16) & 0xff) as u8);
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}

fn push_extension(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    push_u16(out, kind);
    push_u16(out, data.len() as u16);
    out.extend_from_slice(data);
}

fn build_client_hello() -> Vec<u8> {
    let mut body = Vec::new();
    push_u16(&mut body, 0x0303);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);

    push_u16(&mut body, 6);
    push_u16(&mut body, 0x1301);
    push_u16(&mut body, 0x1302);
    push_u16(&mut body, 0x1303);

    body.push(1);
    body.push(0);

    let mut extensions = Vec::new();

    let host = b"example.com";
    let mut sni = Vec::new();
    push_u16(&mut sni, (host.len() + 3) as u16);
    sni.push(0);
    push_u16(&mut sni, host.len() as u16);
    sni.extend_from_slice(host);
    push_extension(&mut extensions, 0, &sni);

    let mut groups = Vec::new();
    push_u16(&mut groups, 4);
    push_u16(&mut groups, 29);
    push_u16(&mut groups, 23);
    push_extension(&mut extensions, 10, &groups);

    let point_formats = [1u8, 0u8];
    push_extension(&mut extensions, 11, &point_formats);

    let alpn = b"h2";
    let mut alpn_ext = Vec::new();
    push_u16(&mut alpn_ext, (alpn.len() + 1) as u16);
    alpn_ext.push(alpn.len() as u8);
    alpn_ext.extend_from_slice(alpn);
    push_extension(&mut extensions, 16, &alpn_ext);

    let supported_versions = [4u8, 0x03, 0x04, 0x03, 0x03];
    push_extension(&mut extensions, 43, &supported_versions);

    push_u16(&mut body, extensions.len() as u16);
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(1);
    push_u24(&mut handshake, body.len());
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(22);
    push_u16(&mut record, 0x0301);
    push_u16(&mut record, handshake.len() as u16);
    record.extend_from_slice(&handshake);
    record
}

#[test]
fn extract_client_hello_info_parses_metadata() {
    let info = extract_client_hello_info(&build_client_hello()).expect("info");
    assert_eq!(info.sni.as_deref(), Some("example.com"));
    assert_eq!(info.alpn.as_deref(), Some("h2"));
    assert_eq!(info.tls_version.as_deref(), Some("tls1.3"));
    assert_eq!(
        info.ja3.as_deref(),
        Some("771,4865-4866-4867,0-10-11-16-43,29-23,0")
    );
    assert_eq!(info.ja4.as_deref(), Some("t13dh2_03_05_02"));
    assert_eq!(
        extract_sni(&build_client_hello()).as_deref(),
        Some("example.com")
    );
}

#[test]
fn extract_client_hello_info_can_skip_fingerprints() {
    let info =
        extract_client_hello_info_with_fingerprints(&build_client_hello(), false).expect("info");
    assert_eq!(info.sni.as_deref(), Some("example.com"));
    assert_eq!(info.alpn.as_deref(), Some("h2"));
    assert_eq!(info.tls_version.as_deref(), Some("tls1.3"));
    assert_eq!(info.ja3, None);
    assert_eq!(info.ja4, None);
}
