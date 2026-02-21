// Re-implement the protocol helpers needed for testing, since the binary
// crate's modules are not directly linkable as a library.  We test the
// protocol at the byte level instead.

const FCGI_VERSION: u8 = 1;
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDOUT: u8 = 6;
const FCGI_RESPONDER: u16 = 1;
const FCGI_REQUEST_COMPLETE: u8 = 0;

fn encode_record(record_type: u8, request_id: u16, content: &[u8]) -> Vec<u8> {
    let padding = (8 - (content.len() % 8)) % 8;
    let mut buf = Vec::with_capacity(8 + content.len() + padding);
    buf.push(FCGI_VERSION);
    buf.push(record_type);
    buf.push((request_id >> 8) as u8);
    buf.push((request_id & 0xff) as u8);
    buf.push((content.len() >> 8) as u8);
    buf.push((content.len() & 0xff) as u8);
    buf.push(padding as u8);
    buf.push(0);
    buf.extend_from_slice(content);
    buf.extend(std::iter::repeat_n(0u8, padding));
    buf
}

fn decode_record_header(buf: &[u8; 8]) -> (u8, u8, u16, u16, u8) {
    (
        buf[0],
        buf[1],
        u16::from_be_bytes([buf[2], buf[3]]),
        u16::from_be_bytes([buf[4], buf[5]]),
        buf[6],
    )
}

fn encode_nv_pair(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    if name.len() < 128 {
        buf.push(name.len() as u8);
    } else {
        buf.extend_from_slice(&((name.len() as u32) | 0x8000_0000).to_be_bytes());
    }
    if value.len() < 128 {
        buf.push(value.len() as u8);
    } else {
        buf.extend_from_slice(&((value.len() as u32) | 0x8000_0000).to_be_bytes());
    }
    buf.extend_from_slice(name);
    buf.extend_from_slice(value);
    buf
}

fn decode_nv_pairs(mut data: &[u8]) -> Vec<(String, String)> {
    let mut result = Vec::new();
    while !data.is_empty() {
        let name_len = read_nv_len(&mut data);
        let value_len = read_nv_len(&mut data);
        let name = std::str::from_utf8(&data[..name_len]).unwrap().to_string();
        let value = std::str::from_utf8(&data[name_len..name_len + value_len])
            .unwrap()
            .to_string();
        data = &data[name_len + value_len..];
        result.push((name, value));
    }
    result
}

fn read_nv_len(data: &mut &[u8]) -> usize {
    let first = data[0];
    if first < 128 {
        *data = &data[1..];
        first as usize
    } else {
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) & 0x7fff_ffff;
        *data = &data[4..];
        len as usize
    }
}

#[test]
fn test_record_encode_decode_roundtrip() {
    let content = b"hello world";
    let encoded = encode_record(FCGI_STDOUT, 42, content);

    // Header is 8 bytes.
    assert!(encoded.len() >= 8);
    let hdr: [u8; 8] = encoded[..8].try_into().unwrap();
    let (version, rtype, req_id, content_len, padding_len) = decode_record_header(&hdr);

    assert_eq!(version, FCGI_VERSION);
    assert_eq!(rtype, FCGI_STDOUT);
    assert_eq!(req_id, 42);
    assert_eq!(content_len, content.len() as u16);

    let decoded_content = &encoded[8..8 + content_len as usize];
    assert_eq!(decoded_content, content);

    // Total length should be 8 + content + padding.
    assert_eq!(
        encoded.len(),
        8 + content_len as usize + padding_len as usize
    );
}

#[test]
fn test_empty_record() {
    let encoded = encode_record(FCGI_PARAMS, 1, &[]);
    let hdr: [u8; 8] = encoded[..8].try_into().unwrap();
    let (_, rtype, req_id, content_len, _) = decode_record_header(&hdr);
    assert_eq!(rtype, FCGI_PARAMS);
    assert_eq!(req_id, 1);
    assert_eq!(content_len, 0);
}

#[test]
fn test_nv_pair_short_names() {
    let encoded = encode_nv_pair(b"KEY", b"VALUE");
    let pairs = decode_nv_pairs(&encoded);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, "KEY");
    assert_eq!(pairs[0].1, "VALUE");
}

#[test]
fn test_nv_pair_long_value() {
    let name = b"SHORT";
    let value = "x".repeat(200);
    let encoded = encode_nv_pair(name, value.as_bytes());
    let pairs = decode_nv_pairs(&encoded);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, "SHORT");
    assert_eq!(pairs[0].1, value);
}

#[test]
fn test_multiple_nv_pairs() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&encode_nv_pair(b"A", b"1"));
    buf.extend_from_slice(&encode_nv_pair(b"B", b"2"));
    buf.extend_from_slice(&encode_nv_pair(b"C", b"3"));

    let pairs = decode_nv_pairs(&buf);
    assert_eq!(pairs.len(), 3);
    assert_eq!(pairs[0], ("A".to_string(), "1".to_string()));
    assert_eq!(pairs[1], ("B".to_string(), "2".to_string()));
    assert_eq!(pairs[2], ("C".to_string(), "3".to_string()));
}

#[test]
fn test_begin_request_record() {
    let mut body = [0u8; 8];
    body[0] = (FCGI_RESPONDER >> 8) as u8;
    body[1] = (FCGI_RESPONDER & 0xff) as u8;
    let encoded = encode_record(FCGI_BEGIN_REQUEST, 1, &body);

    let hdr: [u8; 8] = encoded[..8].try_into().unwrap();
    let (version, rtype, req_id, content_len, _) = decode_record_header(&hdr);
    assert_eq!(version, FCGI_VERSION);
    assert_eq!(rtype, FCGI_BEGIN_REQUEST);
    assert_eq!(req_id, 1);
    assert_eq!(content_len, 8);

    let role = u16::from_be_bytes([encoded[8], encoded[9]]);
    assert_eq!(role, FCGI_RESPONDER);
}

#[test]
fn test_end_request_record() {
    let mut body = [0u8; 8];
    let app_status: u32 = 0;
    body[0..4].copy_from_slice(&app_status.to_be_bytes());
    body[4] = FCGI_REQUEST_COMPLETE;
    let encoded = encode_record(FCGI_END_REQUEST, 1, &body);

    let hdr: [u8; 8] = encoded[..8].try_into().unwrap();
    let (_, rtype, _, content_len, _) = decode_record_header(&hdr);
    assert_eq!(rtype, FCGI_END_REQUEST);
    assert_eq!(content_len, 8);

    let decoded_status = u32::from_be_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]);
    assert_eq!(decoded_status, 0);
    assert_eq!(encoded[12], FCGI_REQUEST_COMPLETE);
}

#[test]
fn test_record_padding_alignment() {
    // Content of length 1 should pad to 8-byte boundary: 7 padding bytes.
    let encoded = encode_record(FCGI_STDOUT, 1, &[0x42]);
    assert_eq!(encoded.len(), 8 + 1 + 7); // header + content + padding

    // Content of length 8 should have 0 padding.
    let encoded = encode_record(FCGI_STDOUT, 1, &[0u8; 8]);
    assert_eq!(encoded.len(), 8 + 8);

    // Content of length 5 should have 3 padding bytes.
    let encoded = encode_record(FCGI_STDOUT, 1, &[0u8; 5]);
    assert_eq!(encoded.len(), 8 + 5 + 3);
}

#[test]
fn test_request_id_encoding() {
    // Test high request IDs.
    let encoded = encode_record(FCGI_STDOUT, 0xFFFF, &[]);
    let hdr: [u8; 8] = encoded[..8].try_into().unwrap();
    let (_, _, req_id, _, _) = decode_record_header(&hdr);
    assert_eq!(req_id, 0xFFFF);

    let encoded = encode_record(FCGI_STDOUT, 256, &[]);
    let hdr: [u8; 8] = encoded[..8].try_into().unwrap();
    let (_, _, req_id, _, _) = decode_record_header(&hdr);
    assert_eq!(req_id, 256);
}
