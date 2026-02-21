//! FastCGI client tests for qpxd.
//!
//! These tests verify FastCGI protocol encoding/decoding at the byte level,
//! matching the implementation used in qpxd's fastcgi_client module.

const FCGI_VERSION: u8 = 1;
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
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

fn decode_record_header(buf: &[u8; 8]) -> (u8, u8, u16, u16, u8) {
    (
        buf[0],
        buf[1],
        u16::from_be_bytes([buf[2], buf[3]]),
        u16::from_be_bytes([buf[4], buf[5]]),
        buf[6],
    )
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

/// End-to-end test: a raw client sends a FastCGI request to a mock server,
/// which responds with CGI-style output.  This verifies the protocol
/// round-trip that qpxd's FastCGI client would perform.
#[tokio::test]
async fn test_fastcgi_protocol_roundtrip() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server: accept one connection, parse the request, send a response.
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Read BEGIN_REQUEST.
        let mut hdr = [0u8; 8];
        stream.read_exact(&mut hdr).await.unwrap();
        let (_, rtype, req_id, content_len, padding_len) = decode_record_header(&hdr);
        assert_eq!(rtype, FCGI_BEGIN_REQUEST);
        let total = content_len as usize + padding_len as usize;
        let mut body = vec![0u8; total];
        if total > 0 {
            stream.read_exact(&mut body).await.unwrap();
        }

        // Read PARAMS until empty.
        let mut params_buf = Vec::new();
        loop {
            stream.read_exact(&mut hdr).await.unwrap();
            let (_, rt, _, cl, pl) = decode_record_header(&hdr);
            assert_eq!(rt, FCGI_PARAMS);
            let t = cl as usize + pl as usize;
            let mut b = vec![0u8; t];
            if t > 0 {
                stream.read_exact(&mut b).await.unwrap();
            }
            if cl == 0 {
                break;
            }
            params_buf.extend_from_slice(&b[..cl as usize]);
        }

        // Read STDIN until empty.
        loop {
            stream.read_exact(&mut hdr).await.unwrap();
            let (_, rt, _, cl, pl) = decode_record_header(&hdr);
            assert_eq!(rt, FCGI_STDIN);
            let t = cl as usize + pl as usize;
            let mut b = vec![0u8; t];
            if t > 0 {
                stream.read_exact(&mut b).await.unwrap();
            }
            if cl == 0 {
                break;
            }
        }

        // Verify params were decoded correctly.
        let pairs = decode_nv_pairs(&params_buf);
        let params: std::collections::HashMap<String, String> = pairs.into_iter().collect();
        assert_eq!(
            params.get("REQUEST_METHOD").map(|s| s.as_str()),
            Some("GET")
        );
        assert_eq!(params.get("SCRIPT_NAME").map(|s| s.as_str()), Some("/test"));

        // Send STDOUT + empty STDOUT + END_REQUEST.
        let cgi_output = b"Content-Type: text/plain\r\nStatus: 200 OK\r\n\r\nHello from mock!";
        stream
            .write_all(&encode_record(FCGI_STDOUT, req_id, cgi_output))
            .await
            .unwrap();
        stream
            .write_all(&encode_record(FCGI_STDOUT, req_id, &[]))
            .await
            .unwrap();

        let mut end_body = [0u8; 8];
        end_body[4] = FCGI_REQUEST_COMPLETE;
        stream
            .write_all(&encode_record(FCGI_END_REQUEST, req_id, &end_body))
            .await
            .unwrap();
        stream.flush().await.unwrap();
    });

    // Client: connect and send a FastCGI request.
    let client = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let request_id: u16 = 1;

        // BEGIN_REQUEST.
        let mut begin_body = [0u8; 8];
        begin_body[0] = (FCGI_RESPONDER >> 8) as u8;
        begin_body[1] = (FCGI_RESPONDER & 0xff) as u8;
        stream
            .write_all(&encode_record(FCGI_BEGIN_REQUEST, request_id, &begin_body))
            .await
            .unwrap();

        // PARAMS.
        let mut params = Vec::new();
        params.extend_from_slice(&encode_nv_pair(b"REQUEST_METHOD", b"GET"));
        params.extend_from_slice(&encode_nv_pair(b"SCRIPT_NAME", b"/test"));
        params.extend_from_slice(&encode_nv_pair(b"QUERY_STRING", b""));
        stream
            .write_all(&encode_record(FCGI_PARAMS, request_id, &params))
            .await
            .unwrap();
        stream
            .write_all(&encode_record(FCGI_PARAMS, request_id, &[]))
            .await
            .unwrap();

        // STDIN (empty).
        stream
            .write_all(&encode_record(FCGI_STDIN, request_id, &[]))
            .await
            .unwrap();
        stream.flush().await.unwrap();

        // Read response.
        let mut stdout_buf = Vec::new();
        loop {
            let mut hdr = [0u8; 8];
            stream.read_exact(&mut hdr).await.unwrap();
            let (_, rtype, _, content_len, padding_len) = decode_record_header(&hdr);
            let total = content_len as usize + padding_len as usize;
            let mut body = vec![0u8; total];
            if total > 0 {
                stream.read_exact(&mut body).await.unwrap();
            }
            match rtype {
                FCGI_STDOUT if content_len > 0 => {
                    stdout_buf.extend_from_slice(&body[..content_len as usize]);
                }
                FCGI_END_REQUEST => break,
                _ => {}
            }
        }

        let output = String::from_utf8_lossy(&stdout_buf).to_string();
        assert!(
            output.contains("Hello from mock!"),
            "output was: {}",
            output
        );
        assert!(
            output.contains("Content-Type: text/plain"),
            "output was: {}",
            output
        );
    });

    server.await.unwrap();
    client.await.unwrap();
}

#[test]
fn test_nv_encoding_roundtrip() {
    let pairs = vec![
        ("REQUEST_METHOD", "POST"),
        ("CONTENT_TYPE", "application/json"),
        ("CONTENT_LENGTH", "42"),
    ];

    let mut encoded = Vec::new();
    for (name, value) in &pairs {
        encoded.extend_from_slice(&encode_nv_pair(name.as_bytes(), value.as_bytes()));
    }

    let decoded = decode_nv_pairs(&encoded);
    assert_eq!(decoded.len(), 3);
    for (i, (name, value)) in pairs.iter().enumerate() {
        assert_eq!(decoded[i].0, *name);
        assert_eq!(decoded[i].1, *value);
    }
}

#[test]
fn test_record_version_and_type() {
    let rec = encode_record(FCGI_STDOUT, 1, b"data");
    assert_eq!(rec[0], FCGI_VERSION);
    assert_eq!(rec[1], FCGI_STDOUT);
}
