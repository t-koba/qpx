use super::*;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

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
    encode_client_hello_records(&build_client_hello_handshake(0))
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

/// Deterministic async input: serves at most `chunk` bytes per poll and never
/// pends, so `read_client_hello_with_timeout` timing behavior is not exercised.
struct ChunkedSliceReader<'a> {
    data: &'a [u8],
    pos: usize,
    chunk: usize,
    read_calls: usize,
}

impl<'a> ChunkedSliceReader<'a> {
    fn new(data: &'a [u8], chunk: usize) -> Self {
        Self {
            data,
            pos: 0,
            chunk: chunk.max(1),
            read_calls: 0,
        }
    }
}

impl AsyncRead for ChunkedSliceReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.read_calls += 1;
        if self.pos >= self.data.len() || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let remaining = self.data.len() - self.pos;
        let n = remaining.min(self.chunk).min(buf.remaining());
        buf.put_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Poll::Ready(Ok(()))
    }
}

fn build_client_hello_handshake(pad_data_len: usize) -> Vec<u8> {
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

    // Unknown extension the parser skips; used only to grow the hello to a
    // target size while keeping the SNI metadata parseable.
    if pad_data_len > 0 {
        let pad_data = vec![0xABu8; pad_data_len];
        push_extension(&mut extensions, 0xFE00, &pad_data);
    }

    push_u16(&mut body, extensions.len() as u16);
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(1);
    push_u24(&mut handshake, body.len());
    handshake.extend_from_slice(&body);

    handshake
}

fn encode_client_hello_records(handshake: &[u8]) -> Vec<u8> {
    const MAX_RECORD_PAYLOAD_BYTES: usize = 16 * 1024;

    let mut records = Vec::new();
    for payload in handshake.chunks(MAX_RECORD_PAYLOAD_BYTES) {
        records.push(22);
        push_u16(&mut records, 0x0301);
        push_u16(&mut records, payload.len() as u16);
        records.extend_from_slice(payload);
    }
    records
}

/// Build a ClientHello fragmented across four TLS records of at most 16 KiB.
fn build_sized_client_hello(total_record_bytes: usize) -> Vec<u8> {
    const RECORD_HEADER_BYTES: usize = 5;
    const RECORD_COUNT: usize = 4;
    let handshake_bytes = total_record_bytes - RECORD_COUNT * RECORD_HEADER_BYTES;
    let base = build_client_hello_handshake(0);
    assert!(
        handshake_bytes >= base.len() + 4,
        "target below base hello size"
    );

    let handshake = build_client_hello_handshake(handshake_bytes - base.len() - 4);
    assert_eq!(handshake.len(), handshake_bytes);
    let records = encode_client_hello_records(&handshake);
    assert_eq!(records.len(), total_record_bytes);
    records
}

#[tokio::test]
async fn production_reader_returns_full_in_budget_hello_at_cap() {
    let hello = build_sized_client_hello(MAX_CLIENT_HELLO_PEEK_BYTES);
    assert_eq!(hello.len(), MAX_CLIENT_HELLO_PEEK_BYTES);
    // Small chunks force the reader past the initial 5-byte peek where the
    // defect returned early once the required target reached the 64 KiB cap.
    let mut reader = ChunkedSliceReader::new(&hello, 512);
    let out = read_client_hello_with_timeout(&mut reader, std::time::Duration::from_secs(5))
        .await
        .expect("read hello");
    assert_eq!(out.len(), MAX_CLIENT_HELLO_PEEK_BYTES);
    assert_eq!(out, hello);
    let info = extract_client_hello_info(&out).expect("info");
    assert_eq!(info.sni.as_deref(), Some("example.com"));
    assert!(reader.read_calls > 2);
    assert_eq!(reader.pos, hello.len());
}

#[tokio::test]
async fn production_reader_bounds_over_cap_hello_to_cap_without_extra_read() {
    let hello = build_sized_client_hello(MAX_CLIENT_HELLO_PEEK_BYTES + 20);
    assert!(hello.len() > MAX_CLIENT_HELLO_PEEK_BYTES);
    let mut input = hello.clone();
    input.extend_from_slice(&[0xCCu8; 2048]);
    let mut reader = ChunkedSliceReader::new(&input, 512);
    let out = read_client_hello_with_timeout(&mut reader, std::time::Duration::from_secs(5))
        .await
        .expect("read hello");
    assert_eq!(out.len(), MAX_CLIENT_HELLO_PEEK_BYTES);
    assert_eq!(out, hello[..MAX_CLIENT_HELLO_PEEK_BYTES]);
    // Exactly the cap was consumed: still inside the hello padding, with the
    // hello tail and trailing sentinel left unread, so no byte past the cap
    // was pulled from the peer.
    assert_eq!(reader.pos, MAX_CLIENT_HELLO_PEEK_BYTES);
    assert_eq!(input[reader.pos], 0xAB);
    assert_eq!(
        input.len() - reader.pos,
        hello.len() - MAX_CLIENT_HELLO_PEEK_BYTES + 2048
    );
    assert_eq!(&input[input.len() - 2048..], &[0xCCu8; 2048]);
}
