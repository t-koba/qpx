use crate::http::codec::h1_common::{MAX_HEADER_BYTES, parse_header_map, take_crlf_line};
use crate::http::codec::lazy_timeout::timeout_after_pending;
use anyhow::{Result, anyhow};
use bytes::{Buf, BytesMut};
use hyper::HeaderMap;
use qpx_http::body::Sender;
use qpx_http::protocol::semantics::validate_request_trailers;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::Duration;

const READ_BUF_SIZE: usize = 16 * 1024;
const MAX_CHUNKED_BODY_BYTES: u64 = 1024 * 1024 * 1024;

pub(crate) async fn forward_content_length_request_body<R>(
    mut read_half: R,
    mut read_buf: BytesMut,
    mut remaining: u64,
    mut sender: Sender,
    read_timeout: Duration,
) -> Result<(R, BytesMut)>
where
    R: AsyncRead + Unpin,
{
    let mut deliver = true;
    if !read_buf.is_empty() {
        let take = std::cmp::min(read_buf.len() as u64, remaining) as usize;
        if take > 0 {
            let chunk = read_buf.split_to(take).freeze();
            if deliver && sender.send_data(chunk).await.is_err() {
                deliver = false;
            }
            remaining -= take as u64;
        }
    }
    let mut chunk = BytesMut::with_capacity(READ_BUF_SIZE);
    while remaining > 0 {
        let cap = std::cmp::min(READ_BUF_SIZE as u64, remaining) as usize;
        chunk.clear();
        chunk.reserve(cap);
        let n =
            read_buf_limited_with_timeout(&mut read_half, &mut chunk, cap, read_timeout).await?;
        if n == 0 {
            return Err(anyhow!(
                "client request body closed before content-length completed"
            ));
        }
        if deliver && sender.send_data(chunk.split().freeze()).await.is_err() {
            deliver = false;
        }
        remaining -= n as u64;
    }
    Ok((read_half, read_buf))
}

/// Re-frames a client chunked body into freshly encoded chunks.
///
/// The chunk-size line and trailer block must have unambiguous CRLF framing:
/// bare LF bytes and unterminated quoted chunk extensions are rejected rather
/// than forwarded with a different framing boundary.
pub(crate) async fn forward_chunked_request_body<R>(
    read_half: R,
    read_buf: BytesMut,
    mut sender: Sender,
    read_timeout: Duration,
) -> Result<(R, BytesMut)>
where
    R: AsyncRead + Unpin,
{
    let result =
        forward_chunked_request_body_inner(read_half, read_buf, &mut sender, read_timeout).await;
    if result.is_err() {
        sender.abort();
    }
    result
}

async fn forward_chunked_request_body_inner<R>(
    mut read_half: R,
    mut read_buf: BytesMut,
    sender: &mut Sender,
    read_timeout: Duration,
) -> Result<(R, BytesMut)>
where
    R: AsyncRead + Unpin,
{
    let mut deliver = true;
    let mut total_body_bytes = 0u64;
    loop {
        let line = read_crlf_line(&mut read_half, &mut read_buf, read_timeout).await?;
        validate_chunk_size_line(&line)?;
        let size_token = line
            .split(|b| *b == b';')
            .next()
            .ok_or_else(|| anyhow!("invalid chunk-size line"))?;
        if size_token.is_empty() || !size_token.iter().all(|b| b.is_ascii_hexdigit()) {
            return Err(anyhow!("invalid chunk-size: expected 1*HEXDIG"));
        }
        let size_str = std::str::from_utf8(size_token)?;
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| anyhow!("invalid chunk-size: {}", size_str))?;
        total_body_bytes = total_body_bytes
            .checked_add(size as u64)
            .ok_or_else(|| anyhow!("chunked request body size overflow"))?;
        if total_body_bytes > MAX_CHUNKED_BODY_BYTES {
            return Err(anyhow!(
                "chunked request body exceeds hard cap of {} bytes",
                MAX_CHUNKED_BODY_BYTES
            ));
        }
        if size == 0 {
            let trailers =
                read_trailer_headers(&mut read_half, &mut read_buf, read_timeout).await?;
            if let Some(trailers) = trailers {
                validate_request_trailers(&trailers)
                    .map_err(|err| anyhow!("invalid HTTP/1 request trailers: {err:?}"))?;
                let _ = if deliver {
                    sender.send_trailers(trailers).await
                } else {
                    Ok(())
                };
            }
            return Ok((read_half, read_buf));
        }

        deliver = forward_chunk_payload_segmented(
            &mut read_half,
            &mut read_buf,
            size,
            &mut *sender,
            deliver,
            read_timeout,
        )
        .await?;
    }
}

/// Validate a chunk-size line before its hex prefix is parsed.
///
/// `read_crlf_line` stops at the first CRLF, so an embedded CR or LF would let
/// an extension hide a second framing boundary. A quoted extension must also
/// close; otherwise a parser that tolerates the line could disagree with one
/// that treats the quote as continuing into the next line.
fn validate_chunk_size_line(line: &[u8]) -> Result<()> {
    if line.contains(&b'\r') || line.contains(&b'\n') {
        return Err(anyhow!("invalid chunk-size line: embedded CR or LF"));
    }
    let Some(extension) = line
        .iter()
        .position(|byte| *byte == b';')
        .map(|index| &line[index + 1..])
    else {
        return Ok(());
    };

    let mut quoted = false;
    let mut escaped = false;
    for byte in extension {
        if quoted && escaped {
            escaped = false;
        } else if quoted && *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' {
            quoted = !quoted;
        }
    }
    if quoted {
        return Err(anyhow!(
            "invalid chunk-size line: unterminated quoted string"
        ));
    }
    Ok(())
}

/// Whether the slice has an LF that is not part of a CRLF.
fn has_bare_lf(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r'))
}

fn reject_bare_lf_trailers(bytes: &[u8]) -> Result<()> {
    if has_bare_lf(bytes) {
        return Err(anyhow!("invalid HTTP/1 request trailers: bare LF"));
    }
    Ok(())
}

async fn forward_chunk_payload_segmented<R>(
    reader: &mut R,
    buf: &mut BytesMut,
    mut remaining: usize,
    sender: &mut Sender,
    mut deliver: bool,
    read_timeout: Duration,
) -> Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = BytesMut::with_capacity(READ_BUF_SIZE);
    while remaining > 0 {
        if !buf.is_empty() {
            let take = buf.len().min(remaining).min(READ_BUF_SIZE);
            let chunk = buf.split_to(take).freeze();
            if deliver && sender.send_data(chunk).await.is_err() {
                deliver = false;
            }
            remaining -= take;
            continue;
        }

        let cap = remaining.min(READ_BUF_SIZE);
        chunk.clear();
        chunk.reserve(cap);
        let n = read_buf_limited_with_timeout(reader, &mut chunk, cap, read_timeout).await?;
        if n == 0 {
            return Err(anyhow!(
                "peer connection closed before chunk payload completed"
            ));
        }
        if deliver && sender.send_data(chunk.split().freeze()).await.is_err() {
            deliver = false;
        }
        remaining -= n;
    }

    fill_buffer(reader, buf, 2, read_timeout).await?;
    if &buf[..2] != b"\r\n" {
        return Err(anyhow!("chunk payload missing trailing CRLF"));
    }
    buf.advance(2);
    Ok(deliver)
}

async fn read_crlf_line<R>(
    reader: &mut R,
    buf: &mut BytesMut,
    read_timeout: Duration,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    loop {
        if let Some(line) = take_crlf_line(buf) {
            return Ok(line.to_vec());
        }
        // Require one more byte than already buffered so an incomplete line
        // cannot return without polling the transport (and its timeout).
        let need = buf.len().saturating_add(1);
        fill_buffer_capped(reader, buf, need, MAX_HEADER_BYTES, read_timeout).await?;
    }
}

async fn read_trailer_headers<R>(
    reader: &mut R,
    buf: &mut BytesMut,
    read_timeout: Duration,
) -> Result<Option<HeaderMap>>
where
    R: AsyncRead + Unpin,
{
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 128];
        match httparse::parse_headers(buf.as_ref(), &mut headers)? {
            httparse::Status::Complete((consumed, parsed)) => {
                // Only the consumed block is trailers; later bytes may belong
                // to the next pipelined request.
                reject_bare_lf_trailers(&buf[..consumed])?;
                if parsed.is_empty() {
                    buf.advance(consumed);
                    return Ok(None);
                }
                let trailers = parse_header_map(parsed)?;
                buf.advance(consumed);
                return Ok(Some(trailers));
            }
            httparse::Status::Partial => {
                // No complete trailer block yet, so the whole buffer is still
                // part of it and must use CRLF line endings.
                reject_bare_lf_trailers(buf.as_ref())?;
                let need = buf.len().saturating_add(1);
                fill_buffer_capped(reader, buf, need, MAX_HEADER_BYTES, read_timeout).await?
            }
        }
    }
}

async fn fill_buffer<R>(
    reader: &mut R,
    buf: &mut BytesMut,
    min_len: usize,
    read_timeout: Duration,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    while buf.len() < min_len {
        let n = read_buf_with_timeout(reader, buf, read_timeout).await?;
        if n == 0 {
            return Err(anyhow!("peer connection closed unexpectedly"));
        }
    }
    Ok(())
}

async fn fill_buffer_capped<R>(
    reader: &mut R,
    buf: &mut BytesMut,
    min_len: usize,
    max_len: usize,
    read_timeout: Duration,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    while buf.len() < min_len {
        if buf.len() >= max_len {
            return Err(anyhow!("HTTP/1 header block exceeded configured limit"));
        }
        // Bound each read so one segment cannot push past the cap.
        let remaining = max_len.saturating_sub(buf.len());
        let n = read_buf_limited_with_timeout(reader, buf, remaining, read_timeout).await?;
        if n == 0 {
            return Err(anyhow!("peer connection closed unexpectedly"));
        }
        if buf.len() > max_len {
            return Err(anyhow!("HTTP/1 header block exceeded configured limit"));
        }
    }
    Ok(())
}

async fn read_buf_with_timeout<R>(
    reader: &mut R,
    buf: &mut BytesMut,
    read_timeout: Duration,
) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    timeout_after_pending(read_timeout, reader.read_buf(buf))
        .await
        .map_err(|_| anyhow!("HTTP/1 request body read timed out"))?
        .map_err(Into::into)
}

async fn read_buf_limited_with_timeout<R>(
    reader: &mut R,
    buf: &mut BytesMut,
    limit: usize,
    read_timeout: Duration,
) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    let mut limited = reader.take(limit as u64);
    timeout_after_pending(read_timeout, limited.read_buf(buf))
        .await
        .map_err(|_| anyhow!("HTTP/1 request body read timed out"))?
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use crate::http::codec::h1_request_body::*;
    use qpx_http::body::Body;
    use tokio::io::{AsyncWriteExt, duplex};

    fn run_with_hard_timeout<T: Send + 'static>(
        hard: std::time::Duration,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(hard)
            .expect("parsing did not return within hard timeout (spin?)")
    }

    #[tokio::test]
    async fn chunked_request_reader_rejects_oversized_chunk_before_payload_allocation() {
        let (mut client, server) = duplex(1024);
        client
            .write_all(b"40000001\r\n")
            .await
            .expect("write chunk header");
        drop(client);
        let (read_half, write_half) = tokio::io::split(server);
        drop(write_half);
        let (sender, _body) = Body::channel();

        let err = forward_chunked_request_body(
            read_half,
            BytesMut::new(),
            sender,
            Duration::from_secs(1),
        )
        .await
        .expect_err("oversized chunk");
        assert!(
            err.to_string().contains("chunked request body exceeds"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn interrupted_chunk_reports_error_to_body_consumer() {
        let (sender, mut body) = Body::channel();
        let result = forward_chunked_request_body(
            tokio::io::empty(),
            BytesMut::from(&b"2\r\nx"[..]),
            sender,
            Duration::from_secs(1),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(body.data().await.unwrap().unwrap(), &b"x"[..]);
        assert!(matches!(body.data().await, Some(Err(_))));
    }

    #[tokio::test]
    async fn request_body_reader_times_out_idle_content_length() {
        let (mut client, server) = duplex(4096);
        client.write_all(b"abc").await.expect("write partial body");
        let (read_half, write_half) = tokio::io::split(server);
        drop(write_half);
        let (sender, _body) = Body::channel();

        let err = forward_content_length_request_body(
            read_half,
            BytesMut::new(),
            10,
            sender,
            Duration::from_millis(10),
        )
        .await
        .expect_err("idle body must time out");
        assert!(err.to_string().contains("request body read timed out"));
    }

    #[tokio::test]
    async fn content_length_request_body_rejects_eof_after_buffered_prefix() {
        let (sender, mut body) = Body::channel();

        let err = forward_content_length_request_body(
            tokio::io::empty(),
            BytesMut::from(&b"abc"[..]),
            4,
            sender,
            Duration::from_secs(1),
        )
        .await
        .expect_err("EOF before declared length must fail");
        assert_eq!(
            err.to_string(),
            "client request body closed before content-length completed"
        );
        assert_eq!(
            body.data()
                .await
                .expect("buffered prefix")
                .expect("body data"),
            &b"abc"[..]
        );
        assert!(body.data().await.is_none());
    }

    #[tokio::test]
    async fn content_length_request_body_preserves_buffered_pipelined_request() {
        let (sender, mut body) = Body::channel();
        let next_request = b"GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut read_buf = BytesMut::from(&b"BODY"[..]);
        read_buf.extend_from_slice(next_request);

        let (_, read_buf) = forward_content_length_request_body(
            tokio::io::empty(),
            read_buf,
            4,
            sender,
            Duration::from_secs(1),
        )
        .await
        .expect("complete buffered body");
        assert_eq!(read_buf.as_ref(), next_request);
        assert_eq!(
            body.data().await.expect("request body").expect("body data"),
            &b"BODY"[..]
        );
        assert!(body.data().await.is_none());
    }

    #[test]
    fn chunk_size_partial_line_times_out_instead_of_spinning() {
        run_with_hard_timeout(std::time::Duration::from_secs(2), || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async {
                let (mut client, server) = duplex(1024);
                client.write_all(b"4").await.expect("partial chunk-size");
                let (read_half, write_half) = tokio::io::split(server);
                drop(write_half);
                let (sender, _body) = Body::channel();
                let err = forward_chunked_request_body(
                    read_half,
                    BytesMut::new(),
                    sender,
                    Duration::from_millis(20),
                )
                .await
                .expect_err("partial chunk-size must time out");
                assert!(
                    err.to_string().contains("timed out"),
                    "unexpected error: {err}"
                );
                // Keep the peer open until the read times out so the server
                // side pends instead of seeing EOF.
                drop(client);
            })
        });
    }

    #[test]
    fn trailer_partial_headers_time_out_instead_of_spinning() {
        run_with_hard_timeout(std::time::Duration::from_secs(2), || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async {
                let (mut client, server) = duplex(4096);
                client
                    .write_all(b"0\r\nX-Test: partial")
                    .await
                    .expect("partial trailers");
                let (read_half, write_half) = tokio::io::split(server);
                drop(write_half);
                let (sender, _body) = Body::channel();
                let err = forward_chunked_request_body(
                    read_half,
                    BytesMut::new(),
                    sender,
                    Duration::from_millis(20),
                )
                .await
                .expect_err("partial trailers must time out");
                assert!(
                    err.to_string().contains("timed out"),
                    "unexpected error: {err}"
                );
                drop(client);
            })
        });
    }

    #[test]
    fn oversized_partial_line_fails_on_cap_instead_of_spinning() {
        run_with_hard_timeout(std::time::Duration::from_secs(2), || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async {
                let (client, server) = duplex(4096);
                let (mut read_half, write_half) = tokio::io::split(server);
                drop(write_half);
                let mut buf = BytesMut::new();
                buf.extend_from_slice(&vec![b'A'; super::super::h1_common::MAX_HEADER_BYTES + 1]);
                let err =
                    super::read_crlf_line(&mut read_half, &mut buf, Duration::from_millis(20))
                        .await
                        .expect_err("oversized partial line must fail on cap");
                assert!(
                    err.to_string().contains("exceeded"),
                    "unexpected error: {err}"
                );
                drop(client);
            })
        });
    }

    type BufferedResult = std::result::Result<(tokio::io::Empty, BytesMut), anyhow::Error>;

    /// Run the parser on a fully preloaded body with no transport reads.
    async fn forward_buffered(bytes: &'static [u8]) -> (BufferedResult, Body) {
        let (sender, body) = Body::channel();
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            forward_chunked_request_body(
                tokio::io::empty(),
                BytesMut::from(bytes),
                sender,
                Duration::from_millis(50),
            ),
        )
        .await
        .expect("buffered chunked parse did not finish within test timeout");
        (result, body)
    }

    #[tokio::test]
    async fn chunked_rejects_unterminated_quoted_chunk_extension() {
        let (result, mut body) =
            forward_buffered(b"0;x=\"\r\n\r\nGET /next HTTP/1.1\r\nHost: example.test\r\n\r\n")
                .await;

        let err = result.expect_err("unterminated quoted extension must be rejected");
        assert!(err.to_string().contains("invalid chunk-size line"), "{err}");
        assert!(
            matches!(body.data().await, Some(Err(_))),
            "the body must not complete successfully"
        );
    }

    #[tokio::test]
    async fn chunked_rejects_backslash_before_unterminated_quote() {
        let (result, mut body) = forward_buffered(b"0;x=\\\"\r\n\r\n").await;

        let err = result.expect_err("backslash outside quoted string must not hide the quote");
        assert!(err.to_string().contains("invalid chunk-size line"), "{err}");
        assert!(matches!(body.data().await, Some(Err(_))));
    }

    #[tokio::test]
    async fn chunked_accepts_balanced_quoted_chunk_extension() {
        let (result, mut body) = forward_buffered(b"0;x=\"ok\"\r\n\r\n").await;

        result.expect("balanced quoted extension");
        assert!(body.trailers().await.expect("trailers").is_none());
        assert!(body.data().await.is_none());
    }

    #[tokio::test]
    async fn chunked_rejects_non_hexdig_chunk_sizes() {
        for bytes in [
            &b"+1\r\nA\r\n0\r\n\r\n"[..],
            &b" 1\r\nA\r\n0\r\n\r\n"[..],
            &b"1 \r\nA\r\n0\r\n\r\n"[..],
            &b"\r\n\r\n"[..],
        ] {
            let (result, mut body) = forward_buffered(bytes).await;

            let err = result.expect_err("non-HEXDIG chunk size must be rejected");
            assert!(err.to_string().contains("invalid chunk-size"), "{err}");
            assert!(matches!(body.data().await, Some(Err(_))));
        }
    }

    #[tokio::test]
    async fn chunked_accepts_uppercase_and_leading_zero_chunk_sizes() {
        let (result, mut body) =
            forward_buffered(b"0002\r\nAB\r\nA\r\n0123456789\r\n0\r\n\r\n").await;

        let (_, leftover) = result.expect("valid HEXDIG chunk sizes");
        assert!(leftover.is_empty());
        assert_eq!(
            body.data().await.expect("first chunk").expect("data"),
            &b"AB"[..]
        );
        assert_eq!(
            body.data().await.expect("second chunk").expect("data"),
            &b"0123456789"[..]
        );
        assert!(body.data().await.is_none());
    }

    #[tokio::test]
    async fn chunked_rejects_bare_lf_in_chunk_size_line() {
        let (result, mut body) = forward_buffered(b"0;x=\"a\nb\"\r\n\r\n").await;

        let err = result.expect_err("bare LF in chunk-size line must be rejected");
        assert!(err.to_string().contains("invalid chunk-size line"), "{err}");
        assert!(matches!(body.data().await, Some(Err(_))));
    }

    #[tokio::test]
    async fn chunked_accepts_plain_and_extended_chunk_size_lines() {
        let (result, mut body) = forward_buffered(
            b"2\r\nAB\r\n2;name=value\r\nCD\r\n2;name=\"value with spaces\"\r\nEF\r\n0\r\n\r\n",
        )
        .await;

        let (_, leftover) = result.expect("valid chunk-size lines");
        assert!(leftover.is_empty());
        for expected in [&b"AB"[..], &b"CD"[..], &b"EF"[..]] {
            assert_eq!(
                body.data().await.expect("chunk data").expect("body data"),
                expected
            );
        }
        assert!(body.data().await.is_none());
    }

    #[tokio::test]
    async fn chunked_rejects_bare_lf_in_trailers() {
        let (result, mut body) = forward_buffered(b"0\r\nX: y\n\r\n").await;

        let err = result.expect_err("bare LF trailer must be rejected");
        let message = err.to_string();
        assert!(message.contains("bare LF"), "{message}");
        assert!(
            message.contains("invalid HTTP/1 request trailers"),
            "{message}"
        );
        assert!(matches!(body.data().await, Some(Err(_))));
    }

    #[tokio::test]
    async fn chunked_accepts_crlf_trailers() {
        let (result, mut body) = forward_buffered(b"0\r\nX: y\r\n\r\n").await;

        let (_, leftover) = result.expect("CRLF trailers");
        assert!(leftover.is_empty());
        let trailers = body
            .trailers()
            .await
            .expect("trailers")
            .expect("trailer block");
        assert_eq!(trailers["x"], "y");
    }

    #[tokio::test]
    async fn chunked_checks_only_the_consumed_trailer_block_for_bare_lf() {
        let next_request = &b"GET /next HTTP/1.1\r\nHost: example.test\n\r\n"[..];
        let (result, mut body) =
            forward_buffered(b"0\r\nX: y\r\n\r\nGET /next HTTP/1.1\r\nHost: example.test\n\r\n")
                .await;

        let (_, leftover) = result.expect("bare LF in the next request is not trailers");
        assert_eq!(leftover.as_ref(), next_request);
        let trailers = body
            .trailers()
            .await
            .expect("trailers")
            .expect("trailer block");
        assert_eq!(trailers["x"], "y");
    }
}
