use bytes::Bytes;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};

pub async fn spawn_slow_chunked_backend(
    chunks: Vec<(Bytes, Duration)>,
    response_headers: Vec<(&'static str, &'static str)>,
    trailers: Option<Vec<(&'static str, &'static str)>>,
) -> (u16, JoinHandle<()>, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let closed = Arc::new(AtomicBool::new(false));
    let closed_for_task = closed.clone();
    let task = tokio::spawn(async move {
        for _ in 0..8 {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            if read_request(&mut stream).await.is_err() {
                continue;
            }
            if serve_slow_chunked_response(
                &mut stream,
                &chunks,
                &response_headers,
                trailers.as_deref(),
            )
            .await
            .is_ok()
            {
                closed_for_task.store(true, Ordering::SeqCst);
                return;
            }
        }
    });
    (port, task, closed)
}

async fn serve_slow_chunked_response(
    stream: &mut tokio::net::TcpStream,
    chunks: &[(Bytes, Duration)],
    response_headers: &[(&'static str, &'static str)],
    trailers: Option<&[(&'static str, &'static str)]>,
) -> std::io::Result<()> {
    let mut head = String::from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n");
    for (name, value) in response_headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    if let Some(trailers) = trailers
        && !trailers.is_empty()
    {
        head.push_str("Trailer: ");
        for (idx, (name, _)) in trailers.iter().enumerate() {
            if idx > 0 {
                head.push_str(", ");
            }
            head.push_str(name);
        }
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    for (chunk, delay) in chunks {
        sleep(*delay).await;
        stream
            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
            .await?;
        stream.write_all(chunk).await?;
        stream.write_all(b"\r\n").await?;
    }
    stream.write_all(b"0\r\n").await?;
    if let Some(trailers) = trailers {
        for (name, value) in trailers {
            stream
                .write_all(format!("{name}: {value}\r\n").as_bytes())
                .await?;
        }
    }
    stream.write_all(b"\r\n").await?;
    stream.flush().await?;
    if trailers.is_some() {
        sleep(Duration::from_millis(10)).await;
    }
    stream.shutdown().await
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> std::io::Result<()> {
    const MAX_REQUEST_BYTES: usize = 64 * 1024;
    let mut request = Vec::with_capacity(1024);
    // Closing with unread request bytes can reset the TCP connection and
    // truncate an otherwise complete streaming response on Linux.
    while request.len() < MAX_REQUEST_BYTES {
        let mut chunk = [0_u8; 1024];
        let available = chunk.len().min(MAX_REQUEST_BYTES - request.len());
        let read = stream.read(&mut chunk[..available]).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "request closed before message completion",
            ));
        }
        request.extend_from_slice(&chunk[..read]);
        if request_message_complete(&request)? {
            return Ok(());
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "request message exceeded the test server limit",
    ))
}

fn request_message_complete(bytes: &[u8]) -> std::io::Result<bool> {
    let invalid = |message| std::io::Error::new(std::io::ErrorKind::InvalidData, message);
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut headers);
    let httparse::Status::Complete(head_len) = request
        .parse(bytes)
        .map_err(|error| invalid(format!("invalid request headers: {error}")))?
    else {
        return Ok(false);
    };
    let mut content_length = None;
    let mut chunked = false;
    for header in request.headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !header.value.trim_ascii().eq_ignore_ascii_case(b"chunked") {
                return Err(invalid("unsupported request transfer encoding".to_string()));
            }
            chunked = true;
        } else if header.name.eq_ignore_ascii_case("content-length") {
            let value = std::str::from_utf8(header.value.trim_ascii())
                .map_err(|_| invalid("invalid request content length".to_string()))?
                .parse::<usize>()
                .map_err(|_| invalid("invalid request content length".to_string()))?;
            if content_length.is_some_and(|previous| previous != value) {
                return Err(invalid("conflicting request content lengths".to_string()));
            }
            content_length = Some(value);
        }
    }
    if !chunked {
        return Ok(bytes.len() - head_len >= content_length.unwrap_or(0));
    }
    if content_length.is_some() {
        return Err(invalid("ambiguous request body framing".to_string()));
    }
    let mut cursor = head_len;
    loop {
        let httparse::Status::Complete((prefix_len, size)) =
            httparse::parse_chunk_size(&bytes[cursor..])
                .map_err(|error| invalid(format!("invalid request chunk size: {error}")))?
        else {
            return Ok(false);
        };
        cursor += prefix_len;
        if size == 0 {
            let mut trailers = [httparse::EMPTY_HEADER; 128];
            return httparse::parse_headers(&bytes[cursor..], &mut trailers)
                .map(|status| status.is_complete())
                .map_err(|error| invalid(format!("invalid request trailers: {error}")));
        }
        let end = usize::try_from(size)
            .ok()
            .and_then(|size| cursor.checked_add(size))
            .and_then(|end| end.checked_add(2))
            .ok_or_else(|| invalid("request chunk length overflow".to_string()))?;
        if end > bytes.len() {
            return Ok(false);
        }
        if &bytes[end - 2..end] != b"\r\n" {
            return Err(invalid("invalid request chunk terminator".to_string()));
        }
        cursor = end;
    }
}

pub async fn spawn_infinite_stream_backend(
    chunk: Bytes,
    interval: Duration,
) -> (u16, JoinHandle<()>, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let closed = Arc::new(AtomicBool::new(false));
    let closed_for_task = closed.clone();
    let task = tokio::spawn(async move {
        for _ in 0..8 {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            if read_request(&mut stream).await.is_err() {
                continue;
            }
            if stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .is_err()
            {
                continue;
            }
            loop {
                sleep(interval).await;
                let frame = format!("{:x}\r\n", chunk.len());
                if stream.write_all(frame.as_bytes()).await.is_err()
                    || stream.write_all(&chunk).await.is_err()
                    || stream.write_all(b"\r\n").await.is_err()
                {
                    closed_for_task.store(true, Ordering::SeqCst);
                    return;
                }
            }
        }
    });
    (port, task, closed)
}

pub async fn spawn_abort_after_partial_backend(
    response_line: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    partial_body: &'static [u8],
    delay_before_abort: Duration,
) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        for _ in 0..8 {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            if read_request(&mut stream).await.is_err() {
                continue;
            }
            let mut head = format!("{response_line}\r\n");
            for (name, value) in &headers {
                head.push_str(name);
                head.push_str(": ");
                head.push_str(value);
                head.push_str("\r\n");
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(partial_body).await;
            sleep(delay_before_abort).await;
            return;
        }
    });
    (port, task)
}

pub async fn spawn_grpc_backend(
    frames: Vec<Bytes>,
    trailers: Vec<(&'static str, &'static str)>,
    content_type: &'static str,
    chunk_split_points: Vec<usize>,
) -> (u16, JoinHandle<()>) {
    let body = Bytes::from(frames.concat());
    let mut chunks = Vec::new();
    let mut offset = 0usize;
    for split in chunk_split_points {
        let end = split.min(body.len());
        if end > offset {
            chunks.push(body.slice(offset..end));
            offset = end;
        }
    }
    if offset < body.len() {
        chunks.push(body.slice(offset..));
    }
    let (port, task, _closed) = spawn_slow_chunked_backend(
        chunks
            .into_iter()
            .map(|chunk| (chunk, Duration::ZERO))
            .collect(),
        vec![("content-type", content_type)],
        Some(trailers),
    )
    .await;
    (port, task)
}

pub fn build_grpc_frame(payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Bytes::from(out)
}

pub fn build_grpc_web_trailer_frame(trailers: &[(&str, &str)]) -> Bytes {
    let mut block = Vec::new();
    for (name, value) in trailers {
        block.extend_from_slice(name.as_bytes());
        block.extend_from_slice(b": ");
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(b"\r\n");
    }
    let mut out = Vec::with_capacity(5 + block.len());
    out.push(0x80);
    out.extend_from_slice(&(block.len() as u32).to_be_bytes());
    out.extend_from_slice(&block);
    Bytes::from(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    async fn assert_request_completion(head: &[u8], partial: &[u8], remainder: &[u8]) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind real request server");
        let address = listener.local_addr().expect("request server address");
        let mut reader = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request connection");
            read_request(&mut stream).await
        });
        let mut client = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect request client");
        client.write_all(head).await.expect("write request headers");
        client
            .write_all(partial)
            .await
            .expect("write partial request body");
        assert!(
            timeout(Duration::from_millis(100), &mut reader)
                .await
                .is_err(),
            "request server must consume the complete request body before closing"
        );
        client
            .write_all(remainder)
            .await
            .expect("finish request body");
        timeout(Duration::from_secs(1), reader)
            .await
            .expect("request completion deadline")
            .expect("request reader task")
            .expect("complete request body");
    }

    #[tokio::test]
    async fn chunked_request_terminator_is_consumed_before_response_completion() {
        assert_request_completion(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"0\r\n",
            b"\r\n",
        )
        .await;
    }

    #[tokio::test]
    async fn fixed_request_body_is_consumed_before_response_completion() {
        assert_request_completion(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\n",
            b"xy",
            b"z",
        )
        .await;
    }

    #[tokio::test]
    async fn chunked_request_payload_and_trailers_are_consumed() {
        assert_request_completion(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"2\r\nxy\r\n0\r\nX-Test: complete\r\n",
            b"\r\n",
        )
        .await;
    }

    #[tokio::test]
    async fn truncated_request_body_reports_unexpected_eof() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind request server");
        let address = listener.local_addr().expect("request server address");
        let reader = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request connection");
            read_request(&mut stream).await
        });
        let mut client = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect request client");
        client
            .write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nxy")
            .await
            .expect("write truncated request");
        client.shutdown().await.expect("close request write half");
        let error = timeout(Duration::from_secs(1), reader)
            .await
            .expect("request read deadline")
            .expect("request reader task")
            .expect_err("reject incomplete request body");
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
