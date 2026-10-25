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
            if let Err(err) = read_request_head(&mut stream).await {
                eprintln!("backend {port}: request head failed: {err}");
                continue;
            }
            eprintln!("backend {port}: serving chunked response");
            match serve_slow_chunked_response(
                &mut stream,
                &chunks,
                &response_headers,
                trailers.as_deref(),
            )
            .await
            {
                Ok(()) => {
                    eprintln!("backend {port}: chunked response complete");
                    closed_for_task.store(true, Ordering::SeqCst);
                    return;
                }
                Err(err) => eprintln!("backend {port}: chunked response failed: {err}"),
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

async fn read_request_head(stream: &mut tokio::net::TcpStream) -> std::io::Result<()> {
    const MAX_REQUEST_HEAD_BYTES: usize = 64 * 1024;
    let mut request = Vec::with_capacity(1024);
    while request.len() < MAX_REQUEST_HEAD_BYTES {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "request closed before the header terminator",
            ));
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(());
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "request header exceeded the test server limit",
    ))
}

pub async fn spawn_delayed_headers_backend(
    header_delay: Duration,
    response_headers: Vec<(&'static str, &'static str)>,
) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        for _ in 0..8 {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            if read_request_head(&mut stream).await.is_err() {
                continue;
            }
            sleep(header_delay).await;
            let mut head = String::from("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n");
            for (name, value) in &response_headers {
                head.push_str(name);
                head.push_str(": ");
                head.push_str(value);
                head.push_str("\r\n");
            }
            head.push_str("\r\n");
            if stream.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
            return;
        }
    });
    (port, task)
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
            if read_request_head(&mut stream).await.is_err() {
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

// The close is a test event, not a timer: an H3 RESET_STREAM may overtake
// queued HEADERS/DATA unless the client has already observed the partial body.
pub async fn spawn_abort_after_partial_backend(
    response_line: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    partial_body: &'static [u8],
) -> (
    u16,
    JoinHandle<std::io::Result<()>>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (abort, observed_partial) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut request_stream = None;
        for _ in 0..8 {
            let (mut stream, _) = listener.accept().await?;
            match read_request_head(&mut stream).await {
                Ok(()) => {
                    request_stream = Some(stream);
                    break;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    eprintln!("backend {port}: skipped empty probe connection: {err}");
                }
                Err(err) => return Err(err),
            }
        }
        let Some(mut stream) = request_stream else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "no request head received after 8 connections",
            ));
        };

        let mut head = format!("{response_line}\r\n");
        for (name, value) in &headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(partial_body).await?;
        stream.flush().await?;
        eprintln!(
            "backend {port}: partial response written; waiting for client DATA acknowledgement"
        );
        tokio::time::timeout(Duration::from_secs(30), observed_partial)
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "client did not acknowledge partial DATA",
                )
            })?
            .map_err(|_| std::io::Error::other("client dropped partial DATA acknowledgement"))?;
        eprintln!(
            "backend {port}: client observed partial DATA; closing short Content-Length response"
        );
        Ok(())
    });
    (port, task, abort)
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
