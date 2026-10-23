use std::io::Read;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub(crate) fn decode_gzip(bytes: &[u8]) -> String {
    let mut decoder = flate2::read::GzDecoder::new(bytes);
    let mut out = String::new();
    decoder.read_to_string(&mut out).expect("decode gzip");
    out
}

/// Read one HTTP request head until `CRLFCRLF`, preserving over-read bytes.
///
/// Test-only exact clone of the inline loops previously scattered across
/// `qpxd` test servers: unbounded `read`, break on EOF (`n == 0`), extend
/// `raw`, break once `raw` contains `CRLFCRLF`. No timeout, same 1024-byte
/// caller buffer, same `expect("read request")` semantics.
pub(crate) async fn read_request_head<S>(stream: &mut S, raw: &mut Vec<u8>, buf: &mut [u8; 1024])
where
    S: AsyncRead + Unpin,
{
    loop {
        let n = stream.read(buf).await.expect("read request");
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
}

pub(crate) async fn spawn_static_http_server(
    status_line: &'static str,
    headers: Vec<(&'static str, String)>,
    body: String,
    accepts: usize,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind static http server");
    let addr = listener.local_addr().expect("server addr");
    tokio::spawn(async move {
        for _ in 0..accepts {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            read_request_head(&mut stream, &mut raw, &mut buf).await;
            drain_declared_request_body(&mut stream, raw.as_slice(), &mut buf).await;
            let mut response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (name, value) in &headers {
                response.push_str(name);
                response.push_str(": ");
                response.push_str(value);
                response.push_str("\r\n");
            }
            response.push_str("\r\n");
            response.push_str(body.as_str());
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        }
    });
    addr
}

#[cfg(feature = "mitm")]
pub(crate) async fn spawn_http1_send_request(
    body: &str,
) -> std::sync::Arc<tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<qpx_http::body::Body>>>
{
    let addr = spawn_static_http_server(
        "200 OK",
        vec![("Content-Type", "text/plain".to_string())],
        body.to_string(),
        1,
    )
    .await;
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (sender, connection) = qpx_http::protocol::common::handshake_http1(stream)
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    std::sync::Arc::new(tokio::sync::Mutex::new(sender))
}

/// The body length a raw request head declares.
///
/// The head is raw text rather than a header map, so its header lines are
/// handed to the owner, which finds the field's own values and owns the
/// member grammar and the conflict rule. A head that declares no length,
/// or one the owner refuses, declares no length here.
pub(crate) fn declared_content_length(head: &str) -> usize {
    let lines = head.lines().filter_map(|line| line.split_once(':'));
    qpx_core::http_content_length::declared_content_length_in_named_values(lines)
        .ok()
        .flatten()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
}

async fn drain_declared_request_body(
    stream: &mut tokio::net::TcpStream,
    raw: &[u8],
    buf: &mut [u8; 1024],
) {
    let Some(header_end) = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
    else {
        return;
    };
    let headers = String::from_utf8_lossy(&raw[..header_end]);
    let content_length = declared_content_length(&headers);
    let mut received_body = raw.len().saturating_sub(header_end);
    while received_body < content_length {
        let n = stream.read(buf).await.expect("read request body");
        if n == 0 {
            break;
        }
        received_body = received_body.saturating_add(n);
    }
}

/// Echo one synthetic request head so dispatch tests can inspect the outgoing wire.
pub(crate) async fn spawn_request_head_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), async move {
            let (mut stream, _) = listener.accept().await.expect("echo accept");
            let mut raw = Vec::new();
            let mut buf = [0; 1024];
            while !raw.windows(4).any(|window| window == b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.expect("echo read");
                assert!(n > 0 && raw.len() + n <= 8192, "bounded request head");
                raw.extend_from_slice(&buf[..n]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                raw.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("echo head");
            stream.write_all(&raw).await.expect("echo body");
        })
        .await
        .expect("echo timeout");
    });
    addr
}
