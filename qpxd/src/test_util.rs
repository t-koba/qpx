use std::io::Read;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub(crate) fn decode_gzip(bytes: &[u8]) -> String {
    let mut decoder = flate2::read::GzDecoder::new(bytes);
    let mut out = String::new();
    decoder.read_to_string(&mut out).expect("decode gzip");
    out
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
        let mut completed_requests = 0;
        while completed_requests < accepts {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.expect("read request");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            // TCP health probes close without sending an HTTP request. They
            // must not consume the finite application-request allowance.
            if raw.is_empty() {
                continue;
            }
            assert!(
                raw.windows(4).any(|window| window == b"\r\n\r\n"),
                "static HTTP server received an incomplete request head"
            );
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
            completed_requests += 1;
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
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
        })
        .unwrap_or(0);
    let mut received_body = raw.len().saturating_sub(header_end);
    while received_body < content_length {
        let n = stream.read(buf).await.expect("read request body");
        if n == 0 {
            break;
        }
        received_body = received_body.saturating_add(n);
    }
}

#[tokio::test]
async fn static_http_server_preserves_request_allowance_after_tcp_health_probe() {
    let addr = spawn_static_http_server("200 OK", Vec::new(), "real body".into(), 1).await;
    let probe = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect health probe");
    drop(probe);
    let mut client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect HTTP client");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("send real request");
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await
    .expect("response before deadline")
    .expect("read real response");
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(b"real body"));
}
