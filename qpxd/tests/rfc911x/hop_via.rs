use super::*;
use anyhow::anyhow;

pub(crate) async fn hop_by_hop_and_via_contract(forward_port: u16) -> Result<()> {
    let backend_response = b"HTTP/1.1 200 OK\r\n\
Connection: x-drop\r\n\
X-Drop: 1\r\n\
Keep-Alive: timeout=5\r\n\
Proxy-Authenticate: Basic realm=\"upstream\"\r\n\
Content-Length: 2\r\n\
\r\n\
OK"
    .to_vec();

    let (backend_addr, captured_rx) = serve_http1_capture_once(backend_response).await?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;
    let req = format!(
        "GET http://{}/hop HTTP/1.1\r\n\
Host: {}\r\n\
Connection: keep-alive, x-remove\r\n\
Keep-Alive: timeout=5\r\n\
TE: trailers\r\n\
Proxy-Authorization: Basic abc\r\n\
X-Remove: 1\r\n\
Via: 1.0 old-proxy\r\n\
\r\n",
        backend_addr, backend_addr
    );
    let (status, resp_headers, _rest) =
        send_http1_and_read_head(proxy_addr, req.as_bytes()).await?;
    if status != 200 {
        return Err(anyhow!("expected 200 from proxy, got {status}"));
    }

    // Response: hop-by-hop stripped + Via/Date added.
    assert_header_absent(&resp_headers, "connection");
    assert_header_absent(&resp_headers, "keep-alive");
    assert_header_absent(&resp_headers, "proxy-authenticate");
    assert_header_absent(&resp_headers, "x-drop");
    assert_header_present_contains(&resp_headers, "via", "1.1 qpx");
    assert_header_present(&resp_headers, "date");

    // Request forwarded upstream: hop-by-hop stripped + Via appended, Proxy-Authorization stripped.
    let captured_bytes = timeout(Duration::from_secs(5), captured_rx)
        .await
        .context("timed out waiting for backend request capture")??;
    let captured = String::from_utf8_lossy(&captured_bytes).to_ascii_lowercase();
    assert!(
        !captured.contains("\r\nconnection:"),
        "upstream request contained connection header:\n{captured}"
    );
    assert!(
        !captured.contains("\r\nkeep-alive:"),
        "upstream request contained keep-alive:\n{captured}"
    );
    assert!(
        !captured.contains("\r\nte:"),
        "upstream request contained te:\n{captured}"
    );
    assert!(
        !captured.contains("\r\nproxy-authorization:"),
        "upstream request leaked proxy-authorization:\n{captured}"
    );
    assert!(
        !captured.contains("\r\nx-remove:"),
        "upstream request contained Connection-nominated header:\n{captured}"
    );
    assert!(
        captured.contains("\r\nvia:"),
        "upstream request missing via:\n{captured}"
    );
    assert!(
        captured.contains("1.1 qpx"),
        "upstream request via missing version token:\n{captured}"
    );
    assert!(
        captured.contains("1.0 old-proxy"),
        "upstream request via did not preserve existing entry:\n{captured}"
    );

    Ok(())
}
