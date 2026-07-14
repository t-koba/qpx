use super::*;

pub(crate) async fn http11_validation_cases(forward_port: u16) -> Result<()> {
    let addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;
    let backend_port = 9_999; // unused; requests are rejected before any upstream I/O.

    // Missing Host (RFC 9112: MUST send Host for HTTP/1.1).
    assert_status(
        addr,
        format!("GET http://127.0.0.1:{backend_port}/ HTTP/1.1\r\n\r\n"),
        400,
    )
    .await?;

    // Multiple Host header fields.
    assert_status(
        addr,
        format!(
            "GET http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nHost: 127.0.0.1:{backend_port}\r\n\r\n"
        ),
        400,
    )
    .await?;

    // Host header with userinfo is invalid.
    assert_status(
        addr,
        format!(
            "GET http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: user@127.0.0.1:{backend_port}\r\n\r\n"
        ),
        400,
    )
    .await?;

    // Host/authority mismatch is rejected.
    assert_status(
        addr,
        format!("GET http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: other.invalid\r\n\r\n"),
        400,
    )
    .await?;

    // Transfer-Encoding + Content-Length is rejected.
    assert_status(
        addr,
        format!(
            "POST http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
        ),
        400,
    )
    .await?;

    // Conflicting multiple Content-Length values are rejected.
    assert_status(
        addr,
        format!(
            "POST http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n"
        ),
        400,
    )
    .await?;

    // Unsupported Expect is rejected with 417.
    assert_status(
        addr,
        format!(
            "POST http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nExpect: totally-not-100-continue\r\nContent-Length: 0\r\n\r\n"
        ),
        417,
    )
    .await?;

    // CONNECT must be authority-form; absolute-form CONNECT is rejected.
    assert_status(
        addr,
        format!(
            "CONNECT http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\n\r\n"
        ),
        400,
    )
    .await?;

    // "*" request-target is only valid for OPTIONS; reject GET *.
    assert_status(
        addr,
        "GET * HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string(),
        400,
    )
    .await?;

    // origin-form must start with "/" (unless "*").
    assert_status(
        addr,
        "GET relative HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string(),
        400,
    )
    .await?;

    Ok(())
}
