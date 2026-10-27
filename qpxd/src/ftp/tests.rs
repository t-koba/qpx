use super::control::{
    FtpDeadline, active_data_peer_allowed, read_ftp_control_line, validate_pasv_data_endpoint,
};
use super::get_put::{read_to_end_limited, stream_ftp_upload_body};
use super::transfer::normalize_ftp_listing_body;
use super::{
    MAX_FTP_CONTROL_LINE, MAX_FTP_DEADLINE, OperationTimedOut, RequestBodyTooLarge,
    ResponseBodyTooLarge, handle_ftp,
};
use hyper::{Method, Request, StatusCode};
use qpx_core::config::FtpConfig;
use qpx_core::http_message::Request as OwnerRequest;
use qpx_http::body::Body;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[test]
fn read_to_end_limited_accepts_within_limit() {
    let mut cursor = Cursor::new(vec![1_u8, 2, 3, 4]);
    let out = read_to_end_limited(&mut cursor, 4).expect("read");
    assert_eq!(out, vec![1_u8, 2, 3, 4]);
}

#[test]
fn read_to_end_limited_rejects_over_limit() {
    let mut cursor = Cursor::new(vec![1_u8, 2, 3, 4, 5]);
    let err = read_to_end_limited(&mut cursor, 4).expect_err("must fail");
    assert!(err.downcast_ref::<ResponseBodyTooLarge>().is_some());
}

#[test]
fn list_reader_rejects_over_limit_before_normalizing() {
    let mut cursor = Cursor::new(b"123\r\n45\r\n".to_vec());
    let err = read_to_end_limited(&mut cursor, 5).expect_err("must fail");
    assert!(err.downcast_ref::<ResponseBodyTooLarge>().is_some());
}

#[test]
fn normalize_ftp_listing_body_preserves_line_boundaries() {
    let out = normalize_ftp_listing_body(b"one\r\n\r\ntwo\n".to_vec());
    assert_eq!(out, b"one\ntwo");
}

#[test]
fn pasv_endpoint_must_match_control_peer() {
    let peer = "203.0.113.10".parse().unwrap();
    let same = SocketAddr::new(peer, 49152);
    validate_pasv_data_endpoint(peer, same).expect("same peer");

    let redirected = SocketAddr::new("127.0.0.1".parse().unwrap(), 22);
    let err = validate_pasv_data_endpoint(peer, redirected).expect_err("redirect must fail");
    assert!(err.to_string().contains("refusing FTP PASV data endpoint"));
}

#[test]
fn active_data_peer_must_match_control_peer() {
    let peer = "203.0.113.10".parse().unwrap();
    assert!(active_data_peer_allowed(peer, peer));
    assert!(!active_data_peer_allowed(
        peer,
        "198.51.100.20".parse().unwrap()
    ));
}

#[tokio::test]
async fn ftp_control_line_rejects_before_unbounded_allocation() {
    let (mut writer, reader) = tokio::io::duplex(MAX_FTP_CONTROL_LINE + 1);
    tokio::spawn(async move {
        writer
            .write_all(&vec![b'x'; MAX_FTP_CONTROL_LINE + 1])
            .await
            .unwrap();
    });
    let mut reader = BufReader::new(reader);
    let err = read_ftp_control_line(&mut reader, FtpDeadline::new(StdDuration::from_secs(1)))
        .await
        .expect_err("oversized control line must fail");
    assert!(err.to_string().contains("FTP control line exceeded"));
}

#[test]
fn ftp_deadline_clamps_oversized_duration_before_instant_add() {
    let deadline = FtpDeadline::new(StdDuration::MAX);
    let remaining = deadline.remaining().expect("remaining deadline");
    assert!(remaining <= MAX_FTP_DEADLINE);
}

#[tokio::test]
async fn stream_ftp_upload_body_rejects_over_limit() {
    let body = Body::from("12345");
    let err = stream_ftp_upload_body(body, 4, StdDuration::from_secs(1))
        .await
        .expect_err("must fail");
    assert!(err.downcast_ref::<RequestBodyTooLarge>().is_some());
}

#[tokio::test]
async fn stream_ftp_upload_body_times_out_idle_body() {
    let (_sender, body) = Body::channel();
    let err = stream_ftp_upload_body(body, 4, StdDuration::from_millis(10))
        .await
        .expect_err("idle body must time out");
    assert!(err.downcast_ref::<OperationTimedOut>().is_some());
}

#[tokio::test]
async fn unsupported_method_does_not_wait_for_request_body() {
    let (_sender, body) = Body::channel();
    let req = OwnerRequest::from_http(
        Request::builder()
            .method(Method::PATCH)
            .uri("ftp://example.com/file.txt")
            .body(body)
            .expect("request"),
    );
    let response = timeout(
        StdDuration::from_millis(50),
        handle_ftp(
            req,
            super::FtpCredentials::default(),
            FtpConfig {
                enabled: true,
                timeout_ms: 1_000,
                max_download_bytes: 1024,
                max_request_body_bytes: 1024,
            },
            Arc::<str>::from("unsupported"),
            Arc::new(Semaphore::new(1)),
        ),
    )
    .await
    .expect("unsupported method should not block on body")
    .expect("response");

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[test]
fn ftp_ingress_strips_userinfo_before_generic_preflight_and_metadata() {
    let mut req = OwnerRequest::from_http(
        Request::builder()
            .uri("ftp://synthetic%2Duser:synthetic%2Dpass@[::1]:2121/file?ok=1")
            .header("host", "[::1]:2121")
            .body(())
            .unwrap(),
    );
    let credentials = super::extract_forward_credentials(&mut req).unwrap();
    assert_eq!(credentials.user, "synthetic-user");
    assert_eq!(credentials.pass, "synthetic-pass");
    assert_eq!(format!("{credentials:?}"), "FtpCredentials(<redacted>)");
    assert_eq!(req.uri().to_string(), "ftp://[::1]:2121/file?ok=1");
    let validated =
        qpx_http::protocol::semantics::validate_incoming_request_with_metadata(&req).unwrap();
    let base = crate::http::protocol::base_fields::extract_base_request_fields(
        &req,
        crate::http::protocol::base_fields::BaseRequestContext {
            validated_request: Some(validated),
            ..Default::default()
        },
    );
    assert_eq!(base.host(), Some("[::1]"));
    assert_eq!(base.request_uri(), "ftp://[::1]:2121/file?ok=1");
    for invalid_userinfo in ["synthetic\\user:pass", "synthetic[user:pass"] {
        assert!(
            Request::builder()
                .uri(format!("ftp://{invalid_userinfo}@host/file"))
                .body(())
                .is_err()
        );
    }
    for scheme in ["http", "https"] {
        let mut req = OwnerRequest::from_http(
            Request::builder()
                .uri(format!("{scheme}://synthetic-user@host/file"))
                .header("host", "host")
                .body(())
                .unwrap(),
        );
        super::extract_forward_credentials(&mut req).unwrap();
        assert!(
            qpx_http::protocol::semantics::validate_incoming_request_with_metadata(&req).is_err()
        );
    }
    // Generic (non-forward) validation still rejects FTP userinfo.
    let req = OwnerRequest::from_http(
        Request::builder()
            .uri("ftp://synthetic-user@host/file")
            .header("host", "host")
            .body(())
            .unwrap(),
    );
    assert!(qpx_http::protocol::semantics::validate_incoming_request_with_metadata(&req).is_err());
    for value in [
        "synthetic-user:%0d%0aNOOP",
        "synthetic-user:%ff",
        "synthetic%00user:pass",
        "synthetic%ZZ:pass",
        "synthetic@user:pass",
    ] {
        let mut req = OwnerRequest::from_http(
            Request::builder()
                .uri(format!("ftp://{value}@host/file"))
                .body(())
                .unwrap(),
        );
        let error = super::extract_forward_credentials(&mut req).unwrap_err();
        assert_eq!(error.to_string(), "invalid FTP credentials");
        assert!(!format!("{error:?}").contains("synthetic"));
    }
}

fn ftp_forward_test_runtime() -> crate::runtime::Runtime {
    let config = serde_yaml::from_str(
        r#"
state_dir: null
edges:
- kind: forward
  name: ftp-test
  listen: 127.0.0.1:0
  default_action: {type: direct}
  ftp: {enabled: true}
"#,
    )
    .unwrap();
    crate::runtime::Runtime::new(config).unwrap()
}

#[tokio::test]
async fn forward_ftp_uri_credentials_authenticate_after_ingress_stripping() {
    use tokio::io::AsyncBufReadExt;
    use tokio::net::TcpListener;
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = control.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = control.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        stream
            .get_mut()
            .write_all(b"220 synthetic FTP server\r\n")
            .await
            .unwrap();
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        assert_eq!(line, "USER synthetic-user\r\n");
        stream
            .get_mut()
            .write_all(b"331 password required\r\n")
            .await
            .unwrap();
        line.clear();
        stream.read_line(&mut line).await.unwrap();
        assert_eq!(line, "PASS synthetic-pass\r\n");
        stream
            .get_mut()
            .write_all(b"230 logged in\r\n")
            .await
            .unwrap();
        line.clear();
        stream.read_line(&mut line).await.unwrap();
        assert_eq!(line, "EPSV\r\n");
        let data = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reply = format!(
            "229 Entering Extended Passive Mode (|||{}|)\r\n",
            data.local_addr().unwrap().port()
        );
        stream.get_mut().write_all(reply.as_bytes()).await.unwrap();
        let (mut data, _) = data.accept().await.unwrap();
        line.clear();
        stream.read_line(&mut line).await.unwrap();
        assert_eq!(line, "RETR file.txt\r\n");
        stream
            .get_mut()
            .write_all(b"150 data follows\r\n")
            .await
            .unwrap();
        data.write_all(b"synthetic file contents").await.unwrap();
        data.shutdown().await.unwrap();
        stream
            .get_mut()
            .write_all(b"226 complete\r\n")
            .await
            .unwrap();
    });
    let runtime = ftp_forward_test_runtime();
    let req = OwnerRequest::from_http(
        Request::builder()
            .uri(format!(
                "ftp://synthetic%2Duser:synthetic%2Dpass@{addr}/file.txt"
            ))
            .header("host", addr.to_string())
            .body(Body::empty())
            .unwrap(),
    );
    let response = timeout(
        StdDuration::from_secs(5),
        crate::forward::handle_request_inner(
            req,
            runtime,
            "ftp-test",
            "127.0.0.1:12345".parse().unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = qpx_http::body::to_bytes(response.into_body())
        .await
        .unwrap();
    assert_eq!(body.as_ref(), b"synthetic file contents");
    server.await.unwrap();
}

#[tokio::test]
async fn forward_http_userinfo_is_rejected_before_dispatch() {
    for scheme in ["http", "https"] {
        let req = OwnerRequest::from_http(
            Request::builder()
                .uri(format!("{scheme}://synthetic-user@host/file"))
                .header("host", "host")
                .body(Body::empty())
                .unwrap(),
        );
        let response = crate::forward::handle_request_inner(
            req,
            ftp_forward_test_runtime(),
            "ftp-test",
            "127.0.0.1:12345".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = qpx_http::body::to_bytes(response.into_body())
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("synthetic-user"));
    }
}

#[tokio::test]
async fn ftp_diagnostics_do_not_include_echoed_credentials() {
    use tokio::io::AsyncBufReadExt;
    use tokio::net::TcpListener;
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = control.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = control.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        stream
            .get_mut()
            .write_all(b"220 synthetic FTP server\r\n")
            .await
            .unwrap();
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        stream
            .get_mut()
            .write_all(b"331 password required\r\n")
            .await
            .unwrap();
        line.clear();
        stream.read_line(&mut line).await.unwrap();
        stream
            .get_mut()
            .write_all(b"530 ftp://synthetic-user:synthetic-pass@host/ denied\r\n")
            .await
            .unwrap();
    });
    let mut client =
        super::control::BasicFtpClient::connect(addr, FtpDeadline::new(StdDuration::from_secs(5)))
            .await
            .unwrap();
    let err = client
        .login("synthetic-user", "synthetic-pass")
        .await
        .unwrap_err();
    let diagnostic = format!("{err:?}");
    assert!(diagnostic.contains("530"));
    assert!(!diagnostic.contains("synthetic-user"));
    assert!(!diagnostic.contains("synthetic-pass"));
    let response = super::ftp_error(err);
    let body = qpx_http::body::to_bytes(response.into_body())
        .await
        .unwrap();
    assert_eq!(body.as_ref(), b"ftp upstream failure");
    server.await.unwrap();
}
