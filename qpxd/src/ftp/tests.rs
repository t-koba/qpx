use super::control::{
    FtpDeadline, active_data_peer_allowed, read_ftp_control_line, validate_pasv_data_endpoint,
};
use super::get_put::{read_to_end_limited, stream_ftp_upload_body};
use super::transfer::normalize_ftp_listing_body;
use super::{
    MAX_FTP_CONTROL_LINE, MAX_FTP_DEADLINE, OperationTimedOut, RequestBodyTooLarge,
    ResponseBodyTooLarge, handle_ftp,
};
use crate::http::body::Body;
use hyper::{Method, Request, StatusCode};
use qpx_core::config::FtpConfig;
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
fn normalize_ftp_listing_body_matches_legacy_join_shape() {
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
    let req = Request::builder()
        .method(Method::PATCH)
        .uri("ftp://example.com/file.txt")
        .body(body)
        .expect("request");
    let response = timeout(
        StdDuration::from_millis(50),
        handle_ftp(
            req,
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
