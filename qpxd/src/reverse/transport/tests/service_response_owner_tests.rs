use super::*;
use http::{StatusCode, Version};
use qpx_core::http_message::Response as OwnerResponse;
use std::io::Write as _;
use tokio::time::{Duration, timeout};

fn reverse(config: &str) -> crate::reverse::ReloadableReverse {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(config.as_bytes()).unwrap();
    let config = qpx_core::config::load_config(file.path()).unwrap();
    let edge = config.reverse_edge_configs()[0].clone();
    crate::reverse::ReloadableReverse::new(
        edge,
        Runtime::new(config).unwrap(),
        StdArc::from("reverse_upstreams_unhealthy"),
    )
    .unwrap()
}

// Exercise both actual dispatch monomorphizations. Only the test reimports the
// standard response after its terminal handoff to share assertions.
async fn dispatch(
    request: http::Request<Body>,
    reverse: &crate::reverse::ReloadableReverse,
    standard_terminal: bool,
) -> OwnerResponse<Body> {
    let conn = ReverseConnInfo::plain("127.0.0.1:1234".parse().unwrap(), 80);
    if standard_terminal {
        let (interim, response) = handle_request_with_interim_ref::<http::Response<Body>>(
            Request::from_http(request),
            reverse,
            &conn,
        )
        .await
        .unwrap();
        assert!(interim.is_empty());
        OwnerResponse::from_http(response)
    } else {
        let (interim, response) = handle_request_with_interim_ref::<OwnerResponse<Body>>(
            Request::from_http(request),
            reverse,
            &conn,
        )
        .await
        .unwrap();
        assert!(interim.is_empty());
        response
    }
}

fn field<'a>(response: &'a OwnerResponse<Body>, name: &str) -> &'a http::HeaderValue {
    response
        .headers()
        .get(&qpx_core::http_message::OrdinaryHeaderName::try_from(name).unwrap())
        .unwrap()
}

#[tokio::test]
async fn webdav_response_owners_preserve_direct_and_controlled_service_behavior() {
    for controlled in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let headers = if controlled {
            "    headers:\n      response_set:\n        x-route: controlled\n"
        } else {
            ""
        };
        let reverse = reverse(&format!(
            "origins:\n  webdav:\n  - name: files\n    root: {}\n    metadata: {}\nedges:\n- kind: reverse\n  name: dav\n  listen: 127.0.0.1:0\n  routes:\n  - match: {{}}\n    target:\n      type: webdav\n      origin: files\n{headers}",
            dir.path().join("data").display(),
            dir.path().join("metadata.redb").display(),
        ));
        for standard_terminal in [false, true] {
            for version in [Version::HTTP_11, Version::HTTP_2] {
                for (method, path, status, payload) in [
                    ("PUT", "/file", StatusCode::CREATED, "payload"),
                    ("GET", "/file", StatusCode::OK, ""),
                    ("HEAD", "/file", StatusCode::OK, ""),
                    ("OPTIONS", "/", StatusCode::NO_CONTENT, ""),
                    ("GET", "/missing", StatusCode::NOT_FOUND, ""),
                ] {
                    let response = dispatch(
                        http::Request::builder()
                            .method(method)
                            .uri(path)
                            .version(version)
                            .header("host", "dav.test")
                            .body(Body::from(payload))
                            .unwrap(),
                        &reverse,
                        standard_terminal,
                    )
                    .await;
                    // Repeated PUT replaces the same resource after the first round.
                    if method == "PUT" {
                        assert!(
                            [StatusCode::CREATED, StatusCode::NO_CONTENT]
                                .contains(&response.status())
                        );
                    } else {
                        assert_eq!(response.status(), status, "{method} {path}");
                    }
                    if controlled {
                        assert_eq!(field(&response, "x-route"), "controlled");
                    }
                    if method == "GET" && path == "/file" || method == "HEAD" {
                        assert_eq!(
                            response.headers().declared_content_length().unwrap(),
                            Some(7)
                        );
                        assert!(!field(&response, "etag").is_empty());
                    }
                    let body = to_bytes(response.into_head_and_body().1).await.unwrap();
                    if method == "GET" && path == "/file" {
                        assert_eq!(body, "payload");
                    } else if method == "HEAD" || method == "OPTIONS" {
                        assert!(body.is_empty());
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn websocket_rejection_owners_preserve_headers_body_and_trailers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        let mut sent = 0;
        while sent < 2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                match stream.read_u8().await {
                    Ok(byte) => request.push(byte),
                    Err(_) if request.is_empty() => break,
                    Err(error) => panic!("read handshake: {error}"),
                }
            }
            if request.is_empty() {
                continue;
            }
            sent += 1;
            stream.write_all(b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\nTrailer: x-check\r\nSet-Cookie: first\r\nSet-Cookie: second\r\nX-Exact: \x80raw\r\nConnection: close, x-hop\r\nX-Hop: removed\r\n\r\n6\r\ndenied\r\n0\r\nX-Check: finished\r\n\r\n").await.unwrap();
        }
    });
    let reverse = reverse(&format!(
        "edges:\n- kind: reverse\n  name: ws\n  listen: 127.0.0.1:0\n  routes:\n  - match: {{}}\n    target:\n      type: upstream\n      upstreams: [\"ws://{addr}\"]\n    headers:\n      response_set:\n        x-route: controlled\n      response_add:\n        set-cookie: third\n"
    ));
    for standard_terminal in [false, true] {
        let mut response = timeout(
            Duration::from_secs(3),
            dispatch(
                http::Request::builder()
                    .uri("/socket")
                    .header("host", "ws.test")
                    .header("connection", "upgrade")
                    .header("upgrade", "websocket")
                    .header("sec-websocket-key", "x3JJHMbDL1EzLkh9GBhXDw==")
                    .header("sec-websocket-version", "13")
                    .body(Body::empty())
                    .unwrap(),
                &reverse,
                standard_terminal,
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(field(&response, "x-route"), "controlled");
        assert_eq!(field(&response, "x-exact").as_bytes(), b"\x80raw");
        let cookies = qpx_core::http_message::OrdinaryHeaderName::try_from("set-cookie").unwrap();
        assert_eq!(
            response
                .headers()
                .get_all(&cookies)
                .map(|v| v.as_bytes())
                .collect::<Vec<_>>(),
            [b"first".as_slice(), b"second", b"third"]
        );
        for name in ["x-hop", "connection", "upgrade"] {
            assert!(!response.headers().contains_key(
                &qpx_core::http_message::OrdinaryHeaderName::try_from(name).unwrap()
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.body_mut().data().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(bytes, b"denied");
        assert_eq!(
            response.body_mut().trailers().await.unwrap().unwrap()["x-check"],
            "finished"
        );
    }
    timeout(Duration::from_secs(3), origin)
        .await
        .unwrap()
        .unwrap();
}
