use super::*;
use http::HeaderValue;
use qpx_core::http_message::Response as OwnerResponse;

fn response(status: u16, body: Body) -> Response<Body> {
    let mut response = Response::builder()
        .status(status)
        .header("date", "Thu, 01 Jan 1970 00:00:00 GMT")
        .header("connection", "x-drop, Upgrade")
        .header("x-drop", "drop")
        .header("upgrade", "websocket")
        .header("via", "1.0 upstream")
        .header("proxy-status", "upstream; received-status=200")
        .header("content-length", "3")
        .header("trailer", "x-check")
        .header("set-cookie", "a=1")
        .header("set-cookie", "b=2")
        .header("x-exact", HeaderValue::from_bytes(b" \x80\t").unwrap())
        .body(body)
        .unwrap();
    for field in ["proxy-authenticate", "proxy-authentication-info"] {
        let mut value = HeaderValue::from_static("Basic realm=\"one\"");
        value.set_sensitive(true);
        response.headers_mut().append(field, value);
        response
            .headers_mut()
            .append(field, HeaderValue::from_static("second"));
    }
    response.extensions_mut().insert(42_u32);
    response
}

fn assert_heads_equal(standard: &Response<Body>, owner: &OwnerResponse<Body>) {
    assert_eq!(standard.status(), owner.status());
    assert_eq!(standard.version(), owner.version());
    assert_eq!(
        standard.extensions().get::<u32>(),
        owner.extensions().get::<u32>()
    );
    let standard_fields: Vec<_> = standard
        .headers()
        .iter()
        .filter(|(n, _)| *n != "content-length")
        .map(|(n, v)| (n.as_str(), v.as_bytes(), v.is_sensitive()))
        .collect();
    let owner_fields: Vec<_> = owner
        .headers()
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_bytes(), v.is_sensitive()))
        .collect();
    assert_eq!(standard_fields, owner_fields);
    assert_eq!(
        qpx_core::http_content_length::declared_content_length(standard.headers()),
        owner.headers().declared_content_length()
    );
}

#[tokio::test]
async fn paired_finalization_status_headers_body_and_controls() {
    let control = request_set_headers(
        r#"
response_set:
  x-configured: set
response_add:
  set-cookie: c=3
response_remove:
- x-removed
"#,
    );
    for status in [100, 101, 103, 200, 204, 205, 304, 407, 502] {
        for method in [Method::GET, Method::HEAD, Method::CONNECT] {
            for preserve in [false, true] {
                let standard = response(status, Body::from("abc"));
                let mut owner = OwnerResponse::from_http(response(status, Body::from("abc")));
                let mut standard = finalize_response_with_headers(
                    &method,
                    http::Version::HTTP_2,
                    "qpx",
                    standard,
                    Some(&control),
                    preserve,
                );
                finalize_response_with_headers_in_place(
                    &method,
                    http::Version::HTTP_2,
                    "qpx",
                    &mut owner,
                    Some(&control),
                    preserve,
                );
                assert_heads_equal(&standard, &owner);
                assert_eq!(
                    standard.body().trailers_are_sanitized(),
                    owner.body().trailers_are_sanitized()
                );
                assert_eq!(standard.headers()["x-configured"], "set");
                assert_eq!(standard.headers().get_all("set-cookie").iter().count(), 3);
                assert!(!standard.headers().contains_key("x-drop"));
                assert_eq!(
                    standard
                        .headers()
                        .get_all("via")
                        .iter()
                        .map(|v| v.to_str().unwrap())
                        .collect::<Vec<_>>(),
                    ["1.0 upstream", "2 qpx"]
                );
                assert_eq!(
                    standard.headers()["proxy-status"],
                    "upstream;received-status=200, qpx"
                );
                let auth: Vec<_> = owner
                    .headers()
                    .get_all(&OrdinaryHeaderName::try_from("proxy-authenticate").unwrap())
                    .collect();
                assert_eq!(auth.len(), if status == 407 { 2 } else { 0 });
                if status == 407 {
                    assert!(auth[0].is_sensitive());
                }
                assert_eq!(
                    standard.body_mut().data().await.transpose().unwrap(),
                    owner.body_mut().data().await.transpose().unwrap()
                );
                assert_eq!(
                    standard.body_mut().trailers().await.unwrap(),
                    owner.body_mut().trailers().await.unwrap()
                );
            }
        }
    }
}

#[test]
fn paired_finalization_length_policy_precedes_hop_and_normalization() {
    // Literal invalid/conflicting lengths must not fail adoption; nominations
    // are consumed after controls, before HEAD/no-body normalization.
    for length in ["0", "3", "3, 3", "bad", "3, 4"] {
        for nominated in [false, true] {
            let control = request_set_headers(&format!(
                r#"
response_set:
  content-length: '{length}'
  connection: '{}'
"#,
                if nominated {
                    "Content-Length"
                } else {
                    "x-drop"
                }
            ));
            let standard = response(200, Body::from("abc"));
            let mut owner = OwnerResponse::from_http(response(200, Body::from("abc")));
            let standard = finalize_response_with_headers(
                &Method::HEAD,
                http::Version::HTTP_11,
                "qpx",
                standard,
                Some(&control),
                false,
            );
            finalize_response_with_headers_in_place(
                &Method::HEAD,
                http::Version::HTTP_11,
                "qpx",
                &mut owner,
                Some(&control),
                false,
            );
            assert_heads_equal(&standard, &owner);
            assert_eq!(owner.headers().contains_content_length(), !nominated);
            if !nominated {
                assert_eq!(standard.headers()["content-length"], length);
                assert_eq!(
                    owner.headers().declared_content_length().is_err(),
                    ["bad", "3, 4"].contains(&length)
                );
            }
        }
    }
}

#[test]
fn paired_finalization_date_and_invalid_proxy_status_repair() {
    for inbound in ["bad=(", "12", "(nested)", "upstream, other"] {
        let make = || {
            Response::builder()
                .header("proxy-status", inbound)
                .body(Body::empty())
                .unwrap()
        };
        let mut standard = make();
        let mut owner = OwnerResponse::from_http(make());
        finalize_response_in_place(
            &Method::GET,
            http::Version::HTTP_11,
            "qpx",
            &mut standard,
            false,
        );
        finalize_response_in_place(
            &Method::GET,
            http::Version::HTTP_11,
            "qpx",
            &mut owner,
            false,
        );
        let date = OrdinaryHeaderName::try_from("date").unwrap();
        assert!(
            httpdate::parse_http_date(owner.headers().get(&date).unwrap().to_str().unwrap())
                .is_ok()
        );
        assert!(httpdate::parse_http_date(standard.headers()["date"].to_str().unwrap()).is_ok());
        // Compare all other bytes, without a wall-clock-second boundary race.
        standard.headers_mut().remove("date");
        owner.headers_mut().remove(&date);
        assert_heads_equal(&standard, &owner);
        assert_eq!(
            standard.headers()["proxy-status"],
            if inbound == "upstream, other" {
                "upstream, other, qpx"
            } else {
                "qpx"
            }
        );
    }
}

#[tokio::test]
async fn paired_finalization_stream_backpressure_trailers_and_errors() {
    for abort in [false, true] {
        let run = async |owned| {
            let (mut sender, body) = Body::channel_with_capacity(1);
            let make = response(200, body);
            let mut owner = if owned {
                OwnerResponse::from_http(make)
            } else {
                let mut standard = make;
                finalize_response_in_place(
                    &Method::GET,
                    http::Version::HTTP_11,
                    "qpx",
                    &mut standard,
                    false,
                );
                OwnerResponse::from_http(standard)
            };
            if owned {
                finalize_response_in_place(
                    &Method::GET,
                    http::Version::HTTP_11,
                    "qpx",
                    &mut owner,
                    false,
                );
            }
            sender.send_data(Bytes::from_static(b"one")).await.unwrap();
            let mut blocked = Box::pin(sender.send_data(Bytes::from_static(b"two")));
            assert!(futures_util::poll!(&mut blocked).is_pending());
            assert_eq!(owner.body_mut().data().await.unwrap().unwrap(), "one");
            blocked.await.unwrap();
            assert_eq!(owner.body_mut().data().await.unwrap().unwrap(), "two");
            if abort {
                sender.abort();
                assert_eq!(
                    owner
                        .body_mut()
                        .data()
                        .await
                        .unwrap()
                        .unwrap_err()
                        .to_string(),
                    "body aborted"
                );
            } else {
                let mut trailers = http::HeaderMap::new();
                trailers.insert("content-length", HeaderValue::from_static("6"));
                trailers.insert("x-check", HeaderValue::from_static("kept"));
                sender.send_trailers(trailers).await.unwrap();
                drop(sender);
                assert!(owner.body_mut().data().await.is_none());
                let trailers = owner.body_mut().trailers().await.unwrap().unwrap();
                assert_eq!(trailers.len(), 1);
                assert_eq!(trailers["x-check"], "kept");
            }
        };
        run(false).await;
        run(true).await;
    }
}

#[test]
fn paired_finalization_raw_head_extension_is_finalized_once() {
    use crate::upstream::raw_http1::RawHttp1ResponseHead;
    for status in [StatusCode::OK, StatusCode::CONTINUE] {
        let parsed = [
            httparse::Header {
                name: "Content-Length",
                value: b"3",
            },
            httparse::Header {
                name: "Date",
                value: b"Thu, 01 Jan 1970 00:00:00 GMT",
            },
        ];
        let raw = Arc::new(
            RawHttp1ResponseHead::from_parsed(
                &parsed,
                &Method::GET,
                status,
                http::Version::HTTP_11,
            )
            .unwrap(),
        );
        let make = || {
            let mut response =
                response(status.as_u16(), Body::from("abc").mark_trailers_sanitized());
            response.extensions_mut().insert(raw.clone());
            response
        };
        let mut standard = make();
        let mut owner = OwnerResponse::from_http(make());
        for _ in 0..2 {
            finalize_response_in_place(
                &Method::GET,
                http::Version::HTTP_11,
                "qpx",
                &mut standard,
                false,
            );
            finalize_response_in_place(
                &Method::GET,
                http::Version::HTTP_11,
                "qpx",
                &mut owner,
                false,
            );
            assert_heads_equal(&standard, &owner);
            let standard_raw = standard
                .extensions()
                .get::<Arc<RawHttp1ResponseHead>>()
                .unwrap();
            let owner_raw = owner
                .extensions()
                .get::<Arc<RawHttp1ResponseHead>>()
                .unwrap();
            assert!(owner_raw.is_finalized());
            assert_eq!(standard_raw.header_lines(), owner_raw.header_lines());
            let bytes = owner_raw.header_lines().to_vec();
            let pointer = Arc::as_ptr(owner_raw);
            finalize_response_in_place(
                &Method::GET,
                http::Version::HTTP_11,
                "qpx",
                &mut owner,
                false,
            );
            let owner_raw = owner
                .extensions()
                .get::<Arc<RawHttp1ResponseHead>>()
                .unwrap();
            assert_eq!(Arc::as_ptr(owner_raw), pointer);
            assert_eq!(owner_raw.header_lines(), bytes);
            assert_eq!(
                standard.body().trailers_are_sanitized(),
                owner.body().trailers_are_sanitized()
            );
        }
        if status == StatusCode::OK {
            assert!(owner.body().trailers_are_sanitized());
        }
        assert_eq!(
            owner.status(),
            if status.is_informational() {
                StatusCode::BAD_GATEWAY
            } else {
                status
            }
        );
        assert!(!raw.is_finalized());
    }
}
