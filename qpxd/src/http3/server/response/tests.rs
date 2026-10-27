use super::*;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Version, header};

#[test]
fn owned_h3_head_matches_standard_preparation() {
    for method in [Method::GET, Method::HEAD, Method::CONNECT] {
        for status in [200, 204, 205, 304] {
            for values in [
                vec![],
                vec!["0"],
                vec!["7"],
                vec!["007", "7"],
                vec!["7, 007"],
                vec!["bad"],
                vec![""],
                vec!["1", "2"],
                vec!["18446744073709551616"],
            ] {
                let mut response = Response::builder()
                    .status(status)
                    .version(Version::HTTP_3)
                    .body(Body::empty())
                    .unwrap();
                for value in &values {
                    response.headers_mut().append(
                        header::CONTENT_LENGTH,
                        HeaderValue::from_str(value).unwrap(),
                    );
                }
                response.headers_mut().insert(
                    header::TRANSFER_ENCODING,
                    HeaderValue::from_static("chunked"),
                );
                response
                    .headers_mut()
                    .insert(header::TRAILER, HeaderValue::from_static("x-end"));
                for bytes in [b"first".as_slice(), b"opaque-\xff"] {
                    let mut value = HeaderValue::from_bytes(bytes).unwrap();
                    value.set_sensitive(true);
                    response.headers_mut().append(header::SET_COOKIE, value);
                }
                response.extensions_mut().insert(42usize);
                let (parts, body) = response.into_parts();
                let expected = prepare_h3_response_head(&parts, &method).unwrap();
                let exported = export_h3_response_for_codec(OwnerResponse::from_http(
                    Response::from_parts(parts, body),
                ))
                .unwrap();
                assert_eq!(exported.version(), Version::HTTP_3);
                assert_eq!(exported.extensions().get::<usize>(), Some(&42));
                let (parts, _) = exported.into_parts();
                let actual = prepare_h3_response_head(&parts, &method).unwrap();
                assert_eq!(actual.body_allowed, expected.body_allowed);
                assert_eq!(actual.content_length, expected.content_length);
                assert_eq!(actual.head.status(), expected.head.status());
                assert_eq!(actual.head.version(), expected.head.version());
                // These are the exact header fields passed to H3's HEADERS
                // encoder, including per-name duplicate order and opaque bytes.
                assert_eq!(actual.head.headers(), expected.head.headers());
                let cookies = actual
                    .head
                    .headers()
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .collect::<Vec<_>>();
                assert_eq!(cookies.len(), 2);
                assert_eq!(cookies[0].as_bytes(), b"first");
                assert_eq!(cookies[1].as_bytes(), b"opaque-\xff");
                assert!(cookies.iter().all(|value| value.is_sensitive()));
            }
        }
    }
}

#[tokio::test]
async fn owned_h3_export_preserves_lazy_body_trailers_and_errors() {
    use futures_util::{StreamExt as _, stream};
    use http_body::Frame;
    use http_body_util::StreamBody;
    use qpx_http::body::BodyError;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    for fail in [false, true] {
        let polls = Arc::new(AtomicUsize::new(0));
        let polled = polls.clone();
        let mut trailers = HeaderMap::new();
        trailers.append("x-end", HeaderValue::from_static("one"));
        trailers.append("x-end", HeaderValue::from_static("two"));
        let last = if fail {
            Err(BodyError::new("test body error"))
        } else {
            Ok(Frame::trailers(trailers.clone()))
        };
        let frames =
            stream::iter([Ok(Frame::data(Bytes::from_static(b"abc"))), last]).inspect(move |_| {
                polled.fetch_add(1, Ordering::SeqCst);
            });
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Body::wrap(StreamBody::new(frames)))
            .unwrap();
        let mut body = export_h3_response_for_codec(OwnerResponse::from_http(response))
            .unwrap()
            .into_body();
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(body.data().await.unwrap().unwrap(), b"abc".as_slice());
        if fail {
            assert_eq!(
                body.data().await.unwrap().unwrap_err().to_string(),
                "test body error"
            );
        } else {
            assert!(body.data().await.is_none());
            assert_eq!(body.trailers().await.unwrap(), Some(trailers));
        }
    }
}
