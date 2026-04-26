use crate::http::body::Body;
use ::http::{Request as Http1Request, Response as Http1Response};
use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use http::header::COOKIE;
use hyper::{Request, Response, Uri};
use tokio::spawn;
use tokio::time::{timeout, Duration};
use tracing::warn;

pub fn h1_headers_to_http(src: &::http::HeaderMap) -> Result<http::HeaderMap> {
    let mut headers = http::HeaderMap::new();
    for (name, value) in src {
        let name = http::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|e| anyhow!("invalid header name from HTTP/3 message: {e}"))?;
        let value = http::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|e| anyhow!("invalid header value from HTTP/3 message: {e}"))?;
        if name == COOKIE {
            if let Some(existing) = headers.get(COOKIE).cloned() {
                let mut merged =
                    Vec::with_capacity(existing.as_bytes().len() + 2 + value.as_bytes().len());
                merged.extend_from_slice(existing.as_bytes());
                merged.extend_from_slice(b"; ");
                merged.extend_from_slice(value.as_bytes());
                headers.insert(COOKIE, http::HeaderValue::from_bytes(merged.as_slice())?);
                continue;
            }
        }
        headers.append(name, value);
    }
    Ok(headers)
}

pub fn http_headers_to_h1(src: &http::HeaderMap) -> Result<::http::HeaderMap> {
    let mut headers = ::http::HeaderMap::new();
    for (name, value) in src {
        let name = ::http::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|e| anyhow!("invalid header name for HTTP/3 message: {e}"))?;
        let value = ::http::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|e| anyhow!("invalid header value for HTTP/3 message: {e}"))?;
        headers.append(name, value);
    }
    Ok(headers)
}

pub fn sanitize_interim_response_for_h3(
    mut response: Http1Response<()>,
) -> Result<Http1Response<()>> {
    if !response.status().is_informational() {
        return Err(anyhow!(
            "non-informational interim status for HTTP/3: {}",
            response.status()
        ));
    }
    if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
        return Err(anyhow!("HTTP/3 interim responses must not use 101"));
    }
    crate::http::semantics::sanitize_interim_response_headers(response.headers_mut());
    Ok(response)
}

pub fn h3_request_to_hyper(
    req: Http1Request<()>,
    body: Bytes,
    trailers: Option<::http::HeaderMap>,
) -> Result<Request<Body>> {
    let (parts, _) = req.into_parts();
    let method = parts
        .method
        .as_str()
        .parse::<http::Method>()
        .map_err(|_| anyhow!("invalid HTTP/3 method"))?;
    let uri = parts
        .uri
        .to_string()
        .parse::<Uri>()
        .or_else(|_| {
            let path = parts
                .uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            Uri::builder().path_and_query(path).build()
        })
        .map_err(|e| anyhow!("invalid HTTP/3 URI: {e}"))?;

    let trailers = trailers.as_ref().map(h1_headers_to_http).transpose()?;
    if let Some(ref t) = trailers {
        crate::http::semantics::validate_request_trailers(t)
            .map_err(|e| anyhow!("invalid HTTP/3 request trailers: {e}"))?;
    }
    let mut out = Request::builder()
        .method(method)
        .uri(uri)
        .body(body_from_h3_parts(body, trailers))?;
    *out.headers_mut() = h1_headers_to_http(&parts.headers)?;
    *out.version_mut() = http::Version::HTTP_3;
    Ok(out)
}

pub async fn hyper_response_to_h3(
    response: Response<Body>,
    request_method: &http::Method,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<(Http1Response<()>, Bytes, Option<::http::HeaderMap>)> {
    let (parts, body) = response.into_parts();
    let status = ::http::StatusCode::from_u16(parts.status.as_u16())
        .map_err(|e| anyhow!("invalid response status for HTTP/3: {e}"))?;
    let mut headers = parts.headers;
    let no_body = *request_method == http::Method::HEAD
        || parts.status.is_informational()
        || parts.status == http::StatusCode::NO_CONTENT
        || parts.status == http::StatusCode::NOT_MODIFIED
        || parts.status == http::StatusCode::RESET_CONTENT;
    let (bytes, trailers) = if no_body {
        if *request_method == http::Method::HEAD {
            crate::http::semantics::strip_message_body_framing_headers(&mut headers);
            if parse_content_length_fields(&headers).is_err() {
                headers.remove(http::header::CONTENT_LENGTH);
            }
        } else {
            crate::http::semantics::strip_message_body_headers(&mut headers);
        }
        (Bytes::new(), None)
    } else {
        let (bytes, mut trailers) =
            collect_body_limited(body, max_body_bytes, body_read_timeout).await?;
        if let Some(ref mut trailers) = trailers {
            let removed = crate::http::semantics::sanitize_response_trailers(trailers);
            if removed > 0 {
                warn!(removed, "dropping forbidden response trailers");
            }
        }
        let body_len = bytes.len() as u64;
        let content_length = parse_content_length_fields(&headers);
        if let Ok(Some(expected)) = content_length {
            if expected != body_len {
                headers.remove(http::header::CONTENT_LENGTH);
            }
        } else if content_length.is_err() || headers.contains_key(http::header::CONTENT_LENGTH) {
            headers.remove(http::header::CONTENT_LENGTH);
        }
        (bytes, trailers)
    };

    let mut out = Http1Response::builder().status(status).body(())?;
    *out.headers_mut() = http_headers_to_h1(&headers)?;
    let trailers = trailers.as_ref().map(http_headers_to_h1).transpose()?;
    Ok((out, bytes, trailers))
}

fn parse_content_length_fields(headers: &http::HeaderMap) -> Result<Option<u64>> {
    let mut parsed: Option<u64> = None;
    for value in headers.get_all(http::header::CONTENT_LENGTH).iter() {
        let raw = value
            .to_str()
            .map_err(|err| anyhow!("invalid Content-Length header: {err}"))?
            .trim();
        if raw.is_empty() {
            return Err(anyhow!("empty Content-Length header"));
        }
        for part in raw.split(',') {
            let next = part
                .trim()
                .parse::<u64>()
                .map_err(|err| anyhow!("invalid Content-Length value: {err}"))?;
            match parsed {
                Some(existing) if existing != next => {
                    return Err(anyhow!("conflicting Content-Length values"));
                }
                Some(_) => {}
                None => parsed = Some(next),
            }
        }
    }
    Ok(parsed)
}

fn body_from_h3_parts(body: Bytes, trailers: Option<http::HeaderMap>) -> Body {
    if trailers.is_none() {
        return Body::from(body);
    }

    let (mut sender, out) = Body::channel();
    spawn(async move {
        if !body.is_empty() && sender.send_data(body).await.is_err() {
            return;
        }
        if let Some(trailers) = trailers {
            let _ = sender.send_trailers(trailers).await;
        }
    });
    out
}

async fn collect_body_limited(
    mut body: Body,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<(Bytes, Option<http::HeaderMap>)> {
    let mut out = BytesMut::new();
    while let Some(frame) = timeout(body_read_timeout, body.data())
        .await
        .map_err(|_| anyhow!("HTTP/3 response body read timed out"))?
    {
        let chunk = frame?;
        let next = out
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("HTTP/3 response body length overflow"))?;
        if next > max_body_bytes {
            return Err(anyhow!(
                "HTTP/3 response body exceeds configured limit: {} bytes",
                max_body_bytes
            ));
        }
        out.extend_from_slice(&chunk);
    }
    let trailers = timeout(body_read_timeout, body.trailers())
        .await
        .map_err(|_| anyhow!("HTTP/3 response trailers read timed out"))??;
    Ok((out.freeze(), trailers))
}

#[cfg(test)]
mod tests {
    use super::sanitize_interim_response_for_h3;
    use super::{h1_headers_to_http, hyper_response_to_h3};
    use crate::http::body::Body;
    use bytes::Bytes;
    use tokio::time::Duration;

    #[test]
    fn h3_cookie_fields_are_merged_for_generic_context() {
        let mut headers = ::http::HeaderMap::new();
        headers.append("cookie", ::http::HeaderValue::from_static("a=1"));
        headers.append("cookie", ::http::HeaderValue::from_static("b=2"));

        let converted = h1_headers_to_http(&headers).expect("headers convert");
        let cookie = converted.get("cookie").expect("cookie header");
        assert_eq!(cookie.to_str().unwrap(), "a=1; b=2");
        assert_eq!(converted.get_all("cookie").iter().count(), 1);
    }

    #[tokio::test]
    async fn h3_response_serializer_removes_conflicting_content_length_fields() {
        let mut response = ::http::Response::builder()
            .status(200)
            .body(Body::from("abc"))
            .expect("response");
        response
            .headers_mut()
            .append(::http::header::CONTENT_LENGTH, "3".parse().unwrap());
        response
            .headers_mut()
            .append(::http::header::CONTENT_LENGTH, "4".parse().unwrap());

        let (head, body, trailers) =
            hyper_response_to_h3(response, &::http::Method::GET, 1024, Duration::from_secs(1))
                .await
                .expect("serialize");
        assert_eq!(body.as_ref(), b"abc");
        assert!(trailers.is_none());
        assert!(!head.headers().contains_key(::http::header::CONTENT_LENGTH));
    }

    #[tokio::test]
    async fn h3_response_serializer_drops_body_and_trailers_for_no_body_status() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-trailer", "value".parse().unwrap());
        let response = ::http::Response::builder()
            .status(::http::StatusCode::RESET_CONTENT)
            .header(::http::header::CONTENT_LENGTH, "7")
            .body(Body::replay(Bytes::from_static(b"payload"), Some(trailers)))
            .expect("response");

        let (head, body, trailers) =
            hyper_response_to_h3(response, &::http::Method::GET, 1024, Duration::from_secs(1))
                .await
                .expect("serialize");
        assert!(body.is_empty());
        assert!(trailers.is_none());
        assert!(!head.headers().contains_key(::http::header::CONTENT_LENGTH));
    }

    #[tokio::test]
    async fn h3_response_serializer_drops_head_body_but_preserves_valid_content_length() {
        let response = ::http::Response::builder()
            .status(::http::StatusCode::OK)
            .header(::http::header::CONTENT_LENGTH, "42")
            .body(Body::from("not serialized"))
            .expect("response");

        let (head, body, trailers) = hyper_response_to_h3(
            response,
            &::http::Method::HEAD,
            1024,
            Duration::from_secs(1),
        )
        .await
        .expect("serialize");
        assert!(body.is_empty());
        assert!(trailers.is_none());
        assert_eq!(
            head.headers()
                .get(::http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("42")
        );
    }

    #[tokio::test]
    async fn h3_response_serializer_times_out_idle_body_before_headers() {
        let (_sender, body) = Body::channel();
        let response = ::http::Response::builder()
            .status(::http::StatusCode::OK)
            .body(body)
            .expect("response");

        let err = hyper_response_to_h3(
            response,
            &::http::Method::GET,
            1024,
            Duration::from_millis(10),
        )
        .await
        .expect_err("idle response body must time out");

        assert!(err.to_string().contains("timed out"));
    }

    #[test]
    fn h3_interim_response_sanitizer_strips_body_framing_headers() {
        let interim = ::http::Response::builder()
            .status(::http::StatusCode::EARLY_HINTS)
            .header(::http::header::LINK, "</app.css>; rel=preload")
            .header(::http::header::CONTENT_LENGTH, "99")
            .header(::http::header::TRANSFER_ENCODING, "chunked")
            .header(::http::header::TRAILER, "x-trailer")
            .body(())
            .expect("interim");

        let interim = sanitize_interim_response_for_h3(interim).expect("sanitize");
        assert_eq!(interim.status(), ::http::StatusCode::EARLY_HINTS);
        assert!(interim.headers().contains_key(::http::header::LINK));
        assert!(!interim
            .headers()
            .contains_key(::http::header::CONTENT_LENGTH));
        assert!(!interim
            .headers()
            .contains_key(::http::header::TRANSFER_ENCODING));
        assert!(!interim.headers().contains_key(::http::header::TRAILER));
    }

    #[test]
    fn h3_interim_response_sanitizer_rejects_final_status() {
        let interim = ::http::Response::builder()
            .status(::http::StatusCode::OK)
            .body(())
            .expect("interim");
        assert!(sanitize_interim_response_for_h3(interim).is_err());
    }
}
