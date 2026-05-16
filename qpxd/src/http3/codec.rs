use crate::http::body::Body;
use ::http::{Request as Http1Request, Response as Http1Response};
use anyhow::{Result, anyhow};
use http::header::COOKIE;
use hyper::{Request, Uri};

pub fn h1_headers_to_http(src: &::http::HeaderMap) -> Result<http::HeaderMap> {
    let mut headers = http::HeaderMap::new();
    for (name, value) in src {
        let name = http::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|e| anyhow!("invalid header name from HTTP/3 message: {e}"))?;
        let value = http::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|e| anyhow!("invalid header value from HTTP/3 message: {e}"))?;
        if name == COOKIE
            && let Some(existing) = headers.get(COOKIE).cloned()
        {
            let mut merged =
                Vec::with_capacity(existing.as_bytes().len() + 2 + value.as_bytes().len());
            merged.extend_from_slice(existing.as_bytes());
            merged.extend_from_slice(b"; ");
            merged.extend_from_slice(value.as_bytes());
            headers.insert(COOKIE, http::HeaderValue::from_bytes(merged.as_slice())?);
            continue;
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

pub fn h3_request_to_hyper(req: Http1Request<()>, body: Body) -> Result<Request<Body>> {
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

    let mut out = Request::builder().method(method).uri(uri).body(body)?;
    *out.headers_mut() = h1_headers_to_http(&parts.headers)?;
    *out.version_mut() = http::Version::HTTP_3;
    Ok(out)
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedH3ResponseHead {
    pub(crate) head: Http1Response<()>,
    pub(crate) body_allowed: bool,
    pub(crate) content_length: Option<u64>,
}

pub(crate) fn prepare_h3_response_head(
    parts: &http::response::Parts,
    request_method: &http::Method,
) -> Result<PreparedH3ResponseHead> {
    let status = ::http::StatusCode::from_u16(parts.status.as_u16())
        .map_err(|e| anyhow!("invalid response status for HTTP/3: {e}"))?;
    let mut headers = parts.headers.clone();
    let no_body = *request_method == http::Method::HEAD
        || parts.status.is_informational()
        || parts.status == http::StatusCode::NO_CONTENT
        || parts.status == http::StatusCode::NOT_MODIFIED
        || parts.status == http::StatusCode::RESET_CONTENT;
    let content_length = if no_body {
        if *request_method == http::Method::HEAD {
            crate::http::semantics::strip_message_body_framing_headers(&mut headers);
            if parse_content_length_fields(&headers).is_err() {
                headers.remove(http::header::CONTENT_LENGTH);
            }
        } else {
            crate::http::semantics::strip_message_body_headers(&mut headers);
        }
        parse_content_length_fields(&headers).ok().flatten()
    } else {
        let content_length = parse_content_length_fields(&headers);
        if content_length.is_err() {
            headers.remove(http::header::CONTENT_LENGTH);
        }
        content_length.ok().flatten()
    };

    let mut out = Http1Response::builder().status(status).body(())?;
    *out.headers_mut() = http_headers_to_h1(&headers)?;
    Ok(PreparedH3ResponseHead {
        head: out,
        body_allowed: !no_body,
        content_length,
    })
}

pub(crate) fn parse_content_length_fields(headers: &http::HeaderMap) -> Result<Option<u64>> {
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

#[cfg(test)]
mod tests {
    use super::sanitize_interim_response_for_h3;
    use super::{h1_headers_to_http, prepare_h3_response_head};

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

    #[test]
    fn h3_response_head_preparation_removes_conflicting_content_length_fields() {
        let mut response = ::http::Response::builder()
            .status(200)
            .body(())
            .expect("response");
        response
            .headers_mut()
            .append(::http::header::CONTENT_LENGTH, "3".parse().unwrap());
        response
            .headers_mut()
            .append(::http::header::CONTENT_LENGTH, "4".parse().unwrap());

        let (parts, _) = response.into_parts();
        let prepared =
            prepare_h3_response_head(&parts, &::http::Method::GET).expect("prepare head");
        assert!(prepared.body_allowed);
        assert_eq!(prepared.content_length, None);
        assert!(
            !prepared
                .head
                .headers()
                .contains_key(::http::header::CONTENT_LENGTH)
        );
    }

    #[test]
    fn h3_response_head_preparation_suppresses_no_body_status() {
        let response = ::http::Response::builder()
            .status(::http::StatusCode::RESET_CONTENT)
            .header(::http::header::CONTENT_LENGTH, "7")
            .body(())
            .expect("response");

        let (parts, _) = response.into_parts();
        let prepared =
            prepare_h3_response_head(&parts, &::http::Method::GET).expect("prepare head");
        assert!(!prepared.body_allowed);
        assert_eq!(prepared.content_length, None);
        assert!(
            !prepared
                .head
                .headers()
                .contains_key(::http::header::CONTENT_LENGTH)
        );
    }

    #[test]
    fn h3_response_head_preparation_preserves_valid_head_content_length() {
        let response = ::http::Response::builder()
            .status(::http::StatusCode::OK)
            .header(::http::header::CONTENT_LENGTH, "42")
            .body(())
            .expect("response");

        let (parts, _) = response.into_parts();
        let prepared =
            prepare_h3_response_head(&parts, &::http::Method::HEAD).expect("prepare head");
        assert!(!prepared.body_allowed);
        assert_eq!(prepared.content_length, Some(42));
        assert_eq!(
            prepared
                .head
                .headers()
                .get(::http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("42")
        );
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
        assert!(
            !interim
                .headers()
                .contains_key(::http::header::CONTENT_LENGTH)
        );
        assert!(
            !interim
                .headers()
                .contains_key(::http::header::TRANSFER_ENCODING)
        );
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
