use ::http::{Request as Http1Request, Response as Http1Response};
use anyhow::{Result, anyhow};
use http::header::COOKIE;
use hyper::{Request, Uri};
use qpx_http::body::Body;
use qpx_http::protocol::semantics::response_status_has_no_body;

pub(crate) fn h1_headers_to_http(src: &::http::HeaderMap) -> Result<http::HeaderMap> {
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

pub(crate) fn http_headers_to_h1(src: &http::HeaderMap) -> Result<::http::HeaderMap> {
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

pub(crate) fn sanitize_interim_response_for_h3(
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
    qpx_http::protocol::semantics::sanitize_interim_response_headers(response.headers_mut());
    Ok(response)
}

// Bound decoded header field count at the semantic boundary, aligned with the
// HTTP/1 edge cap (MAX_HTTP1_REQUEST_HEADERS = 128, mapped to 431) and the H2
// transport cap (H2_MAX_HEADER_COUNT). Byte caps alone still admit thousands
// of tiny fields within budget (HTTP/2 Bomb pattern), so the count ceiling is
// the fail-closed default; per-route guard `header_count` remains the policy
// knob for stricter limits.
pub(crate) const H3_MAX_HEADER_COUNT: usize = 128;

#[derive(Debug, thiserror::Error)]
#[error("HTTP/3 request header fields exceeded configured limits")]
struct H3HeaderCountTooLarge;

pub(crate) fn h3_request_to_hyper(req: Http1Request<()>, body: Body) -> Result<Request<Body>> {
    let (parts, _) = req.into_parts();
    if parts.headers.len() > H3_MAX_HEADER_COUNT {
        return Err(H3HeaderCountTooLarge.into());
    }
    let method = parts
        .method
        .as_str()
        .parse::<http::Method>()
        .map_err(|_| anyhow!("invalid HTTP/3 method"))?;
    let uri =
        Uri::from_parts(parts.uri.into_parts()).map_err(|e| anyhow!("invalid HTTP/3 URI: {e}"))?;

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
    let status =
        qpx_http::protocol::semantics::validate_http_status_class(parts.status, "HTTP/3 response")?;
    let mut headers = parts.headers.clone();
    let no_body =
        *request_method == http::Method::HEAD || response_status_has_no_body(parts.status, false);
    // RFC 9110 section 8.6 gives the field the grammar `1*DIGIT`, so the
    // value a sender writes is one decimal, and the declaration the
    // response carried is replaced with a single instance of the resolved
    // decimal: the field leaves as one field whose value is that decimal,
    // never as two fields and never as a value the grammar does not have.
    let content_length = if no_body {
        if *request_method == http::Method::HEAD {
            qpx_http::protocol::semantics::strip_message_body_framing_headers(&mut headers);
            match parse_content_length_fields(&headers) {
                Ok(Some(length)) => {
                    headers.insert(
                        http::header::CONTENT_LENGTH,
                        qpx_core::http_content_length::canonical_content_length_value(length),
                    );
                }
                Ok(None) => {}
                Err(_) => {
                    headers.remove(http::header::CONTENT_LENGTH);
                }
            }
        } else {
            qpx_http::protocol::semantics::strip_message_body_headers(&mut headers);
        }
        parse_content_length_fields(&headers).ok().flatten()
    } else {
        match parse_content_length_fields(&headers) {
            Ok(Some(length)) => {
                headers.insert(
                    http::header::CONTENT_LENGTH,
                    qpx_core::http_content_length::canonical_content_length_value(length),
                );
                Some(length)
            }
            Ok(None) => None,
            Err(_) => {
                headers.remove(http::header::CONTENT_LENGTH);
                None
            }
        }
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
    qpx_core::http_content_length::declared_content_length(headers).map_err(anyhow::Error::new)
}

#[cfg(test)]
mod tests {
    use super::sanitize_interim_response_for_h3;
    use super::{
        H3_MAX_HEADER_COUNT, h1_headers_to_http, h3_request_to_hyper, prepare_h3_response_head,
    };

    #[test]
    fn h3_options_asterisk_uri_preserves_scheme_and_authority() {
        let uri = ::http::Uri::builder()
            .scheme("https")
            .authority("origin.example.test:443")
            .path_and_query("*")
            .build()
            .expect("asterisk URI");
        let request = ::http::Request::builder()
            .method(::http::Method::OPTIONS)
            .uri(uri)
            .body(())
            .expect("request");

        let converted = h3_request_to_hyper(request, qpx_http::body::Body::empty())
            .expect("convert H3 request");
        assert_eq!(converted.method(), ::http::Method::OPTIONS);
        assert_eq!(converted.uri().scheme_str(), Some("https"));
        assert_eq!(
            converted
                .uri()
                .authority()
                .map(|authority| authority.as_str()),
            Some("origin.example.test:443")
        );
        assert_eq!(converted.uri().path_and_query().unwrap().as_str(), "*");
    }

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

    /// The content-length fields of a prepared head.
    ///
    /// The HTTP/3 writer sends a header list rather than field lines, so
    /// the fixture reads the fields of the head the writer prepares.
    fn content_length_fields(head: &::http::HeaderMap) -> Vec<String> {
        head.get_all(::http::header::CONTENT_LENGTH)
            .iter()
            .map(|value| value.to_str().expect("text value").to_string())
            .collect()
    }

    #[test]
    fn h3_response_head_preparation_writes_one_canonical_content_length_field_for_a_comma_list() {
        // RFC 9110 section 8.6: the value a sender writes is one decimal,
        // so a comma list of equal members leaves as one field whose value
        // is the resolved decimal.
        let mut response = ::http::Response::builder()
            .status(200)
            .body(())
            .expect("response");
        response.headers_mut().append(
            ::http::header::CONTENT_LENGTH,
            ::http::HeaderValue::from_static("42, 42"),
        );

        let (parts, _) = response.into_parts();
        let prepared =
            prepare_h3_response_head(&parts, &::http::Method::GET).expect("prepare head");

        assert_eq!(prepared.content_length, Some(42));
        assert_eq!(content_length_fields(prepared.head.headers()), vec!["42"]);
    }

    #[test]
    fn h3_response_head_preparation_writes_one_canonical_content_length_field_for_two_values() {
        // RFC 9110 section 8.6: the field is one field, so two values
        // that carried it leave as one field whose value is the resolved
        // decimal.
        let mut response = ::http::Response::builder()
            .status(200)
            .body(())
            .expect("response");
        response.headers_mut().append(
            ::http::header::CONTENT_LENGTH,
            ::http::HeaderValue::from_static("42"),
        );
        response.headers_mut().append(
            ::http::header::CONTENT_LENGTH,
            ::http::HeaderValue::from_static("42"),
        );

        let (parts, _) = response.into_parts();
        let prepared =
            prepare_h3_response_head(&parts, &::http::Method::GET).expect("prepare head");

        assert_eq!(prepared.content_length, Some(42));
        assert_eq!(content_length_fields(prepared.head.headers()), vec!["42"]);
    }

    #[test]
    fn h3_response_head_preparation_keeps_a_single_content_length_value() {
        // A value that already is the canonical one reaches the wire as
        // it was received.
        let mut response = ::http::Response::builder()
            .status(200)
            .body(())
            .expect("response");
        response.headers_mut().append(
            ::http::header::CONTENT_LENGTH,
            ::http::HeaderValue::from_static("42"),
        );

        let (parts, _) = response.into_parts();
        let prepared =
            prepare_h3_response_head(&parts, &::http::Method::GET).expect("prepare head");

        assert_eq!(prepared.content_length, Some(42));
        assert_eq!(content_length_fields(prepared.head.headers()), vec!["42"]);
    }

    #[test]
    fn h3_response_head_preparation_does_not_invent_a_content_length() {
        // A response that carried no field carries none on the wire.
        let response = ::http::Response::builder()
            .status(200)
            .body(())
            .expect("response");

        let (parts, _) = response.into_parts();
        let prepared =
            prepare_h3_response_head(&parts, &::http::Method::GET).expect("prepare head");

        assert_eq!(prepared.content_length, None);
        assert!(content_length_fields(prepared.head.headers()).is_empty());
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
    fn h3_header_count_cap_matches_edge_caps() {
        assert_eq!(
            H3_MAX_HEADER_COUNT, 128,
            "H3 decoded-field cap must stay aligned with the H1 edge cap",
        );
        assert_eq!(
            H3_MAX_HEADER_COUNT,
            crate::http::codec::h2::H2_MAX_HEADER_COUNT,
            "H3 decoded-field cap must stay aligned with the H2 transport cap",
        );
    }

    #[test]
    fn h3_request_with_many_tiny_headers_is_refused_at_count_ceiling() {
        // 200 distinct tiny headers total ~2 KiB: far under the 128 KiB byte
        // cap, over the 128-field edge cap, so acceptance would prove the
        // count gap is open.
        let mut builder = ::http::Request::builder()
            .method("GET")
            .uri("https://reverse_edges.test/many-tiny");
        for i in 0..200 {
            builder = builder.header(format!("x-tiny-{i:04}"), "b");
        }
        let request = builder.body(()).expect("request");
        let result = h3_request_to_hyper(request, qpx_http::body::Body::empty());
        assert!(
            result.is_err(),
            "many-tiny-header H3 request must be refused at the count ceiling",
        );
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
