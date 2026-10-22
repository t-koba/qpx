use crate::H3Result as Result;
use anyhow::anyhow;

pub(crate) fn sanitize_interim_response_for_h3(head: &mut http::Response<()>) -> Result<()> {
    if !head.status().is_informational() {
        return Err(anyhow!(
            "interim HTTP/3 response status must be informational: {}",
            head.status()
        )
        .into());
    }
    if head.status() == http::StatusCode::SWITCHING_PROTOCOLS {
        return Err(anyhow!("HTTP/3 interim responses must not use 101").into());
    }
    sanitize_h3_regular_headers(head.headers_mut());
    head.headers_mut().remove(http::header::CONTENT_LENGTH);
    validate_h3_regular_headers(head.headers())
}

pub(crate) fn sanitize_trailers_for_h3(trailers: &mut http::HeaderMap) -> Result<()> {
    sanitize_h3_regular_headers(trailers);
    trailers.remove(http::header::CONTENT_LENGTH);
    let mut removed = Vec::new();
    for name in trailers.keys() {
        if crate::qpack_fields::is_prohibited_trailer_field(name.as_str()) {
            removed.push(name.clone());
        }
    }
    for name in removed {
        trailers.remove(name);
    }
    validate_h3_regular_headers(trailers)
}

pub(crate) fn sanitize_streaming_response_head_for_h3(
    head: &mut http::Response<()>,
) -> Result<Option<bool>> {
    if head.status().is_informational() {
        sanitize_interim_response_for_h3(head)?;
        return Ok(None);
    }
    if head.status() == http::StatusCode::NO_CONTENT
        || head.status() == http::StatusCode::RESET_CONTENT
        || head.status() == http::StatusCode::NOT_MODIFIED
    {
        sanitize_h3_regular_headers(head.headers_mut());
        head.headers_mut().remove(http::header::CONTENT_LENGTH);
        validate_h3_regular_headers(head.headers())?;
        return Ok(Some(false));
    }
    sanitize_h3_regular_headers(head.headers_mut());
    // RFC 9110 section 8.6: the value a sender writes is one decimal, so
    // a declaration that reached this writer leaves in the field's
    // canonical form - one field whose value is the resolved decimal.
    // A declaration the owner refuses names no length, so the field is
    // dropped rather than sent as it was received.
    match parse_content_length(head.headers()) {
        Ok(Some(length)) => {
            head.headers_mut().insert(
                http::header::CONTENT_LENGTH,
                qpx_core::http_content_length::canonical_content_length_value(length),
            );
        }
        Ok(None) => {}
        Err(_) => {
            head.headers_mut().remove(http::header::CONTENT_LENGTH);
        }
    }
    validate_h3_regular_headers(head.headers())?;
    Ok(Some(true))
}

/// The Content-Length that a header set declares.
///
/// The declared Content-Length has one owner, in `qpx-core`, so the HTTP/3
/// path reads the field with the same member grammar and the same conflict
/// rule as the HTTP/1 and HTTP/2 paths: every member of every value declares
/// the same length, and a member that is not a `1*DIGIT` sequence is
/// refused. A leading plus sign is not field syntax, so it is refused here
/// too.
pub(crate) fn parse_content_length(headers: &http::HeaderMap) -> Result<Option<u64>> {
    qpx_core::http_content_length::declared_content_length(headers)
        .map_err(|err| anyhow!("invalid Content-Length: {err}").into())
}

fn sanitize_h3_regular_headers(headers: &mut http::HeaderMap) {
    for forbidden in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(forbidden);
    }
    headers.remove(http::header::TE);
}

fn validate_h3_regular_headers(headers: &http::HeaderMap) -> Result<()> {
    for (name, value) in headers.iter() {
        crate::qpack::validate_h3_regular_field(name.as_str(), value.as_bytes())
            .map_err(|err| anyhow!(err.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_content_length;

    fn headers_with(values: &[&str]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for value in values {
            headers.append(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str(value).expect("header value"),
            );
        }
        headers
    }

    #[test]
    fn the_declared_length_is_read_by_the_owner() {
        assert_eq!(
            parse_content_length(&headers_with(&["5"])).expect("length"),
            Some(5)
        );
        // A comma list of equal members declares one length.
        assert_eq!(
            parse_content_length(&headers_with(&["5, 5"])).expect("length"),
            Some(5)
        );
        assert_eq!(
            parse_content_length(&headers_with(&["5", "5"])).expect("length"),
            Some(5)
        );
        assert_eq!(
            parse_content_length(&headers_with(&[])).expect("length"),
            None
        );
    }

    #[test]
    fn a_signed_declared_length_is_refused() {
        let err = parse_content_length(&headers_with(&["+5"])).expect_err("signed length");
        assert!(err.to_string().contains("invalid Content-Length"), "{err}");
    }

    #[test]
    fn conflicting_declared_lengths_are_refused() {
        let err = parse_content_length(&headers_with(&["5, 6"])).expect_err("conflict");
        assert!(err.to_string().contains("invalid Content-Length"), "{err}");
        let err = parse_content_length(&headers_with(&["5", "6"])).expect_err("conflict");
        assert!(err.to_string().contains("invalid Content-Length"), "{err}");
    }
}
