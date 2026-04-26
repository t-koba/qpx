use anyhow::{anyhow, Result};
use bytes::Bytes;

pub(crate) fn sanitize_response_for_h3(
    head: &mut http::Response<()>,
    body: &mut Bytes,
    request_method: &http::Method,
) -> Result<bool> {
    let status = head.status();
    if status.is_informational() {
        return Err(anyhow!(
            "final HTTP/3 response status must not be informational: {}",
            status
        ));
    }
    let status_forbids_body =
        status == http::StatusCode::NO_CONTENT || status == http::StatusCode::RESET_CONTENT;
    let preserve_head_content_length =
        *request_method == http::Method::HEAD || status == http::StatusCode::NOT_MODIFIED;
    let body_allowed = *request_method != http::Method::HEAD
        && !status_forbids_body
        && status != http::StatusCode::NOT_MODIFIED;
    if !body_allowed {
        *body = Bytes::new();
    }

    let headers = head.headers_mut();
    sanitize_h3_regular_headers(headers);

    let parsed_content_length = parse_content_length(headers);
    headers.remove(http::header::CONTENT_LENGTH);
    match parsed_content_length {
        Ok(Some(length)) if preserve_head_content_length => {
            headers.insert(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str(&length.to_string())?,
            );
        }
        Ok(Some(length)) if body_allowed && length == body.len() as u64 => {
            headers.insert(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str(&length.to_string())?,
            );
        }
        Ok(Some(_)) if body_allowed => {
            headers.insert(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str(&body.len().to_string())?,
            );
        }
        Ok(None) if body_allowed && !body.is_empty() => {
            headers.insert(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str(&body.len().to_string())?,
            );
        }
        Ok(Some(_)) | Ok(None) | Err(_) => {}
    }

    validate_h3_regular_headers(headers)?;
    Ok(body_allowed)
}

pub(crate) fn sanitize_interim_response_for_h3(head: &mut http::Response<()>) -> Result<()> {
    if !head.status().is_informational() {
        return Err(anyhow!(
            "interim HTTP/3 response status must be informational: {}",
            head.status()
        ));
    }
    if head.status() == http::StatusCode::SWITCHING_PROTOCOLS {
        return Err(anyhow!("HTTP/3 interim responses must not use 101"));
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
        if is_prohibited_trailer_field(name.as_str()) {
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
    head.headers_mut().remove(http::header::CONTENT_LENGTH);
    validate_h3_regular_headers(head.headers())?;
    Ok(Some(true))
}

pub(crate) fn parse_content_length(headers: &http::HeaderMap) -> Result<Option<u64>> {
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

fn is_prohibited_trailer_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) {
        return true;
    }
    matches!(
        lower.as_str(),
        "content-length"
            | "host"
            | "authorization"
            | "www-authenticate"
            | "authentication-info"
            | "cookie"
            | "set-cookie"
            | "expect"
            | "range"
            | "if-match"
            | "if-none-match"
            | "if-modified-since"
            | "if-unmodified-since"
            | "if-range"
            | "max-forwards"
            | "cache-control"
            | "expires"
            | "pragma"
            | "age"
            | "content-type"
            | "content-encoding"
            | "content-language"
            | "content-location"
            | "content-range"
    )
}
