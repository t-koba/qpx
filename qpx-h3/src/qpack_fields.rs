use crate::qpack::HeaderDecodeError;
use anyhow::Result;
use http::{HeaderMap, HeaderName, HeaderValue};

pub(crate) fn validate_h3_regular_field(
    name: &str,
    value: &[u8],
) -> std::result::Result<(), HeaderDecodeError> {
    if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(HeaderDecodeError::message(format!(
            "HTTP/3 field name must be lowercase: {name}"
        )));
    }
    let header_name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
    match header_name.as_str() {
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" => Err(
            HeaderDecodeError::message(format!("HTTP/3 forbids connection-specific field {name}")),
        ),
        "te" if !te_value_allows_only_trailers(value) => Err(HeaderDecodeError::message(
            "HTTP/3 TE field may only contain trailers",
        )),
        _ => Ok(()),
    }
}

pub(crate) fn validate_h3_response_field(
    name: &str,
    value: &[u8],
) -> std::result::Result<(), HeaderDecodeError> {
    validate_h3_regular_field(name, value)?;
    let header_name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
    if header_name == http::header::TE {
        return Err(HeaderDecodeError::message(
            "HTTP/3 response fields must not contain TE",
        ));
    }
    Ok(())
}

pub(crate) fn validate_h3_trailer_field(
    name: &str,
    value: &[u8],
) -> std::result::Result<(), HeaderDecodeError> {
    validate_h3_regular_field(name, value)?;
    if is_prohibited_trailer_field(name) {
        return Err(HeaderDecodeError::message(format!(
            "trailers must not contain field {name}"
        )));
    }
    Ok(())
}

pub(crate) fn append_header(headers: &mut HeaderMap, name: &str, value: &[u8]) -> Result<()> {
    let name = HeaderName::from_bytes(name.as_bytes())?;
    let value = HeaderValue::from_bytes(value)?;
    if name == http::header::COOKIE {
        if let Some(existing) = headers.get(http::header::COOKIE).cloned() {
            let mut merged =
                Vec::with_capacity(existing.as_bytes().len() + 2 + value.as_bytes().len());
            merged.extend_from_slice(existing.as_bytes());
            merged.extend_from_slice(b"; ");
            merged.extend_from_slice(value.as_bytes());
            headers.insert(
                http::header::COOKIE,
                HeaderValue::from_bytes(merged.as_slice())?,
            );
            return Ok(());
        }
    }
    headers.append(name, value);
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

fn te_value_allows_only_trailers(value: &[u8]) -> bool {
    let Ok(value) = std::str::from_utf8(value) else {
        return false;
    };
    let mut saw_token = false;
    for token in value.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return false;
        }
        saw_token = true;
        if !token.eq_ignore_ascii_case("trailers") {
            return false;
        }
    }
    saw_token
}
