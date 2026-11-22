use anyhow::Result;
#[cfg(test)]
use bytes::Bytes;
use qpx_core::config::HttpGuardProfileConfig;
use std::io::BufRead;

use super::{HttpGuardReject, payload_too_large};

#[cfg(test)]
pub(super) fn validate_multipart_limits(
    bytes: &Bytes,
    boundary: Option<&str>,
    profile: &HttpGuardProfileConfig,
) -> Option<HttpGuardReject> {
    if profile.multipart.max_parts.is_none()
        && profile.multipart.max_name_bytes.is_none()
        && profile.multipart.max_filename_bytes.is_none()
    {
        return None;
    }
    let boundary = boundary?;
    let marker = format!("--{boundary}");
    let body = String::from_utf8_lossy(bytes.as_ref());
    let mut parts = 0usize;
    for (chunk_index, chunk) in body.split(marker.as_str()).enumerate() {
        let chunk = chunk.trim();
        if chunk_index == 0 || chunk.is_empty() || chunk == "--" {
            continue;
        }
        parts += 1;
        if let Some(limit) = profile.multipart.max_parts
            && parts > limit
        {
            return Some(payload_too_large(
                "multipart part count exceeds http_guard limit",
            ));
        }
        let mut in_headers = true;
        for line in chunk.lines() {
            if line.trim().is_empty() {
                in_headers = false;
                continue;
            }
            if !in_headers
                || !line
                    .to_ascii_lowercase()
                    .starts_with("content-disposition:")
            {
                continue;
            }
            if let Some(name) = semicolon_parameter(line, "name")
                && let Some(limit) = profile.multipart.max_name_bytes
                && name.len() > limit
            {
                return Some(payload_too_large(
                    "multipart field name exceeds http_guard limit",
                ));
            }
            if let Some(filename) = semicolon_parameter(line, "filename")
                && let Some(limit) = profile.multipart.max_filename_bytes
                && filename.len() > limit
            {
                return Some(payload_too_large(
                    "multipart filename exceeds http_guard limit",
                ));
            }
        }
    }
    None
}

pub(super) async fn validate_multipart_limits_reader(
    body: &crate::http::body::size::ObservedBodyReader,
    boundary: Option<String>,
    profile: HttpGuardProfileConfig,
) -> Result<Option<HttpGuardReject>> {
    if profile.multipart.max_parts.is_none()
        && profile.multipart.max_name_bytes.is_none()
        && profile.multipart.max_filename_bytes.is_none()
    {
        return Ok(None);
    }
    let Some(boundary) = boundary else {
        return Ok(None);
    };
    body.with_blocking_reader(move |reader| {
        let marker = format!("--{boundary}");
        let disposition = b"content-disposition:";
        let mut reader = std::io::BufReader::new(reader);
        let mut line = Vec::new();
        let mut parts = 0usize;
        let mut in_headers = false;
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                return Ok(None);
            }
            let trimmed = line.trim_ascii();
            if trimmed.starts_with(marker.as_bytes()) {
                if trimmed.ends_with(b"--") {
                    return Ok(None);
                }
                parts += 1;
                if let Some(limit) = profile.multipart.max_parts
                    && parts > limit
                {
                    return Ok(Some(payload_too_large(
                        "multipart part count exceeds http_guard limit",
                    )));
                }
                in_headers = true;
                continue;
            }
            if line.trim_ascii().is_empty() {
                in_headers = false;
                continue;
            }
            if !in_headers
                || !line
                    .get(..disposition.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(disposition))
            {
                continue;
            }
            let line = String::from_utf8_lossy(&line);
            if let Some(name) = semicolon_parameter(&line, "name")
                && let Some(limit) = profile.multipart.max_name_bytes
                && name.len() > limit
            {
                return Ok(Some(payload_too_large(
                    "multipart field name exceeds http_guard limit",
                )));
            }
            if let Some(filename) = semicolon_parameter(&line, "filename")
                && let Some(limit) = profile.multipart.max_filename_bytes
                && filename.len() > limit
            {
                return Ok(Some(payload_too_large(
                    "multipart filename exceeds http_guard limit",
                )));
            }
        }
    })
    .await
}

pub(super) fn multipart_boundary_from_headers(
    headers: &qpx_core::http_message::Headers,
) -> Option<String> {
    let name = qpx_core::http_message::OrdinaryHeaderName::try_from(http::header::CONTENT_TYPE)
        .expect("Content-Type is ordinary");
    multipart_boundary(headers.get(&name)?.to_str().ok()?)
}

pub(super) fn multipart_boundary(value: &str) -> Option<String> {
    if !value
        .to_ascii_lowercase()
        .starts_with("multipart/form-data")
    {
        return None;
    }
    semicolon_parameter(value, "boundary").filter(|boundary| !boundary.is_empty())
}

fn semicolon_parameter(value: &str, name: &str) -> Option<String> {
    value.split(';').skip(1).find_map(|part| {
        let mut split = part.trim().splitn(2, '=');
        let key = split.next()?.trim();
        let value = split.next()?.trim().trim_matches('"');
        key.eq_ignore_ascii_case(name).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::semicolon_parameter;

    #[test]
    fn semicolon_parameter_preserves_first_match_and_value_text() {
        let value = r#"form-data; NAME = "first=value"; name=second"#;
        assert_eq!(
            semicolon_parameter(value, "name"),
            Some("first=value".to_owned())
        );
        assert_eq!(semicolon_parameter(value, "missing"), None);
    }

    #[test]
    fn semicolon_parameter_ignores_the_initial_token_and_unassigned_parts() {
        assert_eq!(
            semicolon_parameter("boundary=initial; name=actual", "boundary"),
            None
        );
        assert_eq!(semicolon_parameter("form-data; name", "name"), None);
    }
}
