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
    for chunk in body.split(marker.as_str()) {
        let chunk = chunk.trim();
        if chunk.is_empty() || chunk == "--" {
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
        for line in chunk.lines() {
            if !line
                .to_ascii_lowercase()
                .starts_with("content-disposition:")
            {
                continue;
            }
            if let Some(name) = disposition_param(line, "name")
                && let Some(limit) = profile.multipart.max_name_bytes
                && name.len() > limit
            {
                return Some(payload_too_large(
                    "multipart field name exceeds http_guard limit",
                ));
            }
            if let Some(filename) = disposition_param(line, "filename")
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
        let mut reader = std::io::BufReader::new(reader);
        let mut line = String::new();
        let mut parts = 0usize;
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Ok(None);
            }
            let trimmed = line.trim();
            if trimmed.starts_with(marker.as_str()) {
                if trimmed.ends_with("--") {
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
                continue;
            }
            if !line
                .to_ascii_lowercase()
                .starts_with("content-disposition:")
            {
                continue;
            }
            if let Some(name) = disposition_param(&line, "name")
                && let Some(limit) = profile.multipart.max_name_bytes
                && name.len() > limit
            {
                return Ok(Some(payload_too_large(
                    "multipart field name exceeds http_guard limit",
                )));
            }
            if let Some(filename) = disposition_param(&line, "filename")
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

pub(super) fn multipart_boundary(req: &hyper::Request<qpx_http::body::Body>) -> Option<String> {
    multipart_boundary_from_headers(req.headers())
}

pub(super) fn multipart_boundary_from_headers(headers: &http::HeaderMap) -> Option<String> {
    let value = headers.get(http::header::CONTENT_TYPE)?.to_str().ok()?;
    if !value
        .to_ascii_lowercase()
        .starts_with("multipart/form-data")
    {
        return None;
    }
    value
        .split(';')
        .skip(1)
        .find_map(|part| {
            let mut split = part.trim().splitn(2, '=');
            let key = split.next()?.trim();
            let value = split.next()?.trim().trim_matches('"');
            key.eq_ignore_ascii_case("boundary")
                .then(|| value.to_string())
        })
        .filter(|boundary| !boundary.is_empty())
}

fn disposition_param(line: &str, name: &str) -> Option<String> {
    line.split(';').skip(1).find_map(|part| {
        let mut split = part.trim().splitn(2, '=');
        let key = split.next()?.trim();
        let value = split.next()?.trim().trim_matches('"');
        key.eq_ignore_ascii_case(name).then(|| value.to_string())
    })
}
