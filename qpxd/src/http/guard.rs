use crate::http::body::Body;
use anyhow::Result;
use bytes::Bytes;
use hyper::{Request, StatusCode};
use qpx_core::config::HttpGuardProfileConfig;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct CompiledHttpGuardProfile {
    profile: HttpGuardProfileConfig,
}

#[derive(Debug, Clone)]
pub(crate) struct HttpGuardReject {
    pub(crate) status: StatusCode,
    pub(crate) body: String,
}

pub(crate) fn compile_http_guard_profiles(
    profiles: &[HttpGuardProfileConfig],
) -> HashMap<String, Arc<CompiledHttpGuardProfile>> {
    profiles
        .iter()
        .map(|profile| {
            (
                profile.name.clone(),
                Arc::new(CompiledHttpGuardProfile {
                    profile: profile.clone(),
                }),
            )
        })
        .collect()
}

impl CompiledHttpGuardProfile {
    pub(crate) fn requires_request_body_buffering(&self, req: &Request<Body>) -> bool {
        self.profile.limits.body_bytes.is_some()
            || self.profile.json.max_depth.is_some()
            || self.profile.json.max_fields.is_some()
            || (multipart_boundary(req).is_some()
                && (self.profile.multipart.max_parts.is_some()
                    || self.profile.multipart.max_name_bytes.is_some()
                    || self.profile.multipart.max_filename_bytes.is_some()))
    }

    pub(crate) fn request_body_observation_cap(&self) -> Option<usize> {
        self.profile.limits.body_bytes
    }

    pub(crate) fn evaluate_request(&self, req: &Request<Body>) -> Result<Option<HttpGuardReject>> {
        if self.profile.protocol_safety.smuggling {
            if let Some(reject) = validate_smuggling(req) {
                return Ok(Some(reject));
            }
        }
        if self.profile.protocol_safety.invalid_framing {
            if let Some(reject) = validate_invalid_framing(req) {
                return Ok(Some(reject));
            }
        }

        let path = normalized_path(req, self.profile.normalize.path);
        if let Some(limit) = self.profile.limits.path_bytes {
            if path.len() > limit {
                return Ok(Some(payload_too_large(
                    "request path exceeds http_guard limit",
                )));
            }
        }

        let query = normalized_query(req, self.profile.normalize.query);
        if let Some(reject) = validate_query_limits(&query, &self.profile) {
            return Ok(Some(reject));
        }

        if let Some(reject) = validate_header_limits(req, &self.profile) {
            return Ok(Some(reject));
        }

        let body_size = crate::http::body_size::observed_request_size(req);
        if let Some(limit) = self.profile.limits.body_bytes {
            if let Some(size) = body_size {
                if size as usize > limit {
                    return Ok(Some(payload_too_large(
                        "request body exceeds http_guard limit",
                    )));
                }
            }
        }

        let buffered = crate::http::body_size::observed_request_bytes(req);
        if let Some(bytes) = buffered {
            if let Some(reject) = validate_json_limits(bytes, req, &self.profile) {
                return Ok(Some(reject));
            }
            if let Some(reject) = validate_multipart_limits(bytes, req, &self.profile) {
                return Ok(Some(reject));
            }
        }

        Ok(None)
    }
}

fn validate_header_limits(
    req: &Request<Body>,
    profile: &HttpGuardProfileConfig,
) -> Option<HttpGuardReject> {
    if let Some(limit) = profile.limits.header_count {
        if req.headers().len() > limit {
            return Some(bad_request("header count exceeds http_guard limit"));
        }
    }
    if let Some(limit) = profile.limits.header_bytes {
        let total = req
            .headers()
            .iter()
            .map(|(name, value)| {
                let value = if profile.normalize.headers {
                    value.to_str().unwrap_or_default().trim().len()
                } else {
                    value.as_bytes().len()
                };
                name.as_str().len() + value
            })
            .sum::<usize>();
        if total > limit {
            return Some(payload_too_large("header bytes exceed http_guard limit"));
        }
    }
    None
}

fn validate_query_limits(
    query: &[(String, String)],
    profile: &HttpGuardProfileConfig,
) -> Option<HttpGuardReject> {
    if let Some(limit) = profile.limits.query_pairs {
        if query.len() > limit {
            return Some(bad_request("query pair count exceeds http_guard limit"));
        }
    }
    if let Some(limit) = profile.limits.query_key_bytes {
        if query.iter().any(|(key, _)| key.len() > limit) {
            return Some(bad_request("query key exceeds http_guard limit"));
        }
    }
    if let Some(limit) = profile.limits.query_value_bytes {
        if query.iter().any(|(_, value)| value.len() > limit) {
            return Some(bad_request("query value exceeds http_guard limit"));
        }
    }
    None
}

fn validate_json_limits(
    bytes: &Bytes,
    req: &Request<Body>,
    profile: &HttpGuardProfileConfig,
) -> Option<HttpGuardReject> {
    if profile.json.max_depth.is_none() && profile.json.max_fields.is_none() {
        return None;
    }
    let content_type = req
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())?;
    if !(content_type.starts_with("application/json") || content_type.contains("+json")) {
        return None;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes.as_ref()) else {
        return Some(bad_request("invalid JSON body for http_guard profile"));
    };
    let (depth, fields) = json_stats(&value, 1);
    if let Some(limit) = profile.json.max_depth {
        if depth > limit {
            return Some(payload_too_large("JSON depth exceeds http_guard limit"));
        }
    }
    if let Some(limit) = profile.json.max_fields {
        if fields > limit {
            return Some(payload_too_large(
                "JSON field count exceeds http_guard limit",
            ));
        }
    }
    None
}

fn validate_multipart_limits(
    bytes: &Bytes,
    req: &Request<Body>,
    profile: &HttpGuardProfileConfig,
) -> Option<HttpGuardReject> {
    if profile.multipart.max_parts.is_none()
        && profile.multipart.max_name_bytes.is_none()
        && profile.multipart.max_filename_bytes.is_none()
    {
        return None;
    }
    let boundary = multipart_boundary(req)?;
    let marker = format!("--{boundary}");
    let body = String::from_utf8_lossy(bytes.as_ref());
    let mut parts = 0usize;
    for chunk in body.split(marker.as_str()) {
        let chunk = chunk.trim();
        if chunk.is_empty() || chunk == "--" {
            continue;
        }
        parts += 1;
        if let Some(limit) = profile.multipart.max_parts {
            if parts > limit {
                return Some(payload_too_large(
                    "multipart part count exceeds http_guard limit",
                ));
            }
        }
        for line in chunk.lines() {
            if !line
                .to_ascii_lowercase()
                .starts_with("content-disposition:")
            {
                continue;
            }
            if let Some(name) = disposition_param(line, "name") {
                if let Some(limit) = profile.multipart.max_name_bytes {
                    if name.len() > limit {
                        return Some(payload_too_large(
                            "multipart field name exceeds http_guard limit",
                        ));
                    }
                }
            }
            if let Some(filename) = disposition_param(line, "filename") {
                if let Some(limit) = profile.multipart.max_filename_bytes {
                    if filename.len() > limit {
                        return Some(payload_too_large(
                            "multipart filename exceeds http_guard limit",
                        ));
                    }
                }
            }
        }
    }
    None
}

fn validate_smuggling(req: &Request<Body>) -> Option<HttpGuardReject> {
    let content_lengths = req
        .headers()
        .get_all(http::header::CONTENT_LENGTH)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::trim))
        .filter(|value| !value.is_empty())
        .collect::<std::collections::HashSet<_>>();
    if content_lengths.len() > 1 {
        return Some(bad_request("multiple conflicting Content-Length headers"));
    }
    if req.headers().contains_key(http::header::TRANSFER_ENCODING)
        && req.headers().contains_key(http::header::CONTENT_LENGTH)
    {
        return Some(bad_request(
            "Transfer-Encoding with Content-Length is not allowed",
        ));
    }
    None
}

fn validate_invalid_framing(req: &Request<Body>) -> Option<HttpGuardReject> {
    if req.version() == http::Version::HTTP_2 || req.version() == http::Version::HTTP_3 {
        if req.headers().contains_key(http::header::CONNECTION) {
            return Some(bad_request(
                "Connection header is not valid on HTTP/2 or HTTP/3 requests",
            ));
        }
        if let Some(value) = req.headers().get(http::header::TE) {
            let Ok(value) = value.to_str() else {
                return Some(bad_request("invalid TE header"));
            };
            if value
                .split(',')
                .map(str::trim)
                .any(|token| !token.eq_ignore_ascii_case("trailers"))
            {
                return Some(bad_request("HTTP/2 and HTTP/3 TE must be trailers"));
            }
        }
    }
    None
}

fn normalized_path(req: &Request<Body>, enabled: bool) -> String {
    let path = req.uri().path();
    if !enabled {
        return path.to_string();
    }
    let mut stack = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                let _ = stack.pop();
            }
            other => stack.push(other),
        }
    }
    format!("/{}", stack.join("/"))
}

fn normalized_query(req: &Request<Body>, enabled: bool) -> Vec<(String, String)> {
    let Some(query) = req.uri().query() else {
        return Vec::new();
    };
    let mut pairs = url::form_urlencoded::parse(query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if enabled {
        pairs.sort();
    }
    pairs
}

fn multipart_boundary(req: &Request<Body>) -> Option<String> {
    let value = req
        .headers()
        .get(http::header::CONTENT_TYPE)?
        .to_str()
        .ok()?;
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

fn json_stats(value: &serde_json::Value, depth: usize) -> (usize, usize) {
    match value {
        serde_json::Value::Array(items) => items.iter().fold((depth, 0usize), |acc, item| {
            let (child_depth, child_fields) = json_stats(item, depth + 1);
            (acc.0.max(child_depth), acc.1 + child_fields)
        }),
        serde_json::Value::Object(map) => map.values().fold((depth, map.len()), |acc, item| {
            let (child_depth, child_fields) = json_stats(item, depth + 1);
            (acc.0.max(child_depth), acc.1 + child_fields)
        }),
        _ => (depth, 0),
    }
}

fn bad_request(message: &str) -> HttpGuardReject {
    HttpGuardReject {
        status: StatusCode::BAD_REQUEST,
        body: message.to_string(),
    }
}

fn payload_too_large(message: &str) -> HttpGuardReject {
    HttpGuardReject {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        body: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_detects_conflicting_content_length() {
        let profile = CompiledHttpGuardProfile {
            profile: HttpGuardProfileConfig {
                name: "strict".to_string(),
                normalize: Default::default(),
                protocol_safety: Default::default(),
                limits: Default::default(),
                json: Default::default(),
                multipart: Default::default(),
            },
        };
        let mut req = Request::builder()
            .uri("http://example.com/")
            .body(Body::empty())
            .expect("request");
        req.headers_mut().append(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("10"),
        );
        req.headers_mut().append(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("11"),
        );
        let reject = profile.evaluate_request(&req).expect("guard");
        assert!(reject.is_some());
    }
}
