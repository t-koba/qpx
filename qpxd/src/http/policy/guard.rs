use anyhow::Result;
use hyper::{Request, StatusCode};
use qpx_core::config::HttpGuardProfileConfig;
use qpx_http::body::Body;
use std::sync::Arc;

mod json;
mod multipart;

#[cfg(test)]
use self::json::validate_json_limits;
use self::json::validate_json_limits_reader;
#[cfg(test)]
use self::multipart::validate_multipart_limits;
use self::multipart::{
    multipart_boundary, multipart_boundary_from_headers, validate_multipart_limits_reader,
};

#[derive(Debug, Clone)]
pub(crate) struct CompiledHttpGuardProfile {
    profile: HttpGuardProfileConfig,
}

#[derive(Debug, Clone)]
pub(crate) struct HttpGuardReject {
    pub(crate) status: StatusCode,
    pub(crate) body: String,
}

pub(crate) fn compile_http_guard_profile(
    profile: &HttpGuardProfileConfig,
) -> Arc<CompiledHttpGuardProfile> {
    Arc::new(CompiledHttpGuardProfile {
        profile: profile.clone(),
    })
}

impl CompiledHttpGuardProfile {
    pub(crate) fn may_require_request_body_buffering(&self) -> bool {
        self.profile.json.max_depth.is_some()
            || self.profile.json.max_fields.is_some()
            || self.profile.multipart.max_parts.is_some()
            || self.profile.multipart.max_name_bytes.is_some()
            || self.profile.multipart.max_filename_bytes.is_some()
    }

    pub(crate) fn requires_request_body_buffering(&self, req: &Request<Body>) -> bool {
        self.profile.json.max_depth.is_some()
            || self.profile.json.max_fields.is_some()
            || (multipart_boundary(req).is_some()
                && (self.profile.multipart.max_parts.is_some()
                    || self.profile.multipart.max_name_bytes.is_some()
                    || self.profile.multipart.max_filename_bytes.is_some()))
    }

    pub(crate) fn request_body_observation_cap(&self) -> Option<usize> {
        self.profile.limits.body_bytes
    }

    pub(crate) fn request_body_streaming_limit(&self) -> Option<usize> {
        self.profile.limits.body_bytes
    }

    pub(crate) fn evaluate_request_async(
        &self,
        req: &Request<Body>,
    ) -> impl std::future::Future<Output = Result<Option<HttpGuardReject>>> + Send + 'static {
        let head_reject = self.evaluate_request_head(req);
        let profile = self.profile.clone();
        let content_type = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let boundary = multipart_boundary_from_headers(req.headers());
        let body_reader = crate::http::body::size::observed_request_body_reader(req);
        async move {
            if let Some(reject) = head_reject? {
                return Ok(Some(reject));
            }
            if let Some(body_reader) = body_reader {
                if let Some(reject) = validate_json_limits_reader(
                    &body_reader,
                    content_type.as_deref(),
                    profile.clone(),
                )
                .await?
                {
                    return Ok(Some(reject));
                }
                if let Some(reject) =
                    validate_multipart_limits_reader(&body_reader, boundary.clone(), profile)
                        .await?
                {
                    return Ok(Some(reject));
                }
            }
            Ok(None)
        }
    }

    #[cfg(test)]
    pub(crate) fn evaluate_request(&self, req: &Request<Body>) -> Result<Option<HttpGuardReject>> {
        if let Some(reject) = self.evaluate_request_head(req)? {
            return Ok(Some(reject));
        }
        let content_type = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        let boundary = multipart_boundary_from_headers(req.headers());
        let buffered = crate::http::body::size::observed_request_bytes(req);
        if let Some(bytes) = buffered {
            if let Some(reject) = validate_json_limits(&bytes, content_type, &self.profile) {
                return Ok(Some(reject));
            }
            if let Some(reject) =
                validate_multipart_limits(&bytes, boundary.as_deref(), &self.profile)
            {
                return Ok(Some(reject));
            }
        }
        Ok(None)
    }

    fn evaluate_request_head(&self, req: &Request<Body>) -> Result<Option<HttpGuardReject>> {
        if self.profile.protocol_safety.smuggling
            && let Some(reject) = validate_smuggling(req)
        {
            return Ok(Some(reject));
        }
        if self.profile.protocol_safety.invalid_framing
            && let Some(reject) = validate_invalid_framing(req)
        {
            return Ok(Some(reject));
        }

        let path = normalized_path(req, self.profile.normalize.path);
        if let Some(limit) = self.profile.limits.path_bytes
            && path.len() > limit
        {
            return Ok(Some(payload_too_large(
                "request path exceeds http_guard limit",
            )));
        }

        let query = normalized_query(req, self.profile.normalize.query);
        if let Some(reject) = validate_query_limits(&query, &self.profile) {
            return Ok(Some(reject));
        }

        if let Some(reject) = validate_header_limits(req, &self.profile) {
            return Ok(Some(reject));
        }

        let body_size = crate::http::body::size::observed_request_size(req);
        if let Some(limit) = self.profile.limits.body_bytes
            && let Some(size) = body_size
            && size as usize > limit
        {
            return Ok(Some(payload_too_large(
                "request body exceeds http_guard limit",
            )));
        }

        Ok(None)
    }
}

fn validate_header_limits(
    req: &Request<Body>,
    profile: &HttpGuardProfileConfig,
) -> Option<HttpGuardReject> {
    if let Some(limit) = profile.limits.header_count
        && req.headers().len() > limit
    {
        return Some(bad_request("header count exceeds http_guard limit"));
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
    if let Some(limit) = profile.limits.query_pairs
        && query.len() > limit
    {
        return Some(bad_request("query pair count exceeds http_guard limit"));
    }
    if let Some(limit) = profile.limits.query_key_bytes
        && query.iter().any(|(key, _)| key.len() > limit)
    {
        return Some(bad_request("query key exceeds http_guard limit"));
    }
    if let Some(limit) = profile.limits.query_value_bytes
        && query.iter().any(|(_, value)| value.len() > limit)
    {
        return Some(bad_request("query value exceeds http_guard limit"));
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

pub(super) fn bad_request(message: &str) -> HttpGuardReject {
    HttpGuardReject {
        status: StatusCode::BAD_REQUEST,
        body: message.to_string(),
    }
}

pub(super) fn payload_too_large(message: &str) -> HttpGuardReject {
    HttpGuardReject {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        body: message.to_string(),
    }
}

#[cfg(test)]
mod tests;
