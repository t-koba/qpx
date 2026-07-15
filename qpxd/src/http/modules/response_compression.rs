use super::headers::parse_module_settings;
use super::{
    BodyAccess, HttpModule, HttpModuleCapabilities, HttpModuleContext, HttpModuleEvent,
    HttpModuleFactory, HttpModuleStage, ModuleStages,
};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use http::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, VARY,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use hyper::Response;
use qpx_core::config::{HttpModuleConfig, ResponseCompressionModuleConfig};
use qpx_http::body::{Body, to_bytes};
use qpx_http::compression_dictionary::{
    encode_dcb, encode_dcz, parse_available_dictionary, parse_dictionary_id,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::time::Duration;

#[cfg(test)]
use super::HttpModuleRequestView;

mod accept;
mod metrics;
mod streaming;

use self::accept::{accept_encoding_q, append_vary_accept_encoding, parse_accept_encoding};
use self::streaming::{CompressionPool, ContentEncoding, stream_compressed_body};

pub(super) struct ResponseCompressionModuleFactory;

impl HttpModuleFactory for ResponseCompressionModuleFactory {
    fn build(&self, spec: &HttpModuleConfig) -> Result<Arc<dyn HttpModule>> {
        Ok(Arc::new(ResponseCompressionModule::new(
            parse_module_settings(spec)?,
        )?))
    }
}

#[derive(Clone)]
struct ResponseCompressionModule {
    config: ResponseCompressionModuleConfig,
    pool: Arc<CompressionPool>,
    dictionary: Option<Arc<[u8]>>,
    dictionary_hash: Option<[u8; 32]>,
}

#[derive(Clone)]
struct CompressionRequest {
    method: Method,
    headers: HeaderMap,
}

impl CompressionRequest {
    fn from_request(request: &hyper::Request<Body>) -> Option<Self> {
        if !request.headers().contains_key(ACCEPT_ENCODING) {
            return None;
        }
        let mut headers = HeaderMap::with_capacity(3);
        for name in [
            ACCEPT_ENCODING,
            http::HeaderName::from_static("available-dictionary"),
            http::HeaderName::from_static("dictionary-id"),
        ] {
            for value in request.headers().get_all(&name) {
                headers.append(name.clone(), value.clone());
            }
        }
        Some(Self {
            method: request.method().clone(),
            headers,
        })
    }
}

impl ResponseCompressionModule {
    fn new(config: ResponseCompressionModuleConfig) -> Result<Self> {
        let pool = Arc::new(CompressionPool::new(config.worker_count));
        let dictionary = config
            .dictionary
            .as_ref()
            .map(|profile| std::fs::read(&profile.path))
            .transpose()
            .map_err(|error| anyhow!("failed to read compression dictionary: {error}"))?
            .map(Arc::<[u8]>::from);
        let dictionary_hash = dictionary
            .as_deref()
            .map(|body| <[u8; 32]>::from(Sha256::digest(body)));
        Ok(Self {
            config,
            pool,
            dictionary,
            dictionary_hash,
        })
    }

    async fn compress(
        &self,
        ctx: &HttpModuleContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        let Some(compression_request) = ctx.extensions().get::<CompressionRequest>() else {
            return Ok(response);
        };
        let response = if self.config.dictionary.is_some() {
            let request_method = compression_request.method.clone();
            let request_headers = compression_request.headers.clone();
            match self
                .compress_with_dictionary(ctx, &request_method, &request_headers, response)
                .await?
            {
                DictionaryCompressionOutcome::Compressed(response) => return Ok(response),
                DictionaryCompressionOutcome::Unchanged(response) => response,
            }
        } else {
            response
        };
        let Some(encoding) = select_response_encoding_parts(
            &compression_request.method,
            &compression_request.headers,
            &self.config,
            &response,
        )?
        else {
            return Ok(response);
        };
        let (mut parts, body) = response.into_parts();
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.remove(ETAG);
        parts.headers.insert(
            CONTENT_ENCODING,
            HeaderValue::from_static(encoding.http_name()),
        );
        append_vary_accept_encoding(&mut parts.headers);
        let body_read_timeout = Duration::from_millis(
            ctx.runtime_state()
                .plan
                .limits
                .timeouts
                .upstream_http_timeout_ms
                .max(1),
        );
        let body = stream_compressed_body(
            body,
            encoding,
            &self.config,
            self.pool.clone(),
            body_read_timeout,
            ctx.runtime_state().plan.limits.body.body_channel_capacity,
        );
        Ok(Response::from_parts(parts, body))
    }

    async fn compress_with_dictionary(
        &self,
        ctx: &HttpModuleContext,
        request_method: &Method,
        request_headers: &HeaderMap,
        response: Response<Body>,
    ) -> Result<DictionaryCompressionOutcome> {
        let Some(profile) = self.config.dictionary.as_ref() else {
            return Ok(DictionaryCompressionOutcome::Unchanged(response));
        };
        let Some(dictionary) = self.dictionary.as_deref() else {
            return Err(anyhow!("configured compression dictionary is unavailable"));
        };
        let Some(expected_hash) = self.dictionary_hash else {
            return Err(anyhow!(
                "configured compression dictionary hash is unavailable"
            ));
        };
        let available = request_headers
            .get("available-dictionary")
            .map(|value| parse_available_dictionary(value.as_bytes()))
            .transpose()?;
        let dictionary_id = request_headers
            .get("dictionary-id")
            .map(|value| parse_dictionary_id(value.as_bytes()))
            .transpose()?;
        let preferences = parse_accept_encoding(request_headers);
        if available != Some(expected_hash)
            || dictionary_id.as_deref() != profile.id.as_deref()
            || accept_encoding_q(&profile.encoding, &preferences) <= 0
            || !response_is_compressible(request_method, &self.config, &response)?
        {
            return Ok(DictionaryCompressionOutcome::Unchanged(response));
        }
        let (mut parts, body) = response.into_parts();
        let timeout_duration = Duration::from_millis(
            ctx.runtime_state()
                .plan
                .limits
                .timeouts
                .upstream_http_timeout_ms
                .max(1),
        );
        let body = tokio::time::timeout(timeout_duration, to_bytes(body))
            .await
            .map_err(|_| anyhow!("dictionary compression body read timed out"))??;
        if body.len() > self.config.max_body_bytes {
            return Err(anyhow!(
                "dictionary compression body exceeded configured maximum"
            ));
        }
        let encoded = match profile.encoding.as_str() {
            "dcb" => encode_dcb(&body, dictionary, self.config.brotli_level)?,
            "dcz" => encode_dcz(&body, dictionary, self.config.zstd_level)?,
            _ => return Err(anyhow!("unsupported dictionary compression encoding")),
        };
        parts.headers.remove(ETAG);
        parts
            .headers
            .insert(CONTENT_ENCODING, HeaderValue::from_str(&profile.encoding)?);
        parts.headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&encoded.len().to_string())?,
        );
        append_vary_token(&mut parts.headers, "available-dictionary")?;
        append_vary_token(&mut parts.headers, "dictionary-id")?;
        append_vary_accept_encoding(&mut parts.headers);
        Ok(DictionaryCompressionOutcome::Compressed(
            Response::from_parts(parts, Body::from(encoded)),
        ))
    }
}

enum DictionaryCompressionOutcome {
    Compressed(Response<Body>),
    Unchanged(Response<Body>),
}

#[async_trait]
impl HttpModule for ResponseCompressionModule {
    fn order(&self) -> i16 {
        100
    }

    fn capabilities(&self) -> HttpModuleCapabilities {
        let mut stages = ModuleStages::REQUEST_HEADERS;
        stages.insert(ModuleStages::DOWNSTREAM_RESPONSE);
        let mut capabilities = HttpModuleCapabilities::headers_only(stages);
        capabilities.body_access = BodyAccess::Streaming;
        capabilities.mutates_response_headers = true;
        capabilities
    }

    fn applies_to_request_headers(&self, request: &hyper::Request<Body>) -> bool {
        request.headers().contains_key(ACCEPT_ENCODING)
    }

    fn is_inactive_for_request(&self, request: &hyper::Request<Body>) -> bool {
        !request.headers().contains_key(ACCEPT_ENCODING)
    }

    fn applies_to_downstream_response(
        &self,
        ctx: &HttpModuleContext,
        _response: &Response<Body>,
    ) -> bool {
        ctx.extensions().get::<CompressionRequest>().is_some()
    }

    async fn call<'a>(
        &self,
        stage: HttpModuleStage,
        ctx: &mut HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> Result<HttpModuleEvent<'a>> {
        match (stage, event) {
            (HttpModuleStage::RequestHeaders, HttpModuleEvent::RequestHeaders(request)) => {
                if let Some(request) = CompressionRequest::from_request(request) {
                    ctx.extensions_mut().insert(request);
                }
                Ok(HttpModuleEvent::RequestHeadersResult(
                    super::RequestHeadersOutcome::Continue,
                ))
            }
            (
                HttpModuleStage::DownstreamResponse,
                HttpModuleEvent::DownstreamResponse(response),
            ) => Ok(HttpModuleEvent::DownstreamResponse(
                self.compress(ctx, response).await?,
            )),
            (_, event) => Ok(event),
        }
    }
}

#[cfg(test)]
fn select_response_encoding(
    request: &HttpModuleRequestView<'_>,
    config: &ResponseCompressionModuleConfig,
    response: &Response<Body>,
) -> Result<Option<ContentEncoding>> {
    select_response_encoding_parts(request.method(), request.headers(), config, response)
}

fn select_response_encoding_parts(
    request_method: &Method,
    request_headers: &HeaderMap,
    config: &ResponseCompressionModuleConfig,
    response: &Response<Body>,
) -> Result<Option<ContentEncoding>> {
    if !response_is_compressible(request_method, config, response)? {
        return Ok(None);
    }

    let preferences = parse_accept_encoding(request_headers);
    let supported = [
        (ContentEncoding::Brotli, config.brotli),
        (ContentEncoding::Zstd, config.zstd),
        (ContentEncoding::Gzip, config.gzip),
    ];
    let mut best = None;
    for (encoding, enabled) in supported {
        if !enabled {
            continue;
        }
        let q = accept_encoding_q(encoding.http_name(), &preferences);
        if q <= 0 {
            continue;
        }
        match best {
            Some((best_q, _)) if q <= best_q => {}
            _ => best = Some((q, encoding)),
        }
    }
    Ok(best.map(|(_, encoding)| encoding))
}

fn response_is_compressible(
    request_method: &Method,
    config: &ResponseCompressionModuleConfig,
    response: &Response<Body>,
) -> Result<bool> {
    if request_method == Method::HEAD
        || (request_method == Method::CONNECT && response.status().is_success())
        || response.status().is_informational()
        || response.status() == StatusCode::NO_CONTENT
        || response.status() == StatusCode::RESET_CONTENT
        || response.status() == StatusCode::NOT_MODIFIED
        || response.headers().contains_key(CONTENT_ENCODING)
        || response.headers().contains_key(CONTENT_RANGE)
    {
        return Ok(false);
    }

    let content_length = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    let Some(content_length) = content_length else {
        return Ok(false);
    };
    if content_length < config.min_body_bytes || content_length > config.max_body_bytes {
        return Ok(false);
    }
    if !config.force_compress_event_stream && is_event_stream_headers(response.headers()) {
        return Ok(false);
    }
    if !content_type_allowed(response.headers(), &config.content_types) {
        return Ok(false);
    }
    Ok(true)
}

fn append_vary_token(headers: &mut HeaderMap, token: &str) -> Result<()> {
    let existing = headers
        .get_all(VARY)
        .iter()
        .map(|value| value.to_str())
        .collect::<std::result::Result<Vec<_>, _>>()?
        .join(", ");
    if existing
        .split(',')
        .any(|value| value.trim().eq_ignore_ascii_case(token))
    {
        return Ok(());
    }
    let value = if existing.is_empty() {
        token.to_owned()
    } else {
        format!("{existing}, {token}")
    };
    headers.remove(VARY);
    headers.insert(VARY, HeaderValue::from_str(&value)?);
    Ok(())
}

pub(crate) fn is_event_stream_headers(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or(value).trim())
        .map(|value| value.eq_ignore_ascii_case("text/event-stream"))
        .unwrap_or(false)
}

fn content_type_allowed(headers: &HeaderMap, configured: &[String]) -> bool {
    let Some(content_type) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or(value).trim())
    else {
        return false;
    };
    let mut iter: Box<dyn Iterator<Item = &str>> = if configured.is_empty() {
        Box::new(
            [
                "text/*",
                "application/json",
                "application/javascript",
                "application/xml",
                "application/xhtml+xml",
                "image/svg+xml",
            ]
            .iter()
            .copied(),
        )
    } else {
        Box::new(configured.iter().map(String::as_str))
    };
    iter.any(|pattern| mime_pattern_matches(pattern, content_type))
}

fn mime_pattern_matches(pattern: &str, content_type: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return content_type
            .strip_prefix(prefix)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false);
    }
    pattern.eq_ignore_ascii_case(content_type)
}

#[cfg(test)]
mod tests;
