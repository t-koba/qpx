use super::headers::parse_module_settings;
use super::{
    BodyAccess, HttpModule, HttpModuleCapabilities, HttpModuleContext, HttpModuleEvent,
    HttpModuleFactory, HttpModuleRequestView, HttpModuleStage, ModuleStages,
};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use hyper::Response;
use qpx_core::config::{HttpModuleConfig, ResponseCompressionModuleConfig};
use qpx_http::body::Body;
use std::sync::Arc;
use tokio::time::Duration;

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
        )))
    }
}

#[derive(Clone)]
struct ResponseCompressionModule {
    config: ResponseCompressionModuleConfig,
    pool: Arc<CompressionPool>,
}

impl ResponseCompressionModule {
    fn new(config: ResponseCompressionModuleConfig) -> Self {
        let pool = Arc::new(CompressionPool::new(config.worker_count));
        Self { config, pool }
    }

    async fn compress(
        &self,
        ctx: &HttpModuleContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        let request = ctx
            .frozen_request()
            .ok_or_else(|| anyhow!("response compression missing frozen request"))?;
        let Some(encoding) = select_response_encoding(&request, &self.config, &response)? else {
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
}

#[async_trait]
impl HttpModule for ResponseCompressionModule {
    fn order(&self) -> i16 {
        100
    }

    fn capabilities(&self) -> HttpModuleCapabilities {
        let mut capabilities =
            HttpModuleCapabilities::headers_only(ModuleStages::DOWNSTREAM_RESPONSE);
        capabilities.body_access = BodyAccess::Streaming;
        capabilities.mutates_response_headers = true;
        capabilities.needs_frozen_request = true;
        capabilities
    }

    async fn call<'a>(
        &self,
        stage: HttpModuleStage,
        ctx: &mut HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> Result<HttpModuleEvent<'a>> {
        let HttpModuleStage::DownstreamResponse = stage else {
            return Ok(event);
        };
        let HttpModuleEvent::DownstreamResponse(response) = event else {
            return Err(anyhow!(
                "response_compression received invalid downstream_response event"
            ));
        };
        Ok(HttpModuleEvent::DownstreamResponse(
            self.compress(ctx, response).await?,
        ))
    }
}

fn select_response_encoding(
    request: &HttpModuleRequestView<'_>,
    config: &ResponseCompressionModuleConfig,
    response: &Response<Body>,
) -> Result<Option<ContentEncoding>> {
    if request.method() == Method::HEAD
        || (request.method() == Method::CONNECT && response.status().is_success())
        || response.status().is_informational()
        || response.status() == StatusCode::NO_CONTENT
        || response.status() == StatusCode::RESET_CONTENT
        || response.status() == StatusCode::NOT_MODIFIED
        || response.headers().contains_key(CONTENT_ENCODING)
        || response.headers().contains_key(CONTENT_RANGE)
    {
        return Ok(None);
    }

    let content_length = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    let Some(content_length) = content_length else {
        return Ok(None);
    };
    if content_length < config.min_body_bytes || content_length > config.max_body_bytes {
        return Ok(None);
    }
    if !config.force_compress_event_stream && is_event_stream_headers(response.headers()) {
        return Ok(None);
    }
    if !content_type_allowed(response.headers(), &config.content_types) {
        return Ok(None);
    }

    let preferences = parse_accept_encoding(request.headers());
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
