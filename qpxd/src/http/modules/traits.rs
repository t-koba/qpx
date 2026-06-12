use super::HttpModuleContext;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use http::StatusCode;
use hyper::{Request, Response};
use qpx_core::config::HttpModuleConfig;
use qpx_http::body::Body;
use std::sync::Arc;

pub trait HttpModuleFactory: Send + Sync {
    fn build(&self, spec: &HttpModuleConfig) -> Result<Arc<dyn HttpModule>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheLookupStatus {
    Hit,
    Miss,
}

#[derive(Clone, Copy, Debug)]
pub struct RetryEvent<'a> {
    pub attempt: usize,
    pub reason: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleStages(u32);

impl ModuleStages {
    pub const REQUEST_HEADERS: Self = Self(1 << 0);
    pub const CACHE_LOOKUP: Self = Self(1 << 1);
    pub const UPSTREAM_REQUEST: Self = Self(1 << 2);
    pub const UPSTREAM_RESPONSE: Self = Self(1 << 3);
    pub const DOWNSTREAM_RESPONSE: Self = Self(1 << 4);
    pub const RETRY: Self = Self(1 << 5);
    pub const ERROR: Self = Self(1 << 6);
    pub const LOG: Self = Self(1 << 7);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn all() -> Self {
        Self(
            Self::REQUEST_HEADERS.0
                | Self::CACHE_LOOKUP.0
                | Self::UPSTREAM_REQUEST.0
                | Self::UPSTREAM_RESPONSE.0
                | Self::DOWNSTREAM_RESPONSE.0
                | Self::RETRY.0
                | Self::ERROR.0
                | Self::LOG.0,
        )
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyAccess {
    HeadersOnly,
    RequestBodyBuffered {
        max_bytes: usize,
    },
    ResponseBodyBuffered {
        max_bytes: usize,
    },
    RequestAndResponseBodyBuffered {
        max_request_bytes: usize,
        max_response_bytes: usize,
    },
    Streaming,
}

impl BodyAccess {
    pub fn mode_label(self) -> &'static str {
        match self {
            Self::HeadersOnly => "headers_only",
            Self::Streaming => "stream_transform",
            Self::RequestBodyBuffered { .. } => "request_buffer_inspect",
            Self::ResponseBodyBuffered { .. } => "response_buffer_inspect",
            Self::RequestAndResponseBodyBuffered { .. } => "request_and_response_buffer_inspect",
        }
    }

    pub fn streaming_safe(self) -> bool {
        matches!(self, Self::HeadersOnly | Self::Streaming)
    }

    pub fn request_buffer_bytes(self) -> Option<usize> {
        match self {
            Self::RequestBodyBuffered { max_bytes } => Some(max_bytes),
            Self::RequestAndResponseBodyBuffered {
                max_request_bytes, ..
            } => Some(max_request_bytes),
            _ => None,
        }
    }

    pub fn response_buffer_bytes(self) -> Option<usize> {
        match self {
            Self::ResponseBodyBuffered { max_bytes } => Some(max_bytes),
            Self::RequestAndResponseBodyBuffered {
                max_response_bytes, ..
            } => Some(max_response_bytes),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpModuleCapabilities {
    pub stages: ModuleStages,
    pub body_access: BodyAccess,
    pub mutates_request_headers: bool,
    pub mutates_response_headers: bool,
    pub may_short_circuit: bool,
    pub needs_frozen_request: bool,
    pub safe_on_retry: bool,
}

impl HttpModuleCapabilities {
    pub fn headers_only(stages: ModuleStages) -> Self {
        Self {
            stages,
            body_access: BodyAccess::HeadersOnly,
            mutates_request_headers: false,
            mutates_response_headers: false,
            may_short_circuit: false,
            needs_frozen_request: false,
            safe_on_retry: true,
        }
    }

    pub(super) fn merge(&mut self, other: Self) {
        self.stages.insert(other.stages);
        self.body_access = merge_body_access(self.body_access, other.body_access);
        self.mutates_request_headers |= other.mutates_request_headers;
        self.mutates_response_headers |= other.mutates_response_headers;
        self.may_short_circuit |= other.may_short_circuit;
        self.needs_frozen_request |= other.needs_frozen_request;
        self.safe_on_retry &= other.safe_on_retry;
    }
}

impl Default for HttpModuleCapabilities {
    fn default() -> Self {
        Self {
            stages: ModuleStages::empty(),
            body_access: BodyAccess::HeadersOnly,
            mutates_request_headers: false,
            mutates_response_headers: false,
            may_short_circuit: false,
            needs_frozen_request: false,
            safe_on_retry: true,
        }
    }
}

fn merge_body_access(left: BodyAccess, right: BodyAccess) -> BodyAccess {
    match (left, right) {
        (
            BodyAccess::RequestAndResponseBodyBuffered {
                max_request_bytes,
                max_response_bytes,
            },
            other,
        )
        | (
            other,
            BodyAccess::RequestAndResponseBodyBuffered {
                max_request_bytes,
                max_response_bytes,
            },
        ) => match other {
            BodyAccess::RequestBodyBuffered { max_bytes } => {
                BodyAccess::RequestAndResponseBodyBuffered {
                    max_request_bytes: max_request_bytes.max(max_bytes),
                    max_response_bytes,
                }
            }
            BodyAccess::ResponseBodyBuffered { max_bytes } => {
                BodyAccess::RequestAndResponseBodyBuffered {
                    max_request_bytes,
                    max_response_bytes: max_response_bytes.max(max_bytes),
                }
            }
            _ => BodyAccess::RequestAndResponseBodyBuffered {
                max_request_bytes,
                max_response_bytes,
            },
        },
        (
            BodyAccess::RequestBodyBuffered { max_bytes: request },
            BodyAccess::ResponseBodyBuffered {
                max_bytes: response,
            },
        )
        | (
            BodyAccess::ResponseBodyBuffered {
                max_bytes: response,
            },
            BodyAccess::RequestBodyBuffered { max_bytes: request },
        ) => BodyAccess::RequestAndResponseBodyBuffered {
            max_request_bytes: request,
            max_response_bytes: response,
        },
        (
            BodyAccess::RequestBodyBuffered { max_bytes: left },
            BodyAccess::RequestBodyBuffered { max_bytes: right },
        ) => BodyAccess::RequestBodyBuffered {
            max_bytes: left.max(right),
        },
        (
            BodyAccess::ResponseBodyBuffered { max_bytes: left },
            BodyAccess::ResponseBodyBuffered { max_bytes: right },
        ) => BodyAccess::ResponseBodyBuffered {
            max_bytes: left.max(right),
        },
        (BodyAccess::Streaming, BodyAccess::HeadersOnly)
        | (BodyAccess::HeadersOnly, BodyAccess::Streaming)
        | (BodyAccess::Streaming, BodyAccess::Streaming) => BodyAccess::Streaming,
        (BodyAccess::Streaming, other) | (other, BodyAccess::Streaming) => other,
        (BodyAccess::HeadersOnly, other) | (other, BodyAccess::HeadersOnly) => other,
    }
}

#[cfg(test)]
mod tests {
    use super::{BodyAccess, merge_body_access};

    #[test]
    fn streaming_body_access_does_not_hide_buffering_access() {
        assert_eq!(
            merge_body_access(
                BodyAccess::Streaming,
                BodyAccess::RequestBodyBuffered { max_bytes: 1024 }
            ),
            BodyAccess::RequestBodyBuffered { max_bytes: 1024 }
        );
        assert_eq!(
            merge_body_access(
                BodyAccess::ResponseBodyBuffered { max_bytes: 2048 },
                BodyAccess::Streaming
            ),
            BodyAccess::ResponseBodyBuffered { max_bytes: 2048 }
        );
    }

    #[test]
    fn body_access_exposes_mode_and_streaming_safety() {
        assert_eq!(BodyAccess::HeadersOnly.mode_label(), "headers_only");
        assert!(BodyAccess::HeadersOnly.streaming_safe());
        assert_eq!(BodyAccess::Streaming.mode_label(), "stream_transform");
        assert!(BodyAccess::Streaming.streaming_safe());

        let buffered = BodyAccess::RequestAndResponseBodyBuffered {
            max_request_bytes: 1024,
            max_response_bytes: 2048,
        };
        assert_eq!(buffered.mode_label(), "request_and_response_buffer_inspect");
        assert!(!buffered.streaming_safe());
        assert_eq!(buffered.request_buffer_bytes(), Some(1024));
        assert_eq!(buffered.response_buffer_bytes(), Some(2048));
    }
}

pub enum RequestHeadersOutcome {
    Continue,
    Respond(Box<Response<Body>>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpModuleStage {
    RequestHeaders,
    CacheLookup,
    UpstreamRequest,
    UpstreamResponse,
    DownstreamResponse,
    Retry,
    Error,
    Log,
}

pub enum HttpModuleEvent<'a> {
    RequestHeaders(&'a mut Request<Body>),
    RequestHeadersResult(RequestHeadersOutcome),
    CacheLookup(CacheLookupStatus),
    UpstreamRequest(&'a mut Request<Body>),
    UpstreamResponse(Response<Body>),
    DownstreamResponse(Response<Body>),
    Retry(RetryEvent<'a>),
    Error(&'a anyhow::Error),
    Log {
        response_status: Option<StatusCode>,
        err: Option<&'a anyhow::Error>,
    },
    Complete,
}

impl<'a> HttpModuleEvent<'a> {
    pub(super) fn request_headers_result(self, module: &str) -> Result<RequestHeadersOutcome> {
        match self {
            Self::RequestHeadersResult(outcome) => Ok(outcome),
            Self::Complete => Ok(RequestHeadersOutcome::Continue),
            _ => Err(anyhow!(
                "http module {module} returned invalid request_headers event"
            )),
        }
    }

    pub(super) fn into_complete(self, module: &str, stage: HttpModuleStage) -> Result<()> {
        match self {
            Self::Complete => Ok(()),
            _ => Err(anyhow!(
                "http module {module} returned invalid {stage:?} event"
            )),
        }
    }

    pub(super) fn upstream_response(self, module: &str) -> Result<Response<Body>> {
        match self {
            Self::UpstreamResponse(response) => Ok(response),
            _ => Err(anyhow!(
                "http module {module} returned invalid upstream_response event"
            )),
        }
    }

    pub(super) fn downstream_response(self, module: &str) -> Result<Response<Body>> {
        match self {
            Self::DownstreamResponse(response) => Ok(response),
            _ => Err(anyhow!(
                "http module {module} returned invalid downstream_response event"
            )),
        }
    }
}

#[async_trait]
pub trait HttpModule: Send + Sync {
    fn order(&self) -> i16 {
        0
    }

    fn capabilities(&self) -> HttpModuleCapabilities;

    fn explain(&self) -> Vec<String> {
        Vec::new()
    }

    async fn call<'a>(
        &self,
        stage: HttpModuleStage,
        ctx: &mut HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> Result<HttpModuleEvent<'a>>;
}
