use crate::handler::RequestHandler;
use http::{Request, Response};
use qpx_core::config::AccessLogConfig;
use qpx_core::redaction::redact_uri_query_keys;
use std::borrow::Cow;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tracing::Level;

#[derive(Debug, Clone)]
pub struct AccessLogContext {
    pub kind: &'static str,
    pub name: Arc<str>,
}

#[derive(Debug, Clone, Default)]
pub struct RequestLogContext {
    pub subject: Option<String>,
    pub groups: Vec<String>,
    pub device_id: Option<String>,
    pub posture: Vec<String>,
    pub tenant: Option<String>,
    pub auth_strength: Option<String>,
    pub idp: Option<String>,
    pub identity_source: Option<String>,
    pub policy_tags: Vec<String>,
    pub ext_authz_policy_id: Option<String>,
    pub matched_rule: Option<String>,
    pub matched_route: Option<String>,
    pub destination_trace: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RpcLogContext {
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub method: Option<String>,
    pub streaming: Option<String>,
    pub status: Option<String>,
    pub message_size: Option<u64>,
    pub message: Option<String>,
    pub request_message_count: Option<usize>,
    pub response_message_count: Option<usize>,
    pub request_message_bytes: Option<u64>,
    pub response_message_bytes: Option<u64>,
    pub stream_duration_ms: Option<u64>,
}

fn joined_or_empty(values: &[String]) -> Cow<'_, str> {
    match values {
        [] => Cow::Borrowed(""),
        [value] => Cow::Borrowed(value.as_str()),
        _ => Cow::Owned(values.join(",")),
    }
}

#[derive(Debug, Clone)]
pub struct AccessLogService<S> {
    inner: S,
    remote_addr: SocketAddr,
    context: AccessLogContext,
    enabled: bool,
    exclude: Arc<[Arc<str>]>,
    redact_query_keys: Arc<[String]>,
}

impl<S> AccessLogService<S> {
    pub fn new(
        inner: S,
        remote_addr: SocketAddr,
        context: AccessLogContext,
        config: &AccessLogConfig,
    ) -> Self {
        let exclude = config
            .exclude
            .iter()
            .map(|p| Arc::<str>::from(p.as_str()))
            .collect::<Vec<_>>()
            .into();
        Self {
            inner,
            remote_addr,
            context,
            enabled: config.output.enabled,
            exclude,
            redact_query_keys: Arc::from(config.redact.query_keys.clone()),
        }
    }

    fn is_excluded(&self, path: &str) -> bool {
        self.exclude.iter().any(|p| path.starts_with(p.as_ref()))
    }
}

#[derive(Debug)]
pub struct AccessLogFuture<F> {
    inner: F,
    start: Option<Instant>,
    snapshot: Option<AccessLogSnapshot>,
    span: Option<tracing::Span>,
}

#[derive(Debug)]
struct AccessLogSnapshot {
    remote_addr: SocketAddr,
    kind: &'static str,
    name: Arc<str>,
    method: http::Method,
    uri: String,
    version: http::Version,
    host: Option<String>,
    referer: Option<String>,
    user_agent: Option<String>,
}

impl<F, B, E> Future for AccessLogFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
{
    type Output = Result<Response<B>, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let span = {
            let this = unsafe { self.as_mut().get_unchecked_mut() };
            this.span.clone()
        };

        // Safety: we never move `inner` after being pinned.
        let inner = unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.inner) };
        let entered = span.as_ref().map(|span| span.enter());
        let polled = inner.poll(cx);
        drop(entered);

        match polled {
            Poll::Ready(result) => {
                let this = unsafe { self.as_mut().get_unchecked_mut() };
                if let Some(span) = span.as_ref() {
                    use opentelemetry::trace::Status;
                    use tracing_opentelemetry::OpenTelemetrySpanExt;
                    match &result {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            span.record("http.response.status_code", status);
                            if let Some(ctx) = resp.extensions().get::<RequestLogContext>() {
                                if let Some(subject) = ctx.subject.as_deref() {
                                    span.record("enduser.id", subject);
                                }
                                if let Some(device_id) = ctx.device_id.as_deref() {
                                    span.record("qpx.device_id", device_id);
                                }
                                if let Some(rule) = ctx.matched_rule.as_deref() {
                                    span.record("qpx.matched_rule", rule);
                                }
                                if let Some(route) = ctx.matched_route.as_deref() {
                                    span.record("qpx.matched_route", route);
                                }
                                if let Some(policy_id) = ctx.ext_authz_policy_id.as_deref() {
                                    span.record("qpx.ext_authz_policy_id", policy_id);
                                }
                                if !ctx.policy_tags.is_empty() {
                                    let policy_tags = joined_or_empty(&ctx.policy_tags);
                                    span.record("qpx.policy_tags", policy_tags.as_ref());
                                }
                            }
                            if status >= 500 {
                                span.set_status(Status::error(format!("HTTP {status}")));
                            }
                        }
                        Err(_) => {
                            span.set_status(Status::error("request failed"));
                        }
                    }
                }
                if let (Some(start), Some(snapshot), Ok(resp)) =
                    (this.start.take(), this.snapshot.take(), &result)
                {
                    let req_ctx = resp.extensions().get::<RequestLogContext>().cloned();
                    let rpc_ctx = resp.extensions().get::<RpcLogContext>().cloned();
                    let elapsed = start.elapsed();
                    let latency_ms = (elapsed.as_micros() as f64) / 1000.0;
                    let rpc_stream_duration_ms = rpc_ctx
                        .as_ref()
                        .and_then(|ctx| ctx.stream_duration_ms)
                        .unwrap_or(elapsed.as_millis() as u64);
                    if let Some(rpc) = rpc_ctx.as_ref()
                        && matches!(
                            rpc.protocol.as_deref(),
                            Some("grpc" | "grpc_web" | "connect")
                        )
                    {
                        metrics::histogram!(
                            "qpx_grpc_stream_duration_seconds",
                            "listener" => snapshot.name.to_string(),
                            "protocol" => rpc.protocol.clone().unwrap_or_default(),
                            "streaming" => rpc
                                .streaming
                                .clone()
                                .unwrap_or_else(|| "unknown".to_string())
                        )
                        .record(elapsed.as_secs_f64());
                    }
                    let bytes_out = resp
                        .headers()
                        .get(http::header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|raw| raw.trim().parse::<u64>().ok());
                    let groups = req_ctx
                        .as_ref()
                        .map(|ctx| joined_or_empty(&ctx.groups))
                        .unwrap_or(Cow::Borrowed(""));
                    let posture = req_ctx
                        .as_ref()
                        .map(|ctx| joined_or_empty(&ctx.posture))
                        .unwrap_or(Cow::Borrowed(""));
                    let policy_tags = req_ctx
                        .as_ref()
                        .map(|ctx| joined_or_empty(&ctx.policy_tags))
                        .unwrap_or(Cow::Borrowed(""));
                    tracing::info!(
                        target: "access_log",
                        kind = snapshot.kind,
                        name = %snapshot.name,
                        remote = %snapshot.remote_addr,
                        method = %snapshot.method,
                        uri = %snapshot.uri,
                        version = ?snapshot.version,
                        status = resp.status().as_u16(),
                        latency_ms = latency_ms,
                        bytes_out = bytes_out.unwrap_or(0),
                        host = snapshot.host.as_deref().unwrap_or(""),
                        referer = snapshot.referer.as_deref().unwrap_or(""),
                        user_agent = snapshot.user_agent.as_deref().unwrap_or(""),
                        subject = req_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.subject.as_deref())
                            .unwrap_or(""),
                        groups = %groups,
                        device_id = req_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.device_id.as_deref())
                            .unwrap_or(""),
                        posture = %posture,
                        tenant = req_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.tenant.as_deref())
                            .unwrap_or(""),
                        auth_strength = req_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.auth_strength.as_deref())
                            .unwrap_or(""),
                        idp = req_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.idp.as_deref())
                            .unwrap_or(""),
                        identity_source = req_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.identity_source.as_deref())
                            .unwrap_or(""),
                        policy_tags = %policy_tags,
                        ext_authz_policy_id = req_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.ext_authz_policy_id.as_deref())
                            .unwrap_or(""),
                        matched_rule = req_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.matched_rule.as_deref())
                            .unwrap_or(""),
                        matched_route = req_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.matched_route.as_deref())
                            .unwrap_or(""),
                        destination_trace = req_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.destination_trace.as_deref())
                            .unwrap_or(""),
                        rpc_protocol = rpc_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.protocol.as_deref())
                            .unwrap_or(""),
                        rpc_service = rpc_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.service.as_deref())
                            .unwrap_or(""),
                        rpc_method = rpc_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.method.as_deref())
                            .unwrap_or(""),
                        rpc_streaming = rpc_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.streaming.as_deref())
                            .unwrap_or(""),
                        rpc_status = rpc_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.status.as_deref())
                            .unwrap_or(""),
                        rpc_message_size = rpc_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.message_size)
                            .unwrap_or(0),
                        rpc_message = rpc_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.message.as_deref())
                            .unwrap_or(""),
                        rpc_request_message_count = rpc_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.request_message_count)
                            .unwrap_or(0),
                        rpc_response_message_count = rpc_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.response_message_count)
                            .unwrap_or(0),
                        rpc_request_message_bytes = rpc_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.request_message_bytes)
                            .unwrap_or(0),
                        rpc_response_message_bytes = rpc_ctx
                            .as_ref()
                            .and_then(|ctx| ctx.response_message_bytes)
                            .unwrap_or(0),
                        rpc_stream_duration_ms = rpc_stream_duration_ms,
                    );
                }
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S, ReqBody, ResBody> RequestHandler<Request<ReqBody>> for AccessLogService<S>
where
    S: RequestHandler<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = AccessLogFuture<S::Future>;

    fn call(&self, req: Request<ReqBody>) -> Self::Future {
        let should_log = self.enabled && tracing::enabled!(target: "access_log", Level::INFO);
        let path = req.uri().path();
        let should_log = should_log && !self.is_excluded(path);
        let should_trace = crate::otel_enabled();

        let mut host = None;
        let mut user_agent = None;
        if should_log || should_trace {
            host = req
                .headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            user_agent = req
                .headers()
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
        }

        let redacted_uri = if should_log || should_trace {
            Some(redact_uri_query_keys(
                req.uri().to_string().as_str(),
                &self.redact_query_keys,
            ))
        } else {
            None
        };

        let span = if should_trace {
            use tracing_opentelemetry::OpenTelemetrySpanExt;

            let path = req.uri().path();
            let span_name = format!("{} {} {}", self.context.kind, req.method().as_str(), path);
            let span = tracing::info_span!(
                target: "otel",
                "http",
                "otel.name" = span_name,
                "otel.kind" = "server",
                "http.request.method" = %req.method(),
                "url.full" = redacted_uri.as_deref().unwrap_or(""),
                "url.path" = %req.uri().path(),
                "client.address" = %self.remote_addr.ip(),
                "client.port" = self.remote_addr.port(),
                "proxy.kind" = self.context.kind,
                "proxy.name" = %self.context.name,
                "http.request.header.host" = host.as_deref().unwrap_or(""),
                "user_agent.original" = user_agent.as_deref().unwrap_or(""),
                "enduser.id" = tracing::field::Empty,
                "qpx.device_id" = tracing::field::Empty,
                "qpx.matched_rule" = tracing::field::Empty,
                "qpx.matched_route" = tracing::field::Empty,
                "qpx.policy_tags" = tracing::field::Empty,
                "qpx.ext_authz_policy_id" = tracing::field::Empty,
                "http.response.status_code" = tracing::field::Empty,
            );
            let parent = crate::extract_trace_context(req.headers());
            let _ = span.set_parent(parent);
            Some(span)
        } else {
            None
        };

        let (start, snapshot) = if should_log {
            let referer = req
                .headers()
                .get(http::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .map(|s| redact_uri_query_keys(s, &self.redact_query_keys));
            (
                Some(Instant::now()),
                Some(AccessLogSnapshot {
                    remote_addr: self.remote_addr,
                    kind: self.context.kind,
                    name: self.context.name.clone(),
                    method: req.method().clone(),
                    uri: redacted_uri.unwrap_or_else(|| req.uri().to_string()),
                    version: req.version(),
                    host: host.clone(),
                    referer,
                    user_agent: user_agent.clone(),
                }),
            )
        } else {
            (None, None)
        };

        let inner = if let Some(span) = span.as_ref() {
            let _enter = span.enter();
            self.inner.call(req)
        } else {
            self.inner.call(req)
        };

        AccessLogFuture {
            inner,
            start,
            snapshot,
            span,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_log_redacts_uri_and_referer_query_keys() {
        let keys = Arc::<[String]>::from(vec![
            "code".to_string(),
            "access_token".to_string(),
            "id_token".to_string(),
        ]);
        assert_eq!(
            redact_uri_query_keys("/callback?code=secret&ok=1", &keys),
            "/callback?code=<redacted>&ok=1"
        );
        assert_eq!(
            redact_uri_query_keys("https://idp.example/cb?access_token=secret", &keys),
            "https://idp.example/cb?access_token=<redacted>"
        );
        assert_eq!(
            redact_uri_query_keys(
                "https://idp.example/cb#access_token=secret&id_token=jwt&state=ok",
                &keys
            ),
            "https://idp.example/cb#access_token=<redacted>&id_token=<redacted>&state=ok"
        );
    }
}
