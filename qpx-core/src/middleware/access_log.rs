use crate::config::AccessLogConfig;
use http::{Request, Response};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tower_service::Service;
use tracing::Level;

#[derive(Debug, Clone)]
pub struct AccessLogContext {
    pub kind: &'static str,
    pub name: Arc<str>,
}

#[derive(Debug)]
pub struct AccessLogService<S> {
    inner: S,
    remote_addr: SocketAddr,
    context: AccessLogContext,
    enabled: bool,
    exclude: Arc<[Arc<str>]>,
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
                    let elapsed = start.elapsed();
                    let latency_ms = (elapsed.as_micros() as f64) / 1000.0;
                    let bytes_out = resp
                        .headers()
                        .get(http::header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|raw| raw.trim().parse::<u64>().ok());
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
                    );
                }
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AccessLogService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = AccessLogFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let should_log = self.enabled && tracing::enabled!(target: "access_log", Level::INFO);
        let path = req.uri().path();
        let should_log = should_log && !self.is_excluded(path);
        let should_trace = crate::observability::otel_enabled();

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

        let span = if should_trace {
            use tracing_opentelemetry::OpenTelemetrySpanExt;

            let path_and_query = req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            let span_name =
                format!("{} {} {}", self.context.kind, req.method().as_str(), path_and_query);
            let span = tracing::info_span!(
                target: "otel",
                "http",
                "otel.name" = span_name,
                "otel.kind" = "server",
                "http.request.method" = %req.method(),
                "url.full" = %req.uri(),
                "url.path" = %req.uri().path(),
                "client.address" = %self.remote_addr.ip(),
                "client.port" = self.remote_addr.port(),
                "proxy.kind" = self.context.kind,
                "proxy.name" = %self.context.name,
                "http.request.header.host" = host.as_deref().unwrap_or(""),
                "user_agent.original" = user_agent.as_deref().unwrap_or(""),
                "http.response.status_code" = tracing::field::Empty,
            );
            let parent = crate::observability::extract_trace_context(req.headers());
            let _ = span.set_parent(parent);
            Some(span)
        } else {
            None
        };

        let (start, snapshot) = if should_log {
            let host = req
                .headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let referer = req
                .headers()
                .get(http::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let user_agent = req
                .headers()
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            (
                Some(Instant::now()),
                Some(AccessLogSnapshot {
                    remote_addr: self.remote_addr,
                    kind: self.context.kind,
                    name: self.context.name.clone(),
                    method: req.method().clone(),
                    uri: req.uri().to_string(),
                     version: req.version(),
                     host,
                     referer,
                     user_agent,
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
