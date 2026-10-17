use crate::handler::RequestHandler;
use arc_swap::ArcSwapOption;
use http::{Request, Response, StatusCode};
use qpx_core::config::AccessLogConfig;
use qpx_core::redaction::{redact_host_userinfo, redact_request_target, redact_uri_query_keys};
use std::borrow::Cow;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tracing::Level;

/// Returns whether request access-log or OpenTelemetry processing is enabled.
pub fn access_log_service_required(config: &AccessLogConfig) -> bool {
    config.output.enabled || crate::otel_enabled()
}

/// Returns whether downstream response metadata is required by the access-log format.
///
/// Combined logs are produced from the request snapshot and response status only. Building and
/// attaching identity, policy, route, and destination metadata for that format would add request
/// processing cost without changing its output.
pub fn access_log_response_context_required(config: &AccessLogConfig) -> bool {
    config.output.enabled && !config.output.format.eq_ignore_ascii_case("combined")
}

/// Returns whether the raw HTTP/1.1 path may emit the configured combined log directly.
///
/// The direct writer is deliberately limited to the combined format. Structured logs and
/// tracing require the full request/response wrapper because they carry extensions and spans.
pub fn direct_combined_access_log_enabled(config: &AccessLogConfig) -> bool {
    config.output.enabled
        && config.output.format.eq_ignore_ascii_case("combined")
        && crate::logging::direct_combined_access_log_enabled()
}

/// Static access-log identity for a listener or proxy surface.
#[derive(Debug, Clone)]
pub struct AccessLogContext {
    /// Proxy kind emitted in logs and tracing spans.
    pub kind: &'static str,
    /// Listener or route-facing name emitted in logs and tracing spans.
    pub name: Arc<str>,
}

/// Per-request identity and policy fields attached to responses for logging.
#[derive(Debug, Clone, Default)]
pub struct RequestLogContext {
    /// Authenticated subject.
    pub subject: Option<String>,
    /// Authenticated groups.
    pub groups: Vec<String>,
    /// Device identifier.
    pub device_id: Option<String>,
    /// Device or session posture labels.
    pub posture: Vec<String>,
    /// Tenant identifier.
    pub tenant: Option<String>,
    /// Authentication strength label.
    pub auth_strength: Option<String>,
    /// Identity provider label.
    pub idp: Option<String>,
    /// Source of identity material.
    pub identity_source: Option<String>,
    /// Policy tags associated with the decision.
    pub policy_tags: Vec<String>,
    /// External authorization policy identifier.
    pub decision_service_policy_id: Option<String>,
    /// Matched forward rule.
    pub matched_rule: Option<String>,
    /// Matched reverse route.
    pub matched_route: Option<String>,
    /// Destination trace string.
    pub destination_trace: Option<String>,
}

/// Per-request RPC fields attached to responses for logging.
#[derive(Debug, Clone, Default)]
pub struct RpcLogContext {
    /// RPC protocol name.
    pub protocol: Option<String>,
    /// RPC service name.
    pub service: Option<String>,
    /// RPC method name.
    pub method: Option<String>,
    /// RPC streaming mode.
    pub streaming: Option<String>,
    /// RPC status code or label.
    pub status: Option<String>,
    /// Last observed RPC message size.
    pub message_size: Option<u64>,
    /// Last observed RPC message text.
    pub message: Option<String>,
    /// Request message count.
    pub request_message_count: Option<usize>,
    /// Response message count.
    pub response_message_count: Option<usize>,
    /// Request message byte count.
    pub request_message_bytes: Option<u64>,
    /// Response message byte count.
    pub response_message_bytes: Option<u64>,
    /// RPC stream duration in milliseconds.
    pub stream_duration_ms: Option<u64>,
}

fn joined_or_empty(values: &[String]) -> Cow<'_, str> {
    match values {
        [] => Cow::Borrowed(""),
        [value] => Cow::Borrowed(value.as_str()),
        _ => Cow::Owned(values.join(",")),
    }
}

/// Request handler wrapper that emits access logs and tracing spans.
#[derive(Debug, Clone)]
pub struct AccessLogService<S> {
    inner: S,
    remote_addr: SocketAddr,
    direct_remote_prefix: Arc<[u8]>,
    direct_template: Arc<ArcSwapOption<CombinedRequestTemplate>>,
    context: AccessLogContext,
    enabled: bool,
    combined: bool,
    exclude: Arc<[Arc<str>]>,
    redact_query_keys: Arc<[String]>,
    redact_headers: Arc<[String]>,
}

impl<S> AccessLogService<S> {
    fn call_with_otel_enabled<ReqBody, ResBody>(
        &self,
        req: Request<ReqBody>,
        should_trace: bool,
    ) -> impl Future<Output = Result<Response<ResBody>, S::Error>> + Send
    where
        S: RequestHandler<Request<ReqBody>, Response = Response<ResBody>>,
    {
        let direct_combined = self.combined && crate::logging::direct_combined_access_log_enabled();
        let should_log = self.enabled
            && (direct_combined || tracing::enabled!(target: "access_log", Level::INFO));
        let path = req.uri().path();
        let should_log = should_log && !self.is_excluded(path);

        let mut host = None;
        let mut user_agent = None;
        if should_trace || (should_log && !self.combined) {
            host = self.capture_header_value("host", req.headers().get(http::header::HOST));
        }
        if should_trace || (should_log && !direct_combined) {
            user_agent = self
                .capture_header_value("user-agent", req.headers().get(http::header::USER_AGENT));
        }

        let redacted_uri = (should_trace || (should_log && !direct_combined)).then(|| {
            redact_request_target(
                req.method().as_str(),
                &req.uri().to_string(),
                &self.redact_query_keys,
            )
        });

        let span = if should_trace {
            use tracing_opentelemetry::OpenTelemetrySpanExt;

            let path = redact_request_target(
                req.method().as_str(),
                req.uri().path(),
                &self.redact_query_keys,
            );
            let span_name = format!("{} {} {}", self.context.kind, req.method().as_str(), path);
            let span = tracing::info_span!(
                target: "otel",
                "http",
                "otel.name" = span_name,
                "otel.kind" = "server",
                "http.request.method" = %req.method(),
                "url.full" = redacted_uri.as_deref().unwrap_or(""),
                "url.path" = %path,
                "client.address" = %self.remote_addr.ip(),
                "client.port" = self.remote_addr.port(),
                "proxy.kind" = self.context.kind,
                "proxy.name" = %self.context.name,
                "http.request.header.host" = host.as_ref().and_then(|value| value.to_str().ok()).unwrap_or(""),
                "user_agent.original" = user_agent.as_ref().and_then(|value| value.to_str().ok()).unwrap_or(""),
                "enduser.id" = tracing::field::Empty,
                "qpx.device_id" = tracing::field::Empty,
                "qpx.matched_rule" = tracing::field::Empty,
                "qpx.matched_route" = tracing::field::Empty,
                "qpx.policy_tags" = tracing::field::Empty,
                "qpx.decision_service_policy_id" = tracing::field::Empty,
                "http.response.status_code" = tracing::field::Empty,
            );
            let parent = crate::extract_trace_context(req.headers());
            let _ = span.set_parent(parent);
            Some(span)
        } else {
            None
        };

        let start = should_log.then(Instant::now);
        let direct_snapshot =
            (should_log && direct_combined).then(|| self.combined_request_template(&req));
        let snapshot = if should_log && !direct_combined {
            let referer = req
                .headers()
                .get(http::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .map(|s| {
                    if self.header_is_redacted("referer") {
                        "<redacted>".to_string()
                    } else {
                        redact_uri_query_keys(s, &self.redact_query_keys)
                    }
                });
            Some(AccessLogSnapshot {
                remote_addr: self.remote_addr,
                kind: self.context.kind,
                name: self.context.name.clone(),
                method: req.method().clone(),
                uri: redacted_uri.unwrap_or_default(),
                version: req.version(),
                host: host.clone(),
                referer,
                user_agent: user_agent.clone(),
            })
        } else {
            None
        };

        let inner = if let Some(span) = span.as_ref() {
            let _enter = span.enter();
            self.inner.call(req)
        } else {
            self.inner.call(req)
        };

        AccessLogFuture {
            inner,
            active: should_log || should_trace,
            start,
            snapshot,
            direct_snapshot,
            span,
            combined: self.combined,
            direct_combined,
        }
    }

    /// Creates an access-log wrapper around an inner handler.
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
            direct_remote_prefix: Arc::from(format!("{remote_addr} - - [").into_bytes()),
            direct_template: Arc::new(ArcSwapOption::empty()),
            context,
            enabled: config.output.enabled,
            combined: config.output.format.eq_ignore_ascii_case("combined"),
            exclude,
            redact_query_keys: Arc::from(config.redact.query_keys.clone()),
            redact_headers: Arc::from(
                config
                    .redact
                    .headers
                    .iter()
                    .map(|name| name.to_ascii_lowercase())
                    .collect::<Vec<_>>(),
            ),
        }
    }

    fn header_is_redacted(&self, name: &str) -> bool {
        self.redact_headers.iter().any(|header| header == name)
    }

    /// Applies configured whole-header redaction at capture time, so every
    /// emission path (combined template, structured log, span) honors
    /// `redact.headers`. The `<redacted>` marker matches the capture
    /// pipeline's header-redaction marker.
    fn capture_header_value(
        &self,
        name: &str,
        value: Option<&http::HeaderValue>,
    ) -> Option<http::HeaderValue> {
        value.map(|raw| {
            if self.header_is_redacted(name) {
                http::HeaderValue::from_static("<redacted>")
            } else if name == "host" || name == "referer" {
                raw.to_str()
                    .ok()
                    .and_then(|value| {
                        let redacted = redact_uri_query_keys(value, &self.redact_query_keys);
                        let redacted = if name == "host" {
                            redact_host_userinfo(&redacted)
                        } else {
                            redacted
                        };
                        http::HeaderValue::from_str(&redacted).ok()
                    })
                    .unwrap_or_else(|| http::HeaderValue::from_static("<redacted>"))
            } else {
                raw.clone()
            }
        })
    }

    fn is_excluded(&self, path: &str) -> bool {
        self.exclude.iter().any(|p| path.starts_with(p.as_ref()))
    }

    fn combined_request_template<ReqBody>(
        &self,
        request: &Request<ReqBody>,
    ) -> Arc<CombinedRequestTemplate> {
        let referer =
            self.capture_header_value("referer", request.headers().get(http::header::REFERER));
        let user_agent = self.capture_header_value(
            "user-agent",
            request.headers().get(http::header::USER_AGENT),
        );
        if let Some(template) = self.direct_template.load_full()
            && template.matches(request, referer.as_ref(), user_agent.as_ref())
        {
            return template;
        }
        let template = Arc::new(CombinedRequestTemplate::build(
            request,
            referer.as_ref(),
            user_agent.as_ref(),
            self.direct_remote_prefix.clone(),
            &self.redact_query_keys,
        ));
        self.direct_template.store(Some(template.clone()));
        template
    }
}

/// Future returned by [`AccessLogService`].
#[derive(Debug)]
pub struct AccessLogFuture<F> {
    inner: F,
    active: bool,
    start: Option<Instant>,
    snapshot: Option<AccessLogSnapshot>,
    direct_snapshot: Option<Arc<CombinedRequestTemplate>>,
    span: Option<tracing::Span>,
    combined: bool,
    direct_combined: bool,
}

#[derive(Debug)]
struct CombinedRequestTemplate {
    remote_prefix: Arc<[u8]>,
    method: http::Method,
    // Retain only the sanitized URI in the cross-request template cache.
    // Userinfo-bearing requests miss the cache rather than persisting credentials.
    uri: Option<http::Uri>,
    version: http::Version,
    referer: Option<http::HeaderValue>,
    user_agent: Option<http::HeaderValue>,
    request_suffix: Arc<[u8]>,
    metadata_suffix: Arc<[u8]>,
}

impl CombinedRequestTemplate {
    fn matches<ReqBody>(
        &self,
        request: &Request<ReqBody>,
        referer: Option<&http::HeaderValue>,
        user_agent: Option<&http::HeaderValue>,
    ) -> bool {
        self.method == *request.method()
            && self.uri.as_ref().is_some_and(|uri| uri == request.uri())
            && self.version == request.version()
            && self.referer.as_ref() == referer
            && self.user_agent.as_ref() == user_agent
    }

    fn build<ReqBody>(
        request: &Request<ReqBody>,
        referer: Option<&http::HeaderValue>,
        user_agent: Option<&http::HeaderValue>,
        remote_prefix: Arc<[u8]>,
        redact_query_keys: &[String],
    ) -> Self {
        let mut request_suffix = Vec::with_capacity(96);
        request_suffix.extend_from_slice(b"] \"");
        request_suffix.extend_from_slice(request.method().as_str().as_bytes());
        request_suffix.push(b' ');
        let raw_uri = request.uri().to_string();
        let redacted =
            redact_request_target(request.method().as_str(), &raw_uri, redact_query_keys);
        append_escaped(&mut request_suffix, redacted.as_bytes());
        let uri = (redact_request_target(request.method().as_str(), &raw_uri, &[]) == raw_uri)
            .then(|| request.uri().clone());
        request_suffix.push(b' ');
        request_suffix.extend_from_slice(http_version_label(request.version()).as_bytes());
        request_suffix.extend_from_slice(b"\" ");

        let mut metadata_suffix = Vec::with_capacity(64);
        metadata_suffix.push(b' ');
        let referer_bytes = referer
            .and_then(|value| value.to_str().ok())
            .map(|value| redact_uri_query_keys(value, redact_query_keys))
            .unwrap_or_default();
        append_quoted(
            &mut metadata_suffix,
            if referer_bytes.is_empty() {
                b"-"
            } else {
                referer_bytes.as_bytes()
            },
        );
        metadata_suffix.push(b' ');
        let user_agent_bytes = user_agent
            .map(http::HeaderValue::as_bytes)
            .unwrap_or_default();
        append_quoted(
            &mut metadata_suffix,
            if user_agent_bytes.is_empty() {
                b"-"
            } else {
                user_agent_bytes
            },
        );
        metadata_suffix.extend_from_slice(b" latency_ms=");

        Self {
            remote_prefix,
            method: request.method().clone(),
            uri,
            version: request.version(),
            referer: referer.cloned(),
            user_agent: user_agent.cloned(),
            request_suffix: request_suffix.into(),
            metadata_suffix: metadata_suffix.into(),
        }
    }
}

#[derive(Debug)]
struct AccessLogSnapshot {
    remote_addr: SocketAddr,
    kind: &'static str,
    name: Arc<str>,
    method: http::Method,
    uri: String,
    version: http::Version,
    host: Option<http::HeaderValue>,
    referer: Option<String>,
    user_agent: Option<http::HeaderValue>,
}

fn append_escaped(line: &mut Vec<u8>, value: &[u8]) {
    for byte in value {
        if *byte == b'"' || *byte == b'\\' {
            line.push(b'\\');
        }
        line.push(*byte);
    }
}

fn append_quoted(line: &mut Vec<u8>, value: &[u8]) {
    line.push(b'"');
    append_escaped(line, value);
    line.push(b'"');
}

fn append_u64(line: &mut Vec<u8>, mut value: u64) {
    let mut digits = [0_u8; 20];
    let mut index = digits.len();
    loop {
        index -= 1;
        digits[index] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    line.extend_from_slice(&digits[index..]);
}

fn append_fixed_width(line: &mut Vec<u8>, mut value: u32, width: usize) {
    let mut digits = [b'0'; 10];
    let start = digits.len() - width;
    for index in (start..digits.len()).rev() {
        digits[index] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    line.extend_from_slice(&digits[start..]);
}

fn http_version_label(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/?",
    }
}

fn parse_header_u64(value: &http::HeaderValue) -> Option<u64> {
    let mut parsed = 0_u64;
    let mut saw_digit = false;
    let mut trailing_ows = false;
    for byte in value.as_bytes() {
        match byte {
            b'0'..=b'9' if !trailing_ows => {
                saw_digit = true;
                parsed = parsed.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
            }
            b' ' | b'\t' if !saw_digit => {}
            b' ' | b'\t' => {
                trailing_ows = true;
            }
            _ => return None,
        }
    }
    saw_digit.then_some(parsed)
}

struct TimestampPrefixCache {
    monotonic_base: Instant,
    unix_base_micros: u128,
    calibrated: bool,
    seconds: i64,
    prefix: String,
}

thread_local! {
    static TIMESTAMP_PREFIX: std::cell::RefCell<TimestampPrefixCache> =
        std::cell::RefCell::new(TimestampPrefixCache {
            monotonic_base: Instant::now(),
            unix_base_micros: 0,
            calibrated: false,
            seconds: i64::MIN,
            prefix: String::with_capacity(20),
        });
}

fn append_utc_timestamp(line: &mut Vec<u8>, completed: Instant) {
    TIMESTAMP_PREFIX.with(|cached| {
        let mut cached = cached.borrow_mut();
        let since_calibration = completed.checked_duration_since(cached.monotonic_base);
        if !cached.calibrated
            || since_calibration.is_none()
            || since_calibration.is_some_and(|elapsed| elapsed.as_secs() >= 1)
        {
            cached.monotonic_base = completed;
            cached.unix_base_micros = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros();
            cached.calibrated = true;
        }
        let unix_micros = cached.unix_base_micros
            + completed
                .checked_duration_since(cached.monotonic_base)
                .unwrap_or_default()
                .as_micros();
        let seconds = (unix_micros / 1_000_000).min(i64::MAX as u128) as i64;
        if cached.seconds != seconds {
            cached.seconds = seconds;
            cached.prefix.clear();
            append_utc_second(&mut cached.prefix, seconds);
        }
        line.extend_from_slice(cached.prefix.as_bytes());
        line.push(b'.');
        append_fixed_width(line, (unix_micros % 1_000_000) as u32, 6);
        line.push(b'Z');
    });
}

fn append_utc_second(output: &mut String, seconds: i64) {
    use std::fmt::Write as _;

    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let shifted_days = days + 719_468;
    let era = if shifted_days >= 0 {
        shifted_days
    } else {
        shifted_days - 146_096
    } / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    let _ = write!(
        output,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"
    );
}

fn emit_direct_combined_access_log(
    snapshot: &CombinedRequestTemplate,
    status: StatusCode,
    elapsed: std::time::Duration,
    completed: Instant,
    bytes_out: u64,
) -> bool {
    crate::logging::write_direct_combined_access_log(|line| {
        line.extend_from_slice(&snapshot.remote_prefix);
        append_utc_timestamp(line, completed);
        line.extend_from_slice(&snapshot.request_suffix);
        append_u64(line, status.as_u16() as u64);
        line.push(b' ');
        append_u64(line, bytes_out);
        line.extend_from_slice(&snapshot.metadata_suffix);
        let elapsed_micros = elapsed.as_micros().min(u64::MAX as u128) as u64;
        append_u64(line, elapsed_micros / 1_000);
        line.push(b'.');
        append_fixed_width(line, (elapsed_micros % 1_000) as u32, 3);
        line.push(b'\n');
    })
}

/// Records HTTP result attributes on the request span.
///
/// Shared by the direct-combined fast path and the common completion path so
/// enabling combined access logs never changes tracing semantics: handler
/// polls run under the HTTP server span and status/identity/error attributes
/// are recorded on both paths.
fn record_http_result_on_span<B, E>(span: Option<&tracing::Span>, result: &Result<Response<B>, E>) {
    let Some(span) = span else {
        return;
    };
    use opentelemetry::trace::Status;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    match result {
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
                if let Some(policy_id) = ctx.decision_service_policy_id.as_deref() {
                    span.record("qpx.decision_service_policy_id", policy_id);
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

impl<F, B, E> Future for AccessLogFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
{
    type Output = Result<Response<B>, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.active {
            // SAFETY: `AccessLogFuture` is pinned and `inner` is never moved.
            return unsafe { self.as_mut().map_unchecked_mut(|state| &mut state.inner) }.poll(cx);
        }
        let direct_combined = self.as_ref().get_ref().direct_combined;
        if direct_combined {
            let span = {
                // SAFETY: `AccessLogFuture` is pinned, and accessing the non-pinned span
                // field does not move the pinned `inner` future.
                let this = unsafe { self.as_mut().get_unchecked_mut() };
                this.span.clone()
            };
            // SAFETY: `AccessLogFuture` is pinned and `inner` is never moved.
            let inner = unsafe { self.as_mut().map_unchecked_mut(|state| &mut state.inner) };
            // Enter the HTTP server span so async handler polls keep their trace
            // context and downstream propagation, as on the common path.
            let entered = span.as_ref().map(|span| span.enter());
            let polled = inner.poll(cx);
            drop(entered);
            if let Poll::Ready(result) = &polled {
                record_http_result_on_span(span.as_ref(), result);
                // SAFETY: polling is complete, and bookkeeping fields are not
                // structurally pinned.
                let this = unsafe { self.as_mut().get_unchecked_mut() };
                if let (Some(start), Some(snapshot), Ok(response)) =
                    (this.start.take(), this.direct_snapshot.take(), result)
                {
                    let completed = Instant::now();
                    let bytes_out = response
                        .headers()
                        .get(http::header::CONTENT_LENGTH)
                        .and_then(parse_header_u64)
                        .unwrap_or(0);
                    let _ = emit_direct_combined_access_log(
                        &snapshot,
                        response.status(),
                        completed.saturating_duration_since(start),
                        completed,
                        bytes_out,
                    );
                }
            }
            return polled;
        }
        let span = {
            // SAFETY: `AccessLogFuture` is pinned, and accessing the non-pinned span field
            // does not move the pinned `inner` future.
            let this = unsafe { self.as_mut().get_unchecked_mut() };
            this.span.clone()
        };

        // SAFETY: we never move `inner` after being pinned.
        let inner = unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.inner) };
        let entered = span.as_ref().map(|span| span.enter());
        let polled = inner.poll(cx);
        drop(entered);

        match polled {
            Poll::Ready(result) => {
                // SAFETY: polling is complete, and mutating bookkeeping fields does not move
                // the pinned `inner` future.
                let this = unsafe { self.as_mut().get_unchecked_mut() };
                record_http_result_on_span(span.as_ref(), &result);
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
                    let direct_combined = false;
                    if this.combined && !direct_combined {
                        tracing::info!(
                            target: "access_log",
                            remote = %snapshot.remote_addr,
                            method = %snapshot.method,
                            uri = %snapshot.uri,
                            version = ?snapshot.version,
                            status = resp.status().as_u16(),
                            latency_ms = latency_ms,
                            bytes_out = bytes_out.unwrap_or(0),
                            referer = snapshot.referer.as_deref().unwrap_or(""),
                            user_agent = snapshot
                                .user_agent
                                .as_ref()
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or(""),
                        );
                    } else if !this.combined {
                        let req_ctx = resp.extensions().get::<RequestLogContext>().cloned();
                        let rpc_ctx = resp.extensions().get::<RpcLogContext>().cloned();
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
                            crate::metrics::grpc_stream_duration_seconds(
                                snapshot.name.as_ref(),
                                rpc.protocol.clone().unwrap_or_default(),
                                rpc.streaming
                                    .clone()
                                    .unwrap_or_else(|| "unknown".to_string()),
                                elapsed.as_secs_f64(),
                            );
                        }
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
                            host = snapshot
                                .host
                                .as_ref()
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or(""),
                            referer = snapshot.referer.as_deref().unwrap_or(""),
                            user_agent = snapshot
                                .user_agent
                                .as_ref()
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or(""),
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
                            decision_service_policy_id = req_ctx
                                .as_ref()
                                .and_then(|ctx| ctx.decision_service_policy_id.as_deref())
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

    fn call(
        &self,
        req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Response<ResBody>, S::Error>> + Send {
        self.call_with_otel_enabled(req, crate::otel_enabled())
    }
}

impl<S> AccessLogService<S> {
    /// Emits a combined access record for a response produced outside the request wrapper.
    ///
    /// Raw HTTP/1.1 origin responses intentionally bypass the generic dispatch stack. This
    /// method preserves the exact combined-log format and exclusion/redaction rules without
    /// constructing a second response body or tracing span.
    pub fn record_direct_combined_status(
        &self,
        request: &Request<()>,
        status: StatusCode,
        bytes_out: u64,
        started: Instant,
    ) {
        if !direct_combined_access_log_enabled_from_service(self)
            || self.is_excluded(request.uri().path())
        {
            return;
        }
        let completed = Instant::now();
        let snapshot = self.combined_request_template(request);
        let _ = emit_direct_combined_access_log(
            &snapshot,
            status,
            completed.saturating_duration_since(started),
            completed,
            bytes_out,
        );
    }
}

fn direct_combined_access_log_enabled_from_service<S>(service: &AccessLogService<S>) -> bool {
    service.enabled && service.combined && crate::logging::direct_combined_access_log_enabled()
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

    #[test]
    fn combined_access_log_does_not_require_response_context() {
        let mut config = AccessLogConfig::default();
        config.output.enabled = true;
        config.output.format = "combined".to_string();
        assert!(!access_log_response_context_required(&config));

        config.output.format = "json".to_string();
        assert!(access_log_response_context_required(&config));
    }

    #[test]
    fn direct_combined_primitives_are_exact() {
        for (seconds, expected) in [
            (0, "1970-01-01T00:00:00"),
            (-1, "1969-12-31T23:59:59"),
            (951_782_400, "2000-02-29T00:00:00"),
        ] {
            let mut actual = String::new();
            append_utc_second(&mut actual, seconds);
            assert_eq!(actual, expected);
        }

        let mut line = Vec::new();
        append_u64(&mut line, 0);
        line.push(b' ');
        append_u64(&mut line, u64::MAX);
        line.push(b' ');
        append_fixed_width(&mut line, 42, 6);
        line.push(b' ');
        append_quoted(&mut line, br#"a"b\c"#);
        assert_eq!(
            String::from_utf8(line).expect("ASCII log primitives"),
            r#"0 18446744073709551615 000042 "a\"b\\c""#
        );
        assert_eq!(
            parse_header_u64(&http::HeaderValue::from_static(" 1048576\t")),
            Some(1_048_576)
        );
        assert_eq!(
            parse_header_u64(&http::HeaderValue::from_static("12 34")),
            None
        );
    }

    #[test]
    fn combined_template_preserves_fields_and_redaction() {
        let request = Request::builder()
            .method("GET")
            .uri("/items?token=secret&ok=1")
            .header(http::header::REFERER, "https://example.test/?token=secret")
            .header(http::header::USER_AGENT, "agent\\name")
            .body(())
            .expect("request");
        let template = CombinedRequestTemplate::build(
            &request,
            request.headers().get(http::header::REFERER),
            request.headers().get(http::header::USER_AGENT),
            Arc::from(&b"127.0.0.1:8080 - - ["[..]),
            &["token".to_string()],
        );
        assert_eq!(template.remote_prefix.as_ref(), b"127.0.0.1:8080 - - [");
        assert_eq!(
            String::from_utf8(template.request_suffix.to_vec()).expect("ASCII request suffix"),
            "] \"GET /items?token=<redacted>&ok=1 HTTP/1.1\" "
        );
        assert_eq!(
            String::from_utf8(template.metadata_suffix.to_vec()).expect("ASCII metadata suffix"),
            " \"https://example.test/?token=<redacted>\" \"agent\\\\name\" latency_ms="
        );
        assert!(template.matches(
            &request,
            request.headers().get(http::header::REFERER),
            request.headers().get(http::header::USER_AGENT)
        ));
    }
}

#[cfg(test)]
mod access_log_regression_tests {
    use super::*;
    use std::sync::Mutex;
    use tracing_subscriber::util::SubscriberInitExt;

    #[test]
    fn combined_template_escapes_query_free_uri_delimiters() {
        // Query-free origin form must escape delimiters exactly like the query
        // branch, preserving combined-field boundaries.
        let request = Request::builder()
            .method("GET")
            .uri("/a\"b\\c")
            .body(())
            .expect("request");
        assert!(request.uri().query().is_none());
        let template = CombinedRequestTemplate::build(
            &request,
            None,
            None,
            Arc::from(&b"127.0.0.1:8080 - - ["[..]),
            &[],
        );
        assert_eq!(
            String::from_utf8(template.request_suffix.to_vec()).expect("ASCII request suffix"),
            "] \"GET /a\\\"b\\\\c HTTP/1.1\" "
        );

        // Query-free absolute form carries the same escaping contract.
        let absolute = Request::builder()
            .method("GET")
            .uri("http://example.test/a\"b\\c")
            .body(())
            .expect("request");
        assert!(absolute.uri().query().is_none());
        let absolute_template = CombinedRequestTemplate::build(
            &absolute,
            None,
            None,
            Arc::from(&b"127.0.0.1:8080 - - ["[..]),
            &[],
        );
        assert_eq!(
            String::from_utf8(absolute_template.request_suffix.to_vec())
                .expect("ASCII request suffix"),
            "] \"GET http://example.test/a\\\"b\\\\c HTTP/1.1\" "
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn access_log_future_polls_inner_inside_request_span() {
        let _guard = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(Level::INFO)
            .set_default();
        // The direct-combined fast path must preserve the HTTP server span
        // across async handler polls, exactly like the common path.
        for direct_combined in [false, true] {
            let probe = tracing::info_span!("http_probe");
            let expected = probe.clone();
            let seen: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
            let seen_inner = seen.clone();
            let inner = async move {
                // Force a second poll so both polls must run under the span.
                tokio::task::yield_now().await;
                let under_span =
                    tracing::Span::current().id() == expected.id() && expected.id().is_some();
                *seen_inner.lock().expect("lock") = Some(under_span);
                let mut response = Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(())
                    .expect("response");
                response.extensions_mut().insert(RequestLogContext {
                    subject: Some("user-1".to_string()),
                    ..RequestLogContext::default()
                });
                Ok::<_, ()>(response)
            };
            let future = AccessLogFuture {
                inner,
                active: true,
                start: Some(Instant::now()),
                snapshot: None,
                direct_snapshot: None,
                span: Some(probe),
                combined: true,
                direct_combined,
            };
            let response = future.await.expect("response");
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(
                seen.lock().expect("lock").take(),
                Some(true),
                "handler poll ran outside the request span (direct_combined={direct_combined})"
            );
        }
    }
}

#[cfg(test)]
mod access_log_header_redaction_tests {
    use super::*;

    fn redacting_service(headers: &[&str]) -> AccessLogService<()> {
        let mut config = AccessLogConfig::default();
        config.redact.headers = headers.iter().map(|name| name.to_string()).collect();
        config.redact.query_keys = vec!["token".to_string()];
        AccessLogService::new(
            (),
            "127.0.0.1:8080".parse().expect("socket addr"),
            AccessLogContext {
                kind: "test",
                name: Arc::from("test"),
            },
            &config,
        )
    }

    fn probe_request() -> Request<()> {
        Request::builder()
            .method("GET")
            .uri("/items?token=secret&ok=1")
            .header(http::header::REFERER, "https://example.test/?token=secret")
            .header(http::header::USER_AGENT, "AGENT_PROBE")
            .body(())
            .expect("request")
    }

    #[test]
    fn combined_template_redacts_configured_headers() {
        // Mixed-case names prove case-insensitive matching; whole-header
        // redaction replaces the value before query-key redaction runs.
        let service = redacting_service(&["Referer", "USER-AGENT"]);
        let request = probe_request();
        let template = service.combined_request_template(&request);
        assert_eq!(
            String::from_utf8(template.metadata_suffix.to_vec()).expect("ASCII metadata suffix"),
            " \"<redacted>\" \"<redacted>\" latency_ms="
        );
        // The redacted template must cache-hit on repeat: matches() compares
        // the same redacted values it stores.
        let repeated = service.combined_request_template(&request);
        assert!(Arc::ptr_eq(&template, &repeated));
    }

    #[test]
    fn combined_template_keeps_unconfigured_headers() {
        // Control: headers outside redact.headers keep existing behavior —
        // raw User-Agent, query-key-redacted Referer.
        let service = redacting_service(&["cookie"]);
        let request = probe_request();
        let template = service.combined_request_template(&request);
        assert_eq!(
            String::from_utf8(template.metadata_suffix.to_vec()).expect("ASCII metadata suffix"),
            " \"https://example.test/?token=<redacted>\" \"AGENT_PROBE\" latency_ms="
        );
    }

    #[test]
    fn capture_helpers_match_names_case_insensitively() {
        let service = redacting_service(&["X-Custom-Secret"]);
        assert!(service.header_is_redacted("x-custom-secret"));
        assert!(!service.header_is_redacted("referer"));
        assert_eq!(
            service
                .capture_header_value(
                    "x-custom-secret",
                    Some(&http::HeaderValue::from_static("s3"))
                )
                .as_ref()
                .and_then(|v| v.to_str().ok()),
            Some("<redacted>")
        );
        assert_eq!(
            service
                .capture_header_value("referer", Some(&http::HeaderValue::from_static("r")))
                .as_ref()
                .and_then(|v| v.to_str().ok()),
            Some("r")
        );
        assert!(
            service
                .capture_header_value("x-custom-secret", None)
                .is_none()
        );
    }
}

#[cfg(test)]
mod userinfo_output_tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;
    use tracing_subscriber::util::SubscriberInitExt;

    #[derive(Clone, Default)]
    struct Output(Arc<Mutex<Vec<u8>>>);
    impl Write for Output {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn userinfo_absent_from_combined_structured_logs_and_trace_uri_fields() {
        let output = Output::default();
        let writer = output.clone();
        let _guard = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(Level::TRACE)
            .with_writer(move || writer.clone())
            .set_default();
        for scheme in ["ftp", "http", "https", "custom"] {
            for format in ["combined", "json"] {
                for query in ["", "?ok=1"] {
                    let mut config = AccessLogConfig::default();
                    config.output.enabled = true;
                    config.output.format = format.into();
                    config.redact.headers.clear();
                    config.redact.query_keys.clear();
                    let inner = crate::handler_fn(|_: Request<()>| async {
                        Ok::<_, ()>(
                            Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(())
                                .unwrap(),
                        )
                    });
                    let service = AccessLogService::new(
                        inner,
                        "127.0.0.1:12345".parse().unwrap(),
                        AccessLogContext {
                            kind: "forward",
                            name: Arc::from("test"),
                        },
                        &config,
                    );
                    let req = Request::builder()
                        .uri(format!(
                            "{scheme}://synthetic-user:synthetic-pass@host/file{query}"
                        ))
                        .header("host", "synthetic-user:synthetic-pass@host")
                        .header(
                            "referer",
                            format!("{scheme}://synthetic-user:synthetic-pass@host/ref"),
                        )
                        .body(())
                        .unwrap();
                    // Both direct combined templates and structured snapshots must be safe.
                    let template = service.combined_request_template(&req);
                    assert!(template.uri.is_none(), "credential URI retained in cache");
                    let template_debug = format!("{template:?}");
                    assert!(!template_debug.contains("synthetic-user"));
                    assert!(!template_debug.contains("synthetic-pass"));
                    let template_text = format!(
                        "{}{}",
                        String::from_utf8_lossy(&template.request_suffix),
                        String::from_utf8_lossy(&template.metadata_suffix)
                    );
                    assert!(!template_text.contains("synthetic-user"));
                    assert!(!template_text.contains("synthetic-pass"));
                    assert!(template_text.contains(&format!("{scheme}://host/file{query}")));
                    service.call(req).await.unwrap();
                    // The same redacted URI is used as url.full for tracing.
                    let trace_uri = redact_uri_query_keys(
                        &format!("{scheme}://synthetic-user:synthetic-pass@host/file{query}"),
                        &[],
                    );
                    assert_eq!(trace_uri, format!("{scheme}://host/file{query}"));
                }
            }
        }
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("http://host/file"));
        assert!(output.contains("400"));
        assert!(!output.contains("synthetic-user"));
        assert!(!output.contains("synthetic-pass"));
    }
    #[test]
    fn locked_http_rejects_absolute_uris_as_path_and_query() {
        // http 1.5 rejects the old codec fallback representation before the
        // logging service can see it. Exercise the reachable network-path
        // representation below, without weakening the protocol parser.
        let target = "http://synthetic-user:synthetic-pass@host:bad/file";
        assert!(http::Uri::builder().path_and_query(target).build().is_err());
        assert!(target.parse::<http::uri::PathAndQuery>().is_err());
    }

    #[derive(Debug, Clone, Default)]
    struct Spans(Arc<Mutex<Vec<opentelemetry_sdk::trace::SpanData>>>);

    impl opentelemetry_sdk::trace::SpanExporter for Spans {
        async fn export(
            &self,
            batch: Vec<opentelemetry_sdk::trace::SpanData>,
        ) -> opentelemetry_sdk::error::OTelSdkResult {
            self.0.lock().unwrap().extend(batch);
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejected_network_target_in_path_is_safe_in_all_log_and_otel_fields() {
        use opentelemetry::trace::TracerProvider as _;
        use tracing_subscriber::prelude::*;
        let spans = Spans::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(spans.clone())
            .build();
        let output = Output::default();
        let writer = output.clone();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")))
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(move || writer.clone()),
            );
        let _guard = subscriber.set_default();
        for format in ["combined", "json"] {
            for query in ["", "?ok=1"] {
                for host in [
                    "synthetic-user:synthetic-pass@host",
                    "'1bad://synthetic-user:synthetic-pass@host'",
                    "/foo://synthetic-user:synthetic-pass@host",
                    " \"//synthetic-user:synthetic-pass@host\" ",
                ] {
                    let mut config = AccessLogConfig::default();
                    config.output.enabled = true;
                    config.output.format = format.into();
                    config.redact.headers.clear();
                    config.redact.query_keys.clear();
                    let inner = crate::handler_fn(|req: Request<()>| async move {
                        // The logging sanitizer must not change routing inputs.
                        assert!(req.uri().path().contains("synthetic-user"));
                        Ok::<_, ()>(
                            Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(())
                                .unwrap(),
                        )
                    });
                    let service = AccessLogService::new(
                        inner,
                        "127.0.0.1:12345".parse().unwrap(),
                        AccessLogContext {
                            kind: "forward",
                            name: Arc::from("test"),
                        },
                        &config,
                    );
                    let target: http::uri::PathAndQuery =
                        format!("//synthetic-user:synthetic-pass@host:bad/file{query}")
                            .parse()
                            .unwrap();
                    let uri = http::Uri::from(target);
                    assert!(uri.scheme().is_none());
                    assert!(uri.authority().is_none());
                    let req = Request::builder()
                        .uri(uri)
                        .header("host", host)
                        .header(
                            "referer",
                            " '1bad://synthetic-user:synthetic-pass@host/ref' ",
                        )
                        .body(())
                        .unwrap();
                    // Also cover the direct combined writer's cached template.
                    let template = service.combined_request_template(&req);
                    assert!(
                        !String::from_utf8_lossy(&template.request_suffix).contains("synthetic-")
                    );
                    assert!(
                        !String::from_utf8_lossy(&template.metadata_suffix).contains("synthetic-")
                    );
                    assert_eq!(
                        service
                            .call_with_otel_enabled(req, true)
                            .await
                            .unwrap()
                            .status(),
                        StatusCode::BAD_REQUEST
                    );
                }
            }
        }
        provider.force_flush().unwrap();
        let spans = spans.0.lock().unwrap();
        assert_eq!(spans.len(), 16);
        for span in spans.iter() {
            assert!(!format!("{span:?}").contains("synthetic-"));
            assert!(span.name.contains("//host:bad/file"));
            for key in [
                "url.full",
                "url.path",
                "http.request.header.host",
                "http.response.status_code",
            ] {
                assert!(
                    span.attributes.iter().any(|attr| attr.key.as_str() == key),
                    "missing {key}"
                );
            }
        }
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(!output.contains("synthetic-"));
        assert!(output.contains("//host:bad/file"));
        assert!(output.contains("400"));
        assert!(output.contains("1bad://host/ref"));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn connect_authority_userinfo_is_absent_from_logs_cache_and_otel_fields() {
        use opentelemetry::trace::TracerProvider as _;
        use tracing_subscriber::prelude::*;
        let spans = Spans::default();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(spans.clone())
            .build();
        let output = Output::default();
        let writer = output.clone();
        let _guard = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")))
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(move || writer.clone()),
            )
            .set_default();
        for format in ["combined", "json"] {
            let mut config = AccessLogConfig::default();
            config.output.enabled = true;
            config.output.format = format.into();
            config.redact.headers.clear();
            config.redact.query_keys.clear();
            let inner = crate::handler_fn(|req: Request<()>| async move {
                // Sanitization must not change the protocol/routing input.
                assert_eq!(
                    req.uri().to_string(),
                    "synthetic-user:synthetic-pass@host:443"
                );
                Ok::<_, ()>(
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(())
                        .unwrap(),
                )
            });
            let service = AccessLogService::new(
                inner,
                "127.0.0.1:12345".parse().unwrap(),
                AccessLogContext {
                    kind: "forward",
                    name: Arc::from("test"),
                },
                &config,
            );
            let req = Request::builder()
                .method("CONNECT")
                .uri(
                    http::Uri::builder()
                        .authority("synthetic-user:synthetic-pass@host:443")
                        .build()
                        .unwrap(),
                )
                .header("host", "synthetic-user:synthetic-pass@host:443")
                .header("referer", "mailto:alice@example.com")
                .body(())
                .unwrap();
            let template = service.combined_request_template(&req);
            assert!(template.uri.is_none());
            assert!(!format!("{template:?}").contains("synthetic-"));
            assert!(String::from_utf8_lossy(&template.request_suffix).contains("CONNECT host:443"));
            assert!(
                String::from_utf8_lossy(&template.metadata_suffix)
                    .contains("mailto:alice@example.com")
            );
            service.call_with_otel_enabled(req, true).await.unwrap();
        }
        provider.force_flush().unwrap();
        let spans = spans.0.lock().unwrap();
        assert_eq!(spans.len(), 2);
        for span in spans.iter() {
            assert!(!format!("{span:?}").contains("synthetic-"));
            assert!(
                span.attributes.iter().any(
                    |attr| attr.key.as_str() == "url.full" && attr.value.as_str() == "host:443"
                )
            );
            assert!(
                span.attributes
                    .iter()
                    .any(|attr| attr.key.as_str() == "http.request.header.host"
                        && attr.value.as_str() == "host:443")
            );
        }
        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(!output.contains("synthetic-"));
        assert!(output.contains("host:443"));
        assert!(output.contains("mailto:alice@example.com"));
    }
}
