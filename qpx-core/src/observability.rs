use crate::config::{
    AccessLogConfig, AuditLogConfig, LogOutputConfig, MetricsConfig, OtelConfig, SystemLogConfig,
};
use anyhow::{Context, Result};
use cidr::IpCidr;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::EnvFilter;

const MAX_METRICS_REQUEST_BYTES: usize = 16 * 1024;
const METRICS_READ_TIMEOUT: Duration = Duration::from_secs(5);

static OTEL_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn otel_enabled() -> bool {
    OTEL_ENABLED.load(Ordering::Relaxed)
}

#[derive(Debug)]
pub struct LogGuards {
    _access: Option<tracing_appender::non_blocking::WorkerGuard>,
    _audit: Option<tracing_appender::non_blocking::WorkerGuard>,
    _otel: Option<OtelGuard>,
}

#[derive(Debug)]
struct OtelGuard {
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        OTEL_ENABLED.store(false, Ordering::Relaxed);
        let _ = self.provider.force_flush();
        let _ = self.provider.shutdown();
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct AccessLogCombinedFormat {
    timer: tracing_subscriber::fmt::time::SystemTime,
}

struct AccessLogCombinedFields {
    remote: Option<String>,
    method: Option<String>,
    uri: Option<String>,
    version: Option<String>,
    status: Option<u64>,
    bytes_out: Option<u64>,
    referer: Option<String>,
    user_agent: Option<String>,
    latency_ms: Option<f64>,
}

impl tracing::field::Visit for AccessLogCombinedFields {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        if field.name() == "latency_ms" {
            self.latency_ms = Some(value);
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        match field.name() {
            "status" => self.status = Some(value),
            "bytes_out" => self.bytes_out = Some(value),
            _ => {}
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "referer" => self.referer = Some(value.to_string()),
            "user_agent" => self.user_agent = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "remote" => self.remote = Some(format!("{value:?}")),
            "method" => self.method = Some(format!("{value:?}")),
            "uri" => self.uri = Some(format!("{value:?}")),
            "version" => self.version = Some(format!("{value:?}")),
            _ => {}
        }
    }
}

impl AccessLogCombinedFormat {
    fn write_quoted(
        writer: &mut tracing_subscriber::fmt::format::Writer<'_>,
        value: &str,
    ) -> std::fmt::Result {
        writer.write_char('"')?;
        for ch in value.chars() {
            match ch {
                '\\' => writer.write_str("\\\\")?,
                '"' => writer.write_str("\\\"")?,
                _ => writer.write_char(ch)?,
            }
        }
        writer.write_char('"')
    }
}

impl<S, N> tracing_subscriber::fmt::format::FormatEvent<S, N> for AccessLogCombinedFormat
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> tracing_subscriber::fmt::format::FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        _ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let mut fields = AccessLogCombinedFields {
            remote: None,
            method: None,
            uri: None,
            version: None,
            status: None,
            bytes_out: None,
            referer: None,
            user_agent: None,
            latency_ms: None,
        };
        event.record(&mut fields);

        if let Some(remote) = fields.remote.as_deref() {
            writer.write_str(remote)?;
        } else {
            writer.write_str("-")?;
        }

        writer.write_str(" - - [")?;
        self.timer.format_time(&mut writer)?;
        writer.write_str("] \"")?;

        if let Some(method) = fields.method.as_deref() {
            writer.write_str(method)?;
        } else {
            writer.write_str("-")?;
        }
        writer.write_char(' ')?;
        if let Some(uri) = fields.uri.as_deref() {
            writer.write_str(uri)?;
        } else {
            writer.write_str("-")?;
        }
        writer.write_char(' ')?;
        if let Some(version) = fields.version.as_deref() {
            writer.write_str(version)?;
        } else {
            writer.write_str("-")?;
        }
        writer.write_str("\" ")?;

        write!(writer, "{} ", fields.status.unwrap_or(0))?;
        write!(writer, "{} ", fields.bytes_out.unwrap_or(0))?;

        let referer = fields.referer.as_deref().unwrap_or("");
        let referer = if referer.is_empty() { "-" } else { referer };
        Self::write_quoted(&mut writer, referer)?;
        writer.write_char(' ')?;

        let user_agent = fields.user_agent.as_deref().unwrap_or("");
        let user_agent = if user_agent.is_empty() {
            "-"
        } else {
            user_agent
        };
        Self::write_quoted(&mut writer, user_agent)?;

        if let Some(latency_ms) = fields.latency_ms {
            write!(writer, " latency_ms={latency_ms:.3}")?;
        }

        writer.write_char('\n')
    }
}

pub fn init_logging(
    system: &SystemLogConfig,
    access: &AccessLogConfig,
    audit: &AuditLogConfig,
    otel: Option<&OtelConfig>,
) -> Result<LogGuards> {
    use tracing_subscriber::filter::Directive;
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Layer;

    let mut system_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(system.level.clone()));
    // Prevent double output: access/audit targets are handled by dedicated layers.
    system_filter = system_filter
        .add_directive("access_log=off".parse::<Directive>()?)
        .add_directive("audit_log=off".parse::<Directive>()?);

    let system_layer = if system.format.eq_ignore_ascii_case("json") {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_file(false)
            .with_line_number(false)
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .with_filter(system_filter)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_file(false)
            .with_line_number(false)
            .pretty()
            .with_filter(system_filter)
            .boxed()
    };

    let (access_layer, access_guard) = if access.output.enabled {
        let (writer, guard, cleanup) =
            build_non_blocking_writer(&access.output, "access_log", true)?;
        if let Some(cleanup) = cleanup {
            spawn_rotation_cleanup(cleanup);
        }
        let filter = Targets::new().with_target("access_log", LevelFilter::INFO);
        let layer = if access.output.format.eq_ignore_ascii_case("json") {
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_writer(writer)
                .json()
                .with_current_span(false)
                .with_span_list(false)
                .with_filter(filter)
                .boxed()
        } else if access.output.format.eq_ignore_ascii_case("combined") {
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_writer(writer)
                .event_format(AccessLogCombinedFormat::default())
                .with_filter(filter)
                .boxed()
        } else {
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_writer(writer)
                .compact()
                .with_filter(filter)
                .boxed()
        };
        (layer, Some(guard))
    } else {
        (tracing_subscriber::layer::Identity::new().boxed(), None)
    };

    let (audit_layer, audit_guard) = if audit.output.enabled {
        let (writer, guard, cleanup) =
            build_non_blocking_writer(&audit.output, "audit_log", false)?;
        if let Some(cleanup) = cleanup {
            spawn_rotation_cleanup(cleanup);
        }
        let filter = Targets::new().with_target("audit_log", LevelFilter::INFO);
        let layer = if audit.output.format.eq_ignore_ascii_case("json") {
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_writer(writer)
                .json()
                .with_current_span(false)
                .with_span_list(false)
                .with_filter(filter)
                .boxed()
        } else {
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_writer(writer)
                .compact()
                .with_filter(filter)
                .boxed()
        };
        (layer, Some(guard))
    } else {
        (tracing_subscriber::layer::Identity::new().boxed(), None)
    };

    let (otel_layer, otel_guard) = match otel {
        Some(cfg) if cfg.enabled => {
            let (layer, guard) = build_otel_layer(cfg)?;
            (layer, Some(guard))
        }
        _ => (tracing_subscriber::layer::Identity::new().boxed(), None),
    };

    let combined = system_layer
        .and_then(access_layer)
        .and_then(audit_layer)
        .and_then(otel_layer)
        .boxed();

    tracing_subscriber::registry().with(combined).try_init()?;

    Ok(LogGuards {
        _access: access_guard,
        _audit: audit_guard,
        _otel: otel_guard,
    })
}

fn build_otel_layer(
    cfg: &OtelConfig,
) -> Result<(
    Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>,
    OtelGuard,
)> {
    use opentelemetry::global;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
    use tracing_subscriber::filter::Directive;
    use tracing_subscriber::Layer;

    global::set_text_map_propagator(TraceContextPropagator::new());

    if !cfg.headers.is_empty() {
        let mut entries = cfg
            .headers
            .iter()
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let encoded = entries
            .into_iter()
            .map(|(k, v)| {
                let v = url::form_urlencoded::byte_serialize(v.as_bytes())
                    .collect::<String>();
                format!("{k}={v}")
            })
            .collect::<Vec<_>>()
            .join(",");
        // opentelemetry-otlp currently reads headers from env vars for both gRPC and HTTP.
        std::env::set_var("OTEL_EXPORTER_OTLP_HEADERS", encoded.as_str());
        std::env::set_var("OTEL_EXPORTER_OTLP_TRACES_HEADERS", encoded.as_str());
    }

    let endpoint = cfg
        .endpoint
        .as_deref()
        .unwrap_or("http://localhost:4317")
        .trim();
    let endpoint = if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("http://{}", endpoint)
    };

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| anyhow::anyhow!("otel exporter build failed: {e}"))?;

    let sample_percent = cfg.sample_percent.min(100);
    let base = if sample_percent == 0 {
        Sampler::AlwaysOff
    } else if sample_percent >= 100 {
        Sampler::AlwaysOn
    } else {
        Sampler::TraceIdRatioBased((sample_percent as f64) / 100.0)
    };
    let sampler = Sampler::ParentBased(Box::new(base));

    let service_name = cfg.service_name.as_deref().unwrap_or("qpx").trim();
    let resource = opentelemetry_sdk::Resource::builder_empty()
        .with_service_name(service_name.to_string())
        .build();
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(sampler)
        .with_resource(resource)
        .build();
    global::set_tracer_provider(provider.clone());

    let tracer = global::tracer("qpx");
    let mut otel_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(cfg.level.clone()));
    otel_filter = otel_filter
        .add_directive("access_log=off".parse::<Directive>()?)
        .add_directive("audit_log=off".parse::<Directive>()?);
    let layer = tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_filter(otel_filter)
        .boxed();

    OTEL_ENABLED.store(true, Ordering::Relaxed);
    Ok((layer, OtelGuard { provider }))
}

pub fn extract_trace_context(headers: &http::HeaderMap) -> opentelemetry::Context {
    use opentelemetry::propagation::Extractor;

    if !otel_enabled() {
        return opentelemetry::Context::new();
    }

    struct HeaderExtractor<'a>(&'a http::HeaderMap);

    impl<'a> Extractor for HeaderExtractor<'a> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|v| v.to_str().ok())
        }

        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(|k| k.as_str()).collect()
        }
    }

    opentelemetry::global::get_text_map_propagator(|prop| prop.extract(&HeaderExtractor(headers)))
}

pub fn inject_trace_context(headers: &mut http::HeaderMap) {
    use opentelemetry::propagation::Injector;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    if !otel_enabled() {
        return;
    }

    struct HeaderInjector<'a>(&'a mut http::HeaderMap);

    impl<'a> Injector for HeaderInjector<'a> {
        fn set(&mut self, key: &str, value: String) {
            let Ok(name) = http::header::HeaderName::from_bytes(key.as_bytes()) else {
                return;
            };
            let Ok(value) = http::HeaderValue::from_str(value.as_str()) else {
                return;
            };
            self.0.insert(name, value);
        }
    }

    opentelemetry::global::get_text_map_propagator(|prop| {
        prop.inject_context(
            &tracing::Span::current().context(),
            &mut HeaderInjector(headers),
        );
    });
}

fn expand_tilde_path(input: &str) -> PathBuf {
    if let Some(stripped) = input.strip_prefix("~/") {
        if let Some(home) = dirs_next::home_dir() {
            return home.join(stripped);
        }
    }
    PathBuf::from(input)
}

struct RotationCleanup {
    dir: PathBuf,
    base_name: String,
    rotation: String,
    keep: usize,
}

fn build_non_blocking_writer(
    output: &LogOutputConfig,
    label: &'static str,
    lossy: bool,
) -> Result<(
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
    Option<RotationCleanup>,
)> {
    use tracing_appender::non_blocking::NonBlockingBuilder;
    use tracing_appender::rolling;

    let rotation = output.rotation.trim().to_ascii_lowercase();

    if let Some(path) = output.path.as_deref() {
        let path = expand_tilde_path(path.trim());
        let dir = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&dir).with_context(|| {
            format!("{label}: failed to create log directory {}", dir.display())
        })?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("{label}: log path must include a valid file name"))?
            .to_string();

        let appender = match rotation.as_str() {
            "hourly" => rolling::hourly(&dir, file_name.as_str()),
            "daily" => rolling::daily(&dir, file_name.as_str()),
            _ => rolling::never(&dir, file_name.as_str()),
        };
        let (writer, guard) = NonBlockingBuilder::default().lossy(lossy).finish(appender);

        let cleanup = if rotation != "never" {
            Some(RotationCleanup {
                dir,
                base_name: file_name,
                rotation,
                keep: output.rotation_count,
            })
        } else {
            None
        };
        if let Some(cleanup) = cleanup.as_ref() {
            cleanup_old_logs(cleanup);
        }
        return Ok((writer, guard, cleanup));
    }

    let (writer, guard) = NonBlockingBuilder::default()
        .lossy(lossy)
        .finish(std::io::stdout());
    Ok((writer, guard, None))
}

fn spawn_rotation_cleanup(cleanup: RotationCleanup) {
    let interval = if cleanup.rotation.eq_ignore_ascii_case("hourly") {
        Duration::from_secs(3600)
    } else {
        Duration::from_secs(86400)
    };
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let cleanup = RotationCleanup {
                    dir: cleanup.dir.clone(),
                    base_name: cleanup.base_name.clone(),
                    rotation: cleanup.rotation.clone(),
                    keep: cleanup.keep,
                };
                let _ = tokio::task::spawn_blocking(move || cleanup_old_logs(&cleanup)).await;
            }
        });
    }
}

fn cleanup_old_logs(cleanup: &RotationCleanup) {
    if cleanup.keep == 0 {
        return;
    }
    let prefix = format!("{}.", cleanup.base_name);
    let mut entries = match std::fs::read_dir(&cleanup.dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
            .filter(|name| name.starts_with(prefix.as_str()))
            .collect::<Vec<_>>(),
        Err(err) => {
            tracing::warn!(
                error = ?err,
                dir = %cleanup.dir.display(),
                "log cleanup failed"
            );
            return;
        }
    };
    if entries.len() <= cleanup.keep {
        return;
    }
    entries.sort();
    let remove_count = entries.len().saturating_sub(cleanup.keep);
    for name in entries.into_iter().take(remove_count) {
        let path = cleanup.dir.join(&name);
        if let Err(err) = std::fs::remove_file(&path) {
            tracing::warn!(
                error = ?err,
                file = %path.display(),
                "failed to remove old log file"
            );
        }
    }
}

pub fn start_metrics(config: &MetricsConfig) -> Result<()> {
    let listen: SocketAddr = config.listen.parse()?;
    let path = if config.path.starts_with('/') {
        config.path.clone()
    } else {
        format!("/{}", config.path)
    };
    let allow: Vec<IpCidr> = config
        .allow
        .iter()
        .map(|cidr| cidr.parse())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| anyhow::anyhow!("invalid metrics.allow CIDR"))?;
    let allow = std::sync::Arc::new(allow);
    let max_concurrent = config.max_concurrent_connections.max(1);
    let semaphore = std::sync::Arc::new(Semaphore::new(max_concurrent));

    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder)
        .map_err(|e| anyhow::anyhow!("metrics recorder install failed: {}", e))?;

    let runtime = tokio::runtime::Handle::try_current()
        .context("metrics endpoint requires running Tokio runtime")?;
    runtime.spawn(async move {
        let listener = match TcpListener::bind(listen).await {
            Ok(listener) => listener,
            Err(err) => {
                tracing::warn!(error = ?err, "failed to bind metrics listener");
                return;
            }
        };
        loop {
            let (mut stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::warn!(error = ?err, "metrics accept failed");
                    continue;
                }
            };
            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    let _ = timeout(
                        Duration::from_secs(1),
                        stream.write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbusy",
                        ),
                    )
                    .await;
                    let _ = timeout(Duration::from_secs(1), stream.shutdown()).await;
                    continue;
                }
            };
            let handle = handle.clone();
            let path = path.clone();
            let allow = allow.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let peer_ip = peer_addr.ip();
                let allowed = if peer_ip.is_loopback() {
                    true
                } else if allow.is_empty() {
                    false
                } else {
                    allow.iter().any(|cidr| cidr.contains(&peer_ip))
                };
                if !allowed {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nforbidden",
                        )
                        .await;
                    let _ = stream.shutdown().await;
                    return;
                }

                let request_path = match timeout(METRICS_READ_TIMEOUT, read_http_request_path(&mut stream)).await {
                    Ok(Ok(Some(path))) => path,
                    Ok(Ok(None)) => return,
                    Ok(Err(_)) | Err(_) => {
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbad request",
                            )
                            .await;
                        let _ = stream.shutdown().await;
                        return;
                    }
                };

                let (status, body, content_type) = if request_path == "/health" {
                    ("200 OK", "OK".to_string(), "text/plain; charset=utf-8")
                } else if request_path == path {
                    (
                        "200 OK",
                        handle.render(),
                        "text/plain; version=0.0.4; charset=utf-8",
                    )
                } else {
                    (
                        "404 Not Found",
                        "not found".to_string(),
                        "text/plain; charset=utf-8",
                    )
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok(())
}

async fn read_http_request_path(stream: &mut tokio::net::TcpStream) -> Result<Option<String>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        if buf.len().saturating_add(n) > MAX_METRICS_REQUEST_BYTES {
            return Err(anyhow::anyhow!("metrics request header too large"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_header_terminator(&buf) {
            return parse_request_path(&buf[..end]);
        }
    }
}

fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_request_path(raw_headers: &[u8]) -> Result<Option<String>> {
    let request = std::str::from_utf8(raw_headers)
        .map_err(|_| anyhow::anyhow!("metrics request is not valid utf-8"))?;
    let first = request.lines().next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty() || path.is_empty() || version.is_empty() {
        return Err(anyhow::anyhow!("malformed request line"));
    }
    if method != "GET" {
        return Err(anyhow::anyhow!("unsupported method"));
    }
    if !version.starts_with("HTTP/1.") {
        return Err(anyhow::anyhow!("unsupported http version"));
    }
    Ok(Some(path.to_string()))
}
