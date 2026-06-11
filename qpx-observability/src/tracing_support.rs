use anyhow::Result;
use qpx_core::config::OtelConfig;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing_subscriber::EnvFilter;

static OTEL_ENABLED: AtomicBool = AtomicBool::new(false);

/// Returns whether OpenTelemetry tracing is enabled.
pub fn otel_enabled() -> bool {
    OTEL_ENABLED.load(Ordering::Relaxed)
}

#[derive(Debug)]
pub(super) struct OtelGuard {
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        OTEL_ENABLED.store(false, Ordering::Relaxed);
        let _ = self.provider.force_flush();
        let _ = self.provider.shutdown();
    }
}

pub(super) fn build_otel_layer(
    cfg: &OtelConfig,
) -> Result<(
    Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>,
    OtelGuard,
)> {
    use opentelemetry::global;
    use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::Directive;

    global::set_text_map_propagator(TraceContextPropagator::new());

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

    let mut exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint);
    if !cfg.headers.is_empty() {
        let mut headers = http::HeaderMap::new();
        for (key, value) in &cfg.headers {
            let header_name = key.trim().parse::<http::HeaderName>().map_err(|err| {
                anyhow::anyhow!("invalid otel header metadata key {}: {err}", key.trim())
            })?;
            let header_value = value.trim().parse::<http::HeaderValue>().map_err(|err| {
                anyhow::anyhow!(
                    "invalid otel header metadata value for {}: {err}",
                    header_name.as_str()
                )
            })?;
            headers.insert(header_name, header_value);
        }
        let metadata =
            opentelemetry_otlp::tonic_types::metadata::MetadataMap::from_headers(headers);
        exporter = exporter.with_metadata(metadata);
    }
    let exporter = exporter
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
    let mut otel_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(cfg.level.clone()));
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

/// Extracts an OpenTelemetry trace context from HTTP headers.
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

/// Injects the current OpenTelemetry trace context into HTTP headers.
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
