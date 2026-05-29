use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::registry::LookupSpan;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct AccessLogCombinedFormat {
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
